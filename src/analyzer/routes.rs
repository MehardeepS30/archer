//! Route extraction: builder chains, scopes, resources, attribute routes, and guard/middleware evidence.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use syn::{
    Arm, BinOp, Block, Expr, ExprCall, ExprClosure, ExprForLoop, ExprIf, ExprLit, ExprMethodCall,
    ExprPath, ExprWhile, FnArg, ImplItemFn, Item, ItemFn, ItemMod, Lit, Pat, ReturnType, Signature,
    Stmt, TraitItemFn, Type, TypeParamBound,
    spanned::Spanned,
    visit::{self, Visit},
};

use super::{evidence::*, handlers::*, model::*};
use quote::ToTokens;

/// One lexical scope: a block, or the binding region of a function, closure,
/// loop, match arm, or `if let`/`while let`.
#[derive(Default)]
pub(crate) struct BlockScope {
    /// Value bindings in scope at the current point of the walk. A `let`
    /// binding is added only after its statement, so earlier statements and its
    /// own initializer are not shadowed.
    pub(crate) locals: HashSet<String>,
    /// Functions declared directly in a block. They are visible by bare name
    /// throughout that block, including before the declaration, but have no
    /// path and stay out of `HandlerIndex`. `None` marks a name that cannot be
    /// resolved to one function: a duplicate `fn`, or a `const`/`static`.
    pub(crate) items: HashMap<String, Option<Vec<AuthEvidence>>>,
    /// Builders bound to a variable in this block, such as `let admin =
    /// web::scope("/admin").wrap(AdminGuard);`, with any earlier binding they
    /// extend substituted in. Wherever the variable is used, the builder is
    /// read as if written there.
    pub(crate) builders: HashMap<String, Expr>,
    /// Bound builders not yet used; visited when the block ends so that
    /// their routes are not lost.
    pub(crate) unused_builders: Vec<String>,
}

impl BlockScope {
    pub(crate) fn with_locals(locals: HashSet<String>) -> Self {
        Self {
            locals,
            ..Self::default()
        }
    }
}

pub(crate) struct RouteVisitor<'a> {
    pub(crate) file: PathBuf,
    pub(crate) index: &'a HandlerIndex<'a>,
    pub(crate) crate_key: PathBuf,
    pub(crate) module: Vec<String>,
    pub(crate) block_scopes: Vec<BlockScope>,
    /// Guard and middleware evidence of the builder chains being visited,
    /// keyed by chain root: the current scope and its enclosing scopes.
    pub(crate) chain_scopes: Vec<(*const Expr, Vec<AuthEvidence>)>,
    pub(crate) scope_context: String,
    pub(crate) routes: Vec<Route>,
    pub(crate) registrations: Vec<Registration>,
    pub(crate) warnings: Vec<String>,
    /// Definitions named by a `.configure(f)` call. Routes found while
    /// visiting such a function on its own are replaced by its expansions.
    /// Each as `(caller, target)`: the module-level function making the call
    /// (`None` outside one) and the definition it expands.
    pub(crate) configured: Vec<(Option<usize>, usize)>,
    /// The module-level function being visited, outside any expansion.
    pub(crate) enclosing: Option<usize>,
    /// `.configure` targets being expanded, innermost last.
    pub(crate) expanding: Vec<usize>,
    /// Builder variables being read in place, innermost last.
    pub(crate) expanding_builders: Vec<String>,
    /// `.configure(<T as _>::configure)` calls naming a type, which may be a
    /// declared route table.
    pub(crate) table_mounts: Vec<super::route_tables::TableMount>,
    /// Loop variables bound to one string literal of the array a `for` loop
    /// walks, innermost last: `for p in ["/a", "/b"] { .. }` is read once per path.
    pub(crate) loop_values: Vec<(String, String)>,
    /// The project's own `macro_rules!` macros seen so far, by name.
    pub(crate) macros: HashMap<String, Vec<super::macros::Rule>>,
    /// Macro expansions being visited; bounds recursive macros.
    pub(crate) macro_depth: usize,
    /// Prefixes of enclosing `#[actix_web::scope("/p")] mod m { .. }` modules.
    pub(crate) module_scopes: Vec<String>,
    /// String fields of the project's constant route tables.
    pub(crate) field_paths: std::rc::Rc<FieldPaths>,
    /// Route-like call sites seen, by line: a route constructor such as
    /// `web::get()`, a `web::resource(..)`, or a route attribute, with the
    /// code as written. Sites no route was read from are reported.
    pub(crate) route_sites: std::collections::BTreeMap<(usize, usize), String>,
    /// Positions of route-like sites some route was read from.
    pub(crate) read_lines: HashSet<(usize, usize)>,
}

/// A `.service(handler)` call naming a function, with the scope it is made in.
#[derive(Debug, Clone)]
pub(crate) struct Registration {
    pub(crate) definition: usize,
    pub(crate) prefix: String,
    /// Guard and middleware evidence of the registering scope and its parents.
    pub(crate) inherited: Vec<AuthEvidence>,
    pub(crate) enclosing: Option<usize>,
}

impl<'a> RouteVisitor<'a> {
    pub(crate) fn new(file: PathBuf, index: &'a HandlerIndex<'a>) -> Self {
        let (crate_key, module) = index
            .file_modules
            .get(&file)
            .cloned()
            .unwrap_or_else(|| (file.clone(), Vec::new()));
        Self {
            file,
            index,
            crate_key,
            module,
            block_scopes: Vec::new(),
            chain_scopes: Vec::new(),
            scope_context: String::new(),
            routes: Vec::new(),
            registrations: Vec::new(),
            warnings: Vec::new(),
            configured: Vec::new(),
            enclosing: None,
            expanding: Vec::new(),
            expanding_builders: Vec::new(),
            table_mounts: Vec::new(),
            loop_values: Vec::new(),
            macros: HashMap::new(),
            macro_depth: 0,
            module_scopes: Vec::new(),
            field_paths: std::rc::Rc::default(),
            route_sites: std::collections::BTreeMap::new(),
            read_lines: HashSet::new(),
        }
    }

    /// The innermost builder bound to `name`, with the index of its block
    /// scope, unless a value binding shadows it.
    pub(crate) fn builder_binding(&self, name: &str) -> Option<(usize, &Expr)> {
        for (index, scope) in self.block_scopes.iter().enumerate().rev() {
            if let Some(builder) = scope.builders.get(name) {
                return Some((index, builder));
            }
            if scope.locals.contains(name) {
                return None;
            }
        }
        None
    }

    /// `expr` with the builder variable its chain starts from substituted,
    /// if it starts from one: `admin.route(..)` for `let admin =
    /// web::scope("/admin").wrap(G);` becomes `web::scope("/admin").wrap(G).route(..)`.
    pub(crate) fn substituted(&self, expr: &Expr) -> Option<Expr> {
        let Expr::Path(path) = chain_root_expr(expr) else {
            return None;
        };
        let name = path.path.get_ident()?.to_string();
        let (_, builder) = self.builder_binding(&name)?;
        Some(substitute_root(expr, builder))
    }

    /// A copy of a method call with builder variables substituted in its
    /// receiver chain and arguments (`.route("/x", admin_get.to(h))`), or
    /// `None` when it uses none.
    pub(crate) fn resolve_call(&self, node: &ExprMethodCall) -> Option<ExprMethodCall> {
        let receiver = self.substituted(&node.receiver);
        let arguments: Vec<Option<Expr>> =
            node.args.iter().map(|arg| self.substituted(arg)).collect();
        if receiver.is_none() && arguments.iter().all(Option::is_none) {
            return None;
        }
        let mut call = node.clone();
        if let Some(receiver) = receiver {
            call.receiver = Box::new(receiver);
        }
        for (slot, argument) in call.args.iter_mut().zip(arguments) {
            if let Some(argument) = argument {
                *slot = argument;
            }
        }
        Some(call)
    }

    /// The builder an expression evaluates to, with builder variables
    /// substituted, if it is one: a chain starting from `web::scope`,
    /// `web::resource`, a route constructor such as `web::get()`, `App::new()`,
    /// or a variable holding one of these.
    pub(crate) fn builder_value(&self, expr: &Expr) -> Option<Expr> {
        let value = match self.substituted(expr) {
            Some(substituted) => substituted,
            None => is_builder_constructor(chain_root_expr(expr)).then(|| expr.clone())?,
        };
        // A builder extended inside `for p in ["/a", "/b"]` is read later,
        // outside the loop: it keeps the literal `p` stood for here.
        if self.loop_values.is_empty() {
            return Some(value);
        }
        let tokens = replace_loop_values(value.to_token_stream(), &self.loop_values);
        Some(syn::parse2(tokens).unwrap_or(value))
    }

    /// Records `let name = <builder>;` or `name = <builder>;` instead of
    /// visiting it; the builder is read where the variable is used.
    pub(crate) fn bind_builder(&mut self, statement: &Stmt) -> bool {
        match statement {
            Stmt::Local(local) => {
                let Some(init) = &local.init else {
                    return false;
                };
                if init.diverge.is_some() {
                    return false;
                }
                let Some(name) = simple_binding(&local.pat) else {
                    return false;
                };
                let Some(builder) = self.builder_value(&init.expr) else {
                    return false;
                };
                self.mark_extended(&init.expr);
                // A builder rebinding the same name (`let s = s.route(..)`)
                // already contains the earlier one.
                let scope = self.block_scopes.last_mut().expect("inside a block");
                scope.builders.insert(name.clone(), builder);
                scope.unused_builders.retain(|unused| *unused != name);
                scope.unused_builders.push(name.clone());
                scope.locals.insert(name);
                true
            }
            Stmt::Expr(Expr::Assign(assign), _) => {
                let Some(name) = (match &*assign.left {
                    Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
                    _ => None,
                }) else {
                    return false;
                };
                let Some((index, _)) = self.builder_binding(&name) else {
                    return false;
                };
                let Some(builder) = self.builder_value(&assign.right) else {
                    return false;
                };
                self.mark_extended(&assign.right);
                let scope = &mut self.block_scopes[index];
                scope.builders.insert(name.clone(), builder);
                scope.unused_builders.retain(|unused| *unused != name);
                scope.unused_builders.push(name);
                true
            }
            _ => false,
        }
    }

    /// A builder extended into another (`let b = a.route(..)`) is used by it.
    fn mark_extended(&mut self, expr: &Expr) {
        if let Expr::Path(path) = chain_root_expr(expr)
            && let Some(name) = path.path.get_ident().map(ToString::to_string)
            && let Some((index, _)) = self.builder_binding(&name)
        {
            self.block_scopes[index]
                .unused_builders
                .retain(|unused| *unused != name);
        }
    }

    /// Drops a builder binding of the current block, first reading it in
    /// place if it was never used, so that its routes are still reported.
    fn retire_builder(&mut self, name: &str) {
        let scope = self.block_scopes.last_mut().expect("inside a block");
        let was_unused = scope.unused_builders.iter().any(|unused| unused == name);
        scope.unused_builders.retain(|unused| unused != name);
        let Some(builder) = scope.builders.get(name).cloned() else {
            return;
        };
        if was_unused {
            self.expanding_builders.push(name.to_string());
            <Self as Visit<'_>>::visit_expr(self, &builder);
            self.expanding_builders.pop();
        }
        self.block_scopes
            .last_mut()
            .expect("inside a block")
            .builders
            .remove(name);
    }

    /// The definition a `.service`/`.configure` argument names, unless it is
    /// a block-local function (which has no index entry).
    pub(crate) fn named_definition(&self, arg: &Expr) -> Option<usize> {
        let target = handler_target(arg)?;
        if self.block_local_handler(&target).is_some() {
            return None;
        }
        self.index
            .resolve_handler_index(&self.crate_key, &self.module, &target)
            .0
    }

    /// Visits the body of a `.configure(f)` target as if it were written at
    /// the call: under the caller's scope prefix and guard/middleware chain,
    /// resolving names from `f`'s own module. Recursive configuration stops.
    pub(crate) fn expand_configure(&mut self, definition: usize) {
        self.configured.push((self.enclosing, definition));
        if self.expanding.contains(&definition) {
            return;
        }
        let index = self.index;
        let target = &index.definitions[definition];
        let item = &index.items[definition];
        let file = std::mem::replace(&mut self.file, target.file.clone());
        let crate_key = std::mem::replace(&mut self.crate_key, target.crate_key.clone());
        let module = std::mem::replace(&mut self.module, target.module.clone());
        let block_scopes = std::mem::take(&mut self.block_scopes);
        self.expanding.push(definition);
        self.with_locals(signature_bindings(&item.sig), |visitor| {
            visitor.visit_block(&item.block)
        });
        self.expanding.pop();
        self.block_scopes = block_scopes;
        self.module = module;
        self.crate_key = crate_key;
        self.file = file;
    }

    /// Looks a bare handler name up in the enclosing scopes, innermost first;
    /// within a scope, local bindings shadow block items. `None` means no scope
    /// declares the name; `Some(None)` means the innermost declaring scope binds
    /// it to a local value or to more than one item, so it must not resolve.
    pub(crate) fn block_local_handler(
        &self,
        target: &HandlerTarget,
    ) -> Option<Option<&[AuthEvidence]>> {
        let HandlerTarget::Path {
            segments,
            leading_colon: false,
        } = target
        else {
            return None;
        };
        let [name] = segments.as_slice() else {
            return None;
        };
        self.block_scopes.iter().rev().find_map(|scope| {
            if scope.locals.contains(name) {
                Some(None)
            } else {
                scope.items.get(name).map(Option::as_deref)
            }
        })
    }

    pub(crate) fn with_locals(&mut self, locals: HashSet<String>, visit: impl FnOnce(&mut Self)) {
        self.block_scopes.push(BlockScope::with_locals(locals));
        visit(self);
        self.block_scopes.pop();
    }

    /// Visits an `if`/`while` condition. In a `let` chain, each operand sees
    /// the bindings of the `let`s before it, but not its own.
    pub(crate) fn visit_condition(&mut self, condition: &Expr, bound: &mut HashSet<String>) {
        match condition {
            Expr::Binary(binary) if matches!(binary.op, BinOp::And(_)) => {
                self.visit_condition(&binary.left, bound);
                self.visit_condition(&binary.right, bound);
            }
            Expr::Let(expr_let) => {
                self.with_locals(bound.clone(), |visitor| visitor.visit_expr(&expr_let.expr));
                pattern_bindings(&expr_let.pat, bound);
            }
            other => self.with_locals(bound.clone(), |visitor| visitor.visit_expr(other)),
        }
    }

    /// Guard and middleware evidence of the scopes currently being visited.
    pub(crate) fn inherited_evidence(&self) -> Vec<AuthEvidence> {
        self.chain_scopes
            .iter()
            .flat_map(|(_, evidence)| evidence.iter().cloned())
            .collect()
    }

    /// Records `.service(handler)` when `handler` names a module-level
    /// function. Actix also accepts a tuple of services, `.service((a, b))`,
    /// and the `services![a, b]` macro that builds one; each element counts.
    pub(crate) fn add_registration(&mut self, arg: &Expr) {
        match arg {
            Expr::Tuple(tuple) => {
                return tuple
                    .elems
                    .iter()
                    .for_each(|element| self.add_registration(element));
            }
            Expr::Array(array) => {
                return array
                    .elems
                    .iter()
                    .for_each(|element| self.add_registration(element));
            }
            Expr::Paren(paren) => return self.add_registration(&paren.expr),
            Expr::Group(group) => return self.add_registration(&group.expr),
            Expr::Macro(mac) => {
                // `services![a, b]`, `vec![a, b]`, or a project macro that
                // expands to the registered expression.
                if let Some(statements) = self.macro_expansion(&mac.mac) {
                    self.macro_depth += 1;
                    for statement in &statements {
                        if let Stmt::Expr(expr, _) = statement {
                            self.add_registration(expr);
                        }
                    }
                    self.macro_depth -= 1;
                }
                return;
            }
            _ => {}
        }
        let Some(definition) = self.named_definition(arg) else {
            return;
        };
        self.registrations.push(Registration {
            definition,
            prefix: self.scope_context.clone(),
            inherited: self.inherited_evidence(),
            enclosing: self.enclosing,
        });
    }

    pub(crate) fn add_route(&mut self, node: &ExprMethodCall) {
        let name = node.method.to_string();
        // `web::resource("/path").get(handler)`: Resource's per-method
        // shorthand for `.route(web::get().to(handler))`.
        let shorthand =
            ROUTE_METHOD_CONSTRUCTORS.contains(&name.as_str()) && node.args.len() == 1;
        // `web::service("/p").finish(handler)`: a `WebService` answering every method.
        let finish = name == "finish" && node.args.len() == 1;
        if name != "route" && name != "resource" && name != "to" && !shorthand && !finish {
            return;
        }
        // Builders held in variables are read as if written in place.
        let resolved = self.resolve_call(node);
        let node = resolved.as_ref().unwrap_or(node);

        // `cfg.route("/path", builder)` names its path; `web::resource("/path")
        // .route(builder)`, `web::resource("/path").to(handler)` and
        // `web::resource("/path").get(handler)` take it from the resource the
        // chain starts from, one route per path of `web::resource(["/a", "/b"])`.
        let paths = if name == "to" || shorthand || finish || (name == "route" && node.args.len() != 2) {
            self.resource_paths(&node.receiver)
        } else if name == "route" {
            self.path_argument(&node.args[0]).map(|path| vec![path])
        } else {
            first_string_arg(&node.args)
                .zip(first_string_arg_line(&node.args))
                .map(|path| vec![path])
        };
        // A shorthand's receiver must be a resource, so `map.get(key)` has
        // no path and is not a route.
        let Some(paths) = paths.filter(|paths| !paths.is_empty()) else {
            return;
        };
        let handler_call = name == "to" || shorthand || finish;

        let local_prefix = self.scope_prefix(&node.receiver);
        let prefix = join_paths(&self.scope_context, &local_prefix);
        // A resource's own `.to(handler)` answers every method.
        let target = if handler_call {
            node.args
                .first()
                .map(|arg| handler_target(arg).unwrap_or(HandlerTarget::Other))
        } else {
            find_handler(&node.args)
        };
        let closure = if handler_call {
            node.args.first().and_then(as_closure)
        } else {
            find_handler_closure(&node.args)
        };
        let mut resolved_definition = None;
        let (handler_evidence, handler_resolution) = match &target {
            None => (Vec::new(), None),
            Some(HandlerTarget::Other) if closure.is_some() => (
                closure_evidence(&self.file, closure.expect("checked above"), "<closure>"),
                Some(HandlerResolution::Closure),
            ),
            Some(target) => match self.block_local_handler(target) {
                Some(Some(evidence)) => (evidence.to_vec(), Some(HandlerResolution::Local)),
                Some(None) => (Vec::new(), Some(HandlerResolution::Unresolved)),
                None => {
                    let (definition, resolution) =
                        self.index
                            .resolve_handler_index(&self.crate_key, &self.module, target);
                    resolved_definition = definition;
                    (
                        definition.map_or_else(Vec::new, |definition| {
                            self.index.definitions[definition].evidence.clone()
                        }),
                        Some(resolution),
                    )
                }
            },
        };
        let handler = target.as_ref().and_then(HandlerTarget::name);
        let written = target.as_ref().and_then(HandlerTarget::written);
        let unverified = match (&target, &handler_resolution) {
            (Some(HandlerTarget::Other), Some(HandlerResolution::Closure)) => Vec::new(),
            (Some(HandlerTarget::Other), _) => {
                vec!["handler is an expression Archer cannot follow".to_string()]
            }
            (_, Some(HandlerResolution::Ambiguous { .. })) => vec![format!(
                "handler `{}` matches several definitions",
                written.as_deref().unwrap_or("?")
            )],
            (_, Some(HandlerResolution::Unresolved)) => vec![format!(
                "handler `{}` could not be resolved",
                written.as_deref().unwrap_or("?")
            )],
            _ => Vec::new(),
        };
        let mut authorization =
            classify_authorization(node, handler.as_deref(), &handler_evidence, &self.file);
        // Middleware and guards of this route's scope, wherever they appear in
        // its builder chain, and of every enclosing scope. Evidence already
        // found on the route's own receiver chain is not repeated.
        add_inherited_evidence(
            &mut authorization,
            &self.inherited_evidence(),
            handler.as_deref(),
        );

        // `web::resource(p).guard(guard::Method(Method::GET)).to(h)`: the
        // resource's method guards decide what its handler answers.
        let methods = if shorthand {
            vec![name.to_uppercase()]
        } else if name == "to" || name == "finish" {
            vec![resource_guard_method(&node.receiver).unwrap_or_else(|| "UNKNOWN".into())]
        } else {
            node.args
                .last()
                .and_then(route_builder_methods)
                .unwrap_or_else(|| vec!["UNKNOWN".into()])
        };
        // The route-like sites this route was read from.
        if !handler_call
            && let Some(builder) = node.args.last()
        {
            self.read_lines.insert(span_position(chain_root_expr(builder).span()));
        }
        for (method, (path, path_line)) in methods
            .iter()
            .flat_map(|method| paths.iter().map(move |path| (method, path.clone())))
        {
            self.routes.push(Route {
                method: method.clone(),
                path: join_paths(&prefix, &path),
                scope_prefix: prefix.clone(),
                handler: handler.clone(),
                handler_path: written.clone(),
                handler_resolution: handler_resolution.clone(),
                authorization: authorization.clone(),
                line: path_line,
                file: self.file.clone(),
                unverified: unverified.clone(),
                requirement: Requirement::default(),
                resource_keys: Vec::new(),
                caller_use: Vec::new(),
                origin: RouteOrigin {
                    position: span_position(node.method.span()),
                    attribute: None,
                    enclosing: self.enclosing,
                    definition: resolved_definition,
                    called: Vec::new(),
                    takes_credentials: false,
                },
            });
        }
    }
}

impl<'ast> Visit<'ast> for RouteVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.add_attribute_routes(node);
        let enclosing = self.enclosing;
        if self.block_scopes.is_empty() && self.expanding.is_empty() {
            self.enclosing = self.index.definition_in(
                &self.crate_key,
                &self.module,
                &node.sig.ident.to_string(),
            );
        }
        self.with_locals(signature_bindings(&node.sig), |visitor| {
            visit::visit_item_fn(visitor, node)
        });
        self.enclosing = enclosing;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.with_locals(signature_bindings(&node.sig), |visitor| {
            visit::visit_impl_item_fn(visitor, node)
        });
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        self.with_locals(signature_bindings(&node.sig), |visitor| {
            visit::visit_trait_item_fn(visitor, node)
        });
    }

    /// A direct call to a function that registers or builds routes, such as
    /// `admin::config(cfg)` or `.service(admin_scope())`, is expanded at the
    /// call, like `.configure(f)`: its routes take the caller's scope prefix
    /// and middleware.
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if is_route_site(&node.func) {
            let text: String = node.to_token_stream().to_string().chars().take(60).collect();
            self.route_sites.entry(span_position(node.span())).or_insert(text);
        }
        if let Some(definition) = self.named_definition(&node.func)
            && is_route_factory(&self.index.items[definition].sig)
        {
            self.expand_configure(definition);
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast ExprClosure) {
        let mut locals = HashSet::new();
        for input in &node.inputs {
            pattern_bindings(input, &mut locals);
        }
        self.with_locals(locals, |visitor| visit::visit_expr_closure(visitor, node));
    }

    fn visit_expr_for_loop(&mut self, node: &'ast ExprForLoop) {
        self.visit_expr(&node.expr);
        let mut locals = HashSet::new();
        pattern_bindings(&node.pat, &mut locals);
        // `for p in ["/a", "/b"] { cfg.route(p, ..) }`: the body is read once
        // per literal, with `p` standing for it.
        if let (Some(name), Some(values)) = (simple_binding(&node.pat), literal_strings(&node.expr)) {
            for value in values {
                self.loop_values.push((name.clone(), value));
                self.with_locals(locals.clone(), |visitor| visitor.visit_block(&node.body));
                self.loop_values.pop();
            }
            return;
        }
        self.with_locals(locals, |visitor| visitor.visit_block(&node.body));
    }

    fn visit_file(&mut self, node: &'ast syn::File) {
        set_import_aliases(node);
        visit::visit_file(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if node.mac.path.is_ident("macro_rules") {
            if let Some(name) = &node.ident {
                let rules = super::macros::parse_rules(&node.mac.tokens);
                if !rules.is_empty() {
                    self.macros.insert(name.to_string(), rules);
                }
            }
            return;
        }
        self.visit_macro_tokens(&node.mac);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        self.visit_macro_tokens(&node.mac);
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        self.visit_macro_tokens(&node.mac);
    }

    fn visit_arm(&mut self, node: &'ast Arm) {
        // The pattern's bindings cover its guard (part of the pattern) and body.
        let mut locals = HashSet::new();
        pattern_bindings(&node.pat, &mut locals);
        self.with_locals(locals, |visitor| visit::visit_arm(visitor, node));
    }

    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        let mut bound = HashSet::new();
        self.visit_condition(&node.cond, &mut bound);
        self.with_locals(bound, |visitor| visitor.visit_block(&node.then_branch));
        if let Some((_, else_branch)) = &node.else_branch {
            self.visit_expr(else_branch);
        }
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        let mut bound = HashSet::new();
        self.visit_condition(&node.cond, &mut bound);
        self.with_locals(bound, |visitor| visitor.visit_block(&node.body));
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if node.content.is_some() {
            // Items of an enclosing function block are not visible inside a module.
            let block_scopes = std::mem::take(&mut self.block_scopes);
            self.module.push(node.ident.to_string());
            let scope = node.attrs.iter().find_map(scope_attribute);
            let scoped = scope.is_some();
            if let Some(prefix) = scope {
                self.module_scopes.push(prefix);
            }
            visit::visit_item_mod(self, node);
            if scoped {
                self.module_scopes.pop();
            }
            self.module.pop();
            self.block_scopes = block_scopes;
        }
    }

    fn visit_block(&mut self, node: &'ast Block) {
        let mut scope = BlockScope::default();
        for statement in &node.stmts {
            match statement {
                Stmt::Item(Item::Fn(function)) => {
                    scope
                        .items
                        .entry(function.sig.ident.to_string())
                        .and_modify(|entry| *entry = None)
                        .or_insert_with(|| Some(handler_evidence(&self.file, function)));
                }
                Stmt::Item(Item::Const(item)) => {
                    scope.items.insert(item.ident.to_string(), None);
                }
                Stmt::Item(Item::Static(item)) => {
                    scope.items.insert(item.ident.to_string(), None);
                }
                _ => {}
            }
        }
        self.block_scopes.push(scope);
        for statement in &node.stmts {
            if self.bind_builder(statement) {
                continue;
            }
            if let Stmt::Local(local) = statement {
                // A value binding shadows a builder of the same name; an
                // unused builder is read before it goes out of reach.
                let mut names = HashSet::new();
                pattern_bindings(&local.pat, &mut names);
                for name in names {
                    self.retire_builder(&name);
                }
            }
            self.visit_stmt(statement);
            if let Stmt::Local(local) = statement {
                let scope = self
                    .block_scopes
                    .last_mut()
                    .expect("block scope pushed above");
                pattern_bindings(&local.pat, &mut scope.locals);
            }
        }
        let unused = std::mem::take(
            &mut self
                .block_scopes
                .last_mut()
                .expect("block scope pushed above")
                .unused_builders,
        );
        for name in unused {
            if let Some(builder) = self
                .block_scopes
                .last()
                .and_then(|scope| scope.builders.get(&name))
                .cloned()
            {
                self.expanding_builders.push(name);
                <Self as Visit<'_>>::visit_expr(self, &builder);
                self.expanding_builders.pop();
            }
        }
        self.block_scopes.pop();
    }

    /// A variable that holds a builder is read as the builder, here.
    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        if let Some(name) = node.path.get_ident().map(ToString::to_string)
            && !self.expanding_builders.contains(&name)
            && let Some((scope, builder)) = self.builder_binding(&name)
        {
            let builder = builder.clone();
            self.block_scopes[scope]
                .unused_builders
                .retain(|unused| *unused != name);
            self.expanding_builders.push(name);
            <Self as Visit<'_>>::visit_expr(self, &builder);
            self.expanding_builders.pop();
            return;
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        // The outermost call of a builder chain is visited first; collect the
        // chain's guards and middleware there so that every route in the chain,
        // and in scopes nested under it, receives them.
        let root = chain_root(node);
        let starts_chain = self.chain_scopes.last().map(|(chain, _)| *chain) != Some(root);
        if starts_chain {
            let resolved = self.resolve_call(node);
            let evidence =
                chain_configuration_evidence(resolved.as_ref().unwrap_or(node), &self.file);
            self.chain_scopes.push((root, evidence));
        }

        // `.default_service(web::route().to(not_found))`: the fallback for
        // unmatched requests, not a route, so its constructor is accounted for.
        if node.method == "default_service"
            && let Some(arg) = node.args.first()
        {
            self.read_lines.insert(span_position(chain_root_expr(arg).span()));
        }
        if node.method == "service" || node.method == "configure" {
            let previous_context = self.scope_context.clone();
            self.scope_context = join_paths(&previous_context, &self.scope_prefix(&node.receiver));
            for arg in &node.args {
                if node.method == "service" {
                    self.add_registration(arg);
                } else if let Some(definition) = self.named_definition(arg) {
                    // `.configure(f)` or a closure that only forwards to it,
                    // `.configure(|c| f(c))`: expanded once, here. Visiting
                    // the closure's body would expand `f` a second time.
                    self.expand_configure(definition);
                    continue;
                } else if let Some(segments) = super::route_tables::configured_type(arg) {
                    self.table_mounts.push(super::route_tables::TableMount {
                        segments,
                        crate_key: self.crate_key.clone(),
                        module: self.module.clone(),
                        prefix: self.scope_context.clone(),
                        inherited: self.inherited_evidence(),
                        enclosing: self.enclosing,
                    });
                }
                self.visit_expr(arg);
            }
            self.scope_context = previous_context;
            self.visit_expr(&node.receiver);
        } else {
            self.add_route(node);
            visit::visit_expr_method_call(self, node);
        }

        if starts_chain {
            self.chain_scopes.pop();
        }
    }
}

impl RouteVisitor<'_> {
    /// The code a macro invocation stands for, when Archer can read it: a
    /// project `macro_rules!` macro expanded, or the comma-separated
    /// expressions of `services![..]`/`vec![..]`.
    pub(crate) fn macro_expansion(&self, mac: &syn::Macro) -> Option<Vec<Stmt>> {
        let name = mac.path.segments.last()?.ident.to_string();
        let tokens = match self.macros.get(&name) {
            Some(rules) if self.macro_depth < 8 => super::macros::expand(rules, &mac.tokens)?,
            _ if name == "services" || name == "vec" => {
                let elements = mac
                    .parse_body_with(
                        syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
                    )
                    .ok()?;
                return Some(
                    elements
                        .into_iter()
                        .map(|element| Stmt::Expr(element, Some(Default::default())))
                        .collect(),
                );
            }
            _ => return None,
        };
        let braced = quote::quote!({ #tokens });
        syn::parse2::<Block>(braced).ok().map(|block| block.stmts)
    }

    /// Visits the code a macro invocation stands for, in place.
    pub(crate) fn visit_macro_tokens(&mut self, mac: &syn::Macro) {
        let Some(statements) = self.macro_expansion(mac) else {
            return;
        };
        self.macro_depth += 1;
        for statement in &statements {
            match statement {
                Stmt::Item(item) => self.visit_item(item),
                Stmt::Expr(expr, _) => self.visit_expr(expr),
                Stmt::Local(local) => self.visit_local(local),
                Stmt::Macro(mac) => self.visit_stmt_macro(mac),
            }
        }
        self.macro_depth -= 1;
    }

    pub(crate) fn add_attribute_routes(&mut self, node: &ItemFn) {
        let module_prefix = self
            .module_scopes
            .iter()
            .fold(String::new(), |prefix, scope| join_paths(&prefix, scope));
        for (method, path_literal) in node.attrs.iter().flat_map(attribute_routes) {
            let prefix = self.scope_context.clone();
            // `path = "crate::ROUTES.auth.login"`: a field of a constant
            // route table, which a codegen fork resolves at compile time.
            let written = path_literal.value();
            let literal_path = if written.is_empty() || written.starts_with('/') {
                written
            } else {
                match self.field_paths.resolve(&written) {
                    Some(value) => value,
                    None => {
                        self.warnings.push(format!(
                            "{}:{}: path `{}` is not a string literal or resolvable const",
                            self.file.display(),
                            path_literal.span().start().line,
                            written
                        ));
                        format!("<unresolved:{written}>")
                    }
                }
            };
            let position = span_position(path_literal.span());
            self.route_sites.entry(position).or_insert_with(|| format!("#[{}(..)]", method.to_lowercase()));
            self.read_lines.insert(position);
            // `#[scope("/api")] mod api { #[get("/a")] .. }` serves `/api/a`.
            let attribute_path = join_paths(&module_prefix, &literal_path);
            let path = join_paths(&prefix, &attribute_path);
            let handler = node.sig.ident.to_string();
            // Only module-level functions can be named by `.service(handler)`.
            let definition = if self.block_scopes.is_empty() {
                self.index
                    .definition_in(&self.crate_key, &self.module, &handler)
            } else {
                None
            };
            // The index's evidence includes the handler's helpers.
            let mut authorization = definition.map_or_else(
                || handler_evidence(&self.file, node),
                |definition| self.index.definitions[definition].evidence.clone(),
            );
            authorization.extend(attribute_option_evidence(&node.attrs, &self.file, &handler));

            self.routes.push(Route {
                method,
                path,
                scope_prefix: prefix,
                authorization,
                handler_path: Some(handler.clone()),
                handler_resolution: Some(HandlerResolution::Definition),
                handler: Some(handler),
                line: path_literal.span().start().line,
                file: self.file.clone(),
                unverified: Vec::new(),
                requirement: Requirement::default(),
                resource_keys: Vec::new(),
                caller_use: Vec::new(),
                origin: RouteOrigin {
                    position: span_position(path_literal.span()),
                    attribute: definition.map(|definition| (definition, attribute_path.clone())),
                    enclosing: None,
                    definition,
                    called: Vec::new(),
                    takes_credentials: false,
                },
            });
        }
    }
}

/// Middleware and guards a route attribute names in its options:
/// `#[get("/p", wrap = "AuthMiddleware", guard = "is_admin")]`. Each string
/// is read as the expression it names and classified like a `.wrap(..)` or
/// `.guard(..)` argument.
fn attribute_option_evidence(
    attrs: &[syn::Attribute],
    file: &Path,
    handler: &str,
) -> Vec<AuthEvidence> {
    let mut evidence = Vec::new();
    for attribute in attrs {
        if attribute_routes(attribute).is_empty() {
            continue;
        }
        let Ok(args) = attribute
            .parse_args_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)
        else {
            continue;
        };
        for arg in &args {
            let Expr::Assign(assign) = arg else {
                continue;
            };
            let (Expr::Path(key), Expr::Lit(ExprLit { lit: Lit::Str(value), .. })) =
                (&*assign.left, &*assign.right)
            else {
                continue;
            };
            let Some(key) = key.path.get_ident().map(ToString::to_string) else {
                continue;
            };
            if key != "wrap" && key != "guard" {
                continue;
            }
            let Ok(call) = syn::parse_str::<ExprMethodCall>(&format!("route.{key}({})", value.value()))
            else {
                continue;
            };
            let start = evidence.len();
            configuration_call_evidence(&call, file, Some(handler), &mut evidence);
            for found in &mut evidence[start..] {
                found.line = value.span().start().line;
            }
        }
    }
    evidence
}

/// The routes an Actix route attribute declares, as `(method, path)`:
/// `#[get("/p")]`, `#[actix_web::get("/p", wrap = "...")]`, or
/// `#[route("/p", method = "GET", method = "POST")]` (one route per method).
pub(crate) fn attribute_routes(attribute: &syn::Attribute) -> Vec<(String, syn::LitStr)> {
    let segments: Vec<String> = attribute
        .path()
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    // `#[get(..)]`, `#[actix_web::get(..)]`, or a re-export or fork of the
    // codegen crate such as `#[my_codegen::get(..)]`.
    let Some(name) = segments.last() else {
        return Vec::new();
    };
    let fixed_method = match name.as_str() {
        "get" => Some("GET"),
        "post" => Some("POST"),
        "put" => Some("PUT"),
        "patch" => Some("PATCH"),
        "delete" => Some("DELETE"),
        "head" => Some("HEAD"),
        "route" => None,
        _ => return Vec::new(),
    };
    let Ok(args) = attribute
        .parse_args_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)
    else {
        return Vec::new();
    };
    // The path is the first argument, or a `path = ".."` option.
    let path = match args.first() {
        Some(Expr::Lit(ExprLit {
            lit: Lit::Str(path),
            ..
        })) => path.clone(),
        _ => match args.iter().find_map(|arg| match arg {
            Expr::Assign(assign) => match (&*assign.left, &*assign.right) {
                (
                    Expr::Path(key),
                    Expr::Lit(ExprLit {
                        lit: Lit::Str(path),
                        ..
                    }),
                ) if key.path.is_ident("path") => Some(path.clone()),
                _ => None,
            },
            _ => None,
        }) {
            Some(path) => path,
            None => return Vec::new(),
        },
    };
    let methods: Vec<String> = match fixed_method {
        Some(method) => vec![method.to_owned()],
        None => args
            .iter()
            .skip(1)
            .filter_map(|arg| match arg {
                Expr::Assign(assign) => match (&*assign.left, &*assign.right) {
                    (
                        Expr::Path(key),
                        Expr::Lit(ExprLit {
                            lit: Lit::Str(method),
                            ..
                        }),
                    ) if key.path.is_ident("method") => Some(method.value().to_uppercase()),
                    _ => None,
                },
                _ => None,
            })
            .collect(),
    };
    methods
        .into_iter()
        .map(|method| (method, path.clone()))
        .collect()
}

pub(crate) fn first_string_arg(
    args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<String> {
    let first = args.first()?;
    match first {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Some(s.value()),
        _ => None,
    }
}

pub(crate) fn first_string_arg_line(
    args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<usize> {
    let first = args.first()?;
    match first {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Some(s.span().start().line),
        _ => None,
    }
}

/// Method-specific `Route` constructors provided by `actix_web::web`.
pub(crate) const ROUTE_METHOD_CONSTRUCTORS: [&str; 7] =
    ["get", "post", "put", "patch", "delete", "head", "trace"];

/// `http::Method` constants accepted by `web::method(...)` and `Route::method(...)`.
pub(crate) const HTTP_METHOD_CONSTANTS: [&str; 9] = [
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Reads the HTTP method from a route's builder (its last argument). Only the
/// builder's own call chain is followed, so calls nested in guard, handler, or
/// configuration arguments cannot supply the method.
#[cfg(test)]
pub(crate) fn extract_http_method(expr: &ExprMethodCall) -> String {
    expr.args
        .last()
        .and_then(route_builder_method)
        .unwrap_or_else(|| "UNKNOWN".into())
}

#[cfg(test)]
pub(crate) fn route_builder_method(builder: &Expr) -> Option<String> {
    match route_builder_methods(builder)?.as_slice() {
        [method] => Some(method.clone()),
        _ => None,
    }
}

/// The methods a route builder answers: one for `web::get()`, several for
/// `web::route().guard(guard::Any(guard::Get()).or(guard::Post()))`.
pub(crate) fn route_builder_methods(builder: &Expr) -> Option<Vec<String>> {
    let mut methods: Vec<Vec<String>> = Vec::new();
    let mut expr = builder;
    let root = loop {
        match expr {
            Expr::MethodCall(call) => {
                // `Route::method` and a method guard (`.guard(guard::Get())`)
                // constrain the method; other builder calls do not.
                if call.method == "method" {
                    methods.push(vec![method_constant(call.args.first()?)?]);
                } else if call.method == "guard"
                    && let Some(method) = call.args.first().and_then(method_guards)
                {
                    methods.push(method);
                }
                expr = &call.receiver;
            }
            Expr::Paren(paren) => expr = &paren.expr,
            Expr::Group(group) => expr = &group.expr,
            Expr::Call(call) => break call,
            _ => return None,
        }
    };

    let Expr::Path(function) = &*root.func else {
        return None;
    };
    if function.qself.is_some() {
        return None;
    }
    let segments: Vec<String> = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let (name, module) = segments.split_last()?;
    let name = unalias(name);
    let module: Vec<&str> = module.iter().map(String::as_str).collect();
    // `web::get`, `actix_web::web::get`, or a re-export such as
    // `paperclip::actix::web::get`.
    let web_function = matches!(module.as_slice(), [] | [.., "web"]);
    let any_method_route = (web_function && name == "route")
        || (matches!(module.as_slice(), ["Route"] | ["actix_web", "Route"]) && name == "new");

    if web_function && ROUTE_METHOD_CONSTRUCTORS.contains(&name.as_str()) {
        methods.push(vec![name.to_uppercase()]);
    } else if web_function && name == "method" {
        methods.push(vec![method_constant(root.args.first()?)?]);
    } else if !any_method_route {
        // Not a recognized `Route` constructor.
        return None;
    }

    methods.dedup();
    match methods.as_slice() {
        [method] => Some(method.clone()),
        // An any-method route without a method guard, or conflicting guards.
        _ => None,
    }
}

/// A method guard, or `guard::Any(a).or(b)..` over method guards.
fn method_guards(expr: &Expr) -> Option<Vec<String>> {
    if let Expr::MethodCall(call) = expr
        && call.method == "or"
    {
        let mut methods = method_guards(&call.receiver)?;
        methods.extend(method_guards(call.args.first()?)?);
        methods.dedup();
        return Some(methods);
    }
    if let Expr::Call(call) = expr
        && let Expr::Path(function) = &*call.func
        && function.path.segments.last().is_some_and(|segment| segment.ident == "Any")
    {
        return method_guards(call.args.first()?);
    }
    method_guard(expr).map(|method| vec![method])
}

/// Reads a method guard: `guard::Get()`, `actix_web::guard::Post()`, or
/// `guard::Method(Method::PUT)`. Other guards return `None`.
/// The one method a resource's own `.guard(..)` calls restrict it to.
pub(crate) fn resource_guard_method(receiver: &Expr) -> Option<String> {
    let mut methods = Vec::new();
    let mut expr = receiver;
    while let Expr::MethodCall(call) = expr {
        if call.method == "guard"
            && let Some(method) = call.args.first().and_then(method_guard)
        {
            methods.push(method);
        }
        expr = &call.receiver;
    }
    methods.dedup();
    match methods.as_slice() {
        [method] => Some(method.clone()),
        _ => None,
    }
}

pub(crate) fn method_guard(expr: &Expr) -> Option<String> {
    let Expr::Call(call) = expr else {
        return None;
    };
    let Expr::Path(function) = &*call.func else {
        return None;
    };
    let segments: Vec<String> = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let (name, module) = segments.split_last()?;
    let module: Vec<&str> = module.iter().map(String::as_str).collect();
    if !matches!(module.as_slice(), [] | [.., "guard"]) {
        return None;
    }
    if name == "Method" {
        return method_constant(call.args.first()?);
    }
    // `guard::Get`, not `guard::GET` or `guard::get`, which are not guards.
    let method = name.to_uppercase();
    let camel: String = method
        .chars()
        .take(1)
        .chain(method.chars().skip(1).flat_map(char::to_lowercase))
        .collect();
    (HTTP_METHOD_CONSTANTS.contains(&method.as_str()) && *name == camel).then_some(method)
}

/// Reads `Method::PUT`, `http::Method::PUT`, or `actix_web::http::Method::PUT`.
pub(crate) fn method_constant(expr: &Expr) -> Option<String> {
    let Expr::Path(path) = expr else {
        return None;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    match segments.as_slice() {
        [.., kind, method]
            if kind == "Method" && HTTP_METHOD_CONSTANTS.contains(&method.as_str()) =>
        {
            Some(method.clone())
        }
        _ => None,
    }
}

pub(crate) fn classify_authorization(
    route_expr: &ExprMethodCall,
    handler: Option<&str>,
    handler_evidence: &[AuthEvidence],
    file: &Path,
) -> Vec<AuthEvidence> {
    let mut evidence = route_configuration_evidence(route_expr, file, handler);
    evidence.extend(handler_evidence.iter().cloned());
    evidence
}

pub(crate) fn route_configuration_evidence(
    route_expr: &ExprMethodCall,
    file: &Path,
    handler: Option<&str>,
) -> Vec<AuthEvidence> {
    let mut evidence = Vec::new();
    for arg in &route_expr.args {
        visit_route_configuration(arg, file, handler, &mut evidence);
    }
    visit_scope_configuration(&route_expr.receiver, file, handler, &mut evidence);
    evidence
}

pub(crate) fn visit_route_configuration(
    expr: &Expr,
    file: &Path,
    handler: Option<&str>,
    evidence: &mut Vec<AuthEvidence>,
) {
    match expr {
        Expr::MethodCall(method) => {
            configuration_call_evidence(method, file, handler, evidence);
            visit_route_configuration(&method.receiver, file, handler, evidence);
            for arg in &method.args {
                visit_route_configuration(arg, file, handler, evidence);
            }
        }
        Expr::Paren(paren) => visit_route_configuration(&paren.expr, file, handler, evidence),
        Expr::Group(group) => visit_route_configuration(&group.expr, file, handler, evidence),
        _ => {}
    }
}

pub(crate) fn visit_scope_configuration(
    expr: &Expr,
    file: &Path,
    handler: Option<&str>,
    evidence: &mut Vec<AuthEvidence>,
) {
    // Walk the scope's own builder chain. Sibling `.route(...)`, `.resource(...)`,
    // and `.service(...)` registrations are passed through without reading
    // their arguments, so one route's guards never apply to another.
    let Expr::MethodCall(method) = expr else {
        return;
    };
    configuration_call_evidence(method, file, handler, evidence);
    visit_scope_configuration(&method.receiver, file, handler, evidence);
}

/// Records evidence from one `.guard(...)` or `.wrap(...)` call's arguments.
pub(crate) fn configuration_call_evidence(
    method: &ExprMethodCall,
    file: &Path,
    handler: Option<&str>,
    evidence: &mut Vec<AuthEvidence>,
) {
    // Compared without allocating: this runs for every call of every chain
    // a route's receiver walk passes through.
    let (authorization_kind, authorization_strength) = if method.method == "guard" {
        (AuthEvidenceKind::AuthorizationGuard, AuthStrength::Strong)
    } else if method.method == "wrap" || method.method == "wrap_fn" {
        // `wrap_fn(|req, srv| ...)` is middleware written as a closure; the
        // names it calls are classified like a `wrap` argument's.
        (
            AuthEvidenceKind::AuthorizationMiddleware,
            AuthStrength::Medium,
        )
    } else {
        // An application's own builder extension on a route or scope:
        // `web::post().to(h).authorize(Action::PutAlert)`. Named as a check,
        // it wraps the route in that check.
        let name = method.method.to_string();
        if let Some((kind, strength)) = classify_check_name(&name) {
            let mut requirements = name_keys(&name);
            for arg in &method.args {
                requirements.extend(keys_in_expr(arg));
            }
            requirements.sort();
            requirements.dedup();
            evidence.push(AuthEvidence {
                kind,
                mechanism: name.clone(),
                symbol: Some(format!(
                    ".{name}({})",
                    method
                        .args
                        .iter()
                        .map(|arg| arg.to_token_stream().to_string().replace(' ', ""))
                        .collect::<Vec<_>>()
                        .join(",")
                )),
                file: file.to_path_buf(),
                line: method.method.span().start().line,
                handler: handler.map(str::to_owned),
                strength,
                requirements,
                name_based: false,
            });
        }
        return;
    };
    for arg in &method.args {
        // Middleware defined in the crate that checks the caller only for
        // some request paths: which routes it protects is decided at
        // runtime, so it does not count as protection (fail closed).
        if method.method != "guard" {
            if let Some(name) = super::middleware::path_conditional_component(arg) {
                evidence.push(AuthEvidence {
                    kind: AuthEvidenceKind::Delegated,
                    mechanism: format!("`{name}` checks the caller only for some request paths, decided at runtime"),
                    symbol: Some(format!(".{}({name})", method.method)),
                    file: file.to_path_buf(),
                    line: arg.span().start().line,
                    handler: handler.map(str::to_owned),
                    strength: AuthStrength::Weak,
                    requirements: Vec::new(),
                    name_based: false,
                });
                continue;
            }
        }
        // `.wrap(get_middleware())` with `fn get_middleware() -> .. {
        // Authentication::with_identity(ROUTES) }`: read as what it returns.
        if let Some(returned) = helper_return(arg) {
            let call = ExprMethodCall {
                attrs: Vec::new(),
                receiver: Box::new(syn::parse_quote!(route)),
                dot_token: Default::default(),
                method: method.method.clone(),
                turbofish: None,
                paren_token: Default::default(),
                args: std::iter::once(returned).collect(),
            };
            let start = evidence.len();
            HELPER_DEPTH.with(|depth| depth.set(depth.get() + 1));
            configuration_call_evidence(&call, file, handler, evidence);
            HELPER_DEPTH.with(|depth| depth.set(depth.get() - 1));
            let found = &mut evidence[start..];
            // A helper returning a known harmless component
            // (`IdentityService::new(..)`, `Cors::default()`) adds nothing.
            if found.is_empty() {
                continue;
            }
            if found.iter().any(|found| found.kind != AuthEvidenceKind::Unknown) {
                let written = arg.to_token_stream().to_string().replace(' ', "");
                for found in found.iter_mut() {
                    found.line = arg.span().start().line;
                    found.mechanism = format!("{} (returned by `{written}`)", found.mechanism);
                }
                continue;
            }
            evidence.truncate(start);
        }
        let Some((class, identifier)) = route_configuration_name_in_expr(arg) else {
            // Neither authorization, authentication, nor a known harmless
            // component: it may protect the route, so it is kept as unknown.
            // `wrap_fn(|req, srv| ..)`, `guard::fn_guard(|ctx| ..)`: a
            // closure that reads the caller's credentials or role.
            if let Some((kind, requirements)) = closure_check(arg) {
                evidence.push(AuthEvidence {
                    kind,
                    mechanism: format!("`.{}` closure that checks the caller", method.method),
                    symbol: Some(format!(".{}(<closure>)", method.method)),
                    file: file.to_path_buf(),
                    line: arg.span().start().line,
                    handler: handler.map(str::to_owned),
                    strength: AuthStrength::Weak,
                    requirements,
                    name_based: false,
                });
                continue;
            }
            if let Some(name) = unrecognized_component(arg) {
                // Wrapped around the routes, a component named for
                // authentication (`reject_anonymous_users`, `Authentication`)
                // is authentication middleware: the `.wrap` is its shape.
                // Enabled only by configuration (`Condition`), whether it
                // runs is decided at runtime, so it stays unknown.
                let conditional = is_conditional_component(arg);
                let wrapped = method.method != "guard" && !conditional;
                let authorizes = wrapped && names_authorization(&name);
                let authenticates = wrapped && !authorizes && names_authentication(&name);
                let mut requirements = Vec::new();
                if authorizes {
                    requirements = name_keys(&name);
                }
                // Built with a role list, an authentication component also
                // enforces those roles.
                let roles = if authorizes || authenticates { component_roles(arg) } else { Vec::new() };
                let role_list = !roles.is_empty();
                if role_list {
                    requirements = roles;
                }
                evidence.push(AuthEvidence {
                    kind: if role_list {
                        AuthEvidenceKind::RoleCheck
                    } else if authorizes {
                        AuthEvidenceKind::AuthorizationMiddleware
                    } else if authenticates {
                        AuthEvidenceKind::IdentityExtraction
                    } else {
                        AuthEvidenceKind::Unknown
                    },
                    mechanism: name.clone(),
                    symbol: Some(if conditional {
                        format!(".{}(conditional {name})", method.method)
                    } else {
                        format!(".{}({name})", method.method)
                    }),
                    file: file.to_path_buf(),
                    line: arg.span().start().line,
                    handler: handler.map(str::to_owned),
                    strength: AuthStrength::Weak,
                    requirements,
                    name_based: false,
                });
            }
            continue;
        };
        let mut requirements = name_keys(&identifier.name);
        requirements.extend(keys_in_expr(arg));
        requirements.sort();
        requirements.dedup();
        // Authentication-only guards and middleware establish who the caller
        // is, not what they may do.
        let roles = component_roles(arg);
        let (kind, strength) = match class {
            RouteConfigurationName::Authorization => {
                requirements.extend(roles.iter().cloned());
                requirements.sort();
                requirements.dedup();
                (authorization_kind.clone(), authorization_strength.clone())
            }
            // `RequireAuth::allowed_roles(vec![Role::Admin])`: built with a
            // role list, it enforces those roles, not only a login.
            RouteConfigurationName::Authentication if !roles.is_empty() => {
                requirements = roles.clone();
                (AuthEvidenceKind::RoleCheck, AuthStrength::Medium)
            }
            RouteConfigurationName::Authentication => {
                (AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak)
            }
        };
        // A role list read from the arguments marks the evidence as the
        // component's allow-list (see `Requirement::roles_any_of`).
        let symbol = if kind == AuthEvidenceKind::RoleCheck && requirements.len() > 1 {
            format!(".{}({})", method.method, identifier.name)
        } else {
            identifier.name.clone()
        };
        evidence.push(AuthEvidence {
            kind,
            mechanism: identifier.name.clone(),
            symbol: Some(symbol),
            file: file.to_path_buf(),
            line: identifier.line,
            handler: handler.map(str::to_owned),
            strength,
            requirements,
            name_based: false,
        });
    }
}

/// Evidence from every `.guard(...)` / `.wrap(...)` call in a builder chain,
/// starting at its outermost call. Actix applies a scope's middleware to all
/// of the scope's routes, wherever the call appears in the chain.
pub(crate) fn chain_configuration_evidence(
    outermost: &ExprMethodCall,
    file: &Path,
) -> Vec<AuthEvidence> {
    let mut evidence = Vec::new();
    let mut call = outermost;
    loop {
        configuration_call_evidence(call, file, None, &mut evidence);
        match &*call.receiver {
            Expr::MethodCall(receiver) => call = receiver,
            _ => return evidence,
        }
    }
}

/// The expression a method-call chain starts from (`web::scope("/s")` in
/// `web::scope("/s").wrap(X).route(...)`); it identifies the chain.
pub(crate) fn chain_root(call: &ExprMethodCall) -> *const Expr {
    let mut expr = &*call.receiver;
    while let Expr::MethodCall(receiver) = expr {
        expr = &receiver.receiver;
    }
    expr
}

/// Collects the names a pattern binds. A bare identifier is always counted,
/// even when it names a unit variant or constant (`None`), which can only make
/// handler resolution more conservative. Macro and verbatim patterns are opaque.
pub(crate) fn pattern_bindings(pat: &Pat, names: &mut HashSet<String>) {
    match pat {
        Pat::Ident(pat) => {
            names.insert(pat.ident.to_string());
            if let Some((_, subpattern)) = &pat.subpat {
                pattern_bindings(subpattern, names);
            }
        }
        Pat::Guard(pat) => pattern_bindings(&pat.pat, names),
        Pat::Or(pat) => pat
            .cases
            .iter()
            .for_each(|case| pattern_bindings(case, names)),
        Pat::Paren(pat) => pattern_bindings(&pat.pat, names),
        Pat::Reference(pat) => pattern_bindings(&pat.pat, names),
        Pat::Slice(pat) => pat
            .elems
            .iter()
            .for_each(|element| pattern_bindings(element, names)),
        Pat::Struct(pat) => pat
            .fields
            .iter()
            .for_each(|field| pattern_bindings(&field.pat, names)),
        Pat::Tuple(pat) => pat
            .elems
            .iter()
            .for_each(|element| pattern_bindings(element, names)),
        Pat::TupleStruct(pat) => pat
            .elems
            .iter()
            .for_each(|element| pattern_bindings(element, names)),
        Pat::Type(pat) => pattern_bindings(&pat.pat, names),
        _ => {}
    }
}

/// Whether a function registers routes on a `ServiceConfig` argument, or
/// returns a `Scope`, `Resource`, or `impl HttpServiceFactory` for
/// `.service(...)`. Matched by type name, so aliases are not recognized.
pub(crate) fn is_route_factory(signature: &Signature) -> bool {
    fn last_segment_is(ty: &Type, names: &[&str]) -> bool {
        match ty {
            Type::Path(path) => path
                .path
                .segments
                .last()
                .is_some_and(|segment| names.iter().any(|name| segment.ident == name)),
            Type::Reference(reference) => last_segment_is(&reference.elem, names),
            Type::Paren(paren) => last_segment_is(&paren.elem, names),
            Type::Group(group) => last_segment_is(&group.elem, names),
            Type::ImplTrait(bounds) => bounds.bounds.iter().any(|bound| {
                matches!(bound, TypeParamBound::Trait(bound)
                if bound.path.segments.last().is_some_and(|segment| {
                    names.iter().any(|name| segment.ident == name)
                }))
            }),
            _ => false,
        }
    }
    let configures = signature.inputs.iter().any(|input| {
        matches!(input, FnArg::Typed(argument) if last_segment_is(&argument.ty, &["ServiceConfig"]))
    });
    let builds = match &signature.output {
        ReturnType::Type(_, ty) => {
            last_segment_is(ty, &["Scope", "Resource", "HttpServiceFactory"])
        }
        ReturnType::Default => false,
    };
    configures || builds
}

pub(crate) fn signature_bindings(signature: &Signature) -> HashSet<String> {
    let mut names = HashSet::new();
    for input in &signature.inputs {
        if let FnArg::Typed(argument) = input {
            pattern_bindings(&argument.pat, &mut names);
        }
    }
    names
}

impl RouteVisitor<'_> {
    /// A path argument and its line: a string literal, or a string constant
    /// resolved through the index. Anything else becomes an
    /// `<unresolved:...>` segment, with a warning, so the route is kept.
    pub(crate) fn path_argument(&mut self, expr: &Expr) -> Option<(String, usize)> {
        let line = expr.span().start().line;
        let written = match expr {
            Expr::Lit(ExprLit {
                lit: Lit::Str(value),
                ..
            }) => return Some((value.value(), line)),
            Expr::Reference(reference) => return self.path_argument(&reference.expr),
            Expr::Group(group) => return self.path_argument(&group.expr),
            Expr::Paren(paren) => return self.path_argument(&paren.expr),
            Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => {
                return self.path_argument(&unary.expr);
            }
            Expr::Path(path) if path.qself.is_none() => {
                let segments: Vec<String> = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect();
                if let [name] = segments.as_slice()
                    && let Some((_, value)) =
                        self.loop_values.iter().rev().find(|(bound, _)| bound == name)
                {
                    return Some((value.clone(), line));
                }
                if let Some(value) =
                    self.index
                        .resolve_const(&self.crate_key, &self.module, &segments)
                {
                    return Some((value, line));
                }
                segments.join("::")
            }
            // `web::scope(&cfg.common.base_uri)`: kept by its text, so two
            // different runtime prefixes stay apart.
            _ => {
                let text: String = expr
                    .to_token_stream()
                    .to_string()
                    .chars()
                    .filter(|character| !character.is_whitespace() && !"&/<>{}".contains(*character))
                    .take(48)
                    .collect();
                if text.is_empty() { "expression".to_owned() } else { text }
            }
        };
        self.warnings.push(format!(
            "{}:{}: path `{}` is not a string literal or resolvable const",
            self.file.display(),
            line,
            written
        ));
        Some((format!("<unresolved:{written}>"), line))
    }

    /// The prefix a builder chain's `web::scope(...)` root and any `.scope(...)`
    /// calls declare. Walked iteratively, allocating only at scope calls: it
    /// runs once per route, over the route's whole receiver chain.
    pub(crate) fn scope_prefix(&mut self, expr: &Expr) -> String {
        let mut method_prefixes = Vec::new();
        let mut expr = expr;
        let root = loop {
            match expr {
                Expr::MethodCall(method) => {
                    if method.method == "scope" {
                        method_prefixes.push(first_string_arg(&method.args).unwrap_or_default());
                    }
                    expr = &method.receiver;
                }
                Expr::Paren(paren) => expr = &paren.expr,
                Expr::Group(group) => expr = &group.expr,
                Expr::Call(call) if is_scope_call(&call.func) => {
                    break match call.args.first() {
                        Some(arg) => self
                            .path_argument(arg)
                            .map(|(path, _)| symbolic_scope(path))
                            .unwrap_or_default(),
                        None => String::new(),
                    };
                }
                Expr::Path(path) => {
                    let builder = path
                        .path
                        .get_ident()
                        .and_then(|name| self.builder_binding(&name.to_string()))
                        .map(|(_, builder)| builder.clone());
                    break match builder {
                        Some(builder) => self.scope_prefix(&builder),
                        None => String::new(),
                    };
                }
                _ => break String::new(),
            }
        };
        method_prefixes
            .iter()
            .rev()
            .fold(join_paths("", &root), |prefix, path| {
                join_paths(&prefix, path)
            })
    }

    /// The paths and lines of the `web::resource(..)` call a builder chain
    /// starts from, as in `web::resource("/path").wrap(X).route(...)`. A
    /// resource may answer several paths: `web::resource(["/a", "/b"])`.
    pub(crate) fn resource_paths(&mut self, expr: &Expr) -> Option<Vec<(String, usize)>> {
        match expr {
            Expr::MethodCall(method) => self.resource_paths(&method.receiver),
            Expr::Paren(paren) => self.resource_paths(&paren.expr),
            Expr::Group(group) => self.resource_paths(&group.expr),
            Expr::Path(path) => {
                let builder = path
                    .path
                    .get_ident()
                    .and_then(|name| self.builder_binding(&name.to_string()))
                    .map(|(_, builder)| builder.clone())?;
                self.resource_paths(&builder)
            }
            Expr::Call(call) if is_resource_call(&call.func) || constructs(&call.func, "service", "WebService") => {
                self.read_lines.insert(span_position(call.span()));
                let mut argument = call.args.first()?;
                // `["/a", "/b"]`, `&["/a", "/b"]`, `vec!["/a", "/b"]`.
                while let Expr::Reference(reference) = argument {
                    argument = &reference.expr;
                }
                let elements: Option<Vec<Expr>> = match argument {
                    Expr::Array(array) => Some(array.elems.iter().cloned().collect()),
                    Expr::Macro(mac) if mac.mac.path.is_ident("vec") => mac
                        .mac
                        .parse_body_with(
                            syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
                        )
                        .ok()
                        .map(|elements| elements.into_iter().collect()),
                    _ => None,
                };
                match elements {
                    Some(elements) => Some(
                        elements
                            .iter()
                            .filter_map(|element| self.path_argument(element))
                            .collect(),
                    ),
                    None => self.path_argument(argument).map(|path| vec![path]),
                }
            }
            _ => None,
        }
    }
}

/// The mark of a scope prefix Archer could not resolve, kept by the source
/// text of its expression (`web::scope(&cfg.prefix)`) so the routes under
/// it still form a group.
pub(crate) const SYMBOLIC_SCOPE: &str = "<scope:";

/// An unresolved `web::scope(..)` prefix as a symbolic segment, unless
/// ARCHER_P10_R4=0.
fn symbolic_scope(path: String) -> String {
    match path.strip_prefix("<unresolved:") {
        Some(text) if super::caller_use::rule_on("R4") => format!("{SYMBOLIC_SCOPE}{text}"),
        _ => path,
    }
}

/// A symbolic scope that leads the whole path is the application's runtime
/// mount prefix, which every route shares: it reads as unresolved, as
/// before.
pub(crate) fn settle_symbolic_scope(path: &str) -> String {
    match path.strip_prefix("/").and_then(|rest| rest.strip_prefix(SYMBOLIC_SCOPE)) {
        Some(rest) => format!("/<unresolved:{rest}"),
        None => path.to_owned(),
    }
}

/// Whether a path contains a segment that could not be resolved statically.
pub(crate) fn has_unresolved_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment.starts_with("<unresolved:"))
}

/// Whether a path has an unresolved part other than a leading mount prefix.
/// `web::scope(&cfg.base_uri)` wrapping a whole app prefixes every route
/// alike, so routes under it can still be compared with each other.
pub(crate) fn has_unresolved_inner_segment(path: &str) -> bool {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .skip(1)
        .any(|segment| segment.starts_with("<unresolved:"))
}

/// What a closure passed as middleware or a guard checks, from the words it
/// uses: a role or permission, else the caller's credentials. `None` when
/// the argument holds no closure or the closure names neither.
fn closure_check(expr: &Expr) -> Option<(AuthEvidenceKind, Vec<String>)> {
    const PRIVILEGE: [&str; 6] = ["admin", "admins", "role", "roles", "permission", "permissions"];
    const CREDENTIAL: [&str; 11] = [
        "authorization",
        "unauthorized",
        "authenticated",
        "token",
        "bearer",
        "session",
        "claims",
        "jwt",
        "apikey",
        "identity",
        "credentials",
    ];
    let closure = match expr {
        Expr::Closure(closure) => closure,
        Expr::Call(call) => call.args.iter().find_map(|arg| match arg {
            Expr::Closure(closure) => Some(closure),
            _ => None,
        })?,
        _ => return None,
    };
    let text = closure.body.to_token_stream().to_string();
    let mut words: Vec<String> = Vec::new();
    for token in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        words.extend(token.split('_').map(str::to_ascii_lowercase));
        words.extend(camel_case_words(token));
    }
    let mut roles: Vec<String> = words
        .iter()
        .filter(|word| PRIVILEGE.contains(&word.as_str()))
        .cloned()
        .collect();
    roles.sort();
    roles.dedup();
    if !roles.is_empty() {
        return Some((AuthEvidenceKind::RoleCheck, roles));
    }
    words
        .iter()
        .any(|word| CREDENTIAL.contains(&word.as_str()))
        .then(|| (AuthEvidenceKind::IdentityExtraction, Vec::new()))
}

pub(crate) fn is_scope_call(expr: &Expr) -> bool {
    constructs(expr, "scope", "Scope")
}

/// `web::resource(..)` or `Resource::new(..)`.
pub(crate) fn is_resource_call(expr: &Expr) -> bool {
    constructs(expr, "resource", "Resource")
}

/// Whether a called path is `web::<function>` or `<Type>::new`.
fn constructs(expr: &Expr, function: &str, ty: &str) -> bool {
    let Expr::Path(path) = expr else {
        return false;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    match segments.as_slice() {
        // `actix_web::Resource::new`, or `Resource::new` with `Resource`
        // imported from actix-web: a project's own `crate::Resource` is not one.
        [owner, new] if new == "new" => unalias(owner) == ty && imported_from_actix(owner),
        [first, .., owner, new] if new == "new" => unalias(owner) == ty && first == "actix_web",
        [.., last] => unalias(last) == function,
        [] => false,
    }
}

/// The argument of a route's `.to(...)` call.
#[derive(Debug, Clone)]
pub(crate) enum HandlerTarget {
    Path {
        segments: Vec<String>,
        leading_colon: bool,
    },
    /// Closures and other expressions that do not name a function.
    Other,
    /// A method call in a body, `receiver.method(..)`, with the receiver
    /// written as a binding and fields (`principal`, `self.auth`). Its type
    /// is looked up where the call is resolved. Never a route handler.
    Method { receiver: String, method: String },
}

impl HandlerTarget {
    pub(crate) fn name(&self) -> Option<String> {
        match self {
            Self::Path { segments, .. } => segments.last().cloned(),
            Self::Method { method, .. } => Some(method.clone()),
            Self::Other => None,
        }
    }

    pub(crate) fn written(&self) -> Option<String> {
        match self {
            Self::Path {
                segments,
                leading_colon,
            } => Some(format!(
                "{}{}",
                if *leading_colon { "::" } else { "" },
                segments.join("::")
            )),
            Self::Method { receiver, method } => Some(format!("{receiver}.{method}")),
            Self::Other => None,
        }
    }
}

/// The function a handler expression names, if it is a plain path.
pub(crate) fn handler_target(expr: &Expr) -> Option<HandlerTarget> {
    match expr {
        Expr::Path(path) if path.qself.is_none() => Some(HandlerTarget::Path {
            segments: path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect(),
            leading_colon: path.path.leading_colon.is_some(),
        }),
        Expr::Closure(closure) => forwarding_target(closure),
        _ => None,
    }
}

/// The function a closure only forwards its parameters to:
/// `.to(|state, req, path, payload| routing::update(state, req, path, payload))`
/// is the handler `routing::update`. A closure that does anything else is
/// its own handler.
fn forwarding_target(closure: &syn::ExprClosure) -> Option<HandlerTarget> {
    let mut parameters = HashSet::new();
    for input in &closure.inputs {
        let pattern = match input {
            Pat::Type(typed) => &*typed.pat,
            other => other,
        };
        match pattern {
            Pat::Ident(ident) => {
                parameters.insert(ident.ident.to_string());
            }
            _ => return None,
        }
    }
    let mut body = &*closure.body;
    loop {
        body = match body {
            Expr::Async(inner) => match inner.block.stmts.as_slice() {
                [syn::Stmt::Expr(expr, None)] => expr,
                _ => return None,
            },
            Expr::Block(inner) => match inner.block.stmts.as_slice() {
                [syn::Stmt::Expr(expr, None)] => expr,
                _ => return None,
            },
            Expr::Await(inner) => &inner.base,
            Expr::Paren(inner) => &inner.expr,
            _ => break,
        };
    }
    let Expr::Call(call) = body else {
        return None;
    };
    let forwards = !call.args.is_empty()
        && call.args.iter().all(|argument| match argument {
            Expr::Path(path) => path
                .path
                .get_ident()
                .is_some_and(|ident| parameters.contains(&ident.to_string())),
            _ => false,
        })
        && call.args.len() == parameters.len();
    if !forwards {
        return None;
    }
    match &*call.func {
        Expr::Path(_) => handler_target(&call.func),
        _ => None,
    }
}

pub(crate) fn find_handler(
    exprs: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<HandlerTarget> {
    exprs.iter().find_map(find_handler_in_expr)
}

pub(crate) fn find_handler_in_expr(expr: &Expr) -> Option<HandlerTarget> {
    match expr {
        Expr::MethodCall(method) if method.method == "to" => {
            Some(handler_target(method.args.first()?).unwrap_or(HandlerTarget::Other))
        }
        Expr::MethodCall(method) => {
            find_handler(&method.args).or_else(|| find_handler_in_expr(&method.receiver))
        }
        _ => None,
    }
}

/// Adds scope guard and middleware evidence to a route, attributed to its
/// handler. Evidence already present is not repeated.
pub(crate) fn add_inherited_evidence(
    authorization: &mut Vec<AuthEvidence>,
    inherited: &[AuthEvidence],
    handler: Option<&str>,
) {
    for inherited in inherited {
        let mut inherited = inherited.clone();
        inherited.handler = handler.map(str::to_owned);
        if !authorization.contains(&inherited) {
            authorization.push(inherited);
        }
    }
}

/// Re-roots attribute routes at every `.service(handler)` call that registers
/// their handler, taking that scope's prefix and inherited evidence. Attribute
/// routes whose handler is never registered this way keep their own path.
/// Places attribute routes (`#[get("/x")]`) where `.service(handler)`
/// registers them. An attribute route that nothing registers is not served,
/// so it is left out and returned, as `METHOD path handler (file:line)`, for
/// a warning.
pub(crate) fn apply_registrations(
    routes: Vec<Route>,
    registrations: &[Registration],
) -> (Vec<Route>, Vec<String>) {
    let mut unregistered = Vec::new();
    let mut placed = Vec::with_capacity(routes.len());
    for route in routes {
        let Some((definition, attribute_path)) = route.origin.attribute.clone() else {
            placed.push(route);
            continue;
        };
        let matching: Vec<&Registration> = registrations
            .iter()
            .filter(|registration| registration.definition == definition)
            .collect();
        if matching.is_empty() {
            unregistered.push(format!(
                "{} {} {} ({}:{})",
                route.method,
                route.path,
                route.handler.as_deref().unwrap_or("?"),
                route.file.display(),
                route.line
            ));
            continue;
        }
        for registration in matching {
            let mut registered = route.clone();
            registered.path = join_paths(&registration.prefix, &attribute_path);
            registered.scope_prefix = registration.prefix.clone();
            add_inherited_evidence(
                &mut registered.authorization,
                &registration.inherited,
                route.handler.as_deref(),
            );
            placed.push(registered);
        }
    }
    (placed, unregistered)
}

/// Line and column where a span starts.
pub(crate) fn span_position(span: proc_macro2::Span) -> (usize, usize) {
    let start = span.start();
    (start.line, start.column)
}

pub(crate) fn join_paths(prefix: &str, path: &str) -> String {
    let prefix = prefix.trim_matches('/');
    let path = path.trim_start_matches('/');
    match (prefix.is_empty(), path.is_empty()) {
        (true, true) => "/".into(),
        (true, false) => format!("/{path}"),
        (false, true) => format!("/{prefix}"),
        (false, false) => format!("/{prefix}/{path}"),
    }
}

/// The expression a method-call chain starts from, through parentheses.
pub(crate) fn chain_root_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::MethodCall(call) => chain_root_expr(&call.receiver),
        Expr::Paren(paren) => chain_root_expr(&paren.expr),
        Expr::Group(group) => chain_root_expr(&group.expr),
        _ => expr,
    }
}

/// A copy of `expr` whose chain starts from `replacement` instead of its root.
pub(crate) fn substitute_root(expr: &Expr, replacement: &Expr) -> Expr {
    match expr {
        Expr::MethodCall(call) => {
            let mut call = call.clone();
            call.receiver = Box::new(substitute_root(&call.receiver, replacement));
            Expr::MethodCall(call)
        }
        Expr::Paren(paren) => substitute_root(&paren.expr, replacement),
        Expr::Group(group) => substitute_root(&group.expr, replacement),
        _ => replacement.clone(),
    }
}

/// `web::scope(..)`, `web::resource(..)`, `web::get()` and the other route
/// constructors, `App::new()`, `Scope::new(..)`, `Resource::new(..)`, `Route::new()`.
pub(crate) fn is_builder_constructor(expr: &Expr) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    let Expr::Path(path) = &*call.func else {
        return false;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    match segments.as_slice() {
        [.., last] if last == "scope" || last == "resource" => true,
        [.., owner, new]
            if new == "new" && ["App", "Scope", "Resource", "Route"].contains(&owner.as_str()) =>
        {
            true
        }
        [.., module, method] if module == "web" => {
            ROUTE_METHOD_CONSTRUCTORS.contains(&method.as_str())
                || method == "method"
                || method == "route"
        }
        _ => false,
    }
}

/// The name a `let` pattern binds when it binds exactly one name:
/// `admin`, `mut scope`, `admin: Scope`.
fn simple_binding(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) if ident.subpat.is_none() => Some(ident.ident.to_string()),
        Pat::Type(typed) => simple_binding(&typed.pat),
        _ => None,
    }
}

fn as_closure(expr: &Expr) -> Option<&ExprClosure> {
    match expr {
        Expr::Closure(closure) => Some(closure),
        Expr::Paren(paren) => as_closure(&paren.expr),
        Expr::Group(group) => as_closure(&group.expr),
        _ => None,
    }
}

/// The closure a route builder's `.to(...)` takes, if it takes one.
pub(crate) fn find_handler_closure(
    exprs: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<&ExprClosure> {
    fn in_expr(expr: &Expr) -> Option<&ExprClosure> {
        match expr {
            Expr::MethodCall(method) if method.method == "to" => as_closure(method.args.first()?),
            Expr::MethodCall(method) => method
                .args
                .iter()
                .find_map(in_expr)
                .or_else(|| in_expr(&method.receiver)),
            _ => None,
        }
    }
    exprs.iter().find_map(in_expr)
}

/// The prefix of `#[actix_web::scope("/p")]` on a module.
fn scope_attribute(attribute: &syn::Attribute) -> Option<String> {
    let last = attribute.path().segments.last()?;
    if last.ident != "scope" {
        return None;
    }
    attribute.parse_args::<syn::LitStr>().ok().map(|value| value.value())
}

/// The string literals a loop walks: `["/a", "/b"]`, `&[..]`, `vec![..]`,
/// optionally through `.iter()`/`.into_iter()`/`.iter().copied()`.
fn literal_strings(expr: &Expr) -> Option<Vec<String>> {
    let mut expr = expr;
    loop {
        match expr {
            Expr::Reference(reference) => expr = &reference.expr,
            Expr::Paren(paren) => expr = &paren.expr,
            Expr::MethodCall(call)
                if call.args.is_empty()
                    && matches!(
                        call.method.to_string().as_str(),
                        "iter" | "into_iter" | "copied" | "cloned"
                    ) =>
            {
                expr = &call.receiver;
            }
            _ => break,
        }
    }
    let elements: Vec<Expr> = match expr {
        Expr::Array(array) => array.elems.iter().cloned().collect(),
        Expr::Macro(mac) if mac.mac.path.is_ident("vec") => mac
            .mac
            .parse_body_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)
            .ok()?
            .into_iter()
            .collect(),
        _ => return None,
    };
    let values: Vec<String> = elements
        .iter()
        .map(|element| match element {
            Expr::Lit(ExprLit {
                lit: Lit::Str(value),
                ..
            }) => Some(value.value()),
            _ => None,
        })
        .collect::<Option<_>>()?;
    (!values.is_empty()).then_some(values)
}

thread_local! {
    /// `use` renames of the file being visited, alias to original name:
    /// `use actix_web::web::{get as get_route}` maps `get_route` to `get`.
    static IMPORT_ALIASES: std::cell::RefCell<HashMap<String, String>> =
        std::cell::RefCell::new(HashMap::new());
    /// Names the file being visited imports from `actix_web`.
    static ACTIX_IMPORTS: std::cell::RefCell<HashSet<String>> =
        std::cell::RefCell::new(HashSet::new());
}

fn imported_from_actix(name: &str) -> bool {
    ACTIX_IMPORTS.with(|imports| imports.borrow().contains(name))
}

fn set_import_aliases(file: &syn::File) {
    struct Uses(HashMap<String, String>, HashSet<String>);
    fn imported(tree: &syn::UseTree, actix: bool, uses: &mut Uses) {
        match tree {
            syn::UseTree::Path(path) => {
                let actix = actix || path.ident == "actix_web";
                imported(&path.tree, actix, uses);
            }
            syn::UseTree::Name(name) if actix => {
                uses.1.insert(name.ident.to_string());
            }
            syn::UseTree::Rename(rename) => {
                uses.0.insert(rename.rename.to_string(), rename.ident.to_string());
                if actix {
                    uses.1.insert(rename.rename.to_string());
                }
            }
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    imported(tree, actix, uses);
                }
            }
            _ => {}
        }
    }
    impl<'ast> Visit<'ast> for Uses {
        fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
            imported(&node.tree, false, self);
        }
    }
    let mut uses = Uses(HashMap::new(), HashSet::new());
    uses.visit_file(file);
    IMPORT_ALIASES.with(|aliases| *aliases.borrow_mut() = uses.0);
    ACTIX_IMPORTS.with(|imports| *imports.borrow_mut() = uses.1);
}

/// The original name of an imported alias, or the name itself.
fn unalias(name: &str) -> String {
    IMPORT_ALIASES
        .with(|aliases| aliases.borrow().get(name).cloned())
        .unwrap_or_else(|| name.to_owned())
}

/// Every `macro_rules!` macro the project defines, by name, so that a macro
/// exported from one file (`#[macro_use]`, `#[macro_export]`) is read where
/// another file invokes it. A name defined twice differently is dropped.
pub(crate) fn project_macros<'a>(
    files: impl IntoIterator<Item = &'a syn::File>,
) -> HashMap<String, Vec<super::macros::Rule>> {
    struct Definitions(HashMap<String, Option<(String, Vec<super::macros::Rule>)>>);
    impl<'ast> Visit<'ast> for Definitions {
        fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
            if node.mac.path.is_ident("macro_rules")
                && let Some(name) = &node.ident
            {
                let text = node.mac.tokens.to_string();
                let rules = super::macros::parse_rules(&node.mac.tokens);
                self.0
                    .entry(name.to_string())
                    .and_modify(|entry| {
                        if entry.as_ref().is_some_and(|(seen, _)| *seen != text) {
                            *entry = None;
                        }
                    })
                    .or_insert(Some((text, rules)));
            }
        }
    }
    let mut definitions = Definitions(HashMap::new());
    for file in files {
        definitions.visit_file(file);
    }
    definitions
        .0
        .into_iter()
        .filter_map(|(name, entry)| entry.map(|(_, rules)| (name, rules)))
        .filter(|(_, rules)| !rules.is_empty())
        .collect()
}

/// `tokens` with each loop variable that stands alone (not a field or path
/// segment) replaced by the literal it is bound to.
fn replace_loop_values(
    tokens: proc_macro2::TokenStream,
    values: &[(String, String)],
) -> proc_macro2::TokenStream {
    use proc_macro2::TokenTree;
    let mut output = Vec::new();
    let mut previous: Option<TokenTree> = None;
    for token in tokens {
        let replaced = match &token {
            TokenTree::Ident(ident)
                if !matches!(&previous, Some(TokenTree::Punct(p)) if p.as_char() == '.' || p.as_char() == ':') =>
            {
                values
                    .iter()
                    .rev()
                    .find(|(name, _)| ident == name)
                    .map(|(_, value)| {
                        let mut literal = proc_macro2::Literal::string(value);
                        literal.set_span(ident.span());
                        TokenTree::Literal(literal)
                    })
            }
            TokenTree::Group(group) => {
                let mut copy = proc_macro2::Group::new(
                    group.delimiter(),
                    replace_loop_values(group.stream(), values),
                );
                copy.set_span(group.span());
                Some(TokenTree::Group(copy))
            }
            _ => None,
        };
        let token = replaced.unwrap_or(token);
        previous = Some(token.clone());
        output.push(token);
    }
    output.into_iter().collect()
}

/// The string fields of constant route tables, as in
/// `pub const ROUTES: Routes = Routes::new();` with `Routes::new()` building
/// `Self { auth: Auth::new(), .. }` and `Auth::new()` building
/// `Self { login: "/api/v1/signin", .. }`. Types are known by name only; a
/// field path resolves when every type it could pass through gives one value.
#[derive(Default)]
pub(crate) struct FieldPaths {
    /// Constant or static name to the type names it is declared with.
    consts: HashMap<String, HashSet<String>>,
    /// `use a::B as C` renames across the project: `C` to `B`.
    renames: HashMap<String, HashSet<String>>,
    /// `(struct, field)` to the type names of the field.
    fields: HashMap<(String, String), HashSet<String>>,
    /// `(struct, field)` to the string literals written for it.
    values: HashMap<(String, String), HashSet<String>>,
}

impl FieldPaths {
    pub(crate) fn build<'a>(files: impl IntoIterator<Item = &'a syn::File>) -> Self {
        struct Collect {
            paths: FieldPaths,
            impl_type: Vec<Option<String>>,
            /// `let login = "/api/v1/signin";` in the function being visited.
            strings: Vec<HashMap<String, String>>,
        }
        fn type_name(ty: &Type) -> Option<String> {
            match ty {
                Type::Path(path) => path.path.segments.last().map(|segment| segment.ident.to_string()),
                Type::Reference(reference) => type_name(&reference.elem),
                Type::Paren(paren) => type_name(&paren.elem),
                Type::Group(group) => type_name(&group.elem),
                _ => None,
            }
        }
        impl<'ast> Visit<'ast> for Collect {
            fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
                if let Some(name) = type_name(&node.ty) {
                    self.paths.consts.entry(node.ident.to_string()).or_default().insert(name);
                }
                visit::visit_item_const(self, node);
            }
            fn visit_impl_item_const(&mut self, node: &'ast syn::ImplItemConst) {
                if let Some(name) = type_name(&node.ty) {
                    self.paths.consts.entry(node.ident.to_string()).or_default().insert(name);
                }
                visit::visit_impl_item_const(self, node);
            }
            fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
                if let Some(name) = type_name(&node.ty) {
                    self.paths.consts.entry(node.ident.to_string()).or_default().insert(name);
                }
                visit::visit_item_static(self, node);
            }
            fn visit_use_rename(&mut self, node: &'ast syn::UseRename) {
                self.paths
                    .renames
                    .entry(node.rename.to_string())
                    .or_default()
                    .insert(node.ident.to_string());
            }
            fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
                for field in &node.fields {
                    if let (Some(ident), Some(name)) = (&field.ident, type_name(&field.ty)) {
                        self.paths
                            .fields
                            .entry((node.ident.to_string(), ident.to_string()))
                            .or_default()
                            .insert(name);
                    }
                }
                visit::visit_item_struct(self, node);
            }
            fn visit_block(&mut self, node: &'ast Block) {
                let mut strings = self.strings.last().cloned().unwrap_or_default();
                for statement in &node.stmts {
                    if let Stmt::Local(local) = statement
                        && let Some(init) = &local.init
                        && let Expr::Lit(ExprLit { lit: Lit::Str(value), .. }) = &*init.expr
                        && let Some(name) = simple_binding(&local.pat)
                    {
                        strings.insert(name, value.value());
                    }
                }
                self.strings.push(strings);
                visit::visit_block(self, node);
                self.strings.pop();
            }
            fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
                self.impl_type.push(type_name(&node.self_ty));
                visit::visit_item_impl(self, node);
                self.impl_type.pop();
            }
            fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
                let written = node.path.segments.last().map(|segment| segment.ident.to_string());
                let name = match written.as_deref() {
                    Some("Self") => self.impl_type.last().cloned().flatten(),
                    other => other.map(str::to_owned),
                };
                if let Some(name) = name {
                    for field in &node.fields {
                        let syn::Member::Named(ident) = &field.member else {
                            continue;
                        };
                        let value = match &field.expr {
                            Expr::Lit(ExprLit { lit: Lit::Str(value), .. }) => Some(value.value()),
                            // `Auth { login, .. }` after `let login = "/signin";`.
                            Expr::Path(path) => path.path.get_ident().and_then(|local| {
                                self.strings.last().and_then(|strings| strings.get(&local.to_string())).cloned()
                            }),
                            _ => None,
                        };
                        if let Some(value) = value {
                            self.paths
                                .values
                                .entry((name.clone(), ident.to_string()))
                                .or_default()
                                .insert(value);
                        }
                    }
                }
                visit::visit_expr_struct(self, node);
            }
        }
        let mut collect = Collect {
            paths: FieldPaths::default(),
            impl_type: Vec::new(),
            strings: Vec::new(),
        };
        for file in files {
            collect.visit_file(file);
        }
        collect.paths
    }

    /// The string a field path such as `crate::V1_API_ROUTES.auth.login` names.
    pub(crate) fn resolve(&self, written: &str) -> Option<String> {
        let mut expr = syn::parse_str::<Expr>(written).ok()?;
        let mut fields = Vec::new();
        let root = loop {
            match expr {
                Expr::Field(field) => {
                    let syn::Member::Named(name) = &field.member else {
                        return None;
                    };
                    fields.push(name.to_string());
                    expr = *field.base;
                }
                Expr::Path(path) => break path.path.segments.last()?.ident.to_string(),
                _ => return None,
            }
        };
        fields.reverse();
        let (last, through) = fields.split_last()?;
        let mut names: HashSet<String> = HashSet::from([root.clone()]);
        names.extend(self.renames.get(&root).into_iter().flatten().cloned());
        let mut types: HashSet<String> = names
            .iter()
            .filter_map(|name| self.consts.get(name))
            .flatten()
            .cloned()
            .collect();
        for field in through {
            types = types
                .iter()
                .filter_map(|ty| self.fields.get(&(ty.clone(), field.clone())))
                .flatten()
                .cloned()
                .collect();
        }
        let values: HashSet<&String> = types
            .iter()
            .filter_map(|ty| self.values.get(&(ty.clone(), last.clone())))
            .flatten()
            .collect();
        match values.into_iter().collect::<Vec<_>>().as_slice() {
            [value] => Some((*value).clone()),
            _ => None,
        }
    }
}

/// Function name to `(module, returned expression)` per definition.
type HelperReturns = HashMap<String, Vec<(Vec<String>, Option<Expr>)>>;

thread_local! {
    /// The value each project function returns, by function name, with the
    /// module it is defined in, when its body is one expression.
    static HELPER_RETURNS: std::cell::RefCell<HelperReturns> =
        std::cell::RefCell::new(HashMap::new());
    static HELPER_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Records what the project's functions return, for [`helper_return`].
pub(crate) fn set_helper_returns<'a>(files: impl IntoIterator<Item = (Vec<String>, &'a syn::File)>) {
    struct Returns {
        found: HelperReturns,
        module: Vec<String>,
    }
    impl Returns {
        fn add(&mut self, name: String, block: &Block) {
            let tail = match block.stmts.as_slice() {
                [Stmt::Expr(expr, None)] => Some(expr.clone()),
                _ => None,
            };
            self.found.entry(name).or_default().push((self.module.clone(), tail));
        }
    }
    impl<'ast> Visit<'ast> for Returns {
        fn visit_item_mod(&mut self, node: &'ast ItemMod) {
            self.module.push(node.ident.to_string());
            visit::visit_item_mod(self, node);
            self.module.pop();
        }
        fn visit_item_fn(&mut self, node: &'ast ItemFn) {
            self.add(node.sig.ident.to_string(), &node.block);
        }
        fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
            self.add(node.sig.ident.to_string(), &node.block);
        }
    }
    let mut returns = Returns { found: HashMap::new(), module: Vec::new() };
    for (module, file) in files {
        returns.module = module;
        returns.visit_file(file);
    }
    HELPER_RETURNS.with(|helpers| *helpers.borrow_mut() = returns.found);
}

/// What a call to a project function without arguments returns, as in
/// `get_middleware()` or `crate::pages::get_middleware()`. A qualified call
/// picks the definition whose module ends with the qualifier; otherwise all
/// definitions of the name must return the same expression.
fn helper_return(arg: &Expr) -> Option<Expr> {
    if HELPER_DEPTH.with(std::cell::Cell::get) >= 4 {
        return None;
    }
    let Expr::Call(call) = arg else {
        return None;
    };
    if !call.args.is_empty() {
        return None;
    }
    let Expr::Path(function) = &*call.func else {
        return None;
    };
    let segments: Vec<String> = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .filter(|segment| !matches!(segment.as_str(), "crate" | "self" | "super"))
        .collect();
    let (name, qualifier) = segments.split_last()?;
    HELPER_RETURNS.with(|helpers| {
        let helpers = helpers.borrow();
        let candidates: Vec<&(Vec<String>, Option<Expr>)> = helpers
            .get(name)?
            .iter()
            .filter(|(module, _)| module.ends_with(qualifier))
            .collect();
        let first = candidates.first()?.1.clone()?;
        let text = first.to_token_stream().to_string();
        candidates
            .iter()
            .all(|(_, tail)| tail.as_ref().is_some_and(|tail| tail.to_token_stream().to_string() == text))
            .then_some(first)
    })
}

/// Whether a called path builds a route or resource: `web::get`,
/// `web::route`, `web::method`, `web::resource`, `web::service`,
/// `Resource::new`, `Route::new`, or one of those imported from actix-web
/// by name. These are where routes are written, so each should yield a route.
fn is_route_site(func: &Expr) -> bool {
    let Expr::Path(path) = func else {
        return false;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let Some((name, module)) = segments.split_last() else {
        return false;
    };
    let original = unalias(name);
    let builds = ROUTE_METHOD_CONSTRUCTORS.contains(&original.as_str())
        || matches!(original.as_str(), "route" | "method" | "resource" | "service");
    match module {
        [] => builds && imported_from_actix(name),
        [.., web] if web == "web" => builds,
        [.., owner] => {
            original == "new"
                && matches!(owner.as_str(), "Resource" | "Route" | "WebService")
                && (segments.first().is_some_and(|first| first == "actix_web")
                    || imported_from_actix(owner))
        }
    }
}
