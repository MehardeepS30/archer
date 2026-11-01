//! Route extraction: builder chains, scopes, resources, attribute routes, and guard/middleware evidence.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use syn::{
    Arm, BinOp, Block, Expr, ExprCall, ExprClosure, ExprForLoop, ExprIf, ExprLit, ExprMethodCall,
    ExprWhile, FnArg, ImplItemFn, Item, ItemFn, ItemMod, Lit, Pat, ReturnType, Signature, Stmt,
    TraitItemFn, Type, TypeParamBound,
    spanned::Spanned,
    visit::{self, Visit},
};

use super::{evidence::*, handlers::*, model::*};

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
}

impl BlockScope {
    pub(crate) fn with_locals(locals: HashSet<String>) -> Self {
        Self {
            locals,
            items: HashMap::new(),
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
        }
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
        let item = index.items[definition];
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
            Expr::Paren(paren) => return self.add_registration(&paren.expr),
            Expr::Group(group) => return self.add_registration(&group.expr),
            Expr::Macro(mac)
                if mac
                    .mac
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "services") =>
            {
                if let Ok(elements) = mac.mac.parse_body_with(
                    syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
                ) {
                    elements
                        .iter()
                        .for_each(|element| self.add_registration(element));
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
        if name != "route" && name != "resource" && name != "to" {
            return;
        }

        // `cfg.route("/path", builder)` names its path; `web::resource("/path")
        // .route(builder)` and `web::resource("/path").to(handler)` take it
        // from the resource the chain starts from.
        let path = if name == "to" {
            self.resource_path(&node.receiver)
        } else if name == "route" && node.args.len() == 2 {
            self.path_argument(&node.args[0])
        } else if name == "route" {
            self.resource_path(&node.receiver)
        } else {
            first_string_arg(&node.args).zip(first_string_arg_line(&node.args))
        };
        let Some((path, path_line)) = path else {
            return;
        };

        let local_prefix = self.scope_prefix(&node.receiver);
        let prefix = join_paths(&self.scope_context, &local_prefix);
        let path = join_paths(&prefix, &path);
        // A resource's own `.to(handler)` answers every method.
        let target = if name == "to" {
            node.args
                .first()
                .map(|arg| handler_target(arg).unwrap_or(HandlerTarget::Other))
        } else {
            find_handler(&node.args)
        };
        let (handler_evidence, handler_resolution) = match &target {
            None => (Vec::new(), None),
            Some(target) => match self.block_local_handler(target) {
                Some(Some(evidence)) => (evidence.to_vec(), Some(HandlerResolution::Local)),
                Some(None) => (Vec::new(), Some(HandlerResolution::Unresolved)),
                None => {
                    let (definition, resolution) =
                        self.index
                            .resolve_handler(&self.crate_key, &self.module, target);
                    (
                        definition.map_or_else(Vec::new, |definition| definition.evidence.clone()),
                        Some(resolution),
                    )
                }
            },
        };
        let handler = target.as_ref().and_then(HandlerTarget::name);
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

        self.routes.push(Route {
            method: extract_http_method(node),
            path,
            scope_prefix: prefix,
            handler,
            handler_path: target.as_ref().and_then(HandlerTarget::written),
            handler_resolution,
            authorization,
            line: path_line,
            file: self.file.clone(),
            origin: RouteOrigin {
                position: span_position(node.method.span()),
                attribute: None,
                enclosing: self.enclosing,
            },
        });
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
        self.with_locals(locals, |visitor| visitor.visit_block(&node.body));
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
            visit::visit_item_mod(self, node);
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
            self.visit_stmt(statement);
            if let Stmt::Local(local) = statement {
                let scope = self
                    .block_scopes
                    .last_mut()
                    .expect("block scope pushed above");
                pattern_bindings(&local.pat, &mut scope.locals);
            }
        }
        self.block_scopes.pop();
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        // The outermost call of a builder chain is visited first; collect the
        // chain's guards and middleware there so that every route in the chain,
        // and in scopes nested under it, receives them.
        let root = chain_root(node);
        let starts_chain = self.chain_scopes.last().map(|(chain, _)| *chain) != Some(root);
        if starts_chain {
            let evidence = chain_configuration_evidence(node, &self.file);
            self.chain_scopes.push((root, evidence));
        }

        if node.method == "service" || node.method == "configure" {
            let previous_context = self.scope_context.clone();
            self.scope_context = join_paths(&previous_context, &self.scope_prefix(&node.receiver));
            for arg in &node.args {
                if node.method == "service" {
                    self.add_registration(arg);
                } else if let Some(definition) = self.named_definition(arg) {
                    self.expand_configure(definition);
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
    pub(crate) fn add_attribute_routes(&mut self, node: &ItemFn) {
        for (method, path_literal) in node.attrs.iter().flat_map(attribute_routes) {
            let prefix = self.scope_context.clone();
            let path = join_paths(&prefix, &path_literal.value());
            let handler = node.sig.ident.to_string();
            // Only module-level functions can be named by `.service(handler)`.
            let definition = if self.block_scopes.is_empty() {
                self.index
                    .definition_in(&self.crate_key, &self.module, &handler)
            } else {
                None
            };
            // The index's evidence includes the handler's helpers.
            let authorization = definition.map_or_else(
                || handler_evidence(&self.file, node),
                |definition| self.index.definitions[definition].evidence.clone(),
            );

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
                origin: RouteOrigin {
                    position: span_position(path_literal.span()),
                    attribute: definition.map(|definition| (definition, path_literal.value())),
                    enclosing: None,
                },
            });
        }
    }
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
    let name = match segments.as_slice() {
        [name] => name,
        [krate, name] if krate == "actix_web" => name,
        _ => return Vec::new(),
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
    let Some(Expr::Lit(ExprLit {
        lit: Lit::Str(path),
        ..
    })) = args.first()
    else {
        return Vec::new();
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
pub(crate) fn extract_http_method(expr: &ExprMethodCall) -> String {
    expr.args
        .last()
        .and_then(route_builder_method)
        .unwrap_or_else(|| "UNKNOWN".into())
}

pub(crate) fn route_builder_method(builder: &Expr) -> Option<String> {
    let mut methods = Vec::new();
    let mut expr = builder;
    let root = loop {
        match expr {
            Expr::MethodCall(call) => {
                // `Route::method` and a method guard (`.guard(guard::Get())`)
                // constrain the method; other builder calls do not.
                if call.method == "method" {
                    methods.push(method_constant(call.args.first()?)?);
                } else if call.method == "guard"
                    && let Some(method) = call.args.first().and_then(method_guard)
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
    let module: Vec<&str> = module.iter().map(String::as_str).collect();
    let web_function = matches!(module.as_slice(), [] | ["web"] | ["actix_web", "web"]);
    let any_method_route = (web_function && name == "route")
        || (matches!(module.as_slice(), ["Route"] | ["actix_web", "Route"]) && name == "new");

    if web_function && ROUTE_METHOD_CONSTRUCTORS.contains(&name.as_str()) {
        methods.push(name.to_uppercase());
    } else if web_function && name == "method" {
        methods.push(method_constant(root.args.first()?)?);
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

/// Reads a method guard: `guard::Get()`, `actix_web::guard::Post()`, or
/// `guard::Method(Method::PUT)`. Other guards return `None`.
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
    if !matches!(module.as_slice(), [] | ["guard"] | ["actix_web", "guard"]) {
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
        return;
    };
    for arg in &method.args {
        let Some((class, identifier)) = route_configuration_name_in_expr(arg) else {
            continue;
        };
        // Authentication-only guards and middleware establish who the caller
        // is, not what they may do.
        let (kind, strength) = match class {
            RouteConfigurationName::Authorization => {
                (authorization_kind.clone(), authorization_strength.clone())
            }
            RouteConfigurationName::Authentication => {
                (AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak)
            }
        };
        evidence.push(AuthEvidence {
            kind,
            mechanism: identifier.name.clone(),
            symbol: Some(identifier.name),
            file: file.to_path_buf(),
            line: identifier.line,
            handler: handler.map(str::to_owned),
            strength,
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
            Expr::Path(path) if path.qself.is_none() => {
                let segments: Vec<String> = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect();
                if let Some(value) =
                    self.index
                        .resolve_const(&self.crate_key, &self.module, &segments)
                {
                    return Some((value, line));
                }
                segments.join("::")
            }
            _ => "expression".to_owned(),
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
                            .map(|(path, _)| path)
                            .unwrap_or_default(),
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

    /// The path and line of the `web::resource("/path")` call a builder chain
    /// starts from, as in `web::resource("/path").wrap(X).route(...)`.
    pub(crate) fn resource_path(&mut self, expr: &Expr) -> Option<(String, usize)> {
        match expr {
            Expr::MethodCall(method) => self.resource_path(&method.receiver),
            Expr::Paren(paren) => self.resource_path(&paren.expr),
            Expr::Group(group) => self.resource_path(&group.expr),
            Expr::Call(call)
                if matches!(
                    &*call.func,
                    Expr::Path(path)
                        if path.path.segments.last().is_some_and(|segment| segment.ident == "resource")
                ) =>
            {
                self.path_argument(call.args.first()?)
            }
            _ => None,
        }
    }
}

/// Whether a path contains a segment that could not be resolved statically.
pub(crate) fn has_unresolved_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment.starts_with("<unresolved:"))
}

pub(crate) fn is_scope_call(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "scope")
    )
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
}

impl HandlerTarget {
    pub(crate) fn name(&self) -> Option<String> {
        match self {
            Self::Path { segments, .. } => segments.last().cloned(),
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
pub(crate) fn apply_registrations(
    routes: Vec<Route>,
    registrations: &[Registration],
) -> Vec<Route> {
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
            placed.push(route);
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
    placed
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
