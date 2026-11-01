//! Route extraction: builder chains, scopes, resources, attribute routes, and guard/middleware evidence.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use syn::{
    Arm, BinOp, Block, Expr, ExprClosure, ExprForLoop, ExprIf, ExprLit, ExprMethodCall, ExprWhile,
    FnArg, ImplItemFn, Item, ItemFn, ItemMod, Lit, Pat, Signature, Stmt, TraitItemFn,
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
    pub(crate) index: &'a HandlerIndex,
    pub(crate) crate_key: PathBuf,
    pub(crate) module: Vec<String>,
    pub(crate) block_scopes: Vec<BlockScope>,
    /// Guard and middleware evidence of the builder chains being visited,
    /// keyed by chain root: the current scope and its enclosing scopes.
    pub(crate) chain_scopes: Vec<(*const Expr, Vec<AuthEvidence>)>,
    pub(crate) scope_context: String,
    pub(crate) routes: Vec<Route>,
}

impl<'a> RouteVisitor<'a> {
    pub(crate) fn new(file: PathBuf, index: &'a HandlerIndex) -> Self {
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
        }
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

    pub(crate) fn add_route(&mut self, node: &ExprMethodCall) {
        let name = node.method.to_string();
        if name != "route" && name != "resource" {
            return;
        }

        // `cfg.route("/path", builder)` names its path; `web::resource("/path")
        // .route(builder)` takes it from the resource the chain starts from.
        let Some((path, path_line)) = first_string_arg(&node.args)
            .zip(first_string_arg_line(&node.args))
            .or_else(|| {
                (name == "route")
                    .then(|| resource_path(&node.receiver))
                    .flatten()
            })
        else {
            return;
        };

        let local_prefix = scope_prefix(&node.receiver);
        let prefix = join_paths(&self.scope_context, &local_prefix);
        let path = join_paths(&prefix, &path);
        let target = find_handler(&node.args);
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
        for inherited in self.chain_scopes.iter().flat_map(|(_, evidence)| evidence) {
            let mut inherited = inherited.clone();
            inherited.handler = handler.clone();
            if !authorization.contains(&inherited) {
                authorization.push(inherited);
            }
        }

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
            },
        });
    }
}

impl<'ast> Visit<'ast> for RouteVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.add_attribute_routes(node);
        self.with_locals(signature_bindings(&node.sig), |visitor| {
            visit::visit_item_fn(visitor, node)
        });
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

        if node.method == "service" {
            let previous_context = self.scope_context.clone();
            self.scope_context = join_paths(&previous_context, &scope_prefix(&node.receiver));
            for arg in &node.args {
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
        for attribute in &node.attrs {
            let Some(method) = attribute_route_method(attribute) else {
                continue;
            };
            let Ok(path_literal) = attribute.parse_args::<syn::LitStr>() else {
                continue;
            };

            let prefix = self.scope_context.clone();
            let path = join_paths(&prefix, &path_literal.value());
            let handler = node.sig.ident.to_string();
            let authorization = handler_evidence(&self.file, node);

            self.routes.push(Route {
                method: method.into(),
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
                },
            });
        }
    }
}

pub(crate) fn attribute_route_method(attribute: &syn::Attribute) -> Option<&'static str> {
    for (name, method) in [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
        ("head", "HEAD"),
    ] {
        if attribute.path().is_ident(name) {
            return Some(method);
        }
    }
    None
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
                // `Route::method` adds a method guard; other builder calls
                // (`to`, `guard`, ...) do not constrain the method.
                if call.method == "method" {
                    methods.push(method_constant(call.args.first()?)?);
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
    let (authorization_kind, authorization_strength) = match method.method.to_string().as_str() {
        "guard" => (AuthEvidenceKind::AuthorizationGuard, AuthStrength::Strong),
        "wrap" => (
            AuthEvidenceKind::AuthorizationMiddleware,
            AuthStrength::Medium,
        ),
        _ => return,
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

pub(crate) fn signature_bindings(signature: &Signature) -> HashSet<String> {
    let mut names = HashSet::new();
    for input in &signature.inputs {
        if let FnArg::Typed(argument) = input {
            pattern_bindings(&argument.pat, &mut names);
        }
    }
    names
}

pub(crate) fn scope_prefix(expr: &Expr) -> String {
    match expr {
        Expr::MethodCall(method) => {
            let prefix = if method.method == "scope" {
                first_string_arg(&method.args).unwrap_or_default()
            } else {
                String::new()
            };
            join_paths(&scope_prefix(&method.receiver), &prefix)
        }
        Expr::Call(call) if call.args.first().is_some() && is_scope_call(&call.func) => {
            join_paths("", &first_string_arg(&call.args).unwrap_or_default())
        }
        Expr::Paren(paren) => scope_prefix(&paren.expr),
        Expr::Group(group) => scope_prefix(&group.expr),
        _ => String::new(),
    }
}

/// The path and line of the `web::resource("/path")` call a builder chain
/// starts from, as in `web::resource("/path").wrap(X).route(...)`.
pub(crate) fn resource_path(expr: &Expr) -> Option<(String, usize)> {
    match expr {
        Expr::MethodCall(method) => resource_path(&method.receiver),
        Expr::Paren(paren) => resource_path(&paren.expr),
        Expr::Group(group) => resource_path(&group.expr),
        Expr::Call(call)
            if matches!(
                &*call.func,
                Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment| segment.ident == "resource")
            ) =>
        {
            first_string_arg(&call.args).zip(first_string_arg_line(&call.args))
        }
        _ => None,
    }
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

pub(crate) fn find_handler(
    exprs: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<HandlerTarget> {
    exprs.iter().find_map(find_handler_in_expr)
}

pub(crate) fn find_handler_in_expr(expr: &Expr) -> Option<HandlerTarget> {
    match expr {
        Expr::MethodCall(method) if method.method == "to" => Some(match method.args.first()? {
            Expr::Path(path) if path.qself.is_none() => HandlerTarget::Path {
                segments: path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect(),
                leading_colon: path.path.leading_colon.is_some(),
            },
            _ => HandlerTarget::Other,
        }),
        Expr::MethodCall(method) => {
            find_handler(&method.args).or_else(|| find_handler_in_expr(&method.receiver))
        }
        _ => None,
    }
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
