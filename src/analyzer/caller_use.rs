//! How a handler treats its caller: which identity values it takes, which of
//! their fields it reads, which calls it hands them to, and whether it
//! compares them with something else.
//!
//! These facts are recorded without deciding what they mean. A route is
//! later compared with peers that take the same identity type: when nearly
//! all of them hand it to the same call (`check_private_instance`), read the
//! same field (`auth.profile`), or compare it with a record, a route that
//! does not is reported (see `drift::peer_checks`). The vocabulary comes from
//! the scanned application, not from a list of names.
//!
//! Features are strings of the form `kind:Type` or `kind:Type:detail`:
//! - `takes:T`: a handler or a closure inside it binds a parameter of
//!   identity type `T` to a name it can use (not `_` or `_name`);
//! - `reads:T:field`: it reads `binding.field` of such a parameter;
//! - `checks:T:callee`: it passes the parameter, a field of it, or a value
//!   computed from it to `callee` (as an argument or the receiver), where
//!   the call decides something: its value is discarded after `?`
//!   (`check_private_instance(&user, &site)?;`) or it is a branch condition
//!   (`if !is_mod_or_admin(..)`). A call whose result is kept is a fetch
//!   (`let post = Post::read(&mut pool, id, &user)?`), not a check;
//! - `scheme:Name`: it names an authentication scheme value
//!   (`&auth::AdminApiAuth`, `auth::JWTAuth { .. }`), as handlers that pass
//!   their scheme to a wrapper do;
//! - `compares:T`: it compares a value derived from the parameter with a
//!   value that is not (a record's owner field, an id from the path).

use std::collections::{BTreeSet, HashMap, HashSet};
use syn::{
    BinOp, Expr, ExprClosure, FnArg, GenericArgument, ItemFn, Pat, PathArguments, Type,
    visit::{self, Visit},
};

use super::{
    evidence::{identity_type, names_authentication},
    handlers::{HandlerIndex, MAX_HELPER_DEPTH},
    model::{HandlerResolution, Route},
    routes::{HandlerTarget, handler_target},
};

/// Calls that only convert, copy, or unwrap a value; passing an identity
/// through them passes the identity.
const TRANSPARENT_CALLS: [&str; 22] = [
    "clone",
    "as_ref",
    "as_mut",
    "into_inner",
    "to_owned",
    "to_string",
    "borrow",
    "into",
    "deref",
    "as_deref",
    "map",
    "and_then",
    "unwrap",
    "unwrap_or",
    "unwrap_or_default",
    "expect",
    "ok",
    "ok_or",
    "ok_or_else",
    "get_id",
    "Some",
    "Ok",
];

/// The label of an identity whose type Archer cannot see.
pub(crate) const UNKNOWN_TYPE: &str = "?";

/// Methods that probe a value's shape (`user.is_none()`), not the caller's
/// rights; presence of an identity is authentication, judged elsewhere.
const PROBES: [&str; 7] = [
    "is_none",
    "is_some",
    "is_ok",
    "is_err",
    "is_empty",
    "is_some_and",
    "is_none_or",
];

/// Caller-use features for each route, parallel to `routes`.
///
/// A handler's features include those of the repository functions it
/// calls, up to `MAX_HELPER_DEPTH` deep. A helper's parameter counts as the
/// caller's identity when its type is an identity type or when the call
/// passes it a value derived from one (`delete_evidence(state,
/// auth.profile_id, ..)`), so a check made in a service function is the
/// handler's check.
pub(crate) fn caller_use(index: &HandlerIndex, routes: &[Route]) -> Vec<Vec<String>> {
    let mut analyzed: HashMap<(usize, Vec<(usize, String)>), Analysis> = HashMap::new();
    let mut analyze = |definition: usize, bound: &[(usize, String)]| -> Analysis {
        analyzed
            .entry((definition, bound.to_vec()))
            .or_insert_with(|| analyze_function(index.items[definition], bound))
            .clone()
    };
    let mut combined: HashMap<usize, Vec<String>> = HashMap::new();
    for route in routes {
        let Some(definition) = route.origin.definition else {
            continue;
        };
        if combined.contains_key(&definition) {
            continue;
        }
        let root = analyze(definition, &[]);
        let mut features = root.features.clone();
        let mut stack = vec![(definition, root, 0usize)];
        let mut seen: HashSet<(usize, Vec<(usize, String)>)> =
            HashSet::from([(definition, Vec::new())]);
        while let Some((current, analysis, depth)) = stack.pop() {
            if depth == MAX_HELPER_DEPTH {
                continue;
            }
            let caller = &index.definitions[current];
            let mut callees: Vec<(usize, Vec<(usize, String)>)> = Vec::new();
            for (target, bound) in &analysis.flows {
                if let (Some(callee), resolution) =
                    index.resolve_handler_index(&caller.crate_key, &caller.module, target)
                    && !matches!(resolution, HandlerResolution::UniqueName)
                    && callee != current
                {
                    callees.push((callee, bound.clone()));
                }
            }
            for (callee, _) in index.resolved_calls(current).calls {
                callees.push((callee, Vec::new()));
            }
            for (callee, bound) in callees {
                if !seen.insert((callee, bound.clone())) {
                    continue;
                }
                let helper = analyze(callee, &bound);
                // A helper's parameters are values handed to it, not
                // extractors: only what it reads, checks, and compares
                // is the handler's doing.
                features.extend(
                    helper
                        .features
                        .iter()
                        .filter(|feature| {
                            !feature.starts_with("takes:") && !feature.starts_with("scheme:")
                        })
                        .cloned(),
                );
                stack.push((callee, helper, depth + 1));
            }
        }
        combined.insert(definition, features.into_iter().collect());
    }
    routes
        .iter()
        .map(|route| {
            route
                .origin
                .definition
                .and_then(|definition| combined.get(&definition).cloned())
                .unwrap_or_default()
        })
        .collect()
}

#[derive(Clone, Default)]
struct Analysis {
    features: BTreeSet<String>,
    /// Calls by path that receive identity-derived arguments: the target,
    /// and each such argument's position and identity label.
    flows: Vec<(HandlerTarget, Vec<(usize, String)>)>,
}

/// One function's features, with `bound` naming parameters (by position)
/// that hold the caller's identity whatever their type.
fn analyze_function(item: &ItemFn, bound: &[(usize, String)]) -> Analysis {
    let mut visitor = CallerUseVisitor::default();
    for (position, input) in item.sig.inputs.iter().enumerate() {
        let FnArg::Typed(typed) = input else {
            continue;
        };
        match bound.iter().find(|(index, _)| *index == position) {
            Some((_, label)) => {
                visitor.bind_names(&typed.pat, label);
            }
            None => visitor.bind_parameter(&typed.pat, &typed.ty),
        }
    }
    visitor.visit_block(&item.block);
    Analysis {
        features: visitor.features,
        flows: visitor.flows,
    }
}

/// The features of one function: its own parameters and body, and closures
/// written inside it (`server_wrap(.., |state, auth: AuthenticationData, ..| ..)`).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn function_features(item: &ItemFn) -> BTreeSet<String> {
    analyze_function(item, &[]).features
}

/// The features of a closure written as a route handler.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn closure_features(closure: &ExprClosure) -> BTreeSet<String> {
    let mut visitor = CallerUseVisitor::default();
    visitor.visit_expr_closure(closure);
    visitor.features
}

#[derive(Default)]
struct CallerUseVisitor {
    /// Names bound to an identity value, with the identity type's label.
    bindings: HashMap<String, String>,
    features: BTreeSet<String>,
    flows: Vec<(HandlerTarget, Vec<(usize, String)>)>,
}

impl CallerUseVisitor {
    fn bind_parameter(&mut self, pattern: &Pat, ty: &Type) {
        if !identity_type(ty) {
            return;
        }
        let label = type_label(ty);
        if self.bind_names(pattern, &label) {
            self.features.insert(format!("takes:{label}"));
        }
    }

    /// Binds the names a pattern introduces to `label`; false when it binds
    /// none that the code can use (`_`, `_auth`).
    fn bind_names(&mut self, pattern: &Pat, label: &str) -> bool {
        let mut names = HashSet::new();
        super::routes::pattern_bindings(pattern, &mut names);
        let mut bound = false;
        for name in names {
            if name.starts_with('_') {
                continue;
            }
            self.bindings.insert(name, label.to_string());
            bound = true;
        }
        bound
    }

    /// The identity type an expression is derived from: a binding, a field
    /// or method chain on one, a reference or conversion of one.
    fn derived(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Path(path) if path.qself.is_none() => {
                let ident = path.path.get_ident()?;
                self.bindings.get(&ident.to_string()).cloned()
            }
            Expr::Field(field) => self.derived(&field.base),
            Expr::MethodCall(call) => self.derived(&call.receiver),
            Expr::Reference(reference) => self.derived(&reference.expr),
            Expr::Paren(paren) => self.derived(&paren.expr),
            Expr::Group(group) => self.derived(&group.expr),
            Expr::Unary(unary) => self.derived(&unary.expr),
            Expr::Try(inner) => self.derived(&inner.expr),
            Expr::Await(inner) => self.derived(&inner.base),
            Expr::Cast(cast) => self.derived(&cast.expr),
            Expr::Call(call) => match &*call.func {
                Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment| {
                        TRANSPARENT_CALLS.contains(&segment.ident.to_string().as_str())
                    }) =>
                {
                    call.args.iter().find_map(|argument| self.derived(argument))
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// The first field read on an identity binding: `auth.profile` in
    /// `auth.profile.map(..)`, `person` in `local_user_view.person.id`.
    fn first_field(&self, expr: &Expr) -> Option<(String, String)> {
        let Expr::Field(field) = expr else {
            return None;
        };
        match &*field.base {
            Expr::Path(path) if path.qself.is_none() => {
                let ident = path.path.get_ident()?;
                let label = self.bindings.get(&ident.to_string())?;
                let member = match &field.member {
                    syn::Member::Named(name) => name.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };
                Some((label.clone(), member))
            }
            _ => None,
        }
    }

    /// Records the identity values a deciding call receives.
    fn decides(&mut self, expr: &Expr) {
        match expr {
            Expr::Try(inner) => self.decides(&inner.expr),
            Expr::Await(inner) => self.decides(&inner.base),
            Expr::Paren(inner) => self.decides(&inner.expr),
            Expr::Group(inner) => self.decides(&inner.expr),
            Expr::Unary(inner) => self.decides(&inner.expr),
            Expr::Let(inner) => self.decides(&inner.expr),
            Expr::Binary(binary) if matches!(binary.op, BinOp::And(_) | BinOp::Or(_)) => {
                self.decides(&binary.left);
                self.decides(&binary.right);
            }
            Expr::Call(call) => {
                let Expr::Path(path) = &*call.func else {
                    return;
                };
                let Some(callee) = callee_name(&path.path) else {
                    return;
                };
                self.checks(&callee, call.args.iter());
            }
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                if TRANSPARENT_CALLS.contains(&method.as_str()) {
                    // `check(..).await.map_err(..)?`: the check is inside.
                    self.decides(&call.receiver);
                    return;
                }
                self.checks(
                    &method,
                    std::iter::once(&*call.receiver).chain(call.args.iter()),
                );
            }
            _ => {}
        }
    }

    fn checks<'e>(&mut self, callee: &str, arguments: impl Iterator<Item = &'e Expr>) {
        if TRANSPARENT_CALLS.contains(&callee) || PROBES.contains(&callee) {
            return;
        }
        for argument in arguments {
            if let Some(label) = self.derived(argument) {
                self.features.insert(format!("checks:{label}:{callee}"));
            }
        }
    }
}

impl CallerUseVisitor {
    /// A unit or struct value named for authentication: `AdminApiAuth`,
    /// `NoAuth`, `JWTAuthProfileFromRoute`.
    fn scheme(&mut self, path: &syn::Path) {
        let Some(last) = path.segments.last() else {
            return;
        };
        let name = last.ident.to_string();
        if name.chars().next().is_some_and(char::is_uppercase)
            && name.chars().any(char::is_lowercase)
            && names_authentication(&name)
        {
            self.features.insert(format!("scheme:{name}"));
        }
    }
}

/// `Type::function` keeps its type, `Post::read` and `Comment::read` being
/// different calls; a free function is named by its last segment.
fn callee_name(path: &syn::Path) -> Option<String> {
    let segments: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let last = segments.last()?;
    let associated = segments.len() >= 2
        && segments[segments.len() - 2]
            .chars()
            .next()
            .is_some_and(char::is_uppercase);
    Some(if associated {
        segments[segments.len() - 2..].join("::")
    } else {
        last.clone()
    })
}

impl<'ast> Visit<'ast> for CallerUseVisitor {
    fn visit_expr_closure(&mut self, node: &'ast ExprClosure) {
        for input in &node.inputs {
            match input {
                Pat::Type(typed) => self.bind_parameter(&typed.pat, &typed.ty),
                // `|state, auth, req, _|`: the type is inferred from the
                // wrapper. A name that says authentication is taken as an
                // identity of unknown type, so the route is not reported
                // for ignoring the caller, and not compared on its uses.
                Pat::Ident(ident) if names_authentication(&ident.ident.to_string()) => {
                    if self.bind_names(input, UNKNOWN_TYPE) {
                        self.features.insert(format!("takes:{UNKNOWN_TYPE}"));
                    }
                }
                _ => {}
            }
        }
        visit::visit_expr_closure(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        // `let profile_id = auth.profile.map(..)` carries the identity on.
        if let Some(init) = &node.init
            && let Some(label) = self.derived(&init.expr)
        {
            let mut names = HashSet::new();
            super::routes::pattern_bindings(&node.pat, &mut names);
            for name in names {
                if !name.starts_with('_') {
                    self.bindings.entry(name).or_insert_with(|| label.clone());
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        if let Some((label, field)) = self.first_field(&Expr::Field(node.clone())) {
            self.features.insert(format!("reads:{label}:{field}"));
        }
        visit::visit_expr_field(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let bound: Vec<(usize, String)> = node
            .args
            .iter()
            .enumerate()
            .filter_map(|(position, argument)| {
                self.derived(argument).map(|label| (position, label))
            })
            .collect();
        if !bound.is_empty()
            && let Some(target) = handler_target(&node.func)
        {
            self.flows.push((target, bound));
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if let syn::Stmt::Expr(expr, Some(_)) = node {
            self.decides(expr);
        }
        visit::visit_stmt(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.decides(&node.cond);
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            let left = self.derived(&node.left);
            let right = self.derived(&node.right);
            let literal = |expr: &Expr| matches!(expr, Expr::Lit(_));
            match (left, right) {
                (Some(label), None) if !literal(&node.right) && !is_variant(&node.right) => {
                    self.features.insert(format!("compares:{label}"));
                }
                (None, Some(label)) if !literal(&node.left) && !is_variant(&node.left) => {
                    self.features.insert(format!("compares:{label}"));
                }
                _ => {}
            }
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.scheme(&node.path);
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        self.scheme(&node.path);
        visit::visit_expr_struct(self, node);
    }

    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
}

/// An enum variant or constant (`Role::Admin`, `MAX`): comparing the caller
/// with one checks a role or a setting, not ownership.
fn is_variant(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
            segment
                .ident
                .to_string()
                .chars()
                .next()
                .is_some_and(char::is_uppercase)
        }),
        Expr::Reference(reference) => is_variant(&reference.expr),
        Expr::Paren(paren) => is_variant(&paren.expr),
        _ => false,
    }
}

/// A short, stable name for an identity type: its last path segment, with
/// the wrapper kept for `Option` (an optional caller is handled differently
/// from a required one) and dropped for `Box`, `Arc`, and references.
fn type_label(ty: &Type) -> String {
    match ty {
        Type::Reference(reference) => type_label(&reference.elem),
        Type::Paren(paren) => type_label(&paren.elem),
        Type::Group(group) => type_label(&group.elem),
        Type::Path(path) => {
            let Some(segment) = path.path.segments.last() else {
                return String::new();
            };
            let name = segment.ident.to_string();
            let inner = match &segment.arguments {
                PathArguments::AngleBracketed(arguments) => {
                    arguments.args.iter().find_map(|argument| match argument {
                        GenericArgument::Type(inner) if identity_type(inner) => {
                            Some(type_label(inner))
                        }
                        _ => None,
                    })
                }
                _ => None,
            };
            match (name.as_str(), inner) {
                ("Option", Some(inner)) => format!("Option<{inner}>"),
                ("Box" | "Arc" | "Rc", Some(inner)) => inner,
                (_, Some(inner)) => format!("{name}<{inner}>"),
                (_, None) => name,
            }
        }
        _ => String::new(),
    }
}
