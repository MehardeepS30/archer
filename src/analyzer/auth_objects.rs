//! What an application's own authentication objects check, read from the
//! trait method that receives the request, so that an object passed by
//! value to a request wrapper (`server_wrap(.., &auth::SessionAuth, ..)`)
//! is evidence like an extractor, not an opaque delegation.
//!
//! ```rust,ignore
//! impl<A> Authenticate<A> for SessionWithRoleFromRoute {
//!     async fn authenticate(&self, headers: &HeaderMap, state: &A) -> Result<..> {
//!         let token = parse_token(headers, state).await?;          // identity
//!         check_permission(self.required, &token.role)?;           // privilege
//!         when(token.team_id != self.team_id, || Err(..))?;        // scoped to the route
//!         ..
//!     }
//! }
//! ```
//!
//! A type's method is an authentication method when it belongs to a trait
//! implementation (not `FromRequest`, a middleware `Service` or
//! `Transform`) and takes the request, its headers, or a service request.
//! From its body:
//! - a call of a role or permission check (`check_permission`), or a role
//!   variant it admits, makes it a privilege check;
//! - a comparison of one of the object's own fields (`self.team_id`, set by
//!   the route) with a value from the request scopes the caller to that
//!   route value;
//! - a body that can fail (`?`, `Err`) identifies the caller;
//! - a body that cannot fail admits anyone.
//!
//! A body that hands the request to another object (`OtherAuth.authenticate
//! (..)`) has that object's checks too; one that hands it to its own field
//! (`self.0.authenticate(..)`) wraps an object chosen where it is built.

use std::{cell::RefCell, collections::HashMap};
use syn::{
    Expr, FnArg, ImplItem, Item, Type,
    visit::{self, Visit},
};

use super::model::EvidenceTier;

/// What an authentication object was found to check.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct AuthObject {
    pub(crate) tier: Tier,
    /// Role or permission checks it makes (`check_permission`).
    pub(crate) privileges: Vec<String>,
    /// Its own fields it holds the caller to (`team_id`).
    pub(crate) scopes: Vec<String>,
    /// It hands the request to an object it holds (`self.0`).
    pub(crate) wraps: bool,
    /// Where the authentication method is, `file:line`.
    pub(crate) site: String,
    /// Other objects it hands the request to.
    delegates: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum Tier {
    /// It cannot fail.
    #[default]
    Open,
    Identity,
    Scoped,
    Privilege,
}

impl AuthObject {
    /// The object with the checks of the one it wraps.
    pub(crate) fn wrapping(&self, inner: &AuthObject) -> AuthObject {
        let mut combined = self.clone();
        combined.tier = combined.tier.max(inner.tier);
        combined.privileges.extend(inner.privileges.iter().cloned());
        combined.scopes.extend(inner.scopes.iter().cloned());
        combined.privileges.sort();
        combined.privileges.dedup();
        combined.scopes.sort();
        combined.scopes.dedup();
        combined.wraps = false;
        combined
    }
}

thread_local! {
    static OBJECTS: RefCell<HashMap<String, AuthObject>> = RefCell::new(HashMap::new());
    /// Functions that return one of several authentication objects they
    /// are given (`pick(&a, &b, headers) -> &dyn Auth`).
    static CHOOSERS: RefCell<std::collections::HashSet<String>> = RefCell::new(Default::default());
}

/// The learned checks of an authentication object type, by its name.
pub(crate) fn auth_object(name: &str) -> Option<AuthObject> {
    OBJECTS.with(|map| map.borrow().get(name).cloned())
}

/// Whether a function returns one of the authentication objects it gets:
/// the request may pass any of them, so it is held to the weakest.
pub(crate) fn chooses_between(name: &str) -> bool {
    CHOOSERS.with(|set| set.borrow().contains(name))
}

const REQUEST_TYPES: [&str; 5] = [
    "HeaderMap",
    "HttpRequest",
    "ServiceRequest",
    "RequestHead",
    "HeaderValue",
];
const NOT_AUTH_TRAITS: [&str; 6] = [
    "FromRequest",
    "Service",
    "Transform",
    "Responder",
    "ResponseError",
    "Handler",
];

pub(crate) fn index_auth_objects<'a>(
    files: impl IntoIterator<Item = (&'a std::path::Path, &'a syn::File)>,
) {
    let files: Vec<_> = files.into_iter().collect();
    let mut functions = HashMap::new();
    for (_, file) in &files {
        index_functions(&file.items, &mut functions);
    }
    let mut found: HashMap<String, Vec<AuthObject>> = HashMap::new();
    let mut choosers = std::collections::HashSet::new();
    for (path, file) in &files {
        collect(path, &file.items, &functions, &mut found, &mut choosers);
    }
    // The most restrictive implementation of a type stands for it: which
    // one runs depends on the output type the wrapper asks for.
    let mut objects: HashMap<String, AuthObject> = found
        .into_iter()
        .filter_map(|(name, mut impls)| {
            impls.sort_by_key(|object| (object.tier, object.scopes.len(), object.privileges.len()));
            impls.pop().map(|object| (name, object))
        })
        .collect();
    // Objects that hand the request to other objects have their checks.
    for _ in 0..4 {
        let snapshot = objects.clone();
        let mut changed = false;
        for object in objects.values_mut() {
            for delegate in object.delegates.clone() {
                if let Some(other) = snapshot.get(&delegate) {
                    let combined = object.wrapping(other);
                    let combined = AuthObject {
                        wraps: object.wraps,
                        ..combined
                    };
                    if combined != *object {
                        *object = combined;
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    OBJECTS.with(|map| *map.borrow_mut() = objects);
    CHOOSERS.with(|set| *set.borrow_mut() = choosers);
}

fn last_type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Reference(reference) => last_type_name(&reference.elem),
        Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

/// Free functions by name, which an authentication method may hand the
/// request and its own fields to.
type Functions<'a> = HashMap<String, Vec<&'a syn::ItemFn>>;

fn index_functions<'a>(items: &'a [Item], functions: &mut Functions<'a>) {
    for item in items {
        match item {
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    index_functions(items, functions);
                }
            }
            Item::Fn(function) => functions
                .entry(function.sig.ident.to_string())
                .or_default()
                .push(function),
            _ => {}
        }
    }
}

fn collect(
    path: &std::path::Path,
    items: &[Item],
    functions: &Functions<'_>,
    found: &mut HashMap<String, Vec<AuthObject>>,
    choosers: &mut std::collections::HashSet<String>,
) {
    for item in items {
        match item {
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect(path, items, functions, found, choosers);
                }
            }
            Item::Fn(function) => {
                // `fn pick<'a>(a: &'a dyn Auth, b: &'a dyn Auth, h: &HeaderMap) -> &'a dyn Auth`
                if let syn::ReturnType::Type(_, output) = &function.sig.output {
                    let written = quote::ToTokens::to_token_stream(&**output).to_string();
                    let same = function
                        .sig
                        .inputs
                        .iter()
                        .filter(|input| {
                            matches!(input, FnArg::Typed(typed)
                            if quote::ToTokens::to_token_stream(&*typed.ty).to_string() == written)
                        })
                        .count();
                    if same >= 2 && written.contains("dyn") {
                        choosers.insert(function.sig.ident.to_string());
                    }
                }
            }
            Item::Impl(implementation) => {
                let Some((trait_path, _)) = &implementation.trait_ else {
                    continue;
                };
                if trait_path.segments.last().is_none_or(|segment| {
                    NOT_AUTH_TRAITS.contains(&segment.ident.to_string().as_str())
                }) {
                    continue;
                }
                let Some(name) = last_type_name(&implementation.self_ty) else {
                    continue;
                };
                for item in &implementation.items {
                    let ImplItem::Fn(function) = item else {
                        continue;
                    };
                    let takes_request = function.sig.inputs.iter().any(|input| match input {
                        FnArg::Typed(typed) => last_type_name(&typed.ty)
                            .is_some_and(|ty| REQUEST_TYPES.contains(&ty.as_str())),
                        FnArg::Receiver(_) => false,
                    });
                    if !takes_request
                        || function.sig.receiver().is_none()
                        || matches!(function.sig.output, syn::ReturnType::Default)
                    {
                        continue;
                    }
                    let mut visitor = Body {
                        method: function.sig.ident.to_string(),
                        functions,
                        own: HashMap::new(),
                        locals: HashMap::new(),
                        configured: Default::default(),
                        depth: 0,
                        rejects: false,
                        object: AuthObject::default(),
                    };
                    visitor.visit_block(&function.block);
                    let mut object = visitor.object;
                    // A wrapper's field is the object it wraps, not a value
                    // the route sets.
                    if object.wraps {
                        object.scopes.retain(|field| field != "0");
                    }
                    object.tier = if !object.privileges.is_empty() {
                        Tier::Privilege
                    } else if !object.scopes.is_empty() {
                        Tier::Scoped
                    } else if visitor.rejects {
                        Tier::Identity
                    } else {
                        Tier::Open
                    };
                    // A body that only hands the request on is as strict as
                    // what it hands it to.
                    if object.tier == Tier::Open && (object.wraps || !object.delegates.is_empty()) {
                        object.tier = Tier::Open;
                    }
                    object.privileges.sort();
                    object.privileges.dedup();
                    object.scopes.sort();
                    object.scopes.dedup();
                    object.site = format!(
                        "{}:{}",
                        path.file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        function.sig.ident.span().start().line
                    );
                    found.entry(name.clone()).or_default().push(object);
                }
            }
            _ => {}
        }
    }
}

struct Body<'f> {
    method: String,
    functions: &'f Functions<'f>,
    /// In a function the method calls: its parameters that receive the
    /// object's own fields.
    own: HashMap<String, String>,
    /// Local bindings of other authentication objects: `let api = ApiAuth { .. }`.
    locals: HashMap<String, String>,
    /// Local bindings read from the application's configuration:
    /// `let key = &state.conf().secrets.admin_key`.
    configured: HashMap<String, String>,
    depth: usize,
    rejects: bool,
    object: AuthObject,
}

/// The object's field an expression reads: `self.field`, `self.0`, or a
/// parameter of a called function that received one, through `&`,
/// `.clone()` and similar.
fn own_field(expr: &Expr, own: &HashMap<String, String>) -> Option<String> {
    match expr {
        Expr::Reference(inner) => own_field(&inner.expr, own),
        Expr::Paren(inner) => own_field(&inner.expr, own),
        Expr::MethodCall(call)
            if call.args.is_empty() && CONVERSIONS.contains(&call.method.to_string().as_str()) =>
        {
            own_field(&call.receiver, own)
        }
        Expr::Path(path) => path
            .path
            .get_ident()
            .and_then(|ident| own.get(&ident.to_string()).cloned()),
        Expr::Field(field) => match &*field.base {
            Expr::Path(base) if base.path.is_ident("self") => Some(match &field.member {
                syn::Member::Named(name) => name.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            }),
            _ => None,
        },
        _ => None,
    }
}

/// Names of the application's configuration in an access path:
/// `state.conf().secrets.admin_key`, `settings.api_token`.
const CONFIGURATION: [&str; 5] = ["conf", "config", "configuration", "settings", "secrets"];

/// Whether an expression reads the application's configuration: some field
/// or method on its access path is named for it.
fn reads_configuration(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(inner) => reads_configuration(&inner.expr),
        Expr::Paren(inner) => reads_configuration(&inner.expr),
        Expr::Field(field) => {
            matches!(&field.member, syn::Member::Named(name) if CONFIGURATION.contains(&name.to_string().as_str()))
                || reads_configuration(&field.base)
        }
        Expr::MethodCall(call) => {
            CONFIGURATION.contains(&call.method.to_string().as_str()) || reads_configuration(&call.receiver)
        }
        Expr::Path(path) => path
            .path
            .get_ident()
            .is_some_and(|ident| CONFIGURATION.contains(&ident.to_string().as_str())),
        _ => false,
    }
}

/// Methods that convert or copy a value without changing what it is.
const CONVERSIONS: [&str; 9] = [
    "clone",
    "as_ref",
    "to_owned",
    "as_str",
    "to_string",
    "peek",
    "deref",
    "borrow",
    "get_string_repr",
];

/// The type an expression builds: `Auth`, `Auth { .. }`, `Auth(..)`.
fn built_type(expr: &Expr) -> Option<String> {
    let path = match expr {
        Expr::Reference(inner) => return built_type(&inner.expr),
        Expr::Paren(inner) => return built_type(&inner.expr),
        Expr::Path(path) => &path.path,
        Expr::Struct(item) => &item.path,
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => &path.path,
            _ => return None,
        },
        _ => return None,
    };
    let last = path.segments.last()?.ident.to_string();
    last.chars()
        .next()
        .is_some_and(char::is_uppercase)
        .then_some(last)
}

fn constant(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(_) => true,
        Expr::Path(path) => path.path.segments.len() >= 2 || path.path.is_ident("None"),
        _ => false,
    }
}

impl Body<'_> {
    /// The name of a configured value an expression reads, through
    /// references and conversions.
    fn configured_value(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Reference(inner) => self.configured_value(&inner.expr),
            Expr::Paren(inner) => self.configured_value(&inner.expr),
            Expr::MethodCall(call) if call.args.is_empty() && CONVERSIONS.contains(&call.method.to_string().as_str()) => {
                self.configured_value(&call.receiver)
            }
            Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|ident| self.configured.get(&ident.to_string()).cloned()),
            Expr::Field(field) if reads_configuration(expr) => match &field.member {
                syn::Member::Named(name) => Some(name.to_string()),
                syn::Member::Unnamed(_) => None,
            },
            _ => None,
        }
    }

    /// Follows a call of a crate function the method hands its own fields
    /// or the request to.
    fn follow(
        &mut self,
        name: &str,
        arguments: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    ) {
        if self.depth >= 2 {
            return;
        }
        let Some(candidates) = self.functions.get(name) else {
            return;
        };
        for function in candidates.iter().take(2) {
            let mut own = HashMap::new();
            for (input, argument) in function.sig.inputs.iter().zip(arguments) {
                if let (FnArg::Typed(typed), Some(field)) = (input, own_field(argument, &self.own))
                    && let syn::Pat::Ident(binding) = &*typed.pat
                {
                    own.insert(binding.ident.to_string(), field);
                }
            }
            let mut inner = Body {
                method: self.method.clone(),
                functions: self.functions,
                own,
                locals: HashMap::new(),
                configured: Default::default(),
                depth: self.depth + 1,
                rejects: false,
                object: AuthObject::default(),
            };
            inner.visit_block(&function.block);
            self.rejects |= inner.rejects;
            self.object.privileges.extend(inner.object.privileges);
            self.object.scopes.extend(inner.object.scopes);
            self.object.delegates.extend(inner.object.delegates);
            self.object.wraps |= inner.object.wraps;
        }
    }

    fn check_name(&mut self, name: &str) {
        if let Some((kind, _)) = super::evidence::classify_check_name(name)
            && super::model::EvidenceTier::of(&kind) == EvidenceTier::Privilege
        {
            self.object.privileges.push(name.to_string());
        }
    }
}

impl<'ast> Visit<'ast> for Body<'_> {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(binding), Some(init)) = (&node.pat, &node.init)
            && let Some(ty) = built_type(&init.expr)
        {
            self.locals.insert(binding.ident.to_string(), ty);
        }
        if let (syn::Pat::Ident(binding), Some(init)) = (&node.pat, &node.init)
            && reads_configuration(&init.expr)
        {
            let name = self.configured_value(&init.expr).unwrap_or_else(|| binding.ident.to_string());
            self.configured.insert(binding.ident.to_string(), name);
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.rejects = true;
        visit::visit_expr_try(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func
            && let Some(last) = path.path.segments.last()
        {
            let name = last.ident.to_string();
            if name == "Err" || name == "err" || name == "bail" {
                self.rejects = true;
            }
            self.check_name(&name);
            if path.path.segments.len() <= 2 && name.chars().next().is_some_and(char::is_lowercase)
            {
                let hands_over = node.args.iter().any(|argument| own_field(argument, &self.own).is_some()
                    || matches!(argument, Expr::Path(p) if p.path.get_ident().is_some_and(|i| i.to_string().contains("header"))));
                if hands_over {
                    self.follow(&name, &node.args);
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.segments.last().is_some_and(|segment| {
            ["bail", "ensure", "assert"].contains(&segment.ident.to_string().as_str())
        }) {
            self.rejects = true;
        }
        visit::visit_macro(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if ["ok_or", "ok_or_else", "map_err"].contains(&method.as_str()) {
            self.rejects = true;
        }
        self.check_name(&method);
        if method == self.method {
            match &*node.receiver {
                // `self.0.authenticate(..)`: the object it wraps.
                Expr::Field(field) if matches!(&*field.base, Expr::Path(base) if base.path.is_ident("self")) =>
                {
                    self.object.wraps = true;
                }
                // `OtherAuth.authenticate(..)`, `OtherAuth { .. }.authenticate(..)`
                Expr::Path(path) => {
                    if let Some(ident) = path.path.get_ident()
                        && let Some(ty) = self.locals.get(&ident.to_string())
                    {
                        self.object.delegates.push(ty.clone());
                    } else if let Some(last) = path.path.segments.last()
                        && last
                            .ident
                            .to_string()
                            .chars()
                            .next()
                            .is_some_and(char::is_uppercase)
                    {
                        self.object.delegates.push(last.ident.to_string());
                    }
                }
                Expr::Struct(item) => {
                    if let Some(last) = item.path.segments.last() {
                        self.object.delegates.push(last.ident.to_string());
                    }
                }
                Expr::Call(call) => {
                    if let Expr::Path(path) = &*call.func
                        && let Some(last) = path.path.segments.last()
                    {
                        self.object.delegates.push(last.ident.to_string());
                    }
                }
                _ => {}
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            for (own, other) in [(&*node.left, &*node.right), (&*node.right, &*node.left)] {
                if let Some(field) = own_field(own, &self.own)
                    && own_field(other, &self.own).is_none()
                    && !constant(other)
                {
                    self.object.scopes.push(field);
                }
                // A value from the request compared with one from the
                // application's configuration: the caller presents the
                // operator's own secret.
                if own_field(own, &self.own).is_none()
                    && own_field(other, &self.own).is_none()
                    && !constant(other)
                    && let Some(name) = self.configured_value(own)
                {
                    self.object.privileges.push(name);
                }
            }
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        visit::visit_expr_closure(self, node);
    }
}

/// Prints the learned objects, for debugging.
pub(crate) fn dump() {
    OBJECTS.with(|map| {
        let map = map.borrow();
        let mut names: Vec<_> = map.keys().collect();
        names.sort();
        for name in names {
            eprintln!("auth object {name}: {:?}", map[name]);
        }
    });
    CHOOSERS.with(|set| eprintln!("choosers: {:?}", set.borrow()));
}

/// What a route's learned authentication objects check, from its evidence:
/// for each object passed, the privilege checks of its type and the route
/// values it holds the caller to.
fn passed(route: &super::model::Route) -> Vec<(String, Vec<String>, Vec<String>)> {
    use super::model::AuthEvidenceKind;
    let mut by_symbol: HashMap<&str, (Vec<String>, Vec<String>)> = HashMap::new();
    for evidence in &route.authorization {
        let Some(symbol) = evidence.symbol.as_deref() else {
            continue;
        };
        if !is_learned(evidence) {
            continue;
        }
        let entry = by_symbol.entry(symbol).or_insert_with(|| {
            let mut privileges = Vec::new();
            for name in symbol
                .split(|character: char| !(character.is_alphanumeric() || character == '_'))
                .filter(|word| word.starts_with(|character: char| character.is_ascii_uppercase()))
            {
                if let Some(object) = auth_object(name) {
                    privileges.extend(object.privileges);
                }
            }
            privileges.sort();
            privileges.dedup();
            (privileges, Vec::new())
        });
        if evidence.kind == AuthEvidenceKind::OwnershipCheck {
            entry.1.extend(
                evidence
                    .requirements
                    .iter()
                    .filter_map(|key| key.strip_prefix("scope:"))
                    .map(str::to_string),
            );
        }
    }
    let mut passed: Vec<_> = by_symbol
        .into_iter()
        .map(|(symbol, (privileges, scopes))| (symbol.to_string(), privileges, scopes))
        .collect();
    passed.sort();
    passed
}

/// Evidence read from a learned authentication object passed to a call.
pub(crate) fn is_learned(evidence: &super::model::AuthEvidence) -> bool {
    use super::model::AuthEvidenceKind;
    !matches!(
        evidence.kind,
        AuthEvidenceKind::Delegated | AuthEvidenceKind::Unknown
    ) && evidence.mechanism.contains("` receives `")
}

/// Share of the routes that take a scope value and pass an object of the
/// same checks whose objects must hold the caller to it.
const SCOPE_CONSENSUS: f64 = 0.6;
const SCOPE_MINIMUM: usize = 3;

/// The scope check: a route whose path takes a value (`{team_id}`) that the
/// authentication objects of the other routes taking it hold the caller to
/// (`TeamFromRoute { team_id, .. }`), while the object it passes makes the
/// same checks without that one: a caller of one team reaches another's.
pub(crate) fn unscoped_objects(
    routes: &[super::model::Route],
    peer_groups: &mut Vec<super::model::PeerGroup>,
    invariants: &mut Vec<super::model::AuthorizationInvariant>,
    finding_details: &mut Vec<super::model::Finding>,
) {
    use super::model::*;
    let routes = super::drift::unique_routes(routes.iter());
    let objects: Vec<_> = routes.iter().map(|route| passed(route)).collect();
    let parameters: Vec<Vec<String>> = routes
        .iter()
        .map(|route| {
            route
                .path
                .split('/')
                .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
                .map(|inner| inner.split(':').next().unwrap_or(inner).to_string())
                .collect()
        })
        .collect();
    // A parameter-binding finding (`peer_checks::unbound_parameter`) gives
    // way to this one, which names the object passed instead.
    let binding = |finding: &Finding| {
        finding
            .invariant
            .dominant_requirement
            .as_deref()
            .is_some_and(|requirement| requirement.starts_with(super::caller_use::BINDS))
    };
    let reported: std::collections::HashSet<_> = finding_details
        .iter()
        .filter(|finding| {
            !(finding.category == FindingCategory::UnverifiedProtection && finding.severity == Severity::Low)
                && !binding(finding)
        })
        .map(|finding| {
            (
                finding.suspicious_route.method.clone(),
                finding.suspicious_route.path.clone(),
            )
        })
        .collect();
    let mut found = Vec::new();
    for (index, route) in routes.iter().enumerate() {
        if objects[index].is_empty()
            || reported.contains(&(route.method.clone(), route.path.clone()))
        {
            continue;
        }
        for parameter in &parameters[index] {
            // Some object the route passes already holds the caller to it.
            if objects[index]
                .iter()
                .any(|(_, _, scopes)| scopes.contains(parameter))
            {
                continue;
            }
            for (symbol, privileges, _) in &objects[index] {
                // Routes that take the value and pass an object making the
                // same checks: which of them hold the caller to it.
                let mut scoped = Vec::new();
                let mut population = 0;
                for other in 0..routes.len() {
                    if other == index || !parameters[other].contains(parameter) {
                        continue;
                    }
                    let same: Vec<_> = objects[other]
                        .iter()
                        .filter(|(_, checks, _)| checks == privileges)
                        .collect();
                    if same.is_empty() {
                        continue;
                    }
                    population += 1;
                    if same.iter().any(|(_, _, scopes)| scopes.contains(parameter)) {
                        scoped.push(other);
                    }
                }
                population += 1;
                if scoped.len() < SCOPE_MINIMUM
                    || (scoped.len() as f64) / (population as f64) + 1e-9 < SCOPE_CONSENSUS
                {
                    continue;
                }
                found.push((index, parameter.clone(), symbol.clone(), scoped, population));
                break;
            }
        }
    }
    for (index, parameter, symbol, scoped, population) in found {
        let route = routes[index];
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut group_routes: Vec<RouteReference> = vec![route.into()];
        group_routes.extend(scoped.iter().map(|&other| routes[other].into()));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!(
                "routes taking `{{{parameter}}}` compared on the authentication object they pass"
            ),
            prefix: "/".into(),
            level: GroupLevel::Linked,
            method_class: MethodClass::of(&route.method),
            routes: group_routes,
        });
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "Routes taking `{{{parameter}}}` pass an authentication object that holds the caller to it."
            ),
            total_routes: population,
            routes_with_authorization: scoped.len(),
            routes_without_authorization: population - scoped.len(),
            evidence_patterns: vec![format!("scope:{parameter}")],
            strength: AuthStrength::Medium,
            expected_tier: None,
            dominant_requirement: Some(format!("scope:{parameter}")),
        };
        invariants.push(invariant.clone());
        let example = scoped
            .first()
            .map(|&other| {
                let peer = routes[other];
                let object = peer
                    .authorization
                    .iter()
                    .find(|evidence| {
                        evidence.kind == AuthEvidenceKind::OwnershipCheck
                            && evidence
                                .requirements
                                .iter()
                                .any(|key| key == &format!("scope:{parameter}"))
                    })
                    .and_then(|evidence| evidence.symbol.clone())
                    .unwrap_or_default();
                format!(" (e.g. {} {} passes `{object}`)", peer.method, peer.path)
            })
            .unwrap_or_default();
        finding_details.retain(|finding| {
            !(binding(finding)
                && finding.suspicious_route.method == route.method
                && finding.suspicious_route.path == route.path)
        });
        finding_details.push(Finding {
            peer_group_id: id,
            category: FindingCategory::DifferentAuthorization,
            severity: Severity::Medium,
            rationale: format!(
                "Takes `{{{parameter}}}` but passes `{symbol}`, which checks the caller without holding them to it, where {} of {} routes taking `{{{parameter}}}` with objects making the same checks pass one that does{example}; a caller allowed for one `{parameter}` may act on another. Dismiss if the difference is intended.",
                scoped.len(),
                population,
            ),
            invariant,
            suspicious_route: route.into(),
            suspicious_route_tier: route.best_tier(),
            expected_tier: route.best_tier(),
            suspicious_route_evidence: route.authorization.clone(),
            evidence: Default::default(),
            authorized_peer_routes: scoped.iter().map(|&other| routes[other].into()).collect(),
        });
    }
    super::peer_checks::drop_superseded_unverified(finding_details);
}
