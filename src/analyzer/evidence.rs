//! Authorization evidence inside handler bodies and in guard/middleware names.

use quote::ToTokens;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use syn::{
    BinOp, Block, Expr, ExprAssign, ExprBinary, ExprCall, ExprClosure, ExprField, ExprIf,
    ExprMatch, ExprMethodCall, ExprPath, ExprTry, ExprWhile, FnArg, GenericArgument, ImplItemFn,
    ItemFn, Local, Member, Pat, PathArguments, ReturnType, Stmt, Token, TraitItemFn, Type, UnOp,
    punctuated::Punctuated,
    spanned::Spanned,
    visit::{self, Visit},
};

use super::{
    model::*,
    routes::{HandlerTarget, handler_target, pattern_bindings},
};

/// Where an expression's value goes. This decides whether a check found in
/// it restricts the request, or is only mentioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    /// Evaluated for its effect: a statement, or a body's final value.
    /// Imperative checks (`require_admin(&user)`) enforce here; predicates
    /// (`is_admin(&user)`, `user.role == Role::Admin`) do not.
    Statement,
    /// Decides whether the request is rejected: the condition of an `if`,
    /// `match`, or `while` with a rejecting branch, an `ensure!`/`assert!`
    /// condition, a `let ... else`, or an expression under `?`.
    Enforcing,
    /// The predicate of a `filter`/`retain`/`find` closure: it scopes the
    /// data returned, so ownership comparisons enforce; role comparisons
    /// there select records (`users.filter(|u| u.role == Role::Admin)`).
    Scoping,
    /// Used as a value, such as a display flag or a struct field.
    Value,
}

/// A call of a repository function from a body, with how its result is used.
#[derive(Debug, Clone)]
pub(crate) struct HelperCall {
    pub(crate) target: HandlerTarget,
    pub(crate) use_: Use,
}

/// Evidence of one function, split by how it reaches a caller.
#[derive(Debug, Clone, Default)]
pub(crate) struct FunctionEvidence {
    /// Checks the function itself enforces, including its signature's
    /// extractors and attributes.
    pub(crate) evidence: Vec<AuthEvidence>,
    /// The checks in the function's body alone. A helper contributes only
    /// these to its callers: its parameter types are values passed to it,
    /// not extractors that run on a request (`fn collection_source(manager:
    /// &TileSourceManager)` checks no role).
    pub(crate) body_evidence: Vec<AuthEvidence>,
    /// Checks in the value a `bool` function returns (`fn can_edit(u) -> bool
    /// { u.role == Role::Admin }`). They restrict access only where a caller
    /// enforces that value.
    pub(crate) predicate_evidence: Vec<AuthEvidence>,
    pub(crate) calls: Vec<HelperCall>,
    /// Repository functions called in a `bool` function's returned value.
    pub(crate) predicate_calls: Vec<HandlerTarget>,
    /// Every repository call with the bindings its receiver and arguments
    /// are read from (`check(&user.person)` reads `user`).
    pub(crate) call_roots: Vec<(HandlerTarget, Vec<String>)>,
}

/// Mechanism of a check read from a function's structure: a branch on a
/// caller value that rejects (see `structural_checks`).
pub(crate) const STRUCTURAL_CHECK: &str = "rejects the request unless a caller";

/// The binding an expression is read from: `user` for `&user.person.id`,
/// `principal.validate()?` or `*user`.
pub(crate) fn root_binding(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) if path.qself.is_none() => path.path.get_ident().map(ToString::to_string),
        Expr::Field(field) => root_binding(&field.base),
        Expr::MethodCall(call) => root_binding(&call.receiver),
        Expr::Reference(inner) => root_binding(&inner.expr),
        Expr::Paren(inner) => root_binding(&inner.expr),
        Expr::Group(inner) => root_binding(&inner.expr),
        Expr::Unary(inner) => root_binding(&inner.expr),
        Expr::Try(inner) => root_binding(&inner.expr),
        Expr::Await(inner) => root_binding(&inner.base),
        Expr::Cast(inner) => root_binding(&inner.expr),
        _ => None,
    }
}

pub(crate) fn handler_evidence(file: &Path, item: &ItemFn) -> Vec<AuthEvidence> {
    function_evidence(file, item).evidence
}

pub(crate) fn function_evidence(file: &Path, item: &ItemFn) -> FunctionEvidence {
    function_evidence_in(file, item, None)
}

/// Like `function_evidence`, for a function of an `impl` block of `owner`:
/// in a method of an identity type, `self` is the caller.
pub(crate) fn function_evidence_in(file: &Path, item: &ItemFn, owner: Option<&str>) -> FunctionEvidence {
    let handler = item.sig.ident.to_string();
    let mut evidence = signature_evidence(file, &handler, &item.attrs, &item.sig.inputs);
    let mut visitor = AuthEvidenceVisitor::new(file, &handler);
    visitor.returns_bool = returns_bool(&item.sig.output);
    // A `Result` returned as the body's value is the caller's to propagate:
    // `fn h() -> Result<..> { user.has_role("admin") }` rejects on `Err`.
    let tail = if returns_result(&item.sig.output) {
        Use::Enforcing
    } else {
        Use::Statement
    };
    visitor.visit_body(&item.block, tail);
    let mut body_evidence = visitor.evidence;
    body_evidence.extend(delegation_evidence(
        file,
        &handler,
        &item.block,
        identity_bindings(item.sig.inputs.iter().filter_map(|input| match input {
            FnArg::Typed(typed) => Some((&*typed.pat, &*typed.ty)),
            FnArg::Receiver(_) => None,
        })),
    ));
    let mut caller = identity_bindings(item.sig.inputs.iter().filter_map(|input| match input {
        FnArg::Typed(typed) => Some((&*typed.pat, &*typed.ty)),
        FnArg::Receiver(_) => None,
    }));
    if item.sig.receiver().is_some()
        && owner
            .and_then(|owner| syn::parse_str::<Type>(owner).ok())
            .is_some_and(|ty| identity_type(&ty))
    {
        caller.insert("self".to_owned());
    }
    for found in secret_checks(file, &handler, &item.block) {
        if !body_evidence.iter().any(|existing| existing.line == found.line) {
            body_evidence.push(found);
        }
    }
    for found in structural_checks(file, &handler, &item.block, caller) {
        if !body_evidence
            .iter()
            .any(|existing| existing.line == found.line && EvidenceTier::of(&existing.kind) >= EvidenceTier::of(&found.kind))
        {
            body_evidence.push(found);
        }
    }
    // Ownership read from a field or helper name (`owner_id`, `is_member`)
    // rather than from a rejecting comparison or a scoped query.
    for found in &mut body_evidence {
        if found.kind == AuthEvidenceKind::OwnershipCheck
            && !found.mechanism.starts_with(STRUCTURAL_CHECK)
            && !found.mechanism.contains("query scoped to the caller")
        {
            found.name_based = true;
        }
    }
    evidence.extend(body_evidence.iter().cloned());
    FunctionEvidence {
        evidence,
        body_evidence,
        predicate_evidence: visitor.predicate_evidence,
        calls: visitor.calls,
        predicate_calls: visitor.predicate_calls,
        call_roots: visitor.call_roots,
    }
}

/// Evidence of a closure written as a route handler,
/// `.to(|admin: AdminUser| async move { ... })`: its extractor parameters
/// and its body.
pub(crate) fn closure_evidence(
    file: &Path,
    closure: &ExprClosure,
    handler: &str,
) -> Vec<AuthEvidence> {
    let mut evidence = Vec::new();
    for input in &closure.inputs {
        if let Pat::Type(typed) = input {
            extractor_evidence(&typed.ty, file, handler, &mut evidence);
        }
    }
    let mut visitor = AuthEvidenceVisitor::new(file, handler);
    match &*closure.body {
        Expr::Async(body) => visitor.visit_body(&body.block, Use::Statement),
        Expr::Block(body) => visitor.visit_body(&body.block, Use::Statement),
        body => visitor.visit_expr(body),
    }
    evidence.extend(visitor.evidence);
    let bindings = identity_bindings(closure.inputs.iter().filter_map(|input| match input {
        Pat::Type(typed) => Some((&*typed.pat, &*typed.ty)),
        _ => None,
    }));
    let mut delegations = DelegationVisitor::new(file, handler, bindings);
    delegations.visit_expr(&closure.body);
    evidence.extend(delegations.evidence);
    evidence
}

/// Names bound by parameters whose type is an identity or authorization
/// value: an extractor such as `ActixAuth(auth): ActixAuth` or
/// `principal: ReqPrincipal`, or a helper's `auth: &Auth`.
fn identity_bindings<'p>(
    parameters: impl IntoIterator<Item = (&'p Pat, &'p Type)>,
) -> HashSet<String> {
    let mut names = HashSet::new();
    for (pattern, ty) in parameters {
        if identity_type(ty) {
            pattern_bindings(pattern, &mut names);
        }
    }
    names
}

pub(crate) fn identity_type(ty: &Type) -> bool {
    match ty {
        Type::Path(path) if path.qself.is_none() => {
            let Some(segment) = path.path.segments.last() else {
                return false;
            };
            let name = segment.ident.to_string();
            if name == "ReqData" {
                return first_type_argument_name(&segment.arguments).is_some_and(|inner| {
                    super::structural::caller_type(&inner) || super::extractors::names_caller(&inner)
                });
            }
            if name == "Option" || name == "Box" || name == "Arc" {
                return match &segment.arguments {
                    PathArguments::AngleBracketed(arguments) => {
                        arguments.args.iter().any(|argument| {
                            matches!(argument, GenericArgument::Type(inner) if identity_type(inner))
                        })
                    }
                    _ => false,
                };
            }
            // `GuardedData<Policy, Data<State>>` checks the caller but hands
            // the handler the state: what it is used for is not the caller.
            let wraps_data = matches!(&segment.arguments, PathArguments::AngleBracketed(arguments)
                if arguments.args.iter().any(|argument| matches!(argument,
                    GenericArgument::Type(Type::Path(inner))
                        if inner.path.segments.last().is_some_and(|last| last.ident == "Data"))));
            !DATA_EXTRACTORS.contains(&name.as_str())
                && !wraps_data
                && (super::extractors::learned(&name).is_some()
                    || super::structural::caller_extractor(&name)
                    || classify_extractor_name(&name).is_some()
                    || names_authentication(&name))
        }
        Type::Reference(reference) => identity_type(&reference.elem),
        Type::Paren(paren) => identity_type(&paren.elem),
        Type::Group(group) => identity_type(&group.elem),
        _ => false,
    }
}

/// Evidence that a function hands an identity to code Archer does not
/// analyze; see `AuthEvidenceKind::Delegated`.
fn delegation_evidence(
    file: &Path,
    handler: &str,
    block: &Block,
    bindings: HashSet<String>,
) -> Vec<AuthEvidence> {
    let mut visitor = DelegationVisitor::new(file, handler, bindings);
    visitor.visit_block(block);
    visitor.evidence
}

/// Methods that only convert or copy a value: `auth.clone()` passed to a
/// call passes `auth`.
const TRANSPARENT_METHODS: [&str; 8] = [
    "clone",
    "as_ref",
    "into_inner",
    "to_owned",
    "borrow",
    "into",
    "deref",
    "as_deref",
];

struct DelegationVisitor {
    file: PathBuf,
    handler: String,
    bindings: HashSet<String>,
    evidence: Vec<AuthEvidence>,
    /// Arguments read as learned authentication objects, whose parts are
    /// not delegations of their own.
    resolved: HashSet<usize>,
}

/// An authentication object passed at a call site, with what its type was
/// learned to check (`auth_objects`).
struct PassedObject {
    written: String,
    object: super::auth_objects::AuthObject,
    /// Values its constant fields name: `permission: Permission::Write`.
    requirements: Vec<String>,
    /// Fields it holds the caller to that the route sets from a value it
    /// has: `profile_id: path.profile_id`.
    route_scopes: Vec<String>,
    /// Passed as one of the alternatives a chooser picks from.
    alternative: Option<String>,
}

fn written_path(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn constant_value(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::Lit(_) => Some(Vec::new()),
        Expr::Path(path) if path.path.segments.len() >= 2 => {
            Some(name_keys(&path.path.segments.last()?.ident.to_string()))
        }
        Expr::Reference(inner) => constant_value(&inner.expr),
        _ => None,
    }
}

/// The authentication objects an argument passes, by what their types were
/// learned to check; `None` when it passes none Archer learned.
fn passed_objects(expr: &Expr) -> Option<Vec<PassedObject>> {
    use super::auth_objects::{auth_object, chooses_between};
    match expr {
        Expr::Reference(reference) => passed_objects(&reference.expr),
        Expr::Paren(paren) => passed_objects(&paren.expr),
        Expr::Group(group) => passed_objects(&group.expr),
        Expr::Path(path) if path.qself.is_none() => {
            let object = auth_object(&path.path.segments.last()?.ident.to_string())?;
            Some(vec![PassedObject {
                written: written_path(&path.path),
                object,
                requirements: Vec::new(),
                route_scopes: Vec::new(),
                alternative: None,
            }])
        }
        Expr::Struct(item) => {
            let object = auth_object(&item.path.segments.last()?.ident.to_string())?;
            let mut requirements = Vec::new();
            let mut route_scopes = Vec::new();
            for field in &item.fields {
                let Member::Named(name) = &field.member else {
                    continue;
                };
                let name = name.to_string();
                match constant_value(&field.expr) {
                    Some(keys) => requirements.extend(keys),
                    None if object.scopes.contains(&name) => route_scopes.push(name),
                    None => {}
                }
            }
            Some(vec![PassedObject {
                written: written_path(&item.path),
                object,
                requirements,
                route_scopes,
                alternative: None,
            }])
        }
        Expr::Call(call) => {
            let Expr::Path(func) = &*call.func else {
                return None;
            };
            let name = func.path.segments.last()?.ident.to_string();
            if chooses_between(&name) {
                let alternatives: Vec<PassedObject> = call
                    .args
                    .iter()
                    .filter_map(passed_objects)
                    .flatten()
                    .map(|passed| PassedObject {
                        alternative: Some(name.clone()),
                        ..passed
                    })
                    .collect();
                return (!alternatives.is_empty()).then_some(alternatives);
            }
            let object = auth_object(&name)?;
            if object.wraps
                && let Some(inner) = call.args.first().and_then(passed_objects)
            {
                return Some(
                    inner
                        .into_iter()
                        .map(|passed| PassedObject {
                            written: format!("{}({})", written_path(&func.path), passed.written),
                            object: object.wrapping(&passed.object),
                            ..passed
                        })
                        .collect(),
                );
            }
            let mut requirements = Vec::new();
            let mut route_scopes = Vec::new();
            for (index, argument) in call.args.iter().enumerate() {
                if !object.scopes.contains(&index.to_string()) {
                    continue;
                }
                match constant_value(argument) {
                    Some(keys) => requirements.extend(keys),
                    None => route_scopes.push(match argument {
                        Expr::Path(path) if path.path.get_ident().is_some() => {
                            written_path(&path.path)
                        }
                        _ => index.to_string(),
                    }),
                }
            }
            Some(vec![PassedObject {
                written: written_path(&func.path),
                object,
                requirements,
                route_scopes,
                alternative: None,
            }])
        }
        _ => None,
    }
}

impl DelegationVisitor {
    fn new(file: &Path, handler: &str, bindings: HashSet<String>) -> Self {
        Self {
            file: file.to_path_buf(),
            handler: handler.to_owned(),
            bindings,
            evidence: Vec::new(),
            resolved: HashSet::new(),
        }
    }

    /// Evidence for authentication objects of learned types an argument
    /// passes; false when it passes none.
    fn learned_objects(&mut self, callee: &str, argument: &Expr, line: usize) -> bool {
        use super::auth_objects::Tier;
        let Some(passed) = passed_objects(argument) else {
            return false;
        };
        self.resolved.insert(argument as *const Expr as usize);
        for PassedObject {
            written,
            object,
            mut requirements,
            route_scopes,
            alternative,
        } in passed
        {
            requirements.sort();
            requirements.dedup();
            let how = match &alternative {
                Some(chooser) => format!(
                    "`{callee}` receives `{written}`, one of the objects `{chooser}` chooses from,"
                ),
                None => format!("`{callee}` receives `{written}`, which"),
            };
            let site = &object.site;
            // The constants it is built with (`Permission::Write`) are named,
            // not compared: each operation needs its own permission.
            let naming = if requirements.is_empty() {
                String::new()
            } else {
                format!(
                    " with {}",
                    requirements
                        .iter()
                        .map(|key| format!("`{key}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let mut push =
                |kind: AuthEvidenceKind, mechanism: String, requirements: Vec<String>| {
                    if self
                        .evidence
                        .iter()
                        .any(|existing| existing.mechanism == mechanism)
                    {
                        return;
                    }
                    self.evidence.push(AuthEvidence {
                        kind,
                        mechanism,
                        symbol: Some(written.clone()),
                        file: self.file.clone(),
                        line,
                        handler: Some(self.handler.clone()),
                        strength: AuthStrength::Strong,
                        requirements,
                        name_based: false,
                    });
                };
            match object.tier {
                // It admits any request: the route has no check from it.
                Tier::Open => continue,
                Tier::Privilege => {
                    let kind = object
                        .privileges
                        .iter()
                        .filter_map(|name| classify_check_name(name))
                        .map(|(kind, _)| kind)
                        .find(|kind| EvidenceTier::of(kind) == EvidenceTier::Privilege)
                        .unwrap_or(AuthEvidenceKind::PermissionCheck);
                    let checks = object
                        .privileges
                        .iter()
                        .map(|name| format!("`{name}`"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    push(
                        kind,
                        format!("{how} checks {checks}{naming} ({site})"),
                        Vec::new(),
                    );
                }
                Tier::Identity | Tier::Scoped => push(
                    AuthEvidenceKind::IdentityExtraction,
                    format!("{how} authenticates the caller{naming} ({site})"),
                    Vec::new(),
                ),
            }
            if !route_scopes.is_empty() {
                let scopes = route_scopes
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                push(
                    AuthEvidenceKind::OwnershipCheck,
                    format!("{how} holds the caller to the route's {scopes} ({site})"),
                    route_scopes
                        .iter()
                        .map(|name| format!("scope:{name}"))
                        .collect(),
                );
            }
        }
        true
    }

    /// The identity binding an expression passes, seen through references
    /// and conversions.
    fn binding<'e>(&self, expr: &'e Expr) -> Option<&'e syn::Ident> {
        match expr {
            Expr::Path(path) if path.qself.is_none() => {
                let ident = path.path.get_ident()?;
                self.bindings.contains(&ident.to_string()).then_some(ident)
            }
            Expr::Reference(reference) => self.binding(&reference.expr),
            Expr::Paren(paren) => self.binding(&paren.expr),
            Expr::Group(group) => self.binding(&group.expr),
            Expr::MethodCall(call)
                if TRANSPARENT_METHODS.contains(&call.method.to_string().as_str()) =>
            {
                self.binding(&call.receiver)
            }
            _ => None,
        }
    }

    /// An authentication object built in an argument: `&auth::ApiKeyAuth`,
    /// `auth::HeaderAuth(..)`, `auth::auth_type(..)`. `NoAuth` declares the
    /// route public and is not one.
    fn authentication_object(expr: &Expr) -> Option<String> {
        let path = match expr {
            Expr::Reference(reference) => return Self::authentication_object(&reference.expr),
            Expr::Paren(paren) => return Self::authentication_object(&paren.expr),
            Expr::Path(path) if path.qself.is_none() => &path.path,
            Expr::Struct(item) => &item.path,
            Expr::Call(call) => match &*call.func {
                Expr::Path(path) if path.qself.is_none() => &path.path,
                _ => return None,
            },
            _ => return None,
        };
        let names: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let last = names.last()?;
        // `constants::MESSAGE_LOGIN_SUCCESS` is a value, not an
        // authentication object.
        if last.len() > 1
            && last.chars().any(|c| c.is_ascii_alphabetic())
            && last.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            return None;
        }
        let public = camel_case_words(last)
            .iter()
            .any(|word| word == "no" || word == "none" || word == "public");
        (!public && names_authentication(last)).then(|| names.join("::"))
    }

    fn record(&mut self, mechanism: String, symbol: String, line: usize) {
        if self
            .evidence
            .iter()
            .any(|existing| existing.mechanism == mechanism)
        {
            return;
        }
        self.evidence.push(AuthEvidence {
            kind: AuthEvidenceKind::Delegated,
            mechanism,
            symbol: Some(symbol),
            file: self.file.clone(),
            line,
            handler: Some(self.handler.clone()),
            strength: AuthStrength::Weak,
            requirements: Vec::new(),
            name_based: false,
        });
    }

    fn arguments(&mut self, callee: &str, arguments: &Punctuated<Expr, Token![,]>, line: usize) {
        for argument in arguments {
            if self.binding(argument).is_none() && self.learned_objects(callee, argument, line) {
                continue;
            }
            if let Some(binding) = self.binding(argument) {
                self.record(
                    format!("`{callee}` receives `{binding}`"),
                    format!("{callee}({binding})"),
                    line,
                );
            } else if let Some(object) = Self::authentication_object(argument) {
                self.record(
                    format!("`{callee}` receives `{object}`"),
                    format!("{callee}({object})"),
                    line,
                );
            }
        }
    }
}

impl<'ast> Visit<'ast> for DelegationVisitor {
    fn visit_expr(&mut self, node: &'ast Expr) {
        if !self.resolved.contains(&(node as *const Expr as usize)) {
            visit::visit_expr(self, node);
        }
    }

    /// P8: `auth.check(..)?`: a method of the scanned code that can build an
    /// error is called on the caller, and the error is passed on. (Free
    /// functions given the caller are followed as helpers instead.) That rejects the request unless the check passes,
    /// whatever the function is called. A call whose name already reads as
    /// a check is left to the name test, which also gives its kind.
    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        let mut inner = &*node.expr;
        while let Expr::Await(awaited) = inner {
            inner = &awaited.base;
        }
        let checked = match inner {
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                self.binding(&call.receiver)
                    .filter(|_| {
                        !TRANSPARENT_METHODS.contains(&method.as_str())
                            && classify_check_name(&method).is_none()
                            && super::structural::rejecting_function(&method)
                    })
                    .map(|binding| (format!("{binding}.{method}()"), call.span().start().line))
            }
            _ => None,
        };
        if let Some((written, line)) = checked {
            // What the check requires is not read without its name, so it
            // counts as making sure of the caller, not as a privilege.
            self.evidence.push(AuthEvidence {
                kind: AuthEvidenceKind::IdentityExtraction,
                mechanism: format!("rejects the request unless `{written}` passes for the caller"),
                symbol: Some(written),
                file: self.file.clone(),
                line,
                handler: Some(self.handler.clone()),
                strength: AuthStrength::Weak,
                requirements: Vec::new(),
                name_based: false,
            });
        }
        visit::visit_expr_try(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        let line = node.method.span().start().line;
        if let Some(binding) = self.binding(&node.receiver)
            && !TRANSPARENT_METHODS.contains(&method.as_str())
            && classify_check_name(&method).is_none()
        {
            self.record(
                format!("`{binding}.{method}()` is not analyzed"),
                format!("{binding}.{method}()"),
                line,
            );
        }
        self.arguments(&method, &node.args, line);
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        // Calls of repository functions are followed as helpers; only calls
        // of associated functions (`Type::method`) and of paths outside the
        // repository are opaque. Both are recorded: which paths resolve is
        // decided later, and a resolved helper's own checks still count.
        let callee = match &*node.func {
            Expr::Path(path) => path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        let associated = callee.len() >= 2
            && callee[callee.len() - 2]
                .chars()
                .next()
                .is_some_and(char::is_uppercase);
        if associated {
            let line = node.func.span().start().line;
            self.arguments(&callee.join("::"), &node.args, line);
        } else if let Some(name) = callee.last() {
            // A free function receiving an authentication object built in
            // place (`server_wrap(.., &auth::ApiKeyAuth, ..)`) delegates the
            // check to it; one receiving an identity binding is analyzed as
            // a helper.
            let line = node.func.span().start().line;
            for argument in &node.args {
                if self.binding(argument).is_none() && self.learned_objects(name, argument, line) {
                    continue;
                }
                if self.binding(argument).is_none()
                    && let Some(object) = Self::authentication_object(argument)
                {
                    self.record(
                        format!("`{name}` receives `{object}`"),
                        format!("{name}({object})"),
                        line,
                    );
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast ExprClosure) {
        visit::visit_expr_closure(self, node);
    }

    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
    fn visit_impl_item_fn(&mut self, _: &'ast ImplItemFn) {}
}

fn signature_evidence(
    file: &Path,
    handler: &str,
    attrs: &[syn::Attribute],
    inputs: &Punctuated<FnArg, Token![,]>,
) -> Vec<AuthEvidence> {
    let mut evidence: Vec<AuthEvidence> = attrs
        .iter()
        .filter_map(|attribute| attribute_evidence(attribute, file, handler))
        .collect();
    for input in inputs {
        if let FnArg::Typed(argument) = input {
            extractor_evidence(&argument.ty, file, handler, &mut evidence);
        }
    }
    evidence
}

fn returns_result(output: &ReturnType) -> bool {
    matches!(output, ReturnType::Type(_, ty) if matches!(&**ty, Type::Path(path)
        if path.path.segments.last().is_some_and(|segment| segment.ident.to_string().ends_with("Result"))))
}

fn returns_bool(output: &ReturnType) -> bool {
    matches!(output, ReturnType::Type(_, ty) if matches!(&**ty, Type::Path(path) if path.path.is_ident("bool")))
}

/// An authorization attribute macro on a handler, such as actix-web-grants'
/// `#[protect("ROLE_ADMIN")]` or `#[has_roles("ADMIN")]`, which rejects the
/// request before the handler body runs.
fn attribute_evidence(
    attribute: &syn::Attribute,
    file: &Path,
    handler: &str,
) -> Option<AuthEvidence> {
    let name = attribute.path().segments.last()?.ident.to_string();
    let (kind, strength) = match name.as_str() {
        "protect" | "has_permissions" | "has_any_permission" => {
            (AuthEvidenceKind::PermissionCheck, AuthStrength::Strong)
        }
        "has_role" | "has_roles" | "has_any_role" => {
            (AuthEvidenceKind::RoleCheck, AuthStrength::Strong)
        }
        _ => match classify_check_name(&name)? {
            (AuthEvidenceKind::IdentityExtraction, _) => return None,
            (kind, _) => (kind, AuthStrength::Strong),
        },
    };
    let mut requirements = name_keys(&name);
    if let syn::Meta::List(list) = &attribute.meta {
        requirements.extend(
            token_literals(&list.tokens, false)
                .iter()
                .filter_map(|value| literal_key(value)),
        );
    }
    requirements.sort();
    requirements.dedup();
    Some(AuthEvidence {
        kind,
        mechanism: name,
        symbol: Some(attribute.meta.to_token_stream().to_string()),
        file: file.to_path_buf(),
        line: attribute.span().start().line,
        handler: Some(handler.into()),
        strength,
        requirements,
        name_based: false,
    })
}

/// Extractors whose type parameter is request data or application state,
/// not a check: `web::Json<RoleUpdate>` does not authorize anything. An
/// `Option<AdminUser>` extractor does not reject the request either.
const DATA_EXTRACTORS: [&str; 10] = [
    "Json",
    "Path",
    "Query",
    "Form",
    "Data",
    "ReqData",
    "Bytes",
    "Payload",
    "Option",
    "HttpRequest",
];

/// Words that make a type name request data or a service rather than an
/// authorization extractor (`RoleUpdate`, `PermissionService`).
const EXTRACTOR_EXCLUDED_WORDS: [&str; 26] = [
    "service",
    "services",
    "repository",
    "repo",
    "update",
    "create",
    "request",
    "response",
    "input",
    "payload",
    "dto",
    "query",
    "params",
    "info",
    "data",
    "config",
    "source",
    "sources",
    "store",
    "pool",
    "client",
    "state",
    "context",
    "cache",
    "dispatcher",
    "agent",
];

/// Records handler arguments whose type is an authorization extractor
/// (`AdminUser`, `RequireRole<Admin>`) or an authentication-only extractor
/// (`BearerAuth`). An extractor that implements `FromRequest` rejects the
/// request before the handler runs, so its type is the evidence. An
/// extractor whose `FromRequest` body is in the scanned code is judged by
/// that body (see `extractors`); others by their name.
fn extractor_evidence(ty: &Type, file: &Path, handler: &str, evidence: &mut Vec<AuthEvidence>) {
    match ty {
        Type::Path(path) if path.qself.is_none() => {
            let Some(segment) = path.path.segments.last() else {
                return;
            };
            let name = segment.ident.to_string();
            // `web::ReqData<Claims>`: what authentication middleware stored
            // for the request. Present only once that middleware ran.
            if name == "ReqData"
                && let Some(inner) = first_type_argument_name(&segment.arguments)
                && (super::structural::caller_type(&inner) || super::extractors::names_caller(&inner))
            {
                let name_based = super::structural::enabled() && !super::structural::caller_type(&inner);
                evidence.push(AuthEvidence {
                    kind: AuthEvidenceKind::IdentityExtraction,
                    mechanism: format!("ReqData<{inner}>"),
                    symbol: Some(ty.to_token_stream().to_string().replace(' ', "")),
                    file: file.to_path_buf(),
                    line: ty.span().start().line,
                    handler: Some(handler.into()),
                    strength: AuthStrength::Weak,
                    requirements: Vec::new(),
                    name_based,
                });
                return;
            }
            if DATA_EXTRACTORS.contains(&name.as_str()) {
                return;
            }
            // A policy type argument names the requirement more precisely
            // than the extractor's own body, which only runs the policy.
            if let PathArguments::AngleBracketed(arguments) = &segment.arguments
                && let Some(requirements) = policy_requirements(arguments)
            {
                evidence.push(AuthEvidence {
                    kind: AuthEvidenceKind::PermissionCheck,
                    mechanism: name,
                    symbol: Some(ty.to_token_stream().to_string().replace(' ', "")),
                    file: file.to_path_buf(),
                    line: ty.span().start().line,
                    handler: Some(handler.into()),
                    strength: AuthStrength::Medium,
                    requirements,
                    name_based: false,
                });
                return;
            }
            // What the application's own `impl FromRequest` checks.
            if let Some(learned) = super::extractors::learned(&name) {
                let strength = if learned.kind == AuthEvidenceKind::IdentityExtraction {
                    AuthStrength::Weak
                } else {
                    AuthStrength::Medium
                };
                let mut found = AuthEvidence {
                    kind: learned.kind,
                    mechanism: name,
                    symbol: Some(ty.to_token_stream().to_string().replace(' ', "")),
                    file: file.to_path_buf(),
                    line: ty.span().start().line,
                    handler: Some(handler.into()),
                    strength,
                    requirements: learned.requirements,
                    name_based: learned.name_based,
                };
                // The check is made by an extractor this one runs, or by a
                // comparison in a function it calls: cite that.
                if let Some(via) = learned.via {
                    if via.chain.len() > 1 {
                        found.symbol = Some(via.chain.join(" -> "));
                    }
                    found.mechanism = match &via.site {
                        Some(_) => format!("`{}` {}", via.extractor, super::extractors::CREDENTIAL_PATH_CHECK),
                        None => via.extractor,
                    };
                    if let Some((site_file, site_line)) = via.site {
                        found.file = site_file;
                        found.line = site_line;
                    }
                }
                evidence.push(found);
                return;
            }
            if let Some((kind, strength)) = classify_extractor_name(&name) {
                // `AdminUser` requires `admin`; `RequireRole<Admin>` names it
                // in its type parameter.
                let mut requirements = name_keys(&name);
                if let PathArguments::AngleBracketed(arguments) = &segment.arguments {
                    for argument in &arguments.args {
                        if let GenericArgument::Type(Type::Path(inner)) = argument
                            && let Some(last) = inner.path.segments.last()
                        {
                            requirements.extend(name_keys(&last.ident.to_string()));
                        }
                    }
                }
                requirements.sort();
                requirements.dedup();
                evidence.push(AuthEvidence {
                    kind,
                    mechanism: name,
                    symbol: Some(ty.to_token_stream().to_string().replace(' ', "")),
                    file: file.to_path_buf(),
                    line: ty.span().start().line,
                    handler: Some(handler.into()),
                    strength,
                    requirements,
                    name_based: super::structural::enabled(),
                });
                return;
            }
            if let PathArguments::AngleBracketed(arguments) = &segment.arguments {
                for argument in &arguments.args {
                    if let GenericArgument::Type(inner) = argument {
                        extractor_evidence(inner, file, handler, evidence);
                    }
                }
            }
        }
        Type::Reference(reference) => extractor_evidence(&reference.elem, file, handler, evidence),
        Type::Paren(paren) => extractor_evidence(&paren.elem, file, handler, evidence),
        Type::Group(group) => extractor_evidence(&group.elem, file, handler, evidence),
        Type::Tuple(tuple) => {
            for element in &tuple.elems {
                extractor_evidence(element, file, handler, evidence);
            }
        }
        _ => {}
    }
}

/// The last segment of a type's first type argument: `Claims` in
/// `ReqData<auth::Claims>`.
fn first_type_argument_name(arguments: &PathArguments) -> Option<String> {
    let PathArguments::AngleBracketed(arguments) = arguments else {
        return None;
    };
    arguments.args.iter().find_map(|argument| match argument {
        GenericArgument::Type(Type::Path(inner)) => {
            inner.path.segments.last().map(|last| last.ident.to_string())
        }
        _ => None,
    })
}

/// The requirements of an extractor parameterized by a policy type,
/// `GuardedData<ActionPolicy<{ actions::KEYS_GET }>, Data<..>>`: the
/// extractor runs the policy before the handler, and the policy's own
/// arguments name what it requires (`keys_get`). `None` when no type
/// argument is a policy.
fn policy_requirements(
    arguments: &syn::AngleBracketedGenericArguments,
) -> Option<Vec<String>> {
    arguments.args.iter().find_map(|argument| {
        let GenericArgument::Type(Type::Path(policy)) = argument else {
            return None;
        };
        let last = policy.path.segments.last()?;
        let words = camel_case_words(&last.ident.to_string());
        if !words.iter().any(|word| word == "policy" || word == "policies") {
            return None;
        }
        let mut requirements = Vec::new();
        if let PathArguments::AngleBracketed(inner) = &last.arguments {
            for argument in &inner.args {
                let named = match argument {
                    GenericArgument::Const(expr) => expr_name(expr),
                    GenericArgument::Type(Type::Path(ty)) => {
                        ty.path.segments.last().map(|segment| segment.ident.to_string())
                    }
                    _ => None,
                };
                requirements.extend(named.map(|name| name.to_ascii_lowercase()));
            }
        }
        if requirements.is_empty() {
            requirements = name_keys(&last.ident.to_string());
        }
        requirements.sort();
        requirements.dedup();
        Some(requirements)
    })
}

/// The last path segment an expression names, through `{ .. }` blocks.
fn expr_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => path.path.segments.last().map(|segment| segment.ident.to_string()),
        Expr::Block(block) => match block.block.stmts.as_slice() {
            [syn::Stmt::Expr(inner, None)] => expr_name(inner),
            _ => None,
        },
        _ => None,
    }
}

fn classify_extractor_name(name: &str) -> Option<(AuthEvidenceKind, AuthStrength)> {
    if !name.chars().next().is_some_and(char::is_uppercase) {
        return None;
    }
    let words = camel_case_words(name);
    let has_word =
        |candidates: &[&str]| words.iter().any(|word| candidates.contains(&word.as_str()));
    if has_word(&CONFIGURATION_EXCLUDED_WORDS) || has_word(&EXTRACTOR_EXCLUDED_WORDS) {
        return None;
    }
    if ["BearerAuth", "BasicAuth", "Identity", "AuthenticatedUser"].contains(&name)
        || has_word(&["claims"])
    {
        Some((AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak))
    } else if has_word(&[
        "permission",
        "permissions",
        "acl",
        "authorization",
        "authorize",
        "authorized",
        "authz",
    ]) {
        Some((AuthEvidenceKind::PermissionCheck, AuthStrength::Medium))
    } else if has_word(&[
        "admin",
        "admins",
        "role",
        "roles",
        "rbac",
        "manager",
        "superuser",
    ]) {
        Some((AuthEvidenceKind::RoleCheck, AuthStrength::Medium))
    } else if classify_route_configuration_name(name)
        == Some(RouteConfigurationName::Authentication)
        || (words.len() >= 2
            && has_word(&["user", "principal", "identity", "caller", "auth", "authenticated"]))
    {
        // A handler parameter is an extractor, so a type naming the caller
        // (`LocalUserView`, `ReqPrincipal`, `ActixAuth`) identifies them. A
        // bare `User` or `Auth` may be a domain value, and is not counted.
        Some((AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak))
    } else {
        None
    }
}

/// Name-keyed evidence map used by evidence-classification tests. Route
/// analysis resolves handlers through `HandlerIndex` instead.
#[cfg(test)]
pub(crate) fn collect_authorized_handlers(
    file_path: &Path,
    file: &syn::File,
) -> HashMap<String, Vec<AuthEvidence>> {
    let mut visitor = FunctionVisitor {
        file: file_path.to_path_buf(),
        ..Default::default()
    };
    visitor.visit_file(file);
    visitor.authorized_handlers
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct FunctionVisitor {
    pub(crate) file: PathBuf,
    pub(crate) authorized_handlers: HashMap<String, Vec<AuthEvidence>>,
}

#[cfg(test)]
impl<'ast> Visit<'ast> for FunctionVisitor {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let evidence = handler_evidence(&self.file, item);
        if !evidence.is_empty() {
            self.authorized_handlers
                .insert(item.sig.ident.to_string(), evidence);
        }
        visit::visit_item_fn(self, item);
    }
}

/// Evidence and helper calls recorded while a `let` initializer is visited.
/// They count only if the binding is later read where it is enforced:
/// `let allowed = is_admin(&user); if !allowed { return Err(..) }`.
#[derive(Debug, Clone, Default)]
pub(crate) struct Captured {
    evidence: Vec<AuthEvidence>,
    calls: Vec<HandlerTarget>,
}

pub(crate) struct AuthEvidenceVisitor {
    pub(crate) file: PathBuf,
    pub(crate) handler: String,
    pub(crate) evidence: Vec<AuthEvidence>,
    pub(crate) predicate_evidence: Vec<AuthEvidence>,
    pub(crate) calls: Vec<HelperCall>,
    pub(crate) predicate_calls: Vec<HandlerTarget>,
    pub(crate) call_roots: Vec<(HandlerTarget, Vec<String>)>,
    use_: Use,
    /// The function returns `bool`: its returned value is a predicate.
    returns_bool: bool,
    /// Visiting a `bool` function's returned value.
    in_returned_value: bool,
    capture: Option<Captured>,
    bound: HashMap<String, Captured>,
    /// Bindings that hold the requesting caller's identity, read from a call
    /// named for it (`let username = get_username_from_session(&s)`).
    callers: HashSet<String>,
}

/// Words of a call's name that make its result the caller's identity.
const CALLER_SOURCE_WORDS: [&str; 11] = [
    "username", "userid", "uid", "identity", "principal", "claims", "session", "current",
    "caller", "subject", "whoami",
];

/// Whether an expression reads the caller's identity from a call named for
/// it, through `?`, `.unwrap()` and similar.
fn reads_caller_identity(expr: &Expr) -> bool {
    let name = match strip_conversions(expr) {
        Expr::Try(attempt) => return reads_caller_identity(&attempt.expr),
        Expr::Await(awaited) => return reads_caller_identity(&awaited.base),
        Expr::MethodCall(call)
            if ["unwrap_or", "unwrap_or_default", "unwrap_or_else", "expect", "ok_or", "ok"]
                .iter()
                .any(|method| call.method == method) =>
        {
            return reads_caller_identity(&call.receiver);
        }
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => path.path.segments.last().map(|segment| segment.ident.to_string()),
            _ => None,
        },
        Expr::MethodCall(call) => Some(call.method.to_string()),
        _ => None,
    };
    name.is_some_and(|name| names_caller_source(&name))
}

/// Whether a function or type is named for the caller's identity:
/// `get_username_from_session`, `current_user_id`, `Claims`.
pub(crate) fn names_caller_source(name: &str) -> bool {
    let words: Vec<String> = if name.contains('_') || !name.chars().any(char::is_uppercase) {
        name.to_ascii_lowercase().split('_').map(str::to_owned).collect()
    } else {
        camel_case_words(name)
    };
    words.iter().any(|word| CALLER_SOURCE_WORDS.contains(&word.as_str()))
        || words.windows(2).any(|pair| pair[0] == "user" && pair[1] == "id")
}

impl AuthEvidenceVisitor {
    pub(crate) fn new(file: &Path, handler: &str) -> Self {
        Self {
            file: file.to_path_buf(),
            handler: handler.into(),
            evidence: Vec::new(),
            predicate_evidence: Vec::new(),
            calls: Vec::new(),
            predicate_calls: Vec::new(),
            call_roots: Vec::new(),
            use_: Use::Statement,
            returns_bool: false,
            in_returned_value: false,
            capture: None,
            bound: HashMap::new(),
            callers: HashSet::new(),
        }
    }

    /// A binding that holds the caller's identity.
    fn is_caller_binding(&self, expr: &Expr) -> bool {
        matches!(strip_conversions(expr), Expr::Path(path)
            if path.path.get_ident().is_some_and(|ident| self.callers.contains(&ident.to_string())))
    }

    /// A field of a record that is not the caller (`article.creater`): what
    /// an ownership check compares with the caller's identity.
    fn record_field(&self, expr: &Expr) -> bool {
        matches!(strip_conversions(expr), Expr::Field(field)
            if matches!(&*field.base, Expr::Path(base)
                if base.path.get_ident().is_some_and(|ident| !self.callers.contains(&ident.to_string()))))
    }

    fn with_use(&mut self, use_: Use, visit: impl FnOnce(&mut Self)) {
        let previous = std::mem::replace(&mut self.use_, use_);
        visit(self);
        self.use_ = previous;
    }

    /// Visits a function or closure body; its final expression is the
    /// returned value, a predicate when the function returns `bool`.
    pub(crate) fn visit_body(&mut self, block: &Block, tail: Use) {
        let Some((last, rest)) = block.stmts.split_last() else {
            return;
        };
        self.with_use(Use::Statement, |visitor| {
            for statement in rest {
                visitor.visit_stmt(statement);
            }
        });
        match last {
            Stmt::Expr(expr, None) => self.visit_returned(expr, tail),
            statement => self.with_use(Use::Statement, |visitor| visitor.visit_stmt(statement)),
        }
    }

    fn visit_returned(&mut self, expr: &Expr, use_: Use) {
        if self.returns_bool {
            let previous = std::mem::replace(&mut self.in_returned_value, true);
            self.with_use(Use::Enforcing, |visitor| visitor.visit_expr(expr));
            self.in_returned_value = previous;
        } else {
            self.with_use(use_, |visitor| visitor.visit_expr(expr));
        }
    }

    /// Records a check where it restricts the request. Imperative checks
    /// (`require_admin`, `authorize`) restrict wherever their effect runs;
    /// predicates only where their value decides a rejection. Identity
    /// extraction bound to a variable (`let user = current_user(&req);`)
    /// counts: that is how an extracted identity is used.
    fn record(&mut self, evidence: AuthEvidence, imperative: bool) {
        let enforced = match self.use_ {
            Use::Enforcing => true,
            Use::Statement => imperative,
            Use::Scoping => evidence.kind == AuthEvidenceKind::OwnershipCheck,
            Use::Value => {
                imperative
                    && evidence.kind == AuthEvidenceKind::IdentityExtraction
                    && self.capture.is_some()
            }
        };
        if enforced {
            if self.in_returned_value {
                self.predicate_evidence.push(evidence);
            } else {
                self.evidence.push(evidence);
            }
        } else if let Some(captured) = &mut self.capture {
            captured.evidence.push(evidence);
        }
    }

    fn record_call(&mut self, target: HandlerTarget) {
        if self.in_returned_value && self.use_ == Use::Enforcing {
            self.predicate_calls.push(target);
            return;
        }
        if self.use_ == Use::Value
            && let Some(captured) = &mut self.capture
        {
            captured.calls.push(target.clone());
        }
        self.calls.push(HelperCall {
            target,
            use_: self.use_,
        });
    }

    /// A binding read where it is enforced releases what its initializer
    /// captured.
    fn release(&mut self, name: &str) {
        if self.use_ != Use::Enforcing {
            return;
        }
        let Some(captured) = self.bound.remove(name) else {
            return;
        };
        for evidence in captured.evidence {
            self.record(evidence, true);
        }
        for target in captured.calls {
            self.record_call(target);
        }
    }

    fn evidence(
        &self,
        kind: AuthEvidenceKind,
        mechanism: String,
        line: usize,
        strength: AuthStrength,
    ) -> AuthEvidence {
        AuthEvidence {
            kind,
            symbol: Some(mechanism.clone()),
            mechanism,
            file: self.file.clone(),
            line,
            handler: Some(self.handler.clone()),
            strength,
            requirements: Vec::new(),
            name_based: false,
        }
    }
}

impl<'ast> Visit<'ast> for AuthEvidenceVisitor {
    fn visit_block(&mut self, node: &'ast Block) {
        self.with_use(Use::Statement, |visitor| visit::visit_block(visitor, node));
    }

    fn visit_local(&mut self, node: &'ast Local) {
        let Some(init) = &node.init else {
            return;
        };
        // `let Some(user) = current_user(&req) else { return ... };`
        if let Some((_, diverge)) = &init.diverge {
            self.with_use(Use::Enforcing, |visitor| visitor.visit_expr(&init.expr));
            self.with_use(Use::Statement, |visitor| visitor.visit_expr(diverge));
            return;
        }
        let mut names = HashSet::new();
        pattern_bindings(&node.pat, &mut names);
        if reads_caller_identity(&init.expr) {
            self.callers.extend(names.iter().cloned());
        }
        let previous = self.capture.replace(Captured::default());
        self.with_use(Use::Value, |visitor| visitor.visit_expr(&init.expr));
        let captured = std::mem::replace(&mut self.capture, previous).unwrap_or_default();
        for name in names {
            self.bound.insert(name, captured.clone());
        }
    }

    fn visit_expr_try(&mut self, node: &'ast ExprTry) {
        self.with_use(Use::Enforcing, |visitor| visitor.visit_expr(&node.expr));
    }

    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        let rejecting = block_rejects(&node.then_branch)
            || node
                .else_branch
                .as_ref()
                .is_some_and(|(_, branch)| expr_rejects(branch));
        let condition = if rejecting {
            Use::Enforcing
        } else {
            Use::Value
        };
        self.with_use(condition, |visitor| visitor.visit_expr(&node.cond));
        self.visit_block(&node.then_branch);
        if let Some((_, branch)) = &node.else_branch {
            self.with_use(Use::Statement, |visitor| visitor.visit_expr(branch));
        }
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        let condition = if block_rejects(&node.body) {
            Use::Enforcing
        } else {
            Use::Value
        };
        self.with_use(condition, |visitor| visitor.visit_expr(&node.cond));
        self.visit_block(&node.body);
    }

    /// `match user.role { Role::Admin | Role::Owner => .., _ => return Err(..) }`
    /// is a role check requiring the roles of the arms that do not reject.
    fn visit_expr_match(&mut self, node: &'ast ExprMatch) {
        let rejecting: Vec<bool> = node
            .arms
            .iter()
            .map(|arm| expr_rejects(&arm.body))
            .collect();
        let enforcing = rejecting.iter().any(|rejects| *rejects);
        let condition = if enforcing {
            Use::Enforcing
        } else {
            Use::Value
        };
        self.with_use(condition, |visitor| visitor.visit_expr(&node.expr));
        if enforcing && let Some(kind) = authorization_operand(&node.expr) {
            let admitting: Vec<&syn::Arm> = node
                .arms
                .iter()
                .zip(&rejecting)
                .filter(|(_, rejects)| !**rejects)
                .map(|(arm, _)| arm)
                .collect();
            let mut requirements: Vec<String> =
                admitting.iter().flat_map(|arm| pattern_keys(&arm.pat)).collect();
            if requirements.is_empty() {
                requirements = admitting.iter().flat_map(|arm| pattern_variant_keys(&arm.pat)).collect();
            }
            requirements.sort();
            requirements.dedup();
            let written = node.expr.to_token_stream().to_string().replace(' ', "");
            let mut evidence = self.evidence(
                kind,
                written,
                node.expr.span().start().line,
                AuthStrength::Medium,
            );
            evidence.requirements = requirements;
            self.with_use(Use::Enforcing, |visitor| visitor.record(evidence, false));
        }
        for arm in &node.arms {
            if let Pat::Guard(guarded) = &arm.pat {
                self.with_use(condition, |visitor| visitor.visit_expr(&guarded.guard));
            }
            self.with_use(Use::Statement, |visitor| visitor.visit_expr(&arm.body));
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let symbol = node.func.to_token_stream().to_string().replace(' ', "");
        let line = node.func.span().start().line;
        let name = symbol.rsplit("::").next().unwrap_or(&symbol).to_string();
        let found = evidence_for_handler_call(&symbol, line, &self.file, &self.handler)
            .or_else(|| evidence_for_handler_symbol(&symbol, line, &self.file, &self.handler))
            .or_else(|| rejects_unauthenticated(&name, &symbol, line, &self.file, &self.handler));
        if let Some(mut evidence) = found {
            evidence.requirements = requirement_keys(&name, &node.args);
            let imperative = is_imperative(&name, &evidence.kind);
            self.record(evidence, imperative);
        }
        if let Some(target) = handler_target(&node.func) {
            let roots = node.args.iter().filter_map(root_binding).collect();
            self.call_roots.push((target.clone(), roots));
            self.record_call(target);
        }
        self.with_use(Use::Value, |visitor| {
            for argument in &node.args {
                visitor.visit_expr(argument);
            }
        });
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        // `user.roles.contains(&Role::Admin)`, `role.eq(&Role::Admin)`.
        if ["contains", "eq", "ne"].contains(&method.as_str()) {
            self.record_comparison(std::iter::once(&*node.receiver).chain(&node.args));
        }
        // A method call's span is computed from its whole token stream,
        // receiver chain included, so it is only taken for a match: taking it
        // for every call made a long builder chain quadratic.
        if let Some(mut evidence) =
            evidence_for_handler_method(&method, 0, &self.file, &self.handler)
        {
            evidence.line = node.span().start().line;
            evidence.requirements = requirement_keys(&method, &node.args);
            // Read from the method's name; structural only when the method
            // is one of the scanned code's and can build an error.
            if super::structural::enabled() && !super::structural::rejecting_function(&method) {
                evidence.name_based = true;
            }
            let imperative = is_imperative(&method, &evidence.kind);
            self.record(evidence, imperative);
        }
        // Resolved later by the receiver's type, like a call by path.
        if let Some(receiver) = receiver_path(&node.receiver) {
            let target = HandlerTarget::Method {
                receiver,
                method: method.clone(),
            };
            let roots = std::iter::once(&*node.receiver)
                .chain(&node.args)
                .filter_map(root_binding)
                .collect();
            self.call_roots.push((target.clone(), roots));
            self.record_call(target);
        }
        self.visit_expr(&node.receiver);
        // A filter whose result decides a rejection (`let Some(a) =
        // users.find(|u| is_admin(u)) else { return .. }`) enforces its
        // predicate; otherwise it scopes the records returned.
        let arguments = match (SCOPING_METHODS.contains(&method.as_str()), self.use_) {
            (true, Use::Enforcing) => Use::Enforcing,
            (true, _) => Use::Scoping,
            (false, _) => Use::Value,
        };
        self.with_use(arguments, |visitor| {
            for argument in &node.args {
                visitor.visit_expr(argument);
            }
        });
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        let symbol = node.path.to_token_stream().to_string().replace(' ', "");
        if let Some(evidence) = evidence_for_handler_symbol(
            &symbol,
            node.span().start().line,
            &self.file,
            &self.handler,
        ) {
            self.record(evidence, true);
        }
        if let Some(name) = node.path.get_ident() {
            self.release(&name.to_string());
        }
        visit::visit_expr_path(self, node);
    }

    // Expression and statement macros both reach this hook once. The
    // condition of `ensure!`/`assert!` is enforced; `matches!` is a
    // comparison; other macros' tokens are opaque, apart from SQL string
    // literals that scope a query to the caller.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let Some(name) = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            return;
        };
        let arguments = node.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated);
        if let Ok(arguments) = &arguments {
            if ENFORCING_MACROS.contains(&name.as_str()) {
                let conditions = if name.ends_with("_eq") || name.ends_with("_ne") {
                    2
                } else {
                    1
                };
                for (position, argument) in arguments.iter().enumerate() {
                    let use_ = if position < conditions {
                        Use::Enforcing
                    } else {
                        Use::Value
                    };
                    self.with_use(use_, |visitor| visitor.visit_expr(argument));
                }
            } else if name == "matches" {
                // `matches!(user.role, Role::Admin | Role::Owner)`: the
                // pattern is read as an expression, which a path or `|` of
                // paths parses as.
                self.record_comparison(arguments.iter());
            }
        }
        for literal in token_literals(&node.tokens, true) {
            if sql_scopes_to_caller(&literal) {
                let evidence = self.evidence(
                    AuthEvidenceKind::OwnershipCheck,
                    format!("{name}! query scoped to the caller"),
                    node.path.span().start().line,
                    AuthStrength::Medium,
                );
                self.with_use(Use::Enforcing, |visitor| visitor.record(evidence, true));
            }
        }
        let Some((kind, strength)) = classify_check_name(&name) else {
            return;
        };
        let symbol = node.path.to_token_stream().to_string().replace(' ', "");
        let mut evidence =
            self.evidence(kind, name.clone(), node.path.span().start().line, strength);
        evidence.symbol = Some(format!("{symbol}!"));
        evidence.requirements = name_keys(&name);
        evidence.requirements.extend(
            token_literals(&node.tokens, false)
                .iter()
                .filter_map(|value| literal_key(value)),
        );
        evidence.requirements.sort();
        evidence.requirements.dedup();
        let imperative = is_imperative(&name, &evidence.kind);
        self.record(evidence, imperative);
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        if sql_scopes_to_caller(&node.value()) {
            let evidence = self.evidence(
                AuthEvidenceKind::OwnershipCheck,
                "query scoped to the caller".into(),
                node.span().start().line,
                AuthStrength::Medium,
            );
            self.with_use(Use::Enforcing, |visitor| visitor.record(evidence, true));
        }
    }

    /// `user.role != Role::Admin`, `post.owner_id == user.id`.
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if matches!(node.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            self.record_comparison([&*node.left, &*node.right]);
        } else if matches!(node.op, BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_))
            && let Some((admitted, operand)) = super::roles::ordering_admits(node)
            && let Some(kind) = authorization_operand(operand)
        {
            // `user.role >= Role::Editor`: the roles of an ordered type it
            // admits.
            let written = operand.to_token_stream().to_string().replace(' ', "");
            let mut evidence = self.evidence(kind, written, operand.span().start().line, AuthStrength::Medium);
            let mut admitted = admitted;
            admitted.sort();
            evidence.requirements = admitted;
            self.record(evidence, false);
        }
        visit::visit_expr_binary(self, node);
    }

    /// A boolean flag such as `claims.is_admin`, read like a call to the
    /// helper `is_admin`.
    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        if let Member::Named(member) = &node.member
            && let Some((kind, _)) = classify_check_name(&member.to_string())
        {
            let mut evidence = self.evidence(
                kind,
                member.to_string(),
                member.span().start().line,
                AuthStrength::Medium,
            );
            evidence.symbol = Some(node.to_token_stream().to_string().replace(' ', ""));
            evidence.requirements = name_keys(&member.to_string());
            self.record(evidence, false);
        }
        visit::visit_expr_field(self, node);
    }

    /// Assigning a flag (`user.is_admin = true`) does not check it.
    fn visit_expr_assign(&mut self, node: &'ast ExprAssign) {
        self.with_use(Use::Value, |visitor| visitor.visit_expr(&node.right));
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        self.with_use(Use::Value, |visitor| {
            visit::visit_expr_struct(visitor, node)
        });
    }

    fn visit_expr_array(&mut self, node: &'ast syn::ExprArray) {
        self.with_use(Use::Value, |visitor| visit::visit_expr_array(visitor, node));
    }

    fn visit_expr_tuple(&mut self, node: &'ast syn::ExprTuple) {
        self.with_use(Use::Value, |visitor| visit::visit_expr_tuple(visitor, node));
    }

    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        if let Some(expr) = &node.expr {
            self.visit_returned(expr, Use::Statement);
        }
    }

    /// A closure body keeps an enforcing or scoping use (`.filter(|p|
    /// p.owner_id == user.id)`); otherwise it runs like statements.
    fn visit_expr_closure(&mut self, node: &'ast ExprClosure) {
        let use_ = match self.use_ {
            Use::Enforcing | Use::Scoping => self.use_,
            _ => Use::Statement,
        };
        match &*node.body {
            Expr::Block(body) => self.visit_body(&body.block, use_),
            body => self.with_use(use_, |visitor| visitor.visit_expr(body)),
        }
    }

    // Functions declared inside the handler body, including methods of nested
    // `impl` and `trait` items, do not run as part of that body. Their
    // evidence belongs to them, not to the enclosing handler.
    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}

    fn visit_impl_item_fn(&mut self, _: &'ast ImplItemFn) {}

    fn visit_trait_item_fn(&mut self, _: &'ast TraitItemFn) {}
}

/// Macros whose leading argument is a condition that rejects when false.
/// `debug_assert!` is left out: it does not run in release builds.
pub(crate) const ENFORCING_MACROS: [&str; 6] = [
    "ensure",
    "assert",
    "assert_eq",
    "assert_ne",
    "require",
    "ensure_eq",
];

/// Methods whose closure argument decides which records are returned.
const SCOPING_METHODS: [&str; 7] = [
    "filter",
    "retain",
    "retain_mut",
    "find",
    "filter_map",
    "find_map",
    "position",
];

/// Whether a check name is imperative (`require_admin`, `authorize`,
/// `check_permission`), rejecting by itself, rather than a predicate
/// (`is_admin`, `has_role`, `owns`) whose value must be acted on.
pub(crate) fn is_imperative(name: &str, kind: &AuthEvidenceKind) -> bool {
    let lower = name.to_ascii_lowercase();
    if *kind == AuthEvidenceKind::IdentityExtraction {
        return true;
    }
    !(["is_", "has_", "can_", "may_", "owns"]
        .iter()
        .any(|prefix| lower.starts_with(prefix)))
}

impl AuthEvidenceVisitor {
    /// Records a comparison that checks a role or permission (`user.role ==
    /// Role::Admin`) or resource ownership (`post.owner_id == user.id`).
    fn record_comparison<'e>(&mut self, operands: impl IntoIterator<Item = &'e Expr>) {
        let operands: Vec<&Expr> = operands.into_iter().collect();
        if let Some((kind, operand)) = operands
            .iter()
            .find_map(|operand| authorization_operand(operand).map(|kind| (kind, *operand)))
        {
            let written = operand.to_token_stream().to_string().replace(' ', "");
            let mut evidence = self.evidence(
                kind,
                written,
                operand.span().start().line,
                AuthStrength::Medium,
            );
            let mut requirements: Vec<String> = operands
                .iter()
                .flat_map(|operand| keys_in_expr(operand))
                .collect();
            // Compared with a role, a variant names a role whatever its type
            // is called (`member.rank == Rank::Chief`).
            if requirements.is_empty() {
                requirements = operands
                    .iter()
                    .filter(|other| !std::ptr::eq(**other, operand))
                    .flat_map(|other| variant_keys(other))
                    .collect();
            }
            requirements.sort();
            requirements.dedup();
            evidence.requirements = requirements;
            self.record(evidence, false);
            return;
        }
        if let [left, right] = operands.as_slice()
            && let Some(owned) = [(left, right), (right, left)]
                .into_iter()
                .find(|(owned, caller)| {
                    (ownership_operand(owned) && caller_operand(caller))
                        // `article.creater == username`, where `username`
                        // was read as the caller's identity: whatever the
                        // field is called, the record is held to its owner.
                        || (self.record_field(owned) && self.is_caller_binding(caller))
                })
                .map(|(owned, _)| *owned)
        {
            let written = owned.to_token_stream().to_string().replace(' ', "");
            let evidence = self.evidence(
                AuthEvidenceKind::OwnershipCheck,
                written,
                owned.span().start().line,
                AuthStrength::Medium,
            );
            self.record(evidence, false);
        }
    }
}

/// Fields that name a record's owner.
const OWNERSHIP_FIELDS: [&str; 9] = [
    "owner_id",
    "owner",
    "user_id",
    "author_id",
    "created_by",
    "creator_id",
    "tenant_id",
    "account_id",
    "owned_by",
];

/// Words that make an expression the requesting caller (`user.id`,
/// `claims.sub`, `identity.id()`).
const CALLER_WORDS: [&str; 13] = [
    "user",
    "claims",
    "identity",
    "current",
    "session",
    "principal",
    "caller",
    "auth",
    "subject",
    "sub",
    "me",
    "actor",
    "requester",
];

fn strip_conversions(expr: &Expr) -> &Expr {
    match expr {
        Expr::Paren(paren) => strip_conversions(&paren.expr),
        Expr::Group(group) => strip_conversions(&group.expr),
        Expr::Reference(reference) => strip_conversions(&reference.expr),
        Expr::Unary(unary) if matches!(unary.op, UnOp::Deref(_)) => strip_conversions(&unary.expr),
        Expr::MethodCall(call)
            if call.args.is_empty()
                && [
                    "as_str",
                    "as_ref",
                    "as_deref",
                    "to_string",
                    "to_owned",
                    "clone",
                    "unwrap",
                    "as_uuid",
                    "into",
                ]
                .iter()
                .any(|conversion| call.method == conversion) =>
        {
            strip_conversions(&call.receiver)
        }
        _ => expr,
    }
}

/// Fields that place a record in a tenant (an organization, team or
/// workspace): a record whose tenant is compared with the caller's is held
/// to the caller's tenant, an object-level check like ownership.
const TENANT_FIELDS: [&str; 8] = [
    "org_id",
    "organization_id",
    "team_id",
    "workspace_id",
    "project_id",
    "merchant_id",
    "company_id",
    "namespace_id",
];

fn ownership_operand(expr: &Expr) -> bool {
    let named = |name: &str| {
        let name = name.strip_prefix("get_").unwrap_or(name);
        OWNERSHIP_FIELDS.contains(&name) || TENANT_FIELDS.contains(&name)
    };
    match strip_conversions(expr) {
        Expr::Field(field) => {
            matches!(&field.member, Member::Named(member) if named(&member.to_string()))
        }
        Expr::MethodCall(call) => call.args.is_empty() && named(&call.method.to_string()),
        _ => false,
    }
}

fn caller_operand(expr: &Expr) -> bool {
    // `u.id`, `claims.sub`, `me.uid`: an identifier field of some caller value.
    if let Expr::Field(field) = strip_conversions(expr)
        && let Member::Named(member) = &field.member
        && ["id", "sub", "uid", "user_id", "subject"].contains(&member.to_string().as_str())
    {
        return true;
    }
    let written = expr.to_token_stream().to_string().to_ascii_lowercase();
    written
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|word| CALLER_WORDS.contains(&word))
}

/// Whether a SQL string restricts rows to the caller: `WHERE ... owner_id =
/// $1`, `AND user_id = ?`.
pub(crate) fn sql_scopes_to_caller(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let Some(clause) = lower.find("where") else {
        return false;
    };
    let clause = &lower[clause..];
    OWNERSHIP_FIELDS.iter().any(|field| {
        clause.match_indices(field).any(|(index, _)| {
            let before = clause[..index].chars().next_back();
            if before.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
            {
                return false;
            }
            let rest = clause[index + field.len()..].trim_start();
            let Some(rest) = rest.strip_prefix('=') else {
                return false;
            };
            rest.trim_start()
                .starts_with(['$', '?', ':', '@'])
        })
    })
}

/// Whether a value's rejecting branch exists: an early `return`, `?`, an
/// `Err(..)`, a forbidden/unauthorized response or error, or a panic.
pub(crate) fn block_rejects(block: &Block) -> bool {
    let mut visitor = RejectionVisitor::default();
    visitor.visit_block(block);
    visitor.rejects
}

pub(crate) fn expr_rejects(expr: &Expr) -> bool {
    let mut visitor = RejectionVisitor::default();
    visitor.visit_expr(expr);
    visitor.rejects
}

#[derive(Default)]
struct RejectionVisitor {
    rejects: bool,
}

const REJECTION_WORDS: [&str; 6] = [
    "forbidden",
    "unauthorized",
    "unauthorised",
    "deny",
    "denied",
    "reject",
];
const REJECTION_MACROS: [&str; 5] = ["panic", "unreachable", "bail", "abort", "throw"];

impl<'ast> Visit<'ast> for RejectionVisitor {
    fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
        self.rejects = true;
    }

    fn visit_expr_try(&mut self, node: &'ast ExprTry) {
        self.rejects = true;
        visit::visit_expr_try(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        let written = node.path.to_token_stream().to_string().to_ascii_lowercase();
        if node.path.is_ident("Err") || REJECTION_WORDS.iter().any(|word| written.contains(word)) {
            self.rejects = true;
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string().to_ascii_lowercase();
        if REJECTION_WORDS.iter().any(|word| method.contains(word)) {
            self.rejects = true;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node
            .path
            .segments
            .last()
            .is_some_and(|segment| REJECTION_MACROS.contains(&segment.ident.to_string().as_str()))
        {
            self.rejects = true;
        }
    }

    fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}

    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
}

/// Whether an operand names a role or permission: a variant of a type named
/// like one (`Role::Admin`, `UserRole::Admin`, `Permission::Write`), or a
/// field whose name ends in one (`user.role`, `claims.permissions`), possibly
/// behind a reference or a conversion such as `.as_str()`.
fn authorization_operand(expr: &Expr) -> Option<AuthEvidenceKind> {
    const ROLE_WORDS: [&str; 2] = ["role", "roles"];
    const PERMISSION_WORDS: [&str; 2] = ["permission", "permissions"];
    let kind_of = |word: &str| {
        if ROLE_WORDS.contains(&word) {
            Some(AuthEvidenceKind::RoleCheck)
        } else if PERMISSION_WORDS.contains(&word) {
            Some(AuthEvidenceKind::PermissionCheck)
        } else {
            None
        }
    };
    match expr {
        Expr::Paren(paren) => authorization_operand(&paren.expr),
        Expr::Group(group) => authorization_operand(&group.expr),
        Expr::Reference(reference) => authorization_operand(&reference.expr),
        Expr::Unary(unary) if matches!(unary.op, UnOp::Deref(_)) => {
            authorization_operand(&unary.expr)
        }
        Expr::Binary(binary) if matches!(binary.op, BinOp::BitOr(_)) => {
            authorization_operand(&binary.left).or_else(|| authorization_operand(&binary.right))
        }
        // A conversion keeps the value; `roles.len()` does not.
        Expr::MethodCall(call)
            if call.args.is_empty()
                && [
                    "as_str",
                    "as_ref",
                    "as_deref",
                    "to_string",
                    "to_owned",
                    "to_lowercase",
                    "to_uppercase",
                    "clone",
                    "unwrap",
                ]
                .iter()
                .any(|conversion| call.method == conversion) =>
        {
            authorization_operand(&call.receiver)
        }
        Expr::Path(path) => {
            let segments = &path.path.segments;
            let owner = segments.iter().nth_back(1)?.ident.to_string();
            camel_case_words(&owner)
                .iter()
                .rev()
                .find_map(|word| kind_of(word))
        }
        Expr::Field(field) => match &field.member {
            Member::Named(member) => kind_of(member.to_string().rsplit('_').next()?),
            Member::Unnamed(_) => None,
        },
        _ => None,
    }
}

pub(crate) fn evidence_for_handler_method(
    method: &str,
    line: usize,
    file: &Path,
    handler: &str,
) -> Option<AuthEvidence> {
    let (kind, strength) = classify_check_name(method).or_else(|| {
        (method.contains("identity") || method.contains("claims"))
            .then_some((AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak))
    })?;
    Some(AuthEvidence {
        kind,
        mechanism: method.into(),
        symbol: Some(method.into()),
        file: file.to_path_buf(),
        line,
        handler: Some(handler.into()),
        strength,
        requirements: Vec::new(),
        name_based: false,
    })
}

pub(crate) fn evidence_for_handler_call(
    symbol: &str,
    line: usize,
    file: &Path,
    handler: &str,
) -> Option<AuthEvidence> {
    let name = symbol.rsplit("::").next().unwrap_or(symbol);
    let (kind, strength) = classify_check_name(name)?;
    Some(AuthEvidence {
        kind,
        mechanism: name.into(),
        symbol: Some(symbol.into()),
        file: file.to_path_buf(),
        line,
        handler: Some(handler.into()),
        strength,
        requirements: Vec::new(),
        name_based: false,
    })
}

/// Final words that make a helper name a data, lookup, or logging operation
/// rather than an enforcement check (`ensure_admin_exists`, `check_admin_token`,
/// `role_name`, `permissions_list`, `check_access_log`).
pub(crate) const NON_CHECK_FINAL_WORDS: [&str; 26] = [
    "exists",
    "exist",
    "list",
    "count",
    "name",
    "names",
    "title",
    "id",
    "ids",
    "status",
    "description",
    "log",
    "logs",
    "token",
    "tokens",
    "info",
    "data",
    "config",
    "settings",
    "cache",
    "url",
    "path",
    "email",
    "header",
    "headers",
    "lookup",
];

/// Classifies a called helper by its snake_case name. This is a lexical
/// heuristic: it recognizes conventional enforcement names but cannot see what
/// a helper does, and identity/authentication helpers are never authorization.
pub(crate) fn classify_check_name(name: &str) -> Option<(AuthEvidenceKind, AuthStrength)> {
    let lower = name.to_ascii_lowercase();
    if ["error", "exception", "fault"]
        .iter()
        .any(|marker| lower.contains(marker))
        || (lower.starts_with("author")
            && !lower.starts_with("authoriz")
            && !lower.starts_with("authoris"))
        || lower.starts_with("authority")
    {
        return None;
    }

    let tokens: Vec<&str> = lower.split('_').filter(|token| !token.is_empty()).collect();
    let last = *tokens.last()?;
    if NON_CHECK_FINAL_WORDS.contains(&last) {
        return None;
    }
    let has_token = |candidates: &[&str]| tokens.iter().any(|token| candidates.contains(token));
    let is_one_of = |names: &[&str]| names.contains(&lower.as_str());
    // `access` is an authorization subject only as the final noun (`check_access`,
    // `verify_resource_access`); as a modifier it names authentication artifacts
    // such as `verify_access_token` or logging helpers such as `check_access_log`.
    let ends_with_access = last == "access";
    let uses_check_prefix = [
        "require_", "check_", "verify_", "assert_", "ensure_", "validate_",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix));

    // `host.validate_secret(..)?`, `verify_api_token(..)`: a presented
    // credential is checked, which identifies the caller.
    let credential_check = uses_check_prefix
        && ["secret", "token", "signature", "credentials", "password", "apikey"]
            .contains(&last)
        && !has_token(&["access", "csrf", "reset"]);
    let classification = if credential_check
        || is_one_of(&[
            "require_auth",
            "is_authenticated",
            "require_authenticated_user",
            "current_user",
            "authenticated_user",
        ])
    {
        (AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak)
    } else if is_one_of(&["authorize", "authorise", "is_authorized", "permit"])
        || ["authorize_", "authorise_", "is_authorized_"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
    {
        (
            AuthEvidenceKind::ManualAuthorizationCheck,
            AuthStrength::Strong,
        )
    } else if is_one_of(&[
        "has_role",
        "has_roles",
        "has_any_role",
        "is_admin",
        "require_admin",
        "require_manager",
    ]) || (uses_check_prefix
        && has_token(&["admin", "admins", "manager", "role", "roles"]))
    {
        (AuthEvidenceKind::RoleCheck, AuthStrength::Strong)
    } else if is_one_of(&[
        "has_permission",
        "has_permissions",
        "has_any_permission",
        "check_permission",
        "verify_permission",
    ]) || (uses_check_prefix
        && (has_token(&["permission", "permissions"]) || ends_with_access))
    {
        (AuthEvidenceKind::PermissionCheck, AuthStrength::Strong)
    } else if is_one_of(&["owns", "is_owner", "is_owned_by", "is_member", "belongs_to"])
        || (uses_check_prefix
            && has_token(&["owner", "ownership", "member", "membership", "belongs"]))
    {
        (AuthEvidenceKind::OwnershipCheck, AuthStrength::Medium)
    } else {
        return None;
    };
    Some(classification)
}

/// `HttpResponse::Unauthorized()`, `ErrorUnauthorized(..)`: a handler that
/// builds an unauthenticated rejection turns away callers who are not logged
/// in, so it identifies them itself. Only a call counts; naming the variant
/// as a value does not.
fn rejects_unauthenticated(
    name: &str,
    symbol: &str,
    line: usize,
    file: &Path,
    handler: &str,
) -> Option<AuthEvidence> {
    let lower = name.to_ascii_lowercase();
    // Structural: the crate maps this error to 401, or it is actix's own
    // 401 response. Otherwise only the error's name says so.
    let structural = super::structural::unauthenticated_variant(symbol)
        || name == "ErrorUnauthorized"
        || symbol.ends_with("HttpResponse::Unauthorized");
    let by_name = lower.contains("unauthorized") || lower.contains("unauthenticated");
    (structural || by_name).then(|| AuthEvidence {
        kind: AuthEvidenceKind::IdentityExtraction,
        mechanism: format!("rejects unauthenticated callers (`{name}`)"),
        symbol: Some(symbol.into()),
        file: file.to_path_buf(),
        line,
        handler: Some(handler.into()),
        strength: AuthStrength::Weak,
        requirements: Vec::new(),
        name_based: super::structural::enabled() && !structural,
    })
}

pub(crate) fn evidence_for_handler_symbol(
    symbol: &str,
    line: usize,
    file: &Path,
    handler: &str,
) -> Option<AuthEvidence> {
    let name = symbol.rsplit("::").next().unwrap_or(symbol);
    if name == "require_admin" {
        return Some(AuthEvidence {
            kind: AuthEvidenceKind::RoleCheck,
            mechanism: name.into(),
            symbol: Some(symbol.into()),
            file: file.to_path_buf(),
            line,
            handler: Some(handler.into()),
            strength: AuthStrength::Strong,
            requirements: vec!["admin".into()],
            name_based: false,
        });
    }
    if name.ends_with("Guard") || name.ends_with("Middleware") {
        return None;
    }
    if symbol.contains("Claims") || name == "Identity" || name == "AuthenticatedUser" {
        return Some(AuthEvidence {
            kind: AuthEvidenceKind::IdentityExtraction,
            mechanism: name.into(),
            symbol: Some(symbol.into()),
            file: file.to_path_buf(),
            line,
            handler: Some(handler.into()),
            strength: AuthStrength::Weak,
            requirements: Vec::new(),
            name_based: false,
        });
    }
    None
}

/// What a `.guard(...)` or `.wrap(...)` argument name indicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteConfigurationName {
    /// An authorization guard or middleware, such as `AdminGuard` or `check_admin`.
    Authorization,
    /// Authentication only, such as `AuthMiddleware` or `HttpAuthentication`.
    Authentication,
}

pub(crate) const CONFIGURATION_EXCLUDED_WORDS: [&str; 15] = [
    "error",
    "errors",
    "err",
    "exception",
    "fault",
    "unauthorized",
    "forbidden",
    "log",
    "logs",
    "logger",
    "logging",
    "metrics",
    "tracing",
    "telemetry",
    "audit",
];
pub(crate) const CONFIGURATION_AUTHORIZATION_WORDS: [&str; 14] = [
    "authority",
    "authorities",
    "admin",
    "admins",
    "role",
    "roles",
    "permission",
    "permissions",
    "authorization",
    "authorize",
    "authorized",
    "authz",
    "acl",
    "rbac",
];
pub(crate) const CONFIGURATION_AUTHENTICATION_WORDS: [&str; 10] = [
    "auth",
    "authn",
    "authentication",
    "authenticate",
    "authenticated",
    "jwt",
    "bearer",
    "login",
    "oauth",
    "identity",
];
pub(crate) const CONFIGURATION_SHAPE_WORDS: [&str; 11] = [
    "guard",
    "middleware",
    "filter",
    "gate",
    "only",
    "require",
    "requires",
    "check",
    "verify",
    "enforce",
    "enforcer",
];

/// Classifies one path segment of a guard or middleware argument. snake_case
/// names (guard functions) use the helper-name classifier; type names need an
/// authorization word and a guard-like word, so `PermissionsPolicy`,
/// `RoleLogger`, and `UnauthorizedHandler` are not authorization.
pub(crate) fn classify_route_configuration_name(
    identifier: &str,
) -> Option<RouteConfigurationName> {
    if INFRASTRUCTURE_COMPONENTS.contains(&identifier) {
        return None;
    }
    if !identifier.chars().any(char::is_uppercase) {
        let (kind, _) = classify_check_name(identifier)?;
        return Some(if kind == AuthEvidenceKind::IdentityExtraction {
            RouteConfigurationName::Authentication
        } else {
            RouteConfigurationName::Authorization
        });
    }

    let words = camel_case_words(identifier);
    let has_word =
        |candidates: &[&str]| words.iter().any(|word| candidates.contains(&word.as_str()));
    if has_word(&CONFIGURATION_EXCLUDED_WORDS) {
        None
    } else if has_word(&CONFIGURATION_AUTHORIZATION_WORDS) && has_word(&CONFIGURATION_SHAPE_WORDS) {
        Some(RouteConfigurationName::Authorization)
    } else if identifier == "HttpAuthentication"
        || (has_word(&CONFIGURATION_AUTHENTICATION_WORDS) && has_word(&CONFIGURATION_SHAPE_WORDS))
    {
        Some(RouteConfigurationName::Authentication)
    } else {
        None
    }
}

/// Splits `AdminAuthMiddleware` or `JWTGuard` into lowercase words.
pub(crate) fn camel_case_words(identifier: &str) -> Vec<String> {
    let characters: Vec<char> = identifier.chars().collect();
    let mut words: Vec<String> = Vec::new();
    for (index, &character) in characters.iter().enumerate() {
        let starts_word = index == 0
            || character == '_'
            || character.is_uppercase()
                && (characters[index - 1].is_lowercase()
                    || characters
                        .get(index + 1)
                        .is_some_and(|next| next.is_lowercase()));
        if character == '_' {
            continue;
        }
        if starts_word || words.is_empty() {
            words.push(String::new());
        }
        if let Some(word) = words.last_mut() {
            word.extend(character.to_lowercase());
        }
    }
    words.retain(|word| !word.is_empty());
    words
}

#[derive(Debug, Clone)]
pub(crate) struct NamedIdentifier {
    pub(crate) name: String,
    pub(crate) line: usize,
}

/// Finds the most specific authorization-related name in a guard or
/// middleware argument; an authorization name wins over an authentication one.
pub(crate) fn route_configuration_name_in_expr(
    expr: &Expr,
) -> Option<(RouteConfigurationName, NamedIdentifier)> {
    let mut visitor = RouteConfigurationNameVisitor::default();
    visitor.visit_expr(expr);
    visitor
        .authorization
        .map(|name| (RouteConfigurationName::Authorization, name))
        .or_else(|| {
            visitor
                .authentication
                .map(|name| (RouteConfigurationName::Authentication, name))
        })
}

#[derive(Default)]
pub(crate) struct RouteConfigurationNameVisitor {
    pub(crate) authorization: Option<NamedIdentifier>,
    pub(crate) authentication: Option<NamedIdentifier>,
}

impl<'ast> Visit<'ast> for RouteConfigurationNameVisitor {
    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        for segment in &node.path.segments {
            let name = segment.ident.to_string();
            let slot = match classify_route_configuration_name(&name) {
                Some(RouteConfigurationName::Authorization) => &mut self.authorization,
                Some(RouteConfigurationName::Authentication) => &mut self.authentication,
                None => continue,
            };
            if slot.is_none() {
                *slot = Some(NamedIdentifier {
                    name,
                    line: node.span().start().line,
                });
            }
        }
        visit::visit_expr_path(self, node);
    }
}

/// Words that name the kind or shape of a check, not what it requires:
/// `require_admin` requires `admin`, `RequireRole<Admin>` requires `admin`.
const KEY_STOP_WORDS: &[&str] = &[
    "validate",
    "session",
    "sessions",
    "require",
    "requires",
    "required",
    "check",
    "checks",
    "verify",
    "ensure",
    "assert",
    "enforce",
    "enforcer",
    "is",
    "has",
    "have",
    "can",
    "may",
    "any",
    "all",
    "role",
    "roles",
    "permission",
    "permissions",
    "perm",
    "perms",
    "access",
    "user",
    "users",
    "guard",
    "middleware",
    "only",
    "must",
    "be",
    "a",
    "an",
    "the",
    "of",
    "for",
    "to",
    "in",
    "auth",
    "authn",
    "authz",
    "authorized",
    "authorize",
    "authorise",
    "authorization",
    "rbac",
    "acl",
    "extractor",
    "gate",
    "filter",
    "mw",
    "layer",
    "new",
    "with",
    "from",
    "request",
    "req",
    "claims",
    "policy",
    "grant",
    "grants",
    "level",
];

/// Normalizes a role or permission subject: `ROLE_ADMIN`, `Admins`, and
/// `administrator` all become `admin`.
pub(crate) fn normalize_key(raw: &str) -> Option<String> {
    let mut key = raw.trim().to_ascii_lowercase();
    for prefix in [
        "role_",
        "role:",
        "roles:",
        "perm_",
        "permission:",
        "permissions:",
    ] {
        if let Some(rest) = key.strip_prefix(prefix) {
            key = rest.to_string();
        }
    }
    if [
        "admins",
        "administrator",
        "administrators",
        "superadmin_admin",
    ]
    .contains(&key.as_str())
    {
        key = "admin".into();
    }
    (!key.is_empty()).then_some(key)
}

/// The subject a check's name requires: `admin` for `require_admin`,
/// `AdminUser`, and `AdminGuard`; `billing_admin` for `check_billing_admin`;
/// nothing for `check_role` or `authorize`.
pub(crate) fn name_keys(name: &str) -> Vec<String> {
    let words: Vec<String> = if name.chars().any(char::is_uppercase) {
        camel_case_words(name)
    } else {
        name.to_ascii_lowercase()
            .split('_')
            .filter(|word| !word.is_empty())
            .map(str::to_owned)
            .collect()
    };
    // `validate_api_key_or_admin_session` passes on either alternative, so
    // it names no single requirement to compare against peers.
    if words.iter().any(|word| word == "or") {
        return Vec::new();
    }
    let subject: Vec<&str> = words
        .iter()
        .map(String::as_str)
        .filter(|word| !KEY_STOP_WORDS.contains(word))
        .collect();
    if subject.is_empty() {
        return Vec::new();
    }
    normalize_key(&subject.join("_")).into_iter().collect()
}

/// A string literal that reads as a role or permission name (`"admin"`,
/// `"billing:read"`), not a message.
pub(crate) fn literal_key(value: &str) -> Option<String> {
    let plausible = !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.:-/".contains(character));
    if plausible {
        normalize_key(value)
    } else {
        None
    }
}

/// Requirement subjects of a call: its name's, its string-literal
/// arguments', and its role or permission variants' (`Role::Admin`).
pub(crate) fn requirement_keys(name: &str, arguments: &Punctuated<Expr, Token![,]>) -> Vec<String> {
    let mut keys = name_keys(name);
    for argument in arguments {
        keys.extend(keys_in_expr(argument));
    }
    keys.sort();
    keys.dedup();
    keys
}

/// String literals and role or permission variants anywhere in an
/// expression, outside nested calls' function paths.
pub(crate) fn keys_in_expr(expr: &Expr) -> Vec<String> {
    #[derive(Default)]
    struct KeyVisitor {
        keys: Vec<String>,
    }
    impl<'ast> Visit<'ast> for KeyVisitor {
        fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
            self.keys.extend(literal_key(&node.value()));
        }
        fn visit_expr_path(&mut self, node: &'ast ExprPath) {
            self.keys.extend(variant_key(&node.path));
        }
        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            for argument in &node.args {
                self.visit_expr(argument);
            }
        }
        fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
    }
    let mut visitor = KeyVisitor::default();
    visitor.visit_expr(expr);
    visitor.keys
}

/// Words of a constructor or builder method that take a role list:
/// `allowed_roles`, `with_permissions`, `require_scope`.
const ROLE_LIST_WORDS: [&str; 7] =
    ["role", "roles", "permission", "permissions", "scope", "scopes", "grant"];

/// Roles a guard or middleware is constructed with:
/// `RequireAuth::allowed_roles(vec![UserRole::Admin])`,
/// `RoleGuard::new(&["editor", "admin"])`. Role-typed variants count
/// anywhere in the expression; string literals count only as arguments of a
/// call named for roles or permissions. `vec![..]` and array arguments are
/// read element by element.
pub(crate) fn component_roles(expr: &Expr) -> Vec<String> {
    #[derive(Default)]
    struct Roles {
        keys: Vec<String>,
        in_role_call: usize,
    }
    fn names_roles(name: &str) -> bool {
        let words = if name.contains('_') || !name.chars().any(char::is_uppercase) {
            name.to_ascii_lowercase().split('_').map(str::to_owned).collect()
        } else {
            camel_case_words(name)
        };
        words.iter().any(|word| ROLE_LIST_WORDS.contains(&word.as_str()))
    }
    impl<'ast> Visit<'ast> for Roles {
        fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
            if self.in_role_call > 0 {
                self.keys.extend(literal_key(&node.value()));
            }
        }
        fn visit_expr_path(&mut self, node: &'ast ExprPath) {
            self.keys.extend(variant_key(&node.path));
        }
        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            let role_call = matches!(&*node.func, Expr::Path(path)
                if path.path.segments.iter().any(|segment| names_roles(&segment.ident.to_string())));
            self.in_role_call += usize::from(role_call);
            for argument in &node.args {
                self.visit_expr(argument);
            }
            self.in_role_call -= usize::from(role_call);
        }
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.visit_expr(&node.receiver);
            let role_call = names_roles(&node.method.to_string());
            self.in_role_call += usize::from(role_call);
            for argument in &node.args {
                self.visit_expr(argument);
            }
            self.in_role_call -= usize::from(role_call);
        }
        fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
            if node.mac.path.is_ident("vec") {
                if let Ok(items) = node
                    .mac
                    .parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                {
                    for item in &items {
                        self.visit_expr(item);
                    }
                }
            }
        }
        fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
    }
    let mut roles = Roles::default();
    roles.visit_expr(expr);
    roles.keys.sort();
    roles.keys.dedup();
    roles.keys
}

/// `Role::Admin`, `UserRole::Admin`, `Permission::WriteUsers`: the variant
/// of a type named like a role or permission, as snake case.
fn variant_key(path: &syn::Path) -> Option<String> {
    let segments = &path.segments;
    let owner = segments.iter().nth_back(1)?.ident.to_string();
    let words = camel_case_words(&owner);
    if !words.iter().any(|word| {
        [
            "role",
            "roles",
            "permission",
            "permissions",
            "perm",
            "scope",
            "grant",
        ]
        .contains(&word.as_str())
    }) {
        return None;
    }
    let variant = segments.last()?.ident.to_string();
    normalize_key(&camel_case_words(&variant).join("_"))
}

/// Enum variants an expression names (`Rank::Chief`, `Rank::A | Rank::B`),
/// whatever the type is called: used where the other side is a role.
fn variant_keys(expr: &Expr) -> Vec<String> {
    match expr {
        Expr::Path(path) if path.path.segments.len() >= 2 => any_variant_key(&path.path).into_iter().collect(),
        Expr::Reference(inner) => variant_keys(&inner.expr),
        Expr::Paren(inner) => variant_keys(&inner.expr),
        Expr::Binary(binary) if matches!(binary.op, BinOp::BitOr(_)) => {
            let mut keys = variant_keys(&binary.left);
            keys.extend(variant_keys(&binary.right));
            keys
        }
        _ => Vec::new(),
    }
}

fn any_variant_key(path: &syn::Path) -> Option<String> {
    let variant = path.segments.last()?.ident.to_string();
    variant
        .chars()
        .next()
        .is_some_and(char::is_uppercase)
        .then(|| normalize_key(&camel_case_words(&variant).join("_")))
        .flatten()
}

/// `pattern_keys` for a match on a role, whatever the variants' type is
/// called.
fn pattern_variant_keys(pat: &Pat) -> Vec<String> {
    match pat {
        Pat::Path(path) if path.path.segments.len() >= 2 => any_variant_key(&path.path).into_iter().collect(),
        Pat::TupleStruct(tuple) if tuple.path.segments.len() >= 2 => any_variant_key(&tuple.path).into_iter().collect(),
        Pat::Struct(item) if item.path.segments.len() >= 2 => any_variant_key(&item.path).into_iter().collect(),
        Pat::Or(or) => or.cases.iter().flat_map(pattern_variant_keys).collect(),
        Pat::Paren(paren) => pattern_variant_keys(&paren.pat),
        Pat::Reference(reference) => pattern_variant_keys(&reference.pat),
        Pat::Ident(ident) => ident.subpat.as_ref().map(|(_, sub)| pattern_variant_keys(sub)).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Role or permission variants named by a match arm's pattern.
fn pattern_keys(pat: &Pat) -> Vec<String> {
    match pat {
        Pat::Path(path) => variant_key(&path.path).into_iter().collect(),
        Pat::TupleStruct(tuple) => variant_key(&tuple.path).into_iter().collect(),
        Pat::Struct(item) => variant_key(&item.path).into_iter().collect(),
        Pat::Or(or) => or.cases.iter().flat_map(pattern_keys).collect(),
        Pat::Lit(literal) => match &literal.lit {
            syn::Lit::Str(value) => literal_key(&value.value()).into_iter().collect(),
            _ => Vec::new(),
        },
        Pat::Ident(ident) => ident
            .subpat
            .as_ref()
            .map(|(_, sub)| pattern_keys(sub))
            .unwrap_or_default(),
        Pat::Paren(paren) => pattern_keys(&paren.pat),
        Pat::Guard(guarded) => pattern_keys(&guarded.pat),
        Pat::Reference(reference) => pattern_keys(&reference.pat),
        _ => Vec::new(),
    }
}

/// String literals in a token stream, recursively. With `include_assigned`
/// false, literals right after `=` (`ty = "Role"`, `error = "..."`) are
/// left out: they configure the macro, not the requirement.
pub(crate) fn token_literals(
    tokens: &proc_macro2::TokenStream,
    include_assigned: bool,
) -> Vec<String> {
    let mut values = Vec::new();
    let mut after_equals = false;
    for token in tokens.clone() {
        match token {
            proc_macro2::TokenTree::Literal(literal) => {
                if (include_assigned || !after_equals)
                    && let Ok(value) =
                        syn::parse2::<syn::LitStr>(proc_macro2::TokenTree::Literal(literal).into())
                {
                    values.push(value.value());
                }
                after_equals = false;
            }
            proc_macro2::TokenTree::Group(group) => {
                values.extend(token_literals(&group.stream(), include_assigned));
                after_equals = false;
            }
            proc_macro2::TokenTree::Punct(punct) => after_equals = punct.as_char() == '=',
            proc_macro2::TokenTree::Ident(_) => after_equals = false,
        }
    }
    values
}

/// Middleware that provides sessions, identities, or extracted grants to
/// handlers without rejecting any request. `IdentityMiddleware` lets a
/// handler read an identity; it does not require one, so it is not
/// authentication evidence.
pub(crate) const INFRASTRUCTURE_COMPONENTS: [&str; 11] = [
    "PermissionsPolicy",
    "ContentSecurityPolicy",
    "SecurityHeaders",
    "IdentityMiddleware",
    "IdentityService",
    "SessionMiddleware",
    "CookieSession",
    "CookieIdentityPolicy",
    "GrantsMiddleware",
    "GrantsExtractor",
    "Condition",
];

/// Words of middleware and guards that route, log, shape, or limit
/// requests without deciding who may make them.
const BENIGN_COMPONENT_WORDS: &[&str] = &[
    "logger",
    "logging",
    "log",
    "compress",
    "compression",
    "decompress",
    "cors",
    "header",
    "headers",
    "normalize",
    "error",
    "errors",
    "tracing",
    "trace",
    "tracer",
    "metrics",
    "prometheus",
    "telemetry",
    "sentry",
    "otel",
    "opentelemetry",
    "span",
    "session",
    "sessions",
    "cookie",
    "cookies",
    "governor",
    "ratelimit",
    "ratelimiter",
    "rate",
    "limit",
    "limiter",
    "limits",
    "throttle",
    "timeout",
    "cache",
    "caching",
    "request",
    "compat",
    "panic",
    "csrf",
    "etag",
    "static",
    "files",
    "host",
    "scheme",
    "acceptable",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "connect",
    "method",
    "redirect",
    "https",
    "hsts",
    "encoding",
    "content",
    "json",
    "payload",
    "body",
    "size",
    "default",
    "identity",
    "grants",
    "handler",
    "handlers",
    "unauthorized",
    "forbidden",
];

/// Path segments that only locate a component (`middleware::Logger`,
/// `guard::fn_guard`) or wrap another one (`from_fn(f)`, `Condition::new(..)`).
const TRANSPARENT_COMPONENT_NAMES: &[&str] = &[
    "middleware",
    "web",
    "actix_web",
    "actix_web_lab",
    "guard",
    "http",
    "new",
    "default",
    "from_fn",
    "fn_guard",
    "wrap_fn",
    "with",
    "builder",
    "build",
    "finish",
    "Condition",
    "Some",
    "Any",
    "All",
    "Not",
    "Box",
    "Rc",
    "Arc",
    "clone",
    "into",
    "self",
    "crate",
    "super",
];

/// The component a `.wrap(...)`/`.guard(...)` argument installs, when its
/// name says nothing about authorization or a known harmless purpose:
/// `StaffOnlyGate`, `from_fn(gatekeeper)`, a `wrap_fn` closure. Such a
/// component may protect the route, so it is recorded as unknown.
pub(crate) fn unrecognized_component(expr: &Expr) -> Option<String> {
    component_heads(expr)
        .into_iter()
        .find(|name| !is_benign_component(name))
}

/// Words that name authentication in a middleware or guard function:
/// `reject_anonymous_users`, `Authentication`, `jwt_validator`.
const AUTHENTICATION_COMPONENT_WORDS: [&str; 10] = [
    "auth",
    "authn",
    "authentication",
    "authenticate",
    "authenticated",
    "anonymous",
    "jwt",
    "bearer",
    "oauth",
    "login",
];

/// Whether a component name (snake_case or CamelCase) names authentication,
/// and nothing that makes it an error handler or a logger.
pub(crate) fn names_authentication(name: &str) -> bool {
    let words: Vec<String> = if name.contains('_') || !name.chars().any(char::is_uppercase) {
        name.split('_')
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    } else {
        camel_case_words(name)
    };
    let has = |candidates: &[&str]| words.iter().any(|word| candidates.contains(&word.as_str()));
    has(&AUTHENTICATION_COMPONENT_WORDS) && !has(&CONFIGURATION_EXCLUDED_WORDS)
}

/// Whether a component name names authorization: a variable or function
/// such as `coordinator_authorization_middleware` or `require_admin_role`
/// passed to `.wrap(..)`.
pub(crate) fn names_authorization(name: &str) -> bool {
    let words: Vec<String> = if name.contains('_') || !name.chars().any(char::is_uppercase) {
        name.split('_')
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    } else {
        camel_case_words(name)
    };
    let has = |candidates: &[&str]| words.iter().any(|word| candidates.contains(&word.as_str()));
    has(&CONFIGURATION_AUTHORIZATION_WORDS) && !has(&CONFIGURATION_EXCLUDED_WORDS)
}

/// Whether a middleware expression is enabled only by configuration:
/// `Condition::new(flag, Inner)`, `ConditionEx::from_option(..)`.
pub(crate) fn is_conditional_component(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => matches!(&*call.func, Expr::Path(path)
            if path.path.segments.iter().any(|segment| is_condition_wrapper(&segment.ident.to_string()))),
        Expr::Reference(reference) => is_conditional_component(&reference.expr),
        Expr::Paren(paren) => is_conditional_component(&paren.expr),
        Expr::Group(group) => is_conditional_component(&group.expr),
        _ => false,
    }
}

fn is_condition_wrapper(name: &str) -> bool {
    name == "Condition" || name == "ConditionEx"
}

fn is_benign_component(name: &str) -> bool {
    INFRASTRUCTURE_COMPONENTS.contains(&name)
        || camel_case_words(name)
            .iter()
            .any(|word| BENIGN_COMPONENT_WORDS.contains(&word.as_str()))
}

fn component_heads(expr: &Expr) -> Vec<String> {
    match expr {
        Expr::Call(call) => {
            let Expr::Path(path) = &*call.func else {
                return call.args.iter().flat_map(component_heads).collect();
            };
            // `Condition::new(enabled, Inner)`: the flag is not a component.
            // `ConditionEx::from_option(inner)`: the option holds it.
            if path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == "Condition")
            {
                return call.args.iter().skip(1).flat_map(component_heads).collect();
            }
            if path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == "ConditionEx")
            {
                return call.args.iter().flat_map(component_heads).collect();
            }
            match component_name(&path.path) {
                Some(name) => vec![name],
                None => call.args.iter().flat_map(component_heads).collect(),
            }
        }
        // `keys.map(|keys| AuthTransform::new(keys))`: the component is
        // built in the closure.
        Expr::MethodCall(call) if call.method == "map" => match call.args.first() {
            Some(Expr::Closure(closure)) => component_heads(&closure.body),
            _ => component_heads(&call.receiver),
        },
        Expr::MethodCall(call) => component_heads(&call.receiver),
        Expr::Path(path) => component_name(&path.path).into_iter().collect(),
        // `wrap_fn(|req, srv| srv.call(req).map(|res| res))` hands every
        // request on: it cannot protect anything.
        Expr::Closure(closure) if only_passes_on(closure) => Vec::new(),
        Expr::Closure(_) => vec!["<closure>".into()],
        Expr::Reference(reference) => component_heads(&reference.expr),
        Expr::Paren(paren) => component_heads(&paren.expr),
        Expr::Group(group) => component_heads(&group.expr),
        Expr::Struct(item) => component_name(&item.path).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Whether a middleware closure only calls the next service: it never
/// branches, returns early, builds a response or an error of its own, or
/// reads the request's headers, extensions, or caller.
fn only_passes_on(closure: &ExprClosure) -> bool {
    const WORDS: [&str; 8] = ["if", "match", "return", "status", "auth", "token", "cookie", "headers"];
    const PARTS: [&str; 11] = [
        "?", "err(", "error", "response", "unauthorized", "forbidden", "header(", "extensions",
        "identity", "app_data", "guard",
    ];
    let text = closure.body.to_token_stream().to_string().to_lowercase();
    let words: Vec<&str> = text
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|word| !word.is_empty())
        .collect();
    let compact = text.replace(' ', "");
    compact.contains(".call(")
        && !WORDS.iter().any(|sign| words.contains(sign))
        && !PARTS.iter().any(|sign| compact.contains(sign))
}

/// The meaningful segment of a component path: the last type-like segment
/// (`Logger` in `middleware::Logger::default`), else the last function name
/// that is not a locating or wrapping one.
fn component_name(path: &syn::Path) -> Option<String> {
    let segments: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let meaningful = |name: &&String| !TRANSPARENT_COMPONENT_NAMES.contains(&name.as_str());
    segments
        .iter()
        .rev()
        .filter(meaningful)
        .find(|name| name.chars().next().is_some_and(char::is_uppercase))
        .or_else(|| segments.iter().rev().find(meaningful))
        .cloned()
}

/// A method call's receiver as a binding and fields: `principal`,
/// `self.auth`, `auth.0`, through references and conversions
/// (`principal.clone()`, `&*auth`).
pub(crate) fn receiver_path(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) if path.qself.is_none() => path.path.get_ident().map(ToString::to_string),
        Expr::Field(field) => {
            let base = receiver_path(&field.base)?;
            Some(match &field.member {
                syn::Member::Named(name) => format!("{base}.{name}"),
                syn::Member::Unnamed(index) => format!("{base}.{}", index.index),
            })
        }
        Expr::Reference(reference) => receiver_path(&reference.expr),
        Expr::Paren(paren) => receiver_path(&paren.expr),
        Expr::Group(group) => receiver_path(&group.expr),
        Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => receiver_path(&unary.expr),
        Expr::MethodCall(call)
            if ["clone", "as_ref", "borrow", "deref", "into_inner", "as_deref"]
                .iter()
                .any(|name| call.method == name)
                && call.args.is_empty() =>
        {
            receiver_path(&call.receiver)
        }
        _ => None,
    }
}

/// Checks a function makes by its structure, whatever its names: a branch
/// that rejects the request (`Err(..)`, a 401/403 response, `bail!`) and
/// whose condition depends on the caller. What the condition does with
/// the caller decides the kind:
/// - it tests that a caller value is present (`if let Some(s) =
///   &self.session`, `let Some(u) = .. else`): identity;
/// - it compares a caller value with a value that is neither the caller's
///   nor a constant (`post.creator_id != user.id`): ownership;
/// - it tests a caller attribute or a flag computed from the caller
///   (`if !user.admin`, `if user.banned`, `if !self.is_admin()`): identity
///   as well, since the structure does not say whether the attribute is a
///   privilege or an account state. Named checks (`is_admin`, `has_role`)
///   still raise it to a role check.
///
/// Comparisons with constants (`state == SessionState::Auth`) are left to
/// the named checks: their meaning depends on the constant.
fn structural_checks(
    file: &Path,
    handler: &str,
    block: &Block,
    caller: HashSet<String>,
) -> Vec<AuthEvidence> {
    if caller.is_empty() {
        return Vec::new();
    }
    let mut visitor = StructuralChecks {
        file,
        handler,
        caller,
        relation: HashSet::new(),
        evidence: Vec::new(),
    };
    visitor.visit_block(block);
    visitor.evidence
}

struct StructuralChecks<'f> {
    file: &'f Path,
    handler: &'f str,
    /// Names holding the caller or a value computed from it.
    caller: HashSet<String>,
    /// Names holding the result of a lookup of the caller's relation to
    /// some data: a call given both a caller value and another value
    /// (`let is_member = lookup(pool, group_id, user.id).is_ok()`).
    relation: HashSet<String>,
    evidence: Vec<AuthEvidence>,
}

impl StructuralChecks<'_> {
    /// Whether an expression is a caller value itself: a caller binding, a
    /// field of one, or a method called on one (`self.session`,
    /// `user.local_user.admin`, `principal.is_admin()`), through `&`, `*`,
    /// `?` and `.await`. A value a free function computes from the caller
    /// is not: what it returns need not be about the caller.
    fn derives(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(path) if path.qself.is_none() => path
                .path
                .get_ident()
                .is_some_and(|ident| self.caller.contains(&ident.to_string())),
            Expr::Field(field) => self.derives(&field.base),
            Expr::MethodCall(call) => self.derives(&call.receiver),
            Expr::Reference(inner) => self.derives(&inner.expr),
            Expr::Paren(inner) => self.derives(&inner.expr),
            Expr::Group(inner) => self.derives(&inner.expr),
            Expr::Unary(inner) => self.derives(&inner.expr),
            Expr::Try(inner) => self.derives(&inner.expr),
            Expr::Await(inner) => self.derives(&inner.base),
            Expr::Cast(inner) => self.derives(&inner.expr),
            _ => false,
        }
    }

    fn constant(expr: &Expr) -> bool {
        match expr {
            Expr::Lit(_) => true,
            Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
                segment.ident.to_string().starts_with(char::is_uppercase)
            }),
            Expr::Reference(reference) => Self::constant(&reference.expr),
            Expr::Paren(paren) => Self::constant(&paren.expr),
            Expr::Call(call) => {
                matches!(&*call.func, Expr::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Some"))
                    && call.args.iter().all(Self::constant)
            }
            _ => false,
        }
    }

    /// Whether an expression looks up the caller's relation to other data:
    /// a call, through `.await`, `?` and result probes, given a caller
    /// value and a non-constant value that is not the caller
    /// (`lookup(pool, group_id, user.id).await.is_ok()`).
    fn relation_lookup(&self, expr: &Expr) -> bool {
        let arguments: Vec<&Expr> = match expr {
            Expr::Await(inner) => return self.relation_lookup(&inner.base),
            Expr::Try(inner) => return self.relation_lookup(&inner.expr),
            Expr::Paren(inner) => return self.relation_lookup(&inner.expr),
            Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Not(_)) => {
                return self.relation_lookup(&unary.expr);
            }
            Expr::MethodCall(call)
                if ["is_ok", "is_some", "is_err", "is_none", "unwrap_or", "unwrap_or_default"]
                    .contains(&call.method.to_string().as_str()) =>
            {
                return self.relation_lookup(&call.receiver);
            }
            Expr::Call(call) => call.args.iter().collect(),
            Expr::MethodCall(call) if !self.derives(&call.receiver) => call.args.iter().collect(),
            _ => return false,
        };
        let caller = arguments.iter().any(|argument| self.derives(argument));
        let other = arguments.iter().any(|argument| {
            !self.derives(argument) && !Self::constant(argument) && Self::record_key(argument)
        });
        caller && other
    }

    /// Whether a value names a record by its key (`community_id`,
    /// `data.post_id`, `path.uuid`, `&slug`): what a relation lookup takes
    /// besides the caller. A settings object or a pool is not one.
    fn record_key(expr: &Expr) -> bool {
        let last = expr
            .to_token_stream()
            .into_iter()
            .filter_map(|token| match token {
                proc_macro2::TokenTree::Ident(ident) => Some(ident.to_string().to_lowercase()),
                _ => None,
            })
            .filter(|name| !["clone", "into", "as_ref", "to_owned", "to_string", "into_inner", "unwrap"].contains(&name.as_str()))
            .last();
        last.is_some_and(|name| {
            name == "id"
                || name.ends_with("_id")
                || name.ends_with("_ids")
                || ["uuid", "slug", "key"].contains(&name.as_str())
                || name.ends_with("_uuid")
                || name.ends_with("_slug")
        })
    }

    /// The kind of check a rejecting branch's condition makes.
    fn classify(&self, condition: &Expr) -> Option<AuthEvidenceKind> {
        if self.relation_lookup(condition) {
            return Some(AuthEvidenceKind::OwnershipCheck);
        }
        if let Expr::Path(path) = condition
            && path.path.get_ident().is_some_and(|ident| self.relation.contains(&ident.to_string()))
        {
            return Some(AuthEvidenceKind::OwnershipCheck);
        }
        let strongest = |left: Option<AuthEvidenceKind>, right: Option<AuthEvidenceKind>| match (left, right) {
            (Some(left), Some(right)) => Some(if EvidenceTier::of(&right) > EvidenceTier::of(&left) { right } else { left }),
            (left, right) => left.or(right),
        };
        match condition {
            Expr::Paren(inner) => self.classify(&inner.expr),
            Expr::Group(inner) => self.classify(&inner.expr),
            Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Not(_)) => self.classify(&unary.expr),
            Expr::Await(inner) => self.classify(&inner.base),
            Expr::Let(binding) => self
                .derives(&binding.expr)
                .then_some(AuthEvidenceKind::IdentityExtraction),
            Expr::Binary(binary) => match binary.op {
                BinOp::And(_) | BinOp::Or(_) => {
                    strongest(self.classify(&binary.left), self.classify(&binary.right))
                }
                BinOp::Eq(_) | BinOp::Ne(_) | BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_) => {
                    let (left, right) = (self.derives(&binary.left), self.derives(&binary.right));
                    let other = match (left, right) {
                        (true, false) => &binary.right,
                        (false, true) => &binary.left,
                        _ => return None,
                    };
                    (!Self::constant(other)).then_some(AuthEvidenceKind::OwnershipCheck)
                }
                _ => None,
            },
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                let receiver = self.derives(&call.receiver);
                if ["is_some", "is_none", "is_ok", "is_err"].contains(&method.as_str()) {
                    return receiver.then_some(AuthEvidenceKind::IdentityExtraction);
                }
                if receiver {
                    Some(AuthEvidenceKind::IdentityExtraction)
                } else if call.args.iter().any(|argument| self.derives(argument)) {
                    // `post.editors.contains(&user.id)`: the caller in a
                    // record's list.
                    Some(AuthEvidenceKind::OwnershipCheck)
                } else {
                    None
                }
            }
            Expr::Field(_) | Expr::Path(_) => self
                .derives(condition)
                .then_some(AuthEvidenceKind::IdentityExtraction),
            _ => None,
        }
    }

    fn push(&mut self, kind: AuthEvidenceKind, condition: &Expr, line: usize) {
        let what = match (&kind, condition) {
            (AuthEvidenceKind::OwnershipCheck, _) if self.mentions_relation(condition) => {
                super::model::RELATION_CHECK
            }
            (AuthEvidenceKind::OwnershipCheck, _) => {
                if let Some(data) = self.data_operand(condition) {
                    let described = format!("a caller value matches the data's `{data}`");
                    self.push_described(kind, &described, condition, line);
                    return;
                }
                "a caller value matches the data"
            }
            (_, Expr::Let(_)) => "a caller value is present",
            (_, Expr::MethodCall(call)) if ["is_some", "is_none", "is_ok", "is_err"].iter().any(|probe| call.method == probe) => {
                "a caller value is present"
            }
            _ => "a caller attribute allows it",
        };
        self.push_described(kind, what, condition, line);
    }

    /// The operand a caller value is compared with, when it is a field of
    /// some record (`note.recipient_id` in `user.id != note.recipient_id`).
    fn data_operand(&self, condition: &Expr) -> Option<String> {
        match condition {
            Expr::Paren(inner) => self.data_operand(&inner.expr),
            Expr::Group(inner) => self.data_operand(&inner.expr),
            Expr::Unary(unary) => self.data_operand(&unary.expr),
            Expr::Binary(binary) if matches!(binary.op, BinOp::And(_) | BinOp::Or(_)) => self
                .data_operand(&binary.left)
                .or_else(|| self.data_operand(&binary.right)),
            Expr::Binary(binary) => {
                let other = match (self.derives(&binary.left), self.derives(&binary.right)) {
                    (true, false) => &binary.right,
                    (false, true) => &binary.left,
                    _ => return None,
                };
                matches!(strip_conversions(other), Expr::Field(_) | Expr::MethodCall(_))
                    .then(|| strip_conversions(other).to_token_stream().to_string().replace(' ', ""))
                    .filter(|written| written.len() <= 60)
            }
            _ => None,
        }
    }

    fn mentions_relation(&self, condition: &Expr) -> bool {
        self.relation_lookup(condition)
            || condition
                .to_token_stream()
                .into_iter()
                .any(|token| matches!(token, proc_macro2::TokenTree::Ident(ident) if self.relation.contains(&ident.to_string())))
    }

    fn push_described(&mut self, kind: AuthEvidenceKind, what: &str, condition: &Expr, line: usize) {
        if self.evidence.iter().any(|existing| existing.line == line && existing.kind == kind) {
            return;
        }
        let mut written = condition.to_token_stream().to_string();
        if written.len() > 60 {
            written.truncate(written.floor_char_boundary(57));
            written.push_str("...");
        }
        self.evidence.push(AuthEvidence {
            kind,
            mechanism: format!("rejects the request unless {what} (`{written}`)"),
            symbol: Some(written),
            file: self.file.to_path_buf(),
            line,
            handler: Some(self.handler.to_owned()),
            strength: AuthStrength::Medium,
            requirements: Vec::new(),
            name_based: false,
        });
    }
}

impl<'ast> Visit<'ast> for StructuralChecks<'_> {
    fn visit_local(&mut self, node: &'ast Local) {
        if let Some(init) = &node.init {
            let derived = self.derives(&init.expr);
            if derived
                && let Some((_, diverge)) = &init.diverge
                && super::caller_use::rejects_in(diverge)
            {
                self.push(AuthEvidenceKind::IdentityExtraction, &init.expr, node.let_token.span.start().line);
            }
            if derived {
                let mut names = HashSet::new();
                pattern_bindings(&node.pat, &mut names);
                self.caller.extend(names);
            } else if self.relation_lookup(&init.expr) {
                let mut names = HashSet::new();
                pattern_bindings(&node.pat, &mut names);
                if let Some((_, diverge)) = &init.diverge
                    && super::caller_use::rejects_in(diverge)
                {
                    self.push(AuthEvidenceKind::OwnershipCheck, &init.expr, node.let_token.span.start().line);
                }
                self.relation.extend(names);
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        let rejects = super::caller_use::rejects_in_block(&node.then_branch)
            || node
                .else_branch
                .as_ref()
                .is_some_and(|(_, otherwise)| super::caller_use::rejects_in(otherwise));
        if rejects && let Some(kind) = self.classify(&node.cond) {
            self.push(kind, &node.cond, node.if_token.span.start().line);
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast ExprMatch) {
        if self.derives(&node.expr)
            && node.arms.iter().any(|arm| super::caller_use::rejects_in(&arm.body))
        {
            let presence = node.arms.iter().all(|arm| match &arm.pat {
                Pat::TupleStruct(tuple) => tuple
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| ["Some", "Ok", "Err"].contains(&segment.ident.to_string().as_str())),
                Pat::Ident(ident) => ident.ident == "None",
                Pat::Path(path) => path.path.is_ident("None"),
                Pat::Wild(_) => true,
                _ => false,
            });
            let what = if presence { "a caller value is present" } else { "a caller attribute allows it" };
            self.push_described(AuthEvidenceKind::IdentityExtraction, what, &node.expr, node.match_token.span.start().line);
        }
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
}

/// Mechanism of a secret check (see `secret_checks`).
pub(crate) const SECRET_CHECK: &str = "rejects the request unless a presented secret matches";

/// Library calls that compare secrets or verify a password against a
/// stored hash: their meaning is fixed by the library, not by the app.
pub(crate) const SECRET_COMPARISONS: [&str; 9] = [
    "ct_eq",
    "constant_time_eq",
    "constant_time_compare",
    "secure_compare",
    "verify_slices_are_equal",
    "verify_password",
    "verify_encoded",
    "verify_hmac",
    "verify_signature",
];

/// Words that name a secret value in a field or binding.
pub(crate) const SECRET_WORDS: [&str; 10] = [
    "secret", "token", "signature", "password", "hash", "digest", "apikey", "otp", "nonce", "passcode",
];

/// Secret checks a function makes: a branch that rejects the request
/// (`Err(..)`, a 401/403 response, `bail!`) on a library comparison of
/// secrets (`ct_eq`, `verify_password`), or on an equality between two
/// non-constant values one of which is named as a secret
/// (`stored.client_secret != presented`; reported as name-based). These
/// need no caller: a secret is how a request without an account proves
/// access to one object (an invitation link, a payment's client secret).
fn secret_checks(file: &Path, handler: &str, block: &Block) -> Vec<AuthEvidence> {
    struct Secrets<'f> {
        file: &'f Path,
        handler: &'f str,
        evidence: Vec<AuthEvidence>,
    }
    fn last_name(expr: &Expr) -> Option<String> {
        match strip_conversions(expr) {
            Expr::Field(field) => match &field.member {
                Member::Named(name) => Some(name.to_string()),
                Member::Unnamed(_) => None,
            },
            Expr::MethodCall(call) if call.args.is_empty() => Some(call.method.to_string()),
            Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
            _ => None,
        }
    }
    fn names_secret(expr: &Expr) -> bool {
        last_name(expr).is_some_and(|name| {
            let flat = name.to_ascii_lowercase().replace('_', "");
            SECRET_WORDS.iter().any(|word| flat.contains(word))
        })
    }
    fn constant(expr: &Expr) -> bool {
        match strip_conversions(expr) {
            Expr::Lit(_) => true,
            Expr::Path(path) => path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident.to_string().chars().all(|c| c.is_uppercase() || c == '_' || c.is_ascii_digit())),
            _ => false,
        }
    }
    /// How the condition compares a secret, if it does: `Some(true)` when
    /// only the names say so.
    fn compares(expr: &Expr) -> Option<bool> {
        match expr {
            Expr::Paren(inner) => compares(&inner.expr),
            Expr::Group(inner) => compares(&inner.expr),
            Expr::Unary(unary) => compares(&unary.expr),
            Expr::Try(inner) => compares(&inner.expr),
            Expr::Await(inner) => compares(&inner.base),
            Expr::Binary(binary) => match binary.op {
                BinOp::And(_) | BinOp::Or(_) => match (compares(&binary.left), compares(&binary.right)) {
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    (left, right) => left.or(right),
                },
                BinOp::Eq(_) | BinOp::Ne(_) => (!constant(&binary.left)
                    && !constant(&binary.right)
                    && (names_secret(&binary.left) || names_secret(&binary.right)))
                .then_some(true),
                _ => None,
            },
            Expr::Call(call) => {
                let named = matches!(&*call.func, Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment| SECRET_COMPARISONS.contains(&segment.ident.to_string().as_str())));
                if named {
                    Some(false)
                } else {
                    call.args.iter().find_map(compares)
                }
            }
            Expr::MethodCall(call) => {
                if SECRET_COMPARISONS.contains(&call.method.to_string().as_str()) {
                    Some(false)
                } else {
                    compares(&call.receiver)
                }
            }
            _ => None,
        }
    }
    /// `pairings.get(&body.pair_token)`: a lookup keyed by a value named as
    /// a secret, through `.await`, `?` and adapters. A miss that rejects
    /// the request is a secret check: the presented value must match one
    /// stored.
    fn secret_lookup(expr: &Expr) -> bool {
        if !super::public::rule_on("S1") {
            return false;
        }
        match expr {
            Expr::Paren(inner) => secret_lookup(&inner.expr),
            Expr::Group(inner) => secret_lookup(&inner.expr),
            Expr::Try(inner) => secret_lookup(&inner.expr),
            Expr::Await(inner) => secret_lookup(&inner.base),
            Expr::Call(call) => call.args.iter().any(names_secret),
            Expr::MethodCall(call) => call.args.iter().any(names_secret) || secret_lookup(&call.receiver),
            _ => false,
        }
    }
    /// A match arm taken on a miss: `None`, `Err(..)` or `_`.
    fn on_miss(pattern: &Pat) -> bool {
        match pattern {
            Pat::Ident(ident) => ident.ident == "None",
            Pat::Path(path) => path.path.is_ident("None"),
            Pat::TupleStruct(tuple) => tuple.path.segments.last().is_some_and(|segment| segment.ident == "Err"),
            Pat::Wild(_) => true,
            _ => false,
        }
    }
    impl Secrets<'_> {
        fn push(&mut self, condition: &Expr, by_name: bool, line: usize) {
            if self.evidence.iter().any(|existing| existing.line == line) {
                return;
            }
            let mut written = condition.to_token_stream().to_string();
            if written.len() > 60 {
                written.truncate(written.floor_char_boundary(57));
                written.push_str("...");
            }
            let flag = if by_name { " (name-based)" } else { "" };
            self.evidence.push(AuthEvidence {
                kind: AuthEvidenceKind::SecretCheck,
                mechanism: format!("{SECRET_CHECK} (`{written}`){flag}"),
                symbol: Some(written),
                file: self.file.to_path_buf(),
                line,
                handler: Some(self.handler.to_owned()),
                strength: AuthStrength::Medium,
                requirements: Vec::new(),
                name_based: by_name,
            });
        }
    }
    impl<'ast> Visit<'ast> for Secrets<'_> {
        fn visit_expr_if(&mut self, node: &'ast ExprIf) {
            let rejects = super::caller_use::rejects_in_block(&node.then_branch)
                || node
                    .else_branch
                    .as_ref()
                    .is_some_and(|(_, otherwise)| super::caller_use::rejects_in(otherwise));
            if rejects && let Some(by_name) = compares(&node.cond) {
                self.push(&node.cond, by_name, node.if_token.span.start().line);
            }
            // `if let Some(relay) = pairings.get(&body.pair_token) { .. } else { return Err(..) }`
            if let Expr::Let(binding) = &*node.cond
                && secret_lookup(&binding.expr)
                && node
                    .else_branch
                    .as_ref()
                    .is_some_and(|(_, otherwise)| super::caller_use::rejects_in(otherwise))
            {
                self.push(&binding.expr, true, node.if_token.span.start().line);
            }
            visit::visit_expr_if(self, node);
        }
        // `match pairings.get(&body.pair_token) { Some(..) => .., None => Err(..) }`
        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            if secret_lookup(&node.expr)
                && node
                    .arms
                    .iter()
                    .any(|arm| on_miss(&arm.pat) && super::caller_use::rejects_in(&arm.body))
            {
                self.push(&node.expr, true, node.match_token.span.start().line);
            }
            visit::visit_expr_match(self, node);
        }
        // `let Some(relay) = pairings.get(&body.pair_token) else { return Err(..) };`
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let Some(init) = &node.init
                && let Some((_, diverge)) = &init.diverge
                && secret_lookup(&init.expr)
                && super::caller_use::rejects_in(diverge)
            {
                self.push(&init.expr, true, node.let_token.span.start().line);
            }
            visit::visit_local(self, node);
        }
        // `verify_password(&given, &stored.hash)?;`
        fn visit_expr_try(&mut self, node: &'ast ExprTry) {
            if compares(&node.expr) == Some(false) {
                self.push(&node.expr, false, node.question_token.span.start().line);
            }
            visit::visit_expr_try(self, node);
        }
        fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
        fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
    }
    let mut visitor = Secrets {
        file,
        handler,
        evidence: Vec::new(),
    };
    visitor.visit_block(block);
    visitor.evidence
}
