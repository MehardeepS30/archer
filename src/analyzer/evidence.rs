//! Authorization evidence inside handler bodies and in guard/middleware names.

use quote::ToTokens;
#[cfg(test)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use syn::{
    BinOp, Expr, ExprAssign, ExprBinary, ExprCall, ExprField, ExprMethodCall, ExprPath, FnArg,
    GenericArgument, ImplItemFn, ItemFn, Member, PathArguments, Token, TraitItemFn, Type, UnOp,
    punctuated::Punctuated,
    spanned::Spanned,
    visit::{self, Visit},
};

use super::model::*;

pub(crate) fn handler_evidence(file: &Path, item: &ItemFn) -> Vec<AuthEvidence> {
    let handler = item.sig.ident.to_string();
    let mut evidence: Vec<AuthEvidence> = item
        .attrs
        .iter()
        .filter_map(|attribute| attribute_evidence(attribute, file, &handler))
        .collect();
    for input in &item.sig.inputs {
        if let FnArg::Typed(argument) = input {
            extractor_evidence(&argument.ty, file, &handler, &mut evidence);
        }
    }
    let mut visitor = AuthEvidenceVisitor::new(file, &handler);
    visitor.visit_block(&item.block);
    evidence.extend(visitor.evidence);
    evidence
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
    Some(AuthEvidence {
        kind,
        mechanism: name,
        symbol: Some(attribute.meta.to_token_stream().to_string()),
        file: file.to_path_buf(),
        line: attribute.span().start().line,
        handler: Some(handler.into()),
        strength,
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
const EXTRACTOR_EXCLUDED_WORDS: [&str; 16] = [
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
];

/// Records handler arguments whose type is an authorization extractor
/// (`AdminUser`, `RequireRole<Admin>`) or an authentication-only extractor
/// (`BearerAuth`). An extractor that implements `FromRequest` rejects the
/// request before the handler runs, so its type is the evidence. This is a
/// naming heuristic: the extractor's implementation is not inspected.
fn extractor_evidence(ty: &Type, file: &Path, handler: &str, evidence: &mut Vec<AuthEvidence>) {
    match ty {
        Type::Path(path) if path.qself.is_none() => {
            let Some(segment) = path.path.segments.last() else {
                return;
            };
            let name = segment.ident.to_string();
            if DATA_EXTRACTORS.contains(&name.as_str()) {
                return;
            }
            if let Some((kind, strength)) = classify_extractor_name(&name) {
                evidence.push(AuthEvidence {
                    kind,
                    mechanism: name,
                    symbol: Some(ty.to_token_stream().to_string().replace(' ', "")),
                    file: file.to_path_buf(),
                    line: ty.span().start().line,
                    handler: Some(handler.into()),
                    strength,
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
    {
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

pub(crate) struct AuthEvidenceVisitor {
    pub(crate) file: PathBuf,
    pub(crate) handler: String,
    pub(crate) evidence: Vec<AuthEvidence>,
}

impl AuthEvidenceVisitor {
    pub(crate) fn new(file: &Path, handler: &str) -> Self {
        Self {
            file: file.to_path_buf(),
            handler: handler.into(),
            evidence: Vec::new(),
        }
    }
}

impl<'ast> Visit<'ast> for AuthEvidenceVisitor {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let symbol = node.func.to_token_stream().to_string().replace(' ', "");
        let line = node.func.span().start().line;
        let evidence = evidence_for_handler_call(&symbol, line, &self.file, &self.handler)
            .or_else(|| evidence_for_handler_symbol(&symbol, line, &self.file, &self.handler));
        if let Some(evidence) = evidence {
            self.evidence.push(evidence);
        }
        for argument in &node.args {
            self.visit_expr(argument);
        }
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
            self.evidence.push(evidence);
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        let symbol = node.path.to_token_stream().to_string().replace(' ', "");
        if let Some(evidence) = evidence_for_handler_symbol(
            &symbol,
            node.span().start().line,
            &self.file,
            &self.handler,
        ) {
            self.evidence.push(evidence);
        }
        visit::visit_expr_path(self, node);
    }

    // Expression and statement macros both reach this hook once. Only the
    // macro's own name is classified, with the helper-name rules; its tokens
    // are opaque, so calls written inside a macro (`assert!(is_admin(&user))`)
    // are not evidence.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // `matches!(user.role, Role::Admin | Role::Owner)`: the pattern is
        // read as an expression, which a path or `|` of paths parses as.
        if node.path.is_ident("matches")
            && let Ok(arguments) =
                node.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
        {
            self.record_comparison(arguments.iter());
        }
        let Some(name) = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            return;
        };
        let Some((kind, strength)) = classify_check_name(&name) else {
            return;
        };
        let symbol = node.path.to_token_stream().to_string().replace(' ', "");
        self.evidence.push(AuthEvidence {
            kind,
            mechanism: name,
            symbol: Some(format!("{symbol}!")),
            file: self.file.clone(),
            line: node.path.span().start().line,
            handler: Some(self.handler.clone()),
            strength,
        });
    }

    /// `user.role != Role::Admin`, `claims.permission == Permission::Write`.
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if matches!(node.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            self.record_comparison([&*node.left, &*node.right]);
        }
        visit::visit_expr_binary(self, node);
    }

    /// A boolean flag such as `claims.is_admin`, read like a call to the
    /// helper `is_admin`.
    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        if let Member::Named(member) = &node.member
            && let Some((kind, _)) = classify_check_name(&member.to_string())
        {
            self.evidence.push(AuthEvidence {
                kind,
                mechanism: member.to_string(),
                symbol: Some(node.to_token_stream().to_string().replace(' ', "")),
                file: self.file.clone(),
                line: member.span().start().line,
                handler: Some(self.handler.clone()),
                strength: AuthStrength::Medium,
            });
        }
        visit::visit_expr_field(self, node);
    }

    /// Assigning a flag (`user.is_admin = true`) does not check it.
    fn visit_expr_assign(&mut self, node: &'ast ExprAssign) {
        self.visit_expr(&node.right);
    }

    // Functions declared inside the handler body, including methods of nested
    // `impl` and `trait` items, do not run as part of that body. Their
    // evidence belongs to them, not to the enclosing handler.
    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}

    fn visit_impl_item_fn(&mut self, _: &'ast ImplItemFn) {}

    fn visit_trait_item_fn(&mut self, _: &'ast TraitItemFn) {}
}

impl AuthEvidenceVisitor {
    /// Records the first operand of a comparison that is a role or
    /// permission: comparing one is a check, whatever the other side is.
    fn record_comparison<'e>(&mut self, operands: impl IntoIterator<Item = &'e Expr>) {
        let Some((kind, operand)) = operands
            .into_iter()
            .find_map(|operand| authorization_operand(operand).map(|kind| (kind, operand)))
        else {
            return;
        };
        let written = operand.to_token_stream().to_string().replace(' ', "");
        self.evidence.push(AuthEvidence {
            kind,
            mechanism: written.clone(),
            symbol: Some(written),
            file: self.file.clone(),
            line: operand.span().start().line,
            handler: Some(self.handler.clone()),
            strength: AuthStrength::Medium,
        });
    }
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
    let uses_check_prefix = ["require_", "check_", "verify_", "assert_", "ensure_"]
        .iter()
        .any(|prefix| lower.starts_with(prefix));

    let classification = if is_one_of(&[
        "require_auth",
        "is_authenticated",
        "require_authenticated_user",
        "current_user",
        "authenticated_user",
    ]) {
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
    } else if is_one_of(&["owns", "is_owner", "is_owned_by"])
        || (uses_check_prefix && has_token(&["owner", "ownership"]))
    {
        (AuthEvidenceKind::OwnershipCheck, AuthStrength::Medium)
    } else {
        return None;
    };
    Some(classification)
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
pub(crate) const CONFIGURATION_AUTHORIZATION_WORDS: [&str; 12] = [
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
