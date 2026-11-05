//! What an application's own extractors check, read from their
//! `impl FromRequest` bodies instead of guessed from their names.
//!
//! ```rust,ignore
//! impl FromRequest for OwnerOnly {
//!     fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
//!         match req.extensions().get::<OrganizationRole>() {
//!             Some(OrganizationRole { user, role: UserRole::Owner }) => ready(Ok(Self(user.clone()))),
//!             None => ready(Err(ServiceError::Unauthorized)),
//!             _ => ready(Err(ServiceError::Forbidden)),
//!         }
//!     }
//! }
//! ```
//!
//! An extractor whose `from_request` can fail rejects the request before
//! the handler runs. It checks a privilege when the decision depends on
//! more than the caller's presence: it admits only some variants of a
//! role-like enum (`UserRole::Owner`), it fails with a "forbidden" error,
//! or it branches on a role-like field or call (`if !user.is_admin`).
//! Otherwise it only identifies the caller. Extractors that never fail are
//! not protection, and are left to the name heuristic.

use std::{cell::RefCell, collections::HashMap};
use syn::{
    Expr, ImplItem, Item, Pat,
    visit::{self, Visit},
};

use super::{evidence::camel_case_words, model::AuthEvidenceKind};

/// What an extractor's `from_request` was found to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Learned {
    pub(crate) kind: AuthEvidenceKind,
    /// Admitted role variants (`owner`), or role-like names it branches on.
    pub(crate) requirements: Vec<String>,
}

thread_local! {
    /// By type name. `None`: several impls of that name disagree.
    static LEARNED: RefCell<HashMap<String, Option<Learned>>> = RefCell::new(HashMap::new());
}

/// Words that make an enum, field, or call about privilege.
const PRIVILEGE_WORDS: [&str; 14] = [
    "role",
    "roles",
    "permission",
    "permissions",
    "perm",
    "perms",
    "scope",
    "scopes",
    "admin",
    "owner",
    "privilege",
    "privileges",
    "rank",
    "superuser",
];

/// Error names that refuse an identified caller.
const FORBIDDING_WORDS: [&str; 4] = ["forbidden", "denied", "insufficient", "unprivileged"];

pub(crate) fn index_extractors<'a>(files: impl IntoIterator<Item = &'a syn::File>) {
    let mut learned: HashMap<String, Option<Learned>> = HashMap::new();
    for file in files {
        collect(&file.items, &mut learned);
    }
    LEARNED.with(|map| *map.borrow_mut() = learned);
}

/// The learned classification of an extractor type, by its name.
pub(crate) fn learned(name: &str) -> Option<Learned> {
    LEARNED.with(|map| map.borrow().get(name).cloned().flatten())
}

fn collect(items: &[Item], learned: &mut HashMap<String, Option<Learned>>) {
    for item in items {
        match item {
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect(items, learned);
                }
            }
            Item::Impl(implementation) => {
                let Some((trait_path, _)) = &implementation.trait_ else {
                    continue;
                };
                if trait_path
                    .segments
                    .last()
                    .is_none_or(|segment| segment.ident != "FromRequest")
                {
                    continue;
                }
                let syn::Type::Path(self_type) = &*implementation.self_ty else {
                    continue;
                };
                let Some(name) = self_type.path.segments.last().map(|s| s.ident.to_string()) else {
                    continue;
                };
                let Some(body) = implementation.items.iter().find_map(|item| match item {
                    ImplItem::Fn(function) if function.sig.ident == "from_request" => {
                        Some(&function.block)
                    }
                    _ => None,
                }) else {
                    continue;
                };
                let Some(found) = classify(body) else {
                    continue;
                };
                match learned.get(&name) {
                    None => {
                        learned.insert(name, Some(found));
                    }
                    Some(Some(previous)) if *previous != found => {
                        learned.insert(name, None);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

fn privileged(name: &str) -> bool {
    camel_case_words(name)
        .iter()
        .chain(
            name.split('_')
                .map(|word| word.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .iter(),
        )
        .any(|word| PRIVILEGE_WORDS.contains(&word.as_str()))
}

fn unauthenticated(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("unauthori") || lower.contains("unauthenticated")
}

fn forbidding(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    FORBIDDING_WORDS.iter().any(|word| lower.contains(word))
}

fn classify(body: &syn::Block) -> Option<Learned> {
    let mut visitor = BodyVisitor::default();
    visitor.visit_block(body);
    if !visitor.rejects {
        return None;
    }
    let mut requirements = visitor.variants;
    requirements.sort();
    requirements.dedup();
    // A forbidding error counts only beside an unauthenticated one: some
    // apps answer a missing login with 403 too.
    let refuses_identified = visitor.forbids && visitor.unauthorized;
    if !requirements.is_empty() || refuses_identified || !visitor.conditions.is_empty() {
        if requirements.is_empty() {
            requirements = visitor.conditions;
            requirements.sort();
            requirements.dedup();
        }
        return Some(Learned {
            kind: AuthEvidenceKind::RoleCheck,
            requirements,
        });
    }
    // Failing alone is not about the caller: an extractor that loads the
    // current organization fails too. It identifies the caller when it
    // reads a user, session, token, or credential.
    if !visitor.caller {
        return None;
    }
    Some(Learned {
        kind: AuthEvidenceKind::IdentityExtraction,
        requirements: Vec::new(),
    })
}

/// Words that name the caller or a credential.
const CALLER_WORDS: [&str; 18] = [
    "user",
    "session",
    "token",
    "auth",
    "authorization",
    "authenticated",
    "claims",
    "principal",
    "identity",
    "account",
    "bearer",
    "credential",
    "credentials",
    "login",
    "jwt",
    "apikey",
    "key",
    "caller",
];

pub(crate) fn names_caller(name: &str) -> bool {
    camel_case_words(name)
        .iter()
        .chain(
            name.split('_')
                .map(|word| word.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .iter(),
        )
        .any(|word| CALLER_WORDS.contains(&word.as_str()))
}

#[derive(Default)]
struct BodyVisitor {
    /// It can fail: `Err(..)`, `ok_or`, `?`, `err(..)`.
    rejects: bool,
    /// It names a forbidding error (`ServiceError::Forbidden`).
    forbids: bool,
    /// It names an unauthenticated error (`ServiceError::Unauthorized`).
    unauthorized: bool,
    /// It names the caller or a credential (`get::<LoggedUser>()`, `token`).
    caller: bool,
    /// Role-like enum variants it admits or compares with, lowercased.
    variants: Vec<String>,
    /// Role-like fields or calls in a branch condition (`is_admin`).
    conditions: Vec<String>,
}

impl BodyVisitor {
    /// `UserRole::Owner`: a two-segment path naming a variant of a
    /// role-like type.
    fn variant(&mut self, path: &syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if let [.., ty, variant] = segments.as_slice()
            && ty.starts_with(|c: char| c.is_ascii_uppercase())
            && variant.starts_with(|c: char| c.is_ascii_uppercase())
            && privileged(ty)
        {
            self.variants.push(variant.to_ascii_lowercase());
        }
    }

    fn condition(&mut self, expr: &Expr) {
        let mut names = ConditionNames::default();
        names.visit_expr(expr);
        for name in names.names {
            if privileged(&name) {
                self.conditions.push(name.to_ascii_lowercase());
            }
        }
        // `if role == UserRole::Admin`, `matches!(role, UserRole::Admin)`.
        let mut variants = VariantPaths::default();
        variants.visit_expr(expr);
        for path in variants.paths {
            self.variant(&path);
        }
    }
}

impl<'ast> Visit<'ast> for BodyVisitor {
    fn visit_ident(&mut self, node: &'ast proc_macro2::Ident) {
        let name = node.to_string();
        if names_caller(&name) || unauthenticated(&name) {
            self.caller = true;
        }
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        if names_caller(&node.value()) {
            self.caller = true;
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func
            && let Some(last) = path.path.segments.last()
        {
            let name = last.ident.to_string();
            if name == "Err" || name == "err" || name.starts_with("Error") {
                self.rejects = true;
            }
            if forbidding(&name) {
                self.forbids = true;
            }
            if unauthenticated(&name) {
                self.unauthorized = true;
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if name == "ok_or" || name == "ok_or_else" || name == "map_err" {
            self.rejects = true;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.rejects = true;
        visit::visit_expr_try(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        for segment in &node.path.segments {
            let name = segment.ident.to_string();
            if forbidding(&name) {
                self.forbids = true;
            }
            if unauthenticated(&name) {
                self.unauthorized = true;
            }
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.condition(&node.cond);
        visit::visit_expr_if(self, node);
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        // Variants in an arm that admits the caller: `Some(OrganizationRole
        // { role: UserRole::Owner, .. }) => Ok(..)`.
        let mut admits = Admits::default();
        admits.visit_expr(&node.body);
        if admits.ok {
            let mut variants = VariantPaths::default();
            variants.visit_pat(&node.pat);
            for path in variants.paths {
                self.variant(&path);
            }
        }
        visit::visit_arm(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            let mut variants = VariantPaths::default();
            variants.visit_expr_binary(node);
            for path in variants.paths {
                self.variant(&path);
            }
        }
        visit::visit_expr_binary(self, node);
    }
}

/// Field and method names in an expression.
#[derive(Default)]
struct ConditionNames {
    names: Vec<String>,
}

impl<'ast> Visit<'ast> for ConditionNames {
    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &node.member {
            self.names.push(name.to_string());
        }
        visit::visit_expr_field(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.names.push(node.method.to_string());
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func
            && let Some(last) = path.path.segments.last()
        {
            self.names.push(last.ident.to_string());
        }
        visit::visit_expr_call(self, node);
    }
}

/// Paths of two or more segments, in expressions and patterns.
#[derive(Default)]
struct VariantPaths {
    paths: Vec<syn::Path>,
}

impl<'ast> Visit<'ast> for VariantPaths {
    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node.segments.len() >= 2 {
            self.paths.push(node.clone());
        }
        visit::visit_path(self, node);
    }

    fn visit_pat(&mut self, node: &'ast Pat) {
        visit::visit_pat(self, node);
    }
}

/// Whether an arm's body succeeds: it builds `Ok(..)` and no `Err(..)`.
#[derive(Default)]
struct Admits {
    ok: bool,
    err: bool,
}

impl<'ast> Visit<'ast> for Admits {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func
            && let Some(last) = path.path.segments.last()
        {
            if last.ident == "Ok" {
                self.ok = !self.err;
            } else if last.ident == "Err" || last.ident == "err" {
                self.err = true;
                self.ok = false;
            }
        }
        visit::visit_expr_call(self, node);
    }
}
