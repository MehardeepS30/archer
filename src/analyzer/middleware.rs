//! Middleware written in the scanned crate, evaluated rather than trusted by
//! name.
//!
//! A `.wrap(AuthService)` whose `Service::call` only checks the caller when
//! `req.path()` matches some pattern protects whichever routes match at
//! runtime, which static analysis cannot settle. Such a component is recorded
//! here so the routes it wraps are reported as unverified instead of
//! authenticated.

use std::{cell::RefCell, collections::HashSet};
use syn::{
    Block, Expr, FnArg, ImplItem, Item, ItemImpl, Type,
    visit::{self, Visit},
};

/// Request accessors whose value names the requested route.
const PATH_ACCESSORS: [&str; 6] = [
    "path",
    "uri",
    "match_info",
    "match_pattern",
    "match_name",
    "full_url",
];

thread_local! {
    /// Components of the crate under analysis whose checks depend on the
    /// request path. Set once per analysis, before routes are extracted, on
    /// the analysis thread.
    static PATH_CONDITIONAL: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
    /// Request-taking helpers that read the path, for `wrap_fn` closures.
    static PATH_READERS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
    /// String constants and string-list constants of the crate
    /// (`const IGNORE_ROUTES: [&str; 3] = [..]`, `const LOGIN: &str = ".."`),
    /// by name, so a path rule naming one in another module is read. A name
    /// defined twice with different values maps to `None`.
    static STRING_CONSTS: RefCell<std::collections::HashMap<String, Option<Vec<String>>>> =
        RefCell::new(std::collections::HashMap::new());
}

fn collect_string_consts(items: &[Item], consts: &mut std::collections::HashMap<String, Option<Vec<String>>>) {
    for item in items {
        let (name, expr) = match item {
            Item::Const(item) => (item.ident.to_string(), &*item.expr),
            Item::Static(item) => (item.ident.to_string(), &*item.expr),
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_string_consts(items, consts);
                }
                continue;
            }
            _ => continue,
        };
        let Some(values) = string_literal(expr).map(|value| vec![value]).or_else(|| string_list(expr)) else {
            continue;
        };
        consts
            .entry(name)
            .and_modify(|existing| {
                if existing.as_ref() != Some(&values) {
                    *existing = None;
                }
            })
            .or_insert(Some(values));
    }
}

/// The values of a string or string-list constant named by `path`.
fn const_values(path: &syn::Path) -> Option<Vec<String>> {
    let name = path.segments.last()?.ident.to_string();
    STRING_CONSTS.with(|consts| consts.borrow().get(&name).cloned().flatten())
}

/// Records the path-conditional components of the files about to be analyzed.
pub(crate) fn index_path_conditional<'a>(files: impl IntoIterator<Item = &'a syn::File>) {
    let files: Vec<&syn::File> = files.into_iter().collect();
    let mut consts = std::collections::HashMap::new();
    for file in &files {
        collect_string_consts(&file.items, &mut consts);
    }
    STRING_CONSTS.with(|set| *set.borrow_mut() = consts);
    // Helpers that read the request path (`fn should_skip_auth(req:
    // &ServiceRequest) -> bool`): a condition calling one branches on it.
    let mut readers: HashSet<String> = HashSet::new();
    for file in &files {
        collect_readers(&file.items, &mut readers);
    }
    PATH_RULES.with(|rules| rules.borrow_mut().clear());
    PRIVILEGED.with(|set| set.borrow_mut().clear());
    PATH_READERS.with(|set| *set.borrow_mut() = readers.clone());
    let mut transforms: Vec<(String, String)> = Vec::new();
    let mut conditional: HashSet<String> = HashSet::new();
    for file in &files {
        collect(&file.items, &readers, &mut transforms, &mut conditional);
    }
    // `impl Transform for AuthService { type Transform = AuthMiddleware<S>; }`
    // makes `AuthService` as conditional as the service it builds.
    let mut changed = true;
    while changed {
        changed = false;
        for (factory, service) in &transforms {
            if conditional.contains(service) && conditional.insert(factory.clone()) {
                if let Some(rule) = path_rule_of(service) {
                    PATH_RULES.with(|rules| rules.borrow_mut().insert(factory.clone(), Some(rule)));
                }
                if rule_checks_privilege(service) {
                    PRIVILEGED.with(|set| set.borrow_mut().insert(factory.clone()));
                }
                changed = true;
            }
        }
    }
    PATH_CONDITIONAL.with(|set| *set.borrow_mut() = conditional);
    PATH_READERS.with(|set| *set.borrow_mut() = readers);
}

/// The first component named in a `.wrap(..)` argument whose checks depend
/// on the request path: a crate-defined middleware type or function, or a
/// `wrap_fn` closure that branches on the path itself.
pub(crate) fn path_conditional_component(arg: &Expr) -> Option<String> {
    struct Names<'a> {
        set: &'a HashSet<String>,
        found: Option<String>,
    }
    impl<'ast> Visit<'ast> for Names<'_> {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            if self.found.is_none() {
                if let Some(last) = path.segments.last() {
                    let name = last.ident.to_string();
                    if self.set.contains(&name) {
                        self.found = Some(name);
                    }
                }
            }
            visit::visit_path(self, path);
        }
        fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
            if self.found.is_none() && decides_by_path_expr(&closure.body) {
                self.found = Some("<closure>".into());
            }
            visit::visit_expr_closure(self, closure);
        }
    }
    PATH_CONDITIONAL.with(|set| {
        let set = set.borrow();
        let mut names = Names { set: &set, found: None };
        names.visit_expr(arg);
        names.found
    })
}

/// Functions that take the request and read its path anywhere in their body.
fn collect_readers(items: &[Item], readers: &mut HashSet<String>) {
    let reads = |signature: &syn::Signature, block: &Block| {
        takes_request(signature) && {
            let branches = PathBranches::default();
            let mut found = false;
            struct Any<'a>(&'a PathBranches, &'a mut bool);
            impl<'ast> Visit<'ast> for Any<'_> {
                fn visit_expr(&mut self, expr: &'ast Expr) {
                    if self.0.reads_path(expr) {
                        *self.1 = true;
                    }
                }
            }
            Any(&branches, &mut found).visit_block(block);
            found
        }
    };
    for item in items {
        match item {
            Item::Fn(function) if reads(&function.sig, &function.block) => {
                readers.insert(function.sig.ident.to_string());
            }
            Item::Impl(item) => {
                for member in &item.items {
                    if let ImplItem::Fn(function) = member
                        && reads(&function.sig, &function.block)
                    {
                        readers.insert(function.sig.ident.to_string());
                    }
                }
            }
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_readers(items, readers);
                }
            }
            _ => {}
        }
    }
}

fn collect(
    items: &[Item],
    readers: &HashSet<String>,
    transforms: &mut Vec<(String, String)>,
    conditional: &mut HashSet<String>,
) {
    for item in items {
        match item {
            Item::Impl(item) => collect_impl(item, readers, transforms, conditional),
            Item::Fn(function) => {
                // `from_fn(check)` / `HttpAuthentication::bearer(validator)`:
                // a free function that receives the request.
                if takes_service_request(&function.sig) && decides_by_path(&function.block, readers) {
                    conditional.insert(function.sig.ident.to_string());
                    record_rule(&function.sig.ident.to_string(), &function.block);
                }
            }
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect(items, readers, transforms, conditional);
                }
            }
            _ => {}
        }
    }
}

fn collect_impl(
    item: &ItemImpl,
    readers: &HashSet<String>,
    transforms: &mut Vec<(String, String)>,
    conditional: &mut HashSet<String>,
) {
    let Some((trait_path, _)) = &item.trait_ else {
        return;
    };
    let Some(trait_name) = trait_path.segments.last().map(|segment| segment.ident.to_string()) else {
        return;
    };
    let Some(self_name) = type_name(&item.self_ty) else {
        return;
    };
    match trait_name.as_str() {
        "Transform" => {
            for member in &item.items {
                if let ImplItem::Type(alias) = member {
                    if alias.ident == "Transform" {
                        if let Some(service) = type_name(&alias.ty) {
                            transforms.push((self_name.clone(), service));
                        }
                    }
                }
            }
        }
        "Service" => {
            for member in &item.items {
                if let ImplItem::Fn(function) = member {
                    if function.sig.ident == "call" && decides_by_path(&function.block, readers) {
                        conditional.insert(self_name.clone());
                        record_rule(&self_name, &function.block);
                    }
                }
            }
        }
        _ => {}
    }
}

fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) => path.path.segments.last().map(|segment| segment.ident.to_string()),
        Type::Reference(reference) => type_name(&reference.elem),
        Type::Paren(paren) => type_name(&paren.elem),
        _ => None,
    }
}

fn takes_request(signature: &syn::Signature) -> bool {
    signature.inputs.iter().any(|input| match input {
        FnArg::Typed(typed) => type_name(&typed.ty)
            .is_some_and(|name| name == "ServiceRequest" || name == "HttpRequest"),
        FnArg::Receiver(_) => false,
    })
}

fn takes_service_request(signature: &syn::Signature) -> bool {
    signature.inputs.iter().any(|input| match input {
        FnArg::Typed(typed) => type_name(&typed.ty).is_some_and(|name| name == "ServiceRequest"),
        FnArg::Receiver(_) => false,
    })
}

/// Whether a body branches on the request path: an `if`, `match`, or match
/// guard whose condition reads `req.path()` or similar, directly or through
/// a binding initialized from it.
fn decides_by_path(block: &Block, readers: &HashSet<String>) -> bool {
    let mut visitor = PathBranches { readers: readers.clone(), ..PathBranches::default() };
    visitor.visit_block(block);
    visitor.found
}

fn decides_by_path_expr(expr: &Expr) -> bool {
    let readers = PATH_READERS.with(|set| set.borrow().clone());
    let mut visitor = PathBranches { readers, ..PathBranches::default() };
    visitor.visit_expr(expr);
    visitor.found
}

#[derive(Default)]
struct PathBranches {
    bindings: HashSet<String>,
    readers: HashSet<String>,
    found: bool,
}

impl PathBranches {
    fn reads_path(&self, expr: &Expr) -> bool {
        struct Reads<'a> {
            bindings: &'a HashSet<String>,
            readers: &'a HashSet<String>,
            found: bool,
        }
        impl<'ast> Visit<'ast> for Reads<'_> {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if PATH_ACCESSORS.iter().any(|name| call.method == name)
                    || self.readers.contains(&call.method.to_string())
                {
                    self.found = true;
                }
                visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let Expr::Path(path) = &*call.func
                    && path
                        .path
                        .segments
                        .last()
                        .is_some_and(|segment| self.readers.contains(&segment.ident.to_string()))
                {
                    self.found = true;
                }
                visit::visit_expr_call(self, call);
            }
            fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                if path
                    .path
                    .get_ident()
                    .is_some_and(|ident| self.bindings.contains(&ident.to_string()))
                {
                    self.found = true;
                }
            }
        }
        let mut reads = Reads { bindings: &self.bindings, readers: &self.readers, found: false };
        reads.visit_expr(expr);
        reads.found
    }
}

impl<'ast> Visit<'ast> for PathBranches {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init {
            if self.reads_path(&init.expr) {
                let mut names = HashSet::new();
                super::routes::pattern_bindings(&local.pat, &mut names);
                self.bindings.extend(names);
            }
        }
        visit::visit_local(self, local);
    }
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if self.reads_path(&node.cond) {
            self.found = true;
        }
        visit::visit_expr_if(self, node);
    }
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if self.reads_path(&node.expr) {
            self.found = true;
        }
        visit::visit_expr_match(self, node);
    }
    fn visit_pat_guard(&mut self, node: &'ast syn::PatGuard) {
        if self.reads_path(&node.guard) {
            self.found = true;
        }
        visit::visit_pat_guard(self, node);
    }
    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        if self.reads_path(&node.cond) {
            self.found = true;
        }
        visit::visit_expr_while(self, node);
    }
}

/// When a path-conditional component applies its check, as read from the
/// first branch in its body that tests the request path.
#[derive(Clone, Debug)]
pub(crate) enum PathRule {
    /// The check rejects when `condition` holds (`if !logged_in && path != "/login" { 401 }`).
    RejectsWhen(Cond),
    /// The check is skipped when `condition` holds (`if path == "/login" { return srv.call(req) }`).
    SkipsWhen(Cond),
}

/// A condition over the request path; anything else it tests is `Free`.
#[derive(Clone, Debug)]
pub(crate) enum Cond {
    Free,
    /// Reads the path in a way not modelled: the rule is undecided.
    Opaque,
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
    Equals(Vec<String>),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
}

/// What a route's path makes of a condition: always true, always false, or
/// still depending on something else (`Free`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Truth {
    True,
    False,
    Free,
    Undecided,
}

impl Cond {
    pub(crate) fn eval(&self, path: &str) -> Truth {
        // Path parameters stand for ids, not for the literal words a rule
        // tests: `/users/{id}` does not start with `/users/admin`.
        let concrete: String = {
            let mut out = String::new();
            let mut depth = 0;
            for character in path.chars() {
                match character {
                    '{' => {
                        depth += 1;
                        if depth == 1 {
                            out.push('\u{0}');
                        }
                    }
                    '}' => depth -= 1,
                    _ if depth > 0 => {}
                    _ => out.push(character),
                }
            }
            let trimmed = out.trim_end_matches('/');
            if trimmed.is_empty() { "/".to_owned() } else { trimmed.to_owned() }
        };
        let normalize = |value: &str| {
            let trimmed = value.trim_end_matches('/');
            if trimmed.is_empty() { "/".to_owned() } else { trimmed.to_owned() }
        };
        let truth = |value: bool| if value { Truth::True } else { Truth::False };
        match self {
            Cond::Free => Truth::Free,
            Cond::Opaque => Truth::Undecided,
            Cond::Equals(values) => truth(values.iter().any(|value| normalize(value) == concrete)),
            Cond::StartsWith(value) => truth(concrete.starts_with(value.as_str())),
            Cond::EndsWith(value) => truth(concrete.ends_with(value.trim_end_matches('/'))),
            Cond::Contains(value) => truth(concrete.contains(value.as_str())),
            Cond::Not(inner) => match inner.eval(path) {
                Truth::True => Truth::False,
                Truth::False => Truth::True,
                other => other,
            },
            Cond::And(parts) => {
                let values: Vec<Truth> = parts.iter().map(|part| part.eval(path)).collect();
                if values.contains(&Truth::False) {
                    Truth::False
                } else if values.contains(&Truth::Undecided) {
                    Truth::Undecided
                } else if values.contains(&Truth::Free) {
                    Truth::Free
                } else {
                    Truth::True
                }
            }
            Cond::Or(parts) => {
                let values: Vec<Truth> = parts.iter().map(|part| part.eval(path)).collect();
                if values.contains(&Truth::True) {
                    Truth::True
                } else if values.contains(&Truth::Undecided) {
                    Truth::Undecided
                } else if values.contains(&Truth::Free) {
                    Truth::Free
                } else {
                    Truth::False
                }
            }
        }
    }

    fn reads_path(&self) -> bool {
        match self {
            Cond::Free => false,
            Cond::And(parts) | Cond::Or(parts) => parts.iter().any(Cond::reads_path),
            Cond::Not(inner) => inner.reads_path(),
            _ => true,
        }
    }

    /// The literal paths or prefixes the condition names, for evidence text.
    pub(crate) fn literals(&self) -> Vec<String> {
        match self {
            Cond::Free | Cond::Opaque => Vec::new(),
            Cond::And(parts) | Cond::Or(parts) => parts.iter().flat_map(Cond::literals).collect(),
            Cond::Not(inner) => inner.literals(),
            Cond::Equals(values) => values.clone(),
            Cond::StartsWith(value) => vec![format!("{value}*")],
            Cond::EndsWith(value) => vec![format!("*{value}")],
            Cond::Contains(value) => vec![format!("*{value}*")],
        }
    }
}

/// Whether a component with `rule` checks the caller on `path`:
/// `Some(true)` protected, `Some(false)` exempt, `None` undecided.
pub(crate) fn protects(rule: &PathRule, path: &str) -> Option<bool> {
    match rule {
        PathRule::RejectsWhen(condition) => match condition.eval(path) {
            Truth::False => Some(false),
            Truth::Undecided => None,
            _ => Some(true),
        },
        PathRule::SkipsWhen(condition) => match condition.eval(path) {
            Truth::True => Some(false),
            Truth::Undecided => None,
            _ => Some(true),
        },
    }
}

thread_local! {
    /// The path rule of each path-conditional component, when one was read.
    static PATH_RULES: RefCell<std::collections::HashMap<String, Option<PathRule>>> =
        RefCell::new(std::collections::HashMap::new());
    static PRIVILEGED: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

pub(crate) fn path_rule_of(name: &str) -> Option<PathRule> {
    PATH_RULES.with(|rules| rules.borrow().get(name).cloned().flatten())
}

/// Whether a recorded component checks privileges (roles, permissions),
/// not only who the caller is.
pub(crate) fn rule_checks_privilege(name: &str) -> bool {
    PRIVILEGED.with(|set| set.borrow().contains(name))
}

fn record_rule(name: &str, block: &Block) {
    let text = quote::ToTokens::to_token_stream(block).to_string().to_lowercase();
    // A middleware that skips some paths and, on the rest, only loads the
    // caller (`req.extensions_mut().insert(principal)`) without ever
    // rejecting a request checks nothing: its path rule is not protection.
    let rejects = REJECT_WORDS.iter().any(|word| text.contains(word));
    let rule = read_rule(block).filter(|rule| match rule {
        PathRule::SkipsWhen(_) => rejects,
        PathRule::RejectsWhen(_) => true,
    });
    // A privilege check rejects with a forbidden status, or names a role
    // or permission next to a rejection.
    if text.contains("forbidden")
        || text.contains("403")
        || (rejects && ["has_role", "is_admin", "permission"].iter().any(|word| text.contains(word)))
    {
        PRIVILEGED.with(|set| set.borrow_mut().insert(name.to_owned()));
    }
    PATH_RULES.with(|rules| {
        rules
            .borrow_mut()
            .entry(name.to_owned())
            .and_modify(|entry| *entry = None)
            .or_insert(rule);
    });
}

const REJECT_WORDS: [&str; 6] = ["unauthorized", "forbidden", "unauthenticated", "denied", "reject", "401"];

/// Whether a branch rejects the request, or passes it on unchecked.
fn branch_kind(tokens: &str) -> Option<bool> {
    let lower = tokens.to_lowercase().replace(' ', "");
    if REJECT_WORDS.iter().any(|word| lower.contains(word))
        || lower.contains("status_code::forbidden")
        || lower.contains("err(")
    {
        return Some(true);
    }
    if lower.contains(".call(") {
        return Some(false);
    }
    None
}

/// The rule of the first `if`/`match` on the path in a middleware body.
fn read_rule(block: &Block) -> Option<PathRule> {
    struct First {
        bindings: std::collections::HashMap<String, Expr>,
        flags: HashSet<String>,
        rule: Option<Option<PathRule>>,
    }
    impl<'ast> Visit<'ast> for First {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if let (Some(init), Some(name)) = (&local.init, simple_name(&local.pat)) {
                self.bindings.insert(name, (*init.expr).clone());
            }
            visit::visit_local(self, local);
        }
        // `for route in constants::IGNORE_ROUTES.iter() { if path.starts_with(route) { .. } }`
        fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
            if let (Some(name), Some(values)) = (pattern_name(&node.pat), string_list(&node.expr)) {
                self.bindings.insert(name, list_expr(&values));
            }
            visit::visit_expr_for_loop(self, node);
        }
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if self.rule.is_some() {
                return;
            }
            let condition = cond_of(&node.cond, &self.bindings, 0);
            if condition.reads_path() {
                let then = quote::ToTokens::to_token_stream(&node.then_branch).to_string();
                let otherwise = node
                    .else_branch
                    .as_ref()
                    .map(|(_, branch)| quote::ToTokens::to_token_stream(branch).to_string());
                self.rule = Some(match (branch_kind(&then), otherwise.as_deref().and_then(branch_kind)) {
                    (Some(true), _) | (None, Some(false)) => Some(PathRule::RejectsWhen(condition)),
                    (Some(false), _) | (None, Some(true)) => Some(PathRule::SkipsWhen(condition)),
                    // `if path.contains("/admin") { <check> }`: the branch
                    // holds the check.
                    (None, None) if then.to_lowercase().contains("check") || then.contains('?') => {
                        Some(PathRule::RejectsWhen(Cond::And(vec![condition, Cond::Free])))
                    }
                    // `if path.starts_with(route) { passed = true; break; }`
                    // and later `if !passed { 401 }`: the path skips the check.
                    (None, None)
                        if assigned_true(&node.then_branch).iter().any(|name| self.flags.contains(name)) =>
                    {
                        Some(PathRule::SkipsWhen(condition))
                    }
                    _ => None,
                });
                return;
            }
            visit::visit_expr_if(self, node);
        }
        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            if self.rule.is_some() {
                return;
            }
            if !cond_reads(&node.expr, &self.bindings) {
                visit::visit_expr_match(self, node);
                return;
            }
            let mut literals = Vec::new();
            let mut literal_kind = None;
            let mut rest_kind = None;
            for arm in &node.arms {
                let body = quote::ToTokens::to_token_stream(&arm.body).to_string();
                let kind = branch_kind(&body);
                match pattern_literals(&arm.pat) {
                    Some(values) => {
                        literals.extend(values);
                        literal_kind = literal_kind.or(kind);
                    }
                    _ => rest_kind = rest_kind.or(kind),
                }
            }
            self.rule = Some(match (literal_kind, rest_kind) {
                (Some(false), _) | (None, Some(true)) if !literals.is_empty() => {
                    Some(PathRule::SkipsWhen(Cond::Equals(literals)))
                }
                (Some(true), _) | (None, Some(false)) if !literals.is_empty() => {
                    Some(PathRule::RejectsWhen(Cond::Equals(literals)))
                }
                _ => None,
            });
        }
    }
    let mut first = First { bindings: std::collections::HashMap::new(), flags: pass_flags(block), rule: None };
    first.visit_block(block);
    first.rule.flatten()
}

fn simple_name(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
        syn::Pat::Type(typed) => simple_name(&typed.pat),
        _ => None,
    }
}

fn pattern_literals(pat: &syn::Pat) -> Option<Vec<String>> {
    match pat {
        syn::Pat::Lit(syn::ExprLit { lit: syn::Lit::Str(value), .. }) => Some(vec![value.value()]),
        syn::Pat::Or(or) => {
            let mut values = Vec::new();
            for case in &or.cases {
                values.extend(pattern_literals(case)?);
            }
            Some(values)
        }
        _ => None,
    }
}

fn string_literal(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(value), .. }) => Some(value.value()),
        Expr::Reference(reference) => string_literal(&reference.expr),
        Expr::Paren(paren) => string_literal(&paren.expr),
        // `path == constants::LOGIN`
        Expr::Path(path) if path.qself.is_none() => match const_values(&path.path) {
            Some(values) if values.len() == 1 => values.into_iter().next(),
            _ => None,
        },
        _ => None,
    }
}

fn string_list(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::Reference(reference) => string_list(&reference.expr),
        Expr::Paren(paren) => string_list(&paren.expr),
        Expr::Array(array) => array.elems.iter().map(string_literal).collect(),
        // `vec!["/login", "/health"]`
        Expr::Macro(mac) if mac.mac.path.is_ident("vec") => mac
            .mac
            .parse_body_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)
            .ok()
            .and_then(|elems| elems.iter().map(string_literal).collect()),
        // `constants::IGNORE_ROUTES`, `IGNORE_ROUTES.iter()`
        Expr::Path(path) if path.qself.is_none() => const_values(&path.path),
        Expr::MethodCall(call)
            if ["iter", "into_iter", "to_vec", "as_slice"].contains(&call.method.to_string().as_str()) =>
        {
            string_list(&call.receiver)
        }
        _ => None,
    }
}

/// The value or values an argument of a path test stands for: a literal, a
/// constant, or a loop or closure variable bound to a list (`for route in
/// IGNORE_ROUTES.iter() { path.starts_with(route) }`), which stands for
/// each of the list's entries.
fn argument_values(
    expr: &Expr,
    bindings: &std::collections::HashMap<String, Expr>,
    depth: usize,
) -> Option<Vec<String>> {
    if depth > 4 {
        return None;
    }
    match expr {
        Expr::Reference(reference) => argument_values(&reference.expr, bindings, depth + 1),
        Expr::Paren(paren) => argument_values(&paren.expr, bindings, depth + 1),
        Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => {
            argument_values(&unary.expr, bindings, depth + 1)
        }
        Expr::Path(path) if path.path.get_ident().is_some_and(|ident| bindings.contains_key(&ident.to_string())) => {
            let bound = &bindings[&path.path.get_ident().expect("checked above").to_string()];
            argument_values(bound, bindings, depth + 1)
        }
        _ => string_literal(expr).map(|value| vec![value]).or_else(|| string_list(expr)),
    }
}

/// A list binding as an expression, so a loop or closure variable over a
/// list resolves through the same bindings as a `let`.
fn list_expr(values: &[String]) -> Expr {
    syn::parse_quote!([#(#values),*])
}

fn pattern_name(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Reference(reference) => pattern_name(&reference.pat),
        _ => simple_name(pat),
    }
}

/// `flag = true` as a statement of a branch: the names it sets.
fn assigned_true(block: &Block) -> Vec<String> {
    block
        .stmts
        .iter()
        .filter_map(|stmt| match stmt {
            syn::Stmt::Expr(Expr::Assign(assign), _) => match (&*assign.left, &*assign.right) {
                (Expr::Path(path), Expr::Lit(syn::ExprLit { lit: syn::Lit::Bool(value), .. })) if value.value => {
                    path.path.get_ident().map(ToString::to_string)
                }
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Flags whose falseness rejects the request: `if !passed { 401 }`, or
/// `if passed { srv.call(req) } else { 401 }`. Setting one on a path skips
/// the check there.
fn pass_flags(block: &Block) -> HashSet<String> {
    struct Flags(HashSet<String>);
    impl<'ast> Visit<'ast> for Flags {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            let then = quote::ToTokens::to_token_stream(&node.then_branch).to_string();
            let otherwise = node
                .else_branch
                .as_ref()
                .map(|(_, branch)| quote::ToTokens::to_token_stream(branch).to_string());
            let flag = |expr: &Expr| match expr {
                Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
                _ => None,
            };
            match &*node.cond {
                Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Not(_)) && branch_kind(&then) == Some(true) => {
                    self.0.extend(flag(&unary.expr));
                }
                cond if otherwise.as_deref().and_then(branch_kind) == Some(true)
                    && branch_kind(&then) != Some(true) =>
                {
                    self.0.extend(flag(cond));
                }
                _ => {}
            }
            visit::visit_expr_if(self, node);
        }
    }
    let mut flags = Flags(HashSet::new());
    flags.visit_block(block);
    flags.0
}

/// Whether an expression reads the request path, directly or through a binding.
fn cond_reads(expr: &Expr, bindings: &std::collections::HashMap<String, Expr>) -> bool {
    let readers = PATH_READERS.with(|set| set.borrow().clone());
    let names: HashSet<String> = bindings
        .iter()
        .filter(|(_, value)| PathBranches { readers: readers.clone(), ..PathBranches::default() }.reads_path(value))
        .map(|(name, _)| name.clone())
        .collect();
    PathBranches { bindings: names, readers, found: false }.reads_path(expr)
}

fn cond_of(expr: &Expr, bindings: &std::collections::HashMap<String, Expr>, depth: usize) -> Cond {
    if depth > 8 {
        return Cond::Opaque;
    }
    let recurse = |expr: &Expr| cond_of(expr, bindings, depth + 1);
    match expr {
        Expr::Paren(paren) => recurse(&paren.expr),
        Expr::Group(group) => recurse(&group.expr),
        Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Not(_)) => Cond::Not(Box::new(recurse(&unary.expr))),
        Expr::Binary(binary) => match binary.op {
            syn::BinOp::And(_) => Cond::And(vec![recurse(&binary.left), recurse(&binary.right)]),
            syn::BinOp::Or(_) => Cond::Or(vec![recurse(&binary.left), recurse(&binary.right)]),
            syn::BinOp::Eq(_) | syn::BinOp::Ne(_) => {
                let (left, right) = (&*binary.left, &*binary.right);
                let literal = argument_values(right, bindings, 0)
                    .filter(|_| cond_reads(left, bindings))
                    .or_else(|| argument_values(left, bindings, 0).filter(|_| cond_reads(right, bindings)));
                let equals = match literal {
                    Some(values) => Cond::Equals(values),
                    None if cond_reads(expr, bindings) => Cond::Opaque,
                    None => return Cond::Free,
                };
                if matches!(binary.op, syn::BinOp::Ne(_)) { Cond::Not(Box::new(equals)) } else { equals }
            }
            _ if cond_reads(expr, bindings) => Cond::Opaque,
            _ => Cond::Free,
        },
        Expr::Path(path) => match path.path.get_ident().and_then(|ident| bindings.get(&ident.to_string())) {
            Some(value) => recurse(value),
            None => Cond::Free,
        },
        Expr::MethodCall(call) => {
            let method = call.method.to_string();
            let argument = call.args.first();
            if cond_reads(&call.receiver, bindings) {
                let Some(values) = argument.and_then(|argument| argument_values(argument, bindings, 0)) else {
                    return Cond::Opaque;
                };
                let each = |build: fn(String) -> Cond| {
                    let mut parts: Vec<Cond> = values.iter().cloned().map(build).collect();
                    if parts.len() == 1 { parts.remove(0) } else { Cond::Or(parts) }
                };
                return match method.as_str() {
                    "starts_with" => each(Cond::StartsWith),
                    "ends_with" => each(Cond::EndsWith),
                    "contains" => each(Cond::Contains),
                    "eq" => Cond::Equals(values),
                    _ => Cond::Opaque,
                };
            }
            // `["/login", "/health"].contains(&path)`, `IGNORE_ROUTES.contains(&path)`
            if method == "contains"
                && argument.is_some_and(|argument| cond_reads(argument, bindings))
            {
                return string_list(&call.receiver).map_or(Cond::Opaque, Cond::Equals);
            }
            // `IGNORE_ROUTES.iter().any(|route| path.starts_with(route))`:
            // the closure's variable stands for each entry.
            if method == "any"
                && let (Some(values), Some(Expr::Closure(closure))) = (string_list(&call.receiver), argument)
                && closure.inputs.len() == 1
                && let Some(name) = pattern_name(&closure.inputs[0])
            {
                let mut inner = bindings.clone();
                inner.insert(name, list_expr(&values));
                return cond_of(&closure.body, &inner, depth + 1);
            }
            if cond_reads(expr, bindings) { Cond::Opaque } else { Cond::Free }
        }
        Expr::Macro(mac) if mac.mac.path.is_ident("matches") => {
            let Ok((scrutinee, pattern)) = mac.mac.parse_body_with(|input: syn::parse::ParseStream| {
                let scrutinee: Expr = input.parse()?;
                let _: syn::Token![,] = input.parse()?;
                let pattern = syn::Pat::parse_multi_with_leading_vert(input)?;
                Ok((scrutinee, pattern))
            }) else {
                return Cond::Opaque;
            };
            if !cond_reads(&scrutinee, bindings) {
                return Cond::Free;
            }
            pattern_literals(&pattern).map_or(Cond::Opaque, Cond::Equals)
        }
        _ if cond_reads(expr, bindings) => Cond::Opaque,
        _ => Cond::Free,
    }
}

/// The settled evidence text of a component that exempts named paths and
/// checks this one.
pub(crate) const SKIP_RULE_MARK: &str = "checks the caller on this path (its path rule skips";

/// Settles path-conditional middleware evidence on a route by its path:
/// a component whose path rule is read checks the caller on every path the
/// rule does not exempt. Evidence for exempt paths is dropped; an
/// undecided rule keeps the fail-closed evidence.
pub(crate) fn settle_path_rules(route: &mut super::model::Route) {
    use super::model::{AuthEvidenceKind, AuthStrength};
    const MARK: &str = "checks the caller only for some request paths";
    let path = route.path.clone();
    route.authorization.retain_mut(|evidence| {
        if evidence.kind != AuthEvidenceKind::Delegated || !evidence.mechanism.contains(MARK) {
            return true;
        }
        let Some(name) = evidence.mechanism.split('`').nth(1).map(str::to_owned) else {
            return true;
        };
        let Some(rule) = path_rule_of(&name) else {
            return true;
        };
        let (condition, verb) = match &rule {
            PathRule::RejectsWhen(condition) => (condition, "applies only to"),
            PathRule::SkipsWhen(condition) => (condition, "skips"),
        };
        let named = condition.literals().join(", ");
        match protects(&rule, &path) {
            Some(true) => {
                evidence.kind = if rule_checks_privilege(&name) {
                    AuthEvidenceKind::AuthorizationMiddleware
                } else {
                    AuthEvidenceKind::IdentityExtraction
                };
                evidence.strength = AuthStrength::Medium;
                evidence.mechanism = format!("`{name}` checks the caller on this path (its path rule {verb} {named})");
                true
            }
            Some(false) => false,
            None => true,
        }
    });
}
