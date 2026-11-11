//! Structural signals that stand in for name tests (P8).
//!
//! Several decisions used to rest on identifier words: an extractor or a
//! `ReqData<T>` was the caller when its type name said `user` or `auth`, a
//! middleware authenticated when its name said `auth` or `anonymous`, and an
//! error rejected an unauthenticated caller when its variant was called
//! `Unauthorized`. Each app picks its own words, so this module reads what
//! the code does instead:
//!
//! - **Credential readers.** A function reads a credential when it calls a
//!   request method that returns one (`headers`, `cookie`, `get_session`,
//!   `get_identity`), names a credential type of the actix crates
//!   (`Session`, `Identity`, `BearerAuth`, `BasicAuth`), runs the
//!   `from_request` of an extractor that does, or calls a function of the
//!   scanned code that does.
//! - **Caller types.** A type is the caller when a credential reader puts a
//!   value of it into the request extensions
//!   (`req.extensions_mut().insert(UserId(id))`). An extractor that takes a
//!   caller type out of the extensions, and `ReqData<T>` of one, identify the
//!   caller.
//! - **Rejecting status.** An error variant rejects an unauthenticated (or
//!   unprivileged) caller when the crate's `ResponseError` impl maps it to
//!   401 (or 403).
//! - **Authentication middleware.** A `from_fn` function, or a middleware
//!   type whose `Service::call` (or its `Transform`'s service) reads a
//!   credential and can reject, or puts a caller type into the extensions.
//!
//! The name tests stay as a fallback; evidence they alone decide is tagged
//! `name_based`. `ARCHER_P8=0` turns this module off.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    path::Path,
};
use syn::{
    Expr, GenericArgument, ImplItem, Item, PathArguments, ReturnType, Type,
    visit::{self, Visit},
};

pub(crate) fn enabled() -> bool {
    std::env::var("ARCHER_P8").map_or(true, |value| value != "0")
}

/// Request methods that return a credential the request presents.
const CREDENTIAL_METHODS: [&str; 4] = ["cookie", "cookies", "get_session", "get_identity"];
/// Header constants of the `http` crate that carry a credential.
const CREDENTIAL_HEADERS: [&str; 3] = ["AUTHORIZATION", "PROXY_AUTHORIZATION", "COOKIE"];
/// Header names, as string literals, that carry a credential. These are
/// protocol strings, not application identifiers.
const CREDENTIAL_HEADER_TEXT: [&str; 7] =
    ["authorization", "cookie", "token", "api-key", "apikey", "api_key", "bearer"];
/// Credential types of the actix crates.
const CREDENTIAL_TYPES: [&str; 4] = ["Session", "Identity", "BearerAuth", "BasicAuth"];
/// Method names too common to resolve to one function of the scanned code.
const UNRESOLVED_METHODS: [&str; 24] = [
    "new", "get", "call", "from", "into", "clone", "insert", "remove", "map", "and_then", "ok", "err",
    "unwrap", "expect", "to_string", "as_str", "as_ref", "default", "iter", "len", "is_empty",
    "contains", "push", "send",
];

#[derive(Default)]
struct State {
    caller_types: HashSet<String>,
    /// Extractor types whose `from_request` takes a caller type out of the
    /// request extensions.
    caller_extractors: HashSet<String>,
    /// Extractor types whose `from_request` reads a credential.
    credential_extractors: HashSet<String>,
    /// Function names and middleware type names that authenticate.
    components: HashSet<String>,
    /// Functions and methods of the scanned code that build an error,
    /// themselves or through what they call, by name.
    rejecting: HashSet<String>,
    /// `(enum, variant)` and `("", variant)` mapped to 401.
    unauthenticated: HashSet<(String, String)>,
    /// Mapped to 403.
    forbidding: HashSet<(String, String)>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

pub(crate) fn caller_type(name: &str) -> bool {
    enabled() && STATE.with(|state| state.borrow().caller_types.contains(name))
}

pub(crate) fn caller_extractor(name: &str) -> bool {
    enabled() && STATE.with(|state| state.borrow().caller_extractors.contains(name))
}

/// A function or method of the scanned code that can build an error.
pub(crate) fn rejecting_function(name: &str) -> bool {
    enabled() && STATE.with(|state| state.borrow().rejecting.contains(name))
}

pub(crate) fn credential_extractor(name: &str) -> bool {
    enabled() && STATE.with(|state| state.borrow().credential_extractors.contains(name))
}

pub(crate) fn authenticating_component(name: &str) -> bool {
    enabled() && STATE.with(|state| state.borrow().components.contains(name))
}

fn variant_in(set: &HashSet<(String, String)>, path: &str) -> bool {
    let segments: Vec<&str> = path.split("::").filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        [.., ty, variant] => set.contains(&(ty.to_string(), variant.to_string())),
        [variant] => set.contains(&(String::new(), variant.to_string())),
        _ => false,
    }
}

/// `AppError::Unauthorized` when the crate's `ResponseError` maps it to 401.
pub(crate) fn unauthenticated_variant(path: &str) -> bool {
    enabled() && STATE.with(|state| variant_in(&state.borrow().unauthenticated, path))
}

pub(crate) fn forbidding_variant(path: &str) -> bool {
    enabled() && STATE.with(|state| variant_in(&state.borrow().forbidding, path))
}

struct FnInfo<'a> {
    owner: Option<String>,
    name: String,
    block: &'a syn::Block,
    output: Option<&'a Type>,
}

/// What one function body does, before following calls.
#[derive(Default)]
struct Facts {
    reads_credential: bool,
    /// `req.headers()`: a credential only beside a credential header name.
    reads_headers: bool,
    /// Names a credential header (`header::AUTHORIZATION`, `"x-api-key"`).
    names_credential_header: bool,
    rejects: bool,
    /// Builds an error itself (`Err(..)`, `ErrorUnauthorized(..)`), rather
    /// than only passing one on with `?`.
    builds_error: bool,
    /// `(owner, name)`: `Type::f(..)` or `f(..)`; methods have no owner.
    calls: Vec<(Option<String>, String, bool)>,
    /// `T::from_request` / `T::extract` runs.
    extracts: Vec<String>,
    /// Inserted into the request extensions.
    inserted: Vec<Expr>,
    /// `get::<T>()`/`remove::<T>()` turbofish types.
    taken: Vec<String>,
}

fn last_type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()),
        Type::Reference(reference) => last_type_name(&reference.elem),
        Type::Paren(paren) => last_type_name(&paren.elem),
        Type::Group(group) => last_type_name(&group.elem),
        _ => None,
    }
}

/// The value type of `Result<T, E>`, `Option<T>`, `SomeResult<T>`, `T`.
fn value_type(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else { return last_type_name(ty) };
    let segment = path.path.segments.last()?;
    let name = segment.ident.to_string();
    if (name == "Option" || name.ends_with("Result") || name == "Box" || name == "Arc" || name == "Rc")
        && let PathArguments::AngleBracketed(arguments) = &segment.arguments
        && let Some(GenericArgument::Type(inner)) = arguments.args.first()
    {
        return value_type(inner);
    }
    Some(name)
}

impl<'ast> Visit<'ast> for Facts {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if CREDENTIAL_METHODS.contains(&method.as_str()) {
            self.reads_credential = true;
        }
        if method == "headers" {
            self.reads_headers = true;
        }
        if method == "insert"
            && let Expr::MethodCall(receiver) = &*node.receiver
            && receiver.method == "extensions_mut"
        {
            if let Some(turbofish) = &node.turbofish {
                for argument in &turbofish.args {
                    if let GenericArgument::Type(ty) = argument
                        && let Some(name) = last_type_name(ty)
                    {
                        let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
                        self.inserted.push(syn::parse_quote!(#ident));
                    }
                }
            }
            if let Some(argument) = node.args.first() {
                self.inserted.push(argument.clone());
            }
        }
        if (method == "get" || method == "remove")
            && let Some(turbofish) = &node.turbofish
        {
            for argument in &turbofish.args {
                if let GenericArgument::Type(ty) = argument
                    && let Some(name) = last_type_name(ty)
                {
                    self.taken.push(name);
                }
            }
        }
        if !UNRESOLVED_METHODS.contains(&method.as_str()) {
            self.calls.push((None, method, true));
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func {
            let segments: Vec<String> = path.path.segments.iter().map(|s| s.ident.to_string()).collect();
            if let Some(last) = segments.last() {
                if last == "Err" || last == "err" || last.starts_with("Error") {
                    self.rejects = true;
                    self.builds_error = true;
                }
                let owner = (segments.len() >= 2).then(|| segments[segments.len() - 2].clone());
                if last == "from_request" || last == "extract" {
                    if let Some(qself) = &path.qself {
                        if let Some(name) = last_type_name(&qself.ty) {
                            self.extracts.push(name);
                        }
                    } else if let Some(owner) = &owner {
                        self.extracts.push(owner.clone());
                    }
                }
                self.calls.push((owner, last.clone(), false));
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.rejects = true;
        visit::visit_expr_try(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node
            .segments
            .iter()
            .any(|segment| CREDENTIAL_TYPES.contains(&segment.ident.to_string().as_str()))
        {
            self.reads_credential = true;
        }
        if node
            .segments
            .last()
            .is_some_and(|segment| CREDENTIAL_HEADERS.contains(&segment.ident.to_string().as_str()))
        {
            self.names_credential_header = true;
        }
        visit::visit_path(self, node);
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        let text = node.value().to_ascii_lowercase();
        if text.len() < 40 && CREDENTIAL_HEADER_TEXT.iter().any(|word| text.contains(word)) {
            self.names_credential_header = true;
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // `format!("Bearer {token}")`, `header!("x-api-key")`.
        if let Ok(arguments) = node.parse_body_with(
            syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
        ) {
            for argument in &arguments {
                self.visit_expr(argument);
            }
        }
    }
}

/// Every function of the scanned code, with the trait it implements.
fn collect<'a>(items: &'a [Item], out: &mut Vec<(FnInfo<'a>, Option<String>)>, impls: &mut Vec<&'a syn::ItemImpl>) {
    for item in items {
        match item {
            Item::Fn(function) => out.push((
                FnInfo {
                    owner: None,
                    name: function.sig.ident.to_string(),
                    block: &function.block,
                    output: match &function.sig.output {
                        ReturnType::Type(_, ty) => Some(ty),
                        ReturnType::Default => None,
                    },
                },
                None,
            )),
            Item::Impl(block) => {
                impls.push(block);
                let owner = last_type_name(&block.self_ty);
                let trait_name = block
                    .trait_
                    .as_ref()
                    .and_then(|(path, _)| path.segments.last().map(|s| s.ident.to_string()));
                for member in &block.items {
                    if let ImplItem::Fn(function) = member {
                        out.push((
                            FnInfo {
                                owner: owner.clone(),
                                name: function.sig.ident.to_string(),
                                block: &function.block,
                                output: match &function.sig.output {
                                    ReturnType::Type(_, ty) => Some(ty),
                                    ReturnType::Default => None,
                                },
                            },
                            trait_name.clone(),
                        ));
                    }
                }
            }
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect(items, out, impls);
                }
            }
            _ => {}
        }
    }
}

struct ItemMacros(Vec<proc_macro2::TokenStream>);

impl<'ast> Visit<'ast> for ItemMacros {
    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if node.ident.is_none() {
            self.0.push(node.mac.tokens.clone());
        }
    }
}

fn braced_items(tokens: proc_macro2::TokenStream, out: &mut Vec<syn::File>, depth: usize) {
    if depth > 3 {
        return;
    }
    for tree in tokens {
        if let proc_macro2::TokenTree::Group(group) = tree
            && group.delimiter() == proc_macro2::Delimiter::Brace
        {
            match syn::parse2::<syn::File>(group.stream()) {
                Ok(file) if !file.items.is_empty() => out.push(file),
                _ => braced_items(group.stream(), out, depth + 1),
            }
        }
    }
}

/// Status words of an arm body: 401 or 403.
fn status_of(body: &Expr) -> (bool, bool) {
    let written = quote::ToTokens::to_token_stream(body).to_string();
    let unauthorized = written.contains("UNAUTHORIZED")
        || written.contains("Unauthorized ()")
        || written.contains("ErrorUnauthorized")
        || written.contains("401");
    let forbidden = written.contains("FORBIDDEN")
        || written.contains("Forbidden ()")
        || written.contains("ErrorForbidden")
        || written.contains("403");
    (unauthorized, forbidden)
}

#[derive(Default)]
struct StatusArms {
    unauthenticated: HashSet<(String, String)>,
    forbidding: HashSet<(String, String)>,
}

impl<'ast> Visit<'ast> for StatusArms {
    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        let (unauthorized, forbidden) = status_of(&node.body);
        if unauthorized || forbidden {
            let mut paths = PatPaths::default();
            paths.visit_pat(&node.pat);
            for path in paths.0 {
                let set = if unauthorized { &mut self.unauthenticated } else { &mut self.forbidding };
                if let [.., ty, variant] = path.as_slice() {
                    set.insert((ty.clone(), variant.clone()));
                }
                if let Some(variant) = path.last() {
                    set.insert((String::new(), variant.clone()));
                }
            }
        }
        visit::visit_arm(self, node);
    }
}

#[derive(Default)]
struct PatPaths(Vec<Vec<String>>);

impl<'ast> Visit<'ast> for PatPaths {
    fn visit_path(&mut self, node: &'ast syn::Path) {
        let segments: Vec<String> = node.segments.iter().map(|s| s.ident.to_string()).collect();
        if segments.len() >= 2 && segments.last().is_some_and(|s| s.starts_with(|c: char| c.is_ascii_uppercase())) {
            self.0.push(segments);
        }
        visit::visit_path(self, node);
    }
}

pub(crate) fn index<'a>(files: impl IntoIterator<Item = (&'a Path, &'a syn::File)>) {
    let files: Vec<&syn::File> = files.into_iter().map(|(_, file)| file).collect();
    // Items written inside an item macro (`cfg_select! { feature = "x" => { .. } }`,
    // `cfg_if!`): parsed from each braced group that holds items.
    let mut embedded: Vec<syn::File> = Vec::new();
    for file in &files {
        let mut macros = ItemMacros(Vec::new());
        macros.visit_file(file);
        for tokens in macros.0 {
            braced_items(tokens, &mut embedded, 0);
        }
    }
    let mut fns = Vec::new();
    let mut impls = Vec::new();
    for file in files.iter().copied().chain(embedded.iter()) {
        collect(&file.items, &mut fns, &mut impls);
    }
    let facts: Vec<Facts> = fns
        .iter()
        .map(|(info, _)| {
            let mut facts = Facts::default();
            facts.visit_block(info.block);
            facts
        })
        .collect();

    // Function lookup: `(owner, name)` and bare names; a name defined more
    // than once is only reached through its owner.
    let mut by_key: HashMap<(Option<String>, String), Vec<usize>> = HashMap::new();
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    let mut extractor_fns: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, (info, trait_name)) in fns.iter().enumerate() {
        by_key.entry((info.owner.clone(), info.name.clone())).or_default().push(i);
        by_name.entry(info.name.clone()).or_default().push(i);
        if trait_name.as_deref() == Some("FromRequest")
            && info.name == "from_request"
            && let Some(owner) = &info.owner
        {
            extractor_fns.entry(owner.clone()).or_default().push(i);
        }
    }
    let callees = |facts: &Facts| -> Vec<usize> {
        let mut out = Vec::new();
        for (owner, name, method) in &facts.calls {
            if let Some(owner) = owner
                && let Some(found) = by_key.get(&(Some(owner.clone()), name.clone()))
            {
                out.extend(found);
                continue;
            }
            if let Some(found) = by_name.get(name)
                && (found.len() == 1 || (!method && owner.is_none()))
            {
                if found.len() == 1 {
                    out.extend(found);
                } else if let Some(free) = by_key.get(&(None, name.clone())) {
                    out.extend(free);
                }
            }
        }
        for extractor in &facts.extracts {
            if let Some(found) = extractor_fns.get(extractor) {
                out.extend(found);
            }
        }
        out
    };
    let edges: Vec<Vec<usize>> = facts.iter().map(callees).collect();
    // For "can it build an error", a method call reaches every method of
    // that name: an over-approximation that only widens what counts as a
    // check, never what counts as a credential.
    let loose: Vec<Vec<usize>> = facts
        .iter()
        .zip(&edges)
        .map(|(facts, strict)| {
            let mut out = strict.clone();
            for (_, name, method) in &facts.calls {
                if *method && let Some(found) = by_name.get(name) {
                    out.extend(found);
                }
            }
            out
        })
        .collect();

    // Header reads and credential header names, each through what a
    // function calls; both together read a credential.
    let closure = |seed: Vec<bool>| -> Vec<bool> {
        let mut set = seed;
        loop {
            let mut changed = false;
            for i in 0..set.len() {
                if !set[i] && edges[i].iter().any(|&j| set[j]) {
                    set[i] = true;
                    changed = true;
                }
            }
            if !changed {
                return set;
            }
        }
    };
    let headers = closure(facts.iter().map(|facts| facts.reads_headers).collect());
    let names = closure(facts.iter().map(|facts| facts.names_credential_header).collect());
    // Credential readers, to a fixed point over the call graph.
    let mut credential: Vec<bool> = facts
        .iter()
        .enumerate()
        .map(|(i, facts)| facts.reads_credential || (headers[i] && names[i]))
        .collect();
    loop {
        let mut changed = false;
        for i in 0..fns.len() {
            if !credential[i] && edges[i].iter().any(|&j| credential[j]) {
                credential[i] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Return value types, for `let v = f(..)?` and builder chains.
    let returns: HashMap<String, String> = {
        let mut seen: HashMap<String, Option<String>> = HashMap::new();
        for (info, _) in &fns {
            let ty = info.output.and_then(value_type).filter(|ty| ty != "Self");
            let ty = ty.or_else(|| {
                info.output
                    .and_then(value_type)
                    .filter(|ty| ty == "Self")
                    .and(info.owner.clone())
            });
            match seen.get(&info.name) {
                None => {
                    seen.insert(info.name.clone(), ty);
                }
                Some(previous) if *previous != ty => {
                    seen.insert(info.name.clone(), None);
                }
                _ => {}
            }
        }
        seen.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))).collect()
    };

    let mut caller_types = HashSet::new();
    for (i, (info, _)) in fns.iter().enumerate() {
        if !credential[i] {
            continue;
        }
        for inserted in &facts[i].inserted {
            if let Some(ty) = expr_type(inserted, info.block, &returns, 0) {
                caller_types.insert(ty);
            }
        }
    }

    // Extractors that take a caller type out of the extensions, themselves
    // or through what they call.
    let mut takes: Vec<bool> = facts
        .iter()
        .map(|facts| facts.taken.iter().any(|ty| caller_types.contains(ty)))
        .collect();
    loop {
        let mut changed = false;
        for i in 0..fns.len() {
            if !takes[i] && edges[i].iter().any(|&j| takes[j]) {
                takes[i] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let caller_extractors: HashSet<String> = extractor_fns
        .iter()
        .filter(|(_, ids)| ids.iter().any(|&i| takes[i]))
        .map(|(name, _)| name.clone())
        .collect();

    let credential_extractors: HashSet<String> = extractor_fns
        .iter()
        .filter(|(_, ids)| ids.iter().any(|&i| credential[i]))
        .map(|(name, _)| name.clone())
        .collect();

    // A function or middleware authenticates when it reads a credential
    // and can reject, or stores a caller value.
    let authenticates = |i: usize| -> bool {
        let stores = facts[i]
            .inserted
            .iter()
            .any(|inserted| expr_type(inserted, fns[i].0.block, &returns, 0).is_some_and(|ty| caller_types.contains(&ty)));
        credential[i] && (facts[i].builds_error || stores)
    };
    let mut components = HashSet::new();
    for (i, (info, trait_name)) in fns.iter().enumerate() {
        if info.owner.is_none() && authenticates(i) {
            components.insert(info.name.clone());
        }
        if trait_name.as_deref() == Some("Service")
            && info.name == "call"
            && let Some(owner) = &info.owner
            && authenticates(i)
        {
            components.insert(owner.clone());
        }
    }
    // `impl Transform for Auth { type Transform = AuthMiddleware<S>; .. }`
    for block in &impls {
        let is_transform = block
            .trait_
            .as_ref()
            .is_some_and(|(path, _)| path.segments.last().is_some_and(|s| s.ident == "Transform"));
        if !is_transform {
            continue;
        }
        let Some(owner) = last_type_name(&block.self_ty) else { continue };
        for member in &block.items {
            if let ImplItem::Type(assoc) = member
                && assoc.ident == "Transform"
                && let Some(service) = last_type_name(&assoc.ty)
                && components.contains(&service)
            {
                components.insert(owner.clone());
            }
        }
    }

    let mut builds: Vec<bool> = facts.iter().map(|facts| facts.builds_error).collect();
    loop {
        let mut changed = false;
        for i in 0..fns.len() {
            if !builds[i] && loose[i].iter().any(|&j| builds[j]) {
                builds[i] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let rejecting: HashSet<String> = fns
        .iter()
        .zip(&builds)
        .filter(|(_, builds)| **builds)
        .map(|((info, _), _)| info.name.clone())
        .collect();

    let mut arms = StatusArms::default();
    for block in &impls {
        let is_response_error = block
            .trait_
            .as_ref()
            .is_some_and(|(path, _)| path.segments.last().is_some_and(|s| s.ident == "ResponseError"));
        if is_response_error {
            arms.visit_item_impl(block);
        }
    }

    if std::env::var_os("ARCHER_DEBUG_STRUCTURAL").is_some() {
        let mut sorted: Vec<_> = caller_types.iter().collect();
        sorted.sort();
        eprintln!("caller types: {sorted:?}");
        let mut sorted: Vec<_> = caller_extractors.iter().collect();
        sorted.sort();
        eprintln!("caller extractors: {sorted:?}");
        let mut sorted: Vec<_> = components.iter().collect();
        sorted.sort();
        eprintln!("authenticating components: {sorted:?}");
        eprintln!("401 variants: {:?}", arms.unauthenticated);
        eprintln!("403 variants: {:?}", arms.forbidding);
    }
    STATE.with(|state| {
        *state.borrow_mut() = State {
            caller_types,
            caller_extractors,
            credential_extractors,
            components,
            rejecting,
            unauthenticated: arms.unauthenticated,
            forbidding: arms.forbidding,
        }
    });
}

/// The type of a value put into the extensions: `T(..)`, `T { .. }`,
/// `T::new(..)`, a builder chain on one of these, a call of a function of
/// the scanned code, or a local bound to one.
fn expr_type(expr: &Expr, block: &syn::Block, returns: &HashMap<String, String>, depth: usize) -> Option<String> {
    if depth > 4 {
        return None;
    }
    match expr {
        Expr::Call(call) => {
            let Expr::Path(path) = &*call.func else { return None };
            let segments: Vec<String> = path.path.segments.iter().map(|s| s.ident.to_string()).collect();
            match segments.as_slice() {
                [.., ty, _function] if ty.starts_with(|c: char| c.is_ascii_uppercase()) && ty != "Some" && ty != "Ok" => Some(ty.clone()),
                [name] if name.starts_with(|c: char| c.is_ascii_uppercase()) => {
                    if name == "Some" || name == "Ok" || name == "Box" || name == "Arc" || name == "Rc" {
                        call.args.first().and_then(|inner| expr_type(inner, block, returns, depth + 1))
                    } else {
                        Some(name.clone())
                    }
                }
                [.., name] => returns.get(name).cloned(),
                [] => None,
            }
        }
        Expr::Struct(literal) => literal.path.segments.last().map(|s| s.ident.to_string()),
        Expr::Path(path) if path.path.segments.len() == 1 => {
            let name = path.path.segments[0].ident.to_string();
            if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                return Some(name);
            }
            let mut finder = LetFinder { name, found: None };
            finder.visit_block(block);
            match finder.found? {
                LetValue::Type(ty) => last_type_name(&ty),
                LetValue::Expr(value) => expr_type(&value, block, returns, depth + 1),
            }
        }
        Expr::MethodCall(call) => {
            if let Some(ty) = returns.get(&call.method.to_string()) {
                return Some(ty.clone());
            }
            // Builder methods return the receiver's type: `Auth::new(..).with_api(..)`,
            // `x.clone()`.
            expr_type(&call.receiver, block, returns, depth + 1)
        }
        Expr::Try(attempt) => expr_type(&attempt.expr, block, returns, depth + 1),
        Expr::Await(awaited) => expr_type(&awaited.base, block, returns, depth + 1),
        Expr::Paren(paren) => expr_type(&paren.expr, block, returns, depth + 1),
        Expr::Reference(reference) => expr_type(&reference.expr, block, returns, depth + 1),
        _ => None,
    }
}

enum LetValue {
    Type(Type),
    Expr(Expr),
}

struct LetFinder {
    name: String,
    found: Option<LetValue>,
}

impl<'ast> Visit<'ast> for LetFinder {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        let (pattern, ty) = match &node.pat {
            syn::Pat::Type(typed) => (&*typed.pat, Some(&*typed.ty)),
            other => (other, None),
        };
        if let syn::Pat::Ident(ident) = pattern
            && ident.ident == self.name
        {
            if let Some(ty) = ty {
                self.found = Some(LetValue::Type(ty.clone()));
            } else if let Some(init) = &node.init {
                self.found = Some(LetValue::Expr((*init.expr).clone()));
            }
        }
        visit::visit_local(self, node);
    }

    // `Some(user_id) => { .. insert(UserId(user_id)) }` binds through a
    // pattern; the inserted value is then read by its constructor.
}
