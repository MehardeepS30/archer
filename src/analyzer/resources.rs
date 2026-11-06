//! Resource links: routes that serve the same data, whatever their paths.
//!
//! Two routes are linked when their handlers are the same definition, call
//! the same repository function (`find_article_content_by_id_and_status`),
//! or name the same model type defined in the repository (`Article::find`,
//! `Json<Article>`). Linked routes of one method class are compared even
//! across scopes: `/view/article/{id}/{status}` serves what
//! `/article/admin/edit/{id}` serves only to the article's owner.

use std::collections::{HashMap, HashSet};
use syn::{
    Item, ItemFn,
    visit::{self, Visit},
};

use super::{evidence::names_caller_source, handlers::HandlerIndex, model::Route};

/// Link keys for each route, parallel to `routes`. A key shared by more
/// handlers than `max_sharing` (a connection helper, a renderer) links
/// unrelated routes and is dropped.
pub(crate) fn resource_keys<'a>(
    index: &HandlerIndex,
    files: impl IntoIterator<Item = &'a syn::File>,
    routes: &[Route],
) -> Vec<(Vec<String>, Vec<String>, bool)> {
    let files: Vec<&syn::File> = files.into_iter().collect();
    let models = model_types(files.iter().copied());
    let credentials = credential_types(files.iter().copied());
    let mut takes_credentials: HashSet<usize> = HashSet::new();
    let handlers: HashSet<usize> = routes.iter().filter_map(|route| route.origin.definition).collect();
    let mut by_definition: HashMap<usize, Vec<String>> = HashMap::new();
    let mut called: HashMap<usize, Vec<String>> = HashMap::new();
    for &definition in &handlers {
        let mut keys = vec![format!("handler {}", index.definitions[definition].rust_path())];
        let mut data = RequestData::default();
        data.start(&index.items[definition].sig);
        data.visit_block(&index.items[definition].block);
        for (callee, _) in index.resolved_calls(definition).calls {
            let target = &index.definitions[callee];
            let checks = !target.own.body_evidence.is_empty() || !target.own.predicate_evidence.is_empty();
            if !handlers.contains(&callee) && !checks {
                called.entry(definition).or_default().push(target.name.clone());
            }
            // Only calls that take a value from the request (`find(id)`
            // with `id` from the path) address the data the route serves;
            // `server_busy_error()` and `get_conn(&pool)` do not.
            if !data.calls.contains(&target.name) {
                continue;
            }
            // Another handler, an authorization helper, or the caller's
            // identity says nothing about which data the route serves.
            if handlers.contains(&callee) || checks || names_caller_source(&target.name) {
                continue;
            }
            keys.push(format!("calls {}", target.rust_path()));
        }
        // The request types the handler takes (`web::Json<LoginForm>`).
        let signature = quote::ToTokens::to_token_stream(&index.items[definition].sig.inputs).to_string();
        if signature
            .split(|character: char| !character.is_alphanumeric() && character != '_')
            .any(|word| credentials.contains(word))
        {
            takes_credentials.insert(definition);
        }
        for name in &data.types {
            if models.contains(name) && !names_caller_source(name) {
                keys.push(format!("uses model {name}"));
            }
        }
        keys.sort();
        keys.dedup();
        by_definition.insert(definition, keys);
    }
    let mut sharing: HashMap<&str, usize> = HashMap::new();
    for keys in by_definition.values() {
        for key in keys {
            *sharing.entry(key.as_str()).or_default() += 1;
        }
    }
    let max_sharing = ((handlers.len() as f64).sqrt().ceil() as usize).max(3);
    routes
        .iter()
        .map(|route| {
            let names = route
                .origin
                .definition
                .and_then(|definition| called.get(&definition))
                .cloned()
                .unwrap_or_default();
            let keys = route
                .origin
                .definition
                .and_then(|definition| by_definition.get(&definition))
                .map(|keys| {
                    keys.iter()
                        .filter(|key| {
                            key.starts_with("handler ")
                                || (2..=max_sharing).contains(&sharing[key.as_str()])
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let credentials = route
                .origin
                .definition
                .is_some_and(|definition| takes_credentials.contains(&definition));
            (keys, names, credentials)
        })
        .collect()
}

/// Structs defined in the repository with a credential field
/// (`password`, `passwd`, `otp_code`): a handler taking one in its request
/// takes credentials.
fn credential_types<'a>(files: impl IntoIterator<Item = &'a syn::File>) -> HashSet<String> {
    const FIELDS: [&str; 6] = ["password", "passwd", "passphrase", "credential", "otp", "totp"];
    fn collect(items: &[Item], out: &mut HashSet<String>) {
        for item in items {
            match item {
                Item::Struct(item) => {
                    let credential = item.fields.iter().any(|field| {
                        field.ident.as_ref().is_some_and(|ident| {
                            let name = ident.to_string().to_ascii_lowercase();
                            FIELDS.iter().any(|word| name.contains(word))
                        })
                    });
                    if credential {
                        out.insert(item.ident.to_string());
                    }
                }
                Item::Mod(module) => {
                    if let Some((_, items)) = &module.content {
                        collect(items, out);
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = HashSet::new();
    for file in files {
        collect(&file.items, &mut out);
    }
    out
}

/// Structs and enums defined in the repository.
fn model_types<'a>(files: impl IntoIterator<Item = &'a syn::File>) -> HashSet<String> {
    fn collect(items: &[Item], out: &mut HashSet<String>) {
        for item in items {
            match item {
                Item::Struct(item) => {
                    out.insert(item.ident.to_string());
                }
                Item::Enum(item) => {
                    out.insert(item.ident.to_string());
                }
                Item::Mod(module) => {
                    if let Some((_, items)) = &module.content {
                        collect(items, out);
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = HashSet::new();
    for file in files {
        collect(&file.items, &mut out);
    }
    out
}

/// Request extractors whose value the client chooses.
const REQUEST_EXTRACTORS: [&str; 5] = ["Path", "Query", "Json", "Form", "Payload"];

/// Calls in a handler body that receive a value taken from the request:
/// free functions by name (`find_article_by_id(&mut conn, article_id)`) and
/// the types of associated calls (`Article::find(id)`).
#[derive(Default)]
struct RequestData {
    tainted: HashSet<String>,
    calls: HashSet<String>,
    types: HashSet<String>,
}

impl RequestData {
    fn start(&mut self, signature: &syn::Signature) {
        for input in &signature.inputs {
            let syn::FnArg::Typed(typed) = input else { continue };
            if extractor_type(&typed.ty) {
                let mut names = HashSet::new();
                super::routes::pattern_bindings(&typed.pat, &mut names);
                self.tainted.extend(names);
            }
        }
    }

    fn reads_request(&self, expr: &syn::Expr) -> bool {
        struct Reads<'a> {
            tainted: &'a HashSet<String>,
            found: bool,
        }
        impl<'ast> Visit<'ast> for Reads<'_> {
            fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
                if self.tainted.contains(&ident.to_string()) {
                    self.found = true;
                }
            }
        }
        let mut reads = Reads { tainted: &self.tainted, found: false };
        reads.visit_expr(expr);
        reads.found
    }
}

fn extractor_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| REQUEST_EXTRACTORS.contains(&segment.ident.to_string().as_str())),
        syn::Type::Reference(reference) => extractor_type(&reference.elem),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for RequestData {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init
            && self.reads_request(&init.expr)
        {
            let mut names = HashSet::new();
            super::routes::pattern_bindings(&local.pat, &mut names);
            self.tainted.extend(names);
        }
        visit::visit_local(self, local);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if call.args.iter().any(|argument| self.reads_request(argument))
            && let syn::Expr::Path(path) = &*call.func
        {
            let segments: Vec<String> =
                path.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
            if let Some(name) = segments.last() {
                self.calls.insert(name.clone());
            }
            if segments.len() >= 2
                && segments[segments.len() - 2].chars().next().is_some_and(char::is_uppercase)
            {
                self.types.insert(segments[segments.len() - 2].clone());
            }
        }
        visit::visit_expr_call(self, call);
    }
    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
}
