//! Repository analysis: file discovery, parsing, and the extraction and inference pipeline.

mod caller_use;
mod config;
mod drift;
mod evidence;
mod handlers;
mod middleware;
mod model;
mod peer_checks;
mod resources;
mod route_tables;
mod routes;
#[cfg(test)]
mod tests;

pub use drift::format_finding;
pub use config::{Config, DismissedFinding};
pub use model::*;

use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
use syn::visit::Visit;
use walkdir::WalkDir;

use self::{drift::*, handlers::*, routes::*};

/// Hidden directories, and at the scan root or beside a `Cargo.toml`, the
/// `target` build directory and, unless requested, `tests`, `examples`, and
/// `benches`. A `target` or `tests` directory inside `src/` is a module and is
/// scanned.
fn is_skipped_directory(root: &Path, entry: &walkdir::DirEntry, options: &AnalysisOptions) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    if name.starts_with('.') {
        return true;
    }
    let crate_level = entry
        .path()
        .parent()
        .is_some_and(|parent| parent == root || parent.join("Cargo.toml").is_file());
    crate_level
        && (name == "target"
            || (!options.include_tests && ["tests", "examples", "benches"].contains(&&*name)))
}

/// Analysis with default options; the binary passes CLI options instead.
#[cfg_attr(not(test), allow(dead_code))]
pub fn analyze_repository(root: &Path) -> Result<Report> {
    analyze_repository_with(root, &AnalysisOptions::default())
}

/// Stack for parsing and visiting. Parsing, visiting, and dropping a syntax
/// tree recurse once per nested expression, and a builder chain is nested one
/// level per call: a few hundred `.route(...)` calls exhaust a 1 MiB main
/// thread stack. The stack is reserved, not committed, until it is used.
const ANALYSIS_STACK_BYTES: usize = 512 * 1024 * 1024;

pub fn analyze_repository_with(root: &Path, options: &AnalysisOptions) -> Result<Report> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("archer-analysis".into())
            .stack_size(ANALYSIS_STACK_BYTES)
            .spawn_scoped(scope, || analyze_on_current_thread(root, options))?
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

fn analyze_on_current_thread(root: &Path, options: &AnalysisOptions) -> Result<Report> {
    if !root.exists() {
        anyhow::bail!("{} does not exist", root.display());
    }
    let config = Config::load(root, options.config_file.as_deref())?;
    let mut files_scanned = 0;
    let mut parse_errors = Vec::new();
    let mut routes = Vec::new();

    let mut rust_files: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| entry.depth() == 0 || !is_skipped_directory(root, entry, options))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rs"))
        .map(|e| e.path().to_path_buf())
        .collect();
    rust_files.sort();

    let mut parsed_files = Vec::new();
    let mut test_only_modules: Vec<(PathBuf, Vec<String>)> = Vec::new();
    for file_path in rust_files {
        files_scanned += 1;
        let source = match fs::read_to_string(&file_path) {
            Ok(source) => source,
            Err(error) => {
                parse_errors.push(format!(
                    "{}: failed to read: {}",
                    file_path.display(),
                    error
                ));
                continue;
            }
        };
        let syntax = match syn::parse_file(&source) {
            Ok(mut syntax) => {
                if !options.include_tests {
                    let (crate_key, module) = module_location(root, &file_path);
                    for name in test_only_module_declarations(&syntax.items) {
                        let mut path = module.clone();
                        path.push(name);
                        test_only_modules.push((crate_key.clone(), path));
                    }
                    strip_test_items(&mut syntax.items);
                }
                syntax
            }
            Err(error) => {
                parse_errors.push(format!("{}: {}", file_path.display(), error));
                continue;
            }
        };
        parsed_files.push((module_location(root, &file_path), file_path, syntax));
    }

    // A module declared `#[cfg(test)] mod tests;` lives in its own file;
    // that file, and the files of its submodules, are test code too.
    if !options.include_tests {
        let test_modules = std::mem::take(&mut test_only_modules);
        parsed_files.retain(|((crate_key, module), _, _)| {
            !test_modules.iter().any(|(test_crate, test_module)| {
                test_crate == crate_key && module.starts_with(test_module)
            })
        });
    }

    // Index every handler definition before extracting routes so that route
    // registrations can resolve handlers defined in other files.
    let crates = workspace_crates(parsed_files.iter().map(|((crate_key, _), _, _)| crate_key));
    let index = HandlerIndex::build(
        parsed_files
            .iter()
            .map(|(location, file_path, syntax)| (file_path.as_path(), location.clone(), syntax)),
        crates,
    );
    middleware::index_path_conditional(parsed_files.iter().map(|(_, _, syntax)| syntax));
    let mut registrations = Vec::new();
    let mut warnings = Vec::new();
    let mut configured = Vec::new();
    let mut table_mounts = Vec::new();
    for (_, file_path, syntax) in &parsed_files {
        let mut visitor = RouteVisitor::new(file_path.clone(), &index);
        visitor.visit_file(syntax);
        routes.extend(visitor.routes);
        registrations.extend(visitor.registrations);
        configured.extend(visitor.configured);
        table_mounts.extend(visitor.table_mounts);
        warnings.extend(visitor.warnings);
    }
    // A scope's prefix is read once per route registered under it.
    warnings.sort();
    warnings.dedup();
    // A function passed to `.configure(f)` registers its routes where it is
    // called; its own top-level visit, with no caller scope, is discarded.
    // That holds only when some chain of such calls starts outside these
    // functions: one reachable only from itself keeps its own routes.
    let configured = reachable_from_roots(&configured);
    let outside_configured = |enclosing: Option<usize>| {
        enclosing.is_none_or(|definition| !configured.contains(&definition))
    };
    routes.retain(|route| outside_configured(route.origin.enclosing));
    registrations.retain(|registration| outside_configured(registration.enclosing));
    table_mounts.retain(|mount| outside_configured(mount.enclosing));
    let tables = route_tables::route_tables(
        parsed_files
            .iter()
            .map(|(location, file_path, syntax)| (location, file_path.as_path(), syntax)),
    );
    let (table_routes, unmounted) = route_tables::table_routes(&index, &tables, &table_mounts);
    routes.extend(table_routes);
    if !unmounted.is_empty() {
        warnings.push(format!(
            "{} route table(s) are declared but never mounted with `.configure(..)` in code Archer could follow, so they are left out: {}",
            unmounted.len(),
            unmounted.iter().take(5).cloned().collect::<Vec<_>>().join("; ")
        ));
    }
    let (mut routes, unregistered) = apply_registrations(routes, &registrations);
    if !unregistered.is_empty() {
        warnings.push(format!(
            "{} attribute route(s) are declared but never registered with `.service(..)` in code Archer could follow, so they are left out: {}",
            unregistered.len(),
            unregistered.iter().take(5).cloned().collect::<Vec<_>>().join("; ")
        ));
    }
    // Builder chains are visited outermost call first; report routes in the
    // order they are written.
    routes.sort_by(|a, b| (&a.file, a.origin.position).cmp(&(&b.file, b.origin.position)));

    // Requirement subjects describe what a privilege check requires; on
    // identity or unrecognized evidence they would only be noise.
    for route in &mut routes {
        for evidence in &mut route.authorization {
            if EvidenceTier::of(&evidence.kind) != EvidenceTier::Privilege {
                evidence.requirements.clear();
            }
        }
        route.requirement = Requirement::of(route);
    }

    let keys = resources::resource_keys(
        &index,
        parsed_files.iter().map(|(_, _, syntax)| syntax),
        &routes,
    );
    for (route, keys) in routes.iter_mut().zip(keys) {
        route.resource_keys = keys;
    }
    let uses = caller_use::caller_use(
        &index,
        parsed_files.iter().map(|(_, _, syntax)| syntax),
        &routes,
    );
    for (route, uses) in routes.iter_mut().zip(uses) {
        route.caller_use = uses;
    }

    // Routes declared public by design are left out of every comparison:
    // they are not judged and do not count as anyone's peers.
    let mut declared_public = Vec::new();
    let judged_routes: Vec<Route> = routes
        .iter()
        .filter(|route| match config.public_rule(route) {
            Some(rule) => {
                declared_public.push(UnjudgedRoute::new(
                    route,
                    UnjudgedReason::DeclaredPublic,
                    rule.reason.clone(),
                ));
                false
            }
            None => true,
        })
        .cloned()
        .collect();
    let (peer_groups, invariants, finding_details, _, mut unjudged) =
        build_analysis_layers_full(&judged_routes, options);
    unjudged.extend(declared_public);
    let mut dismissed = Vec::new();
    let finding_details: Vec<Finding> = finding_details
        .into_iter()
        .filter_map(|finding| match config.dismiss_rule(&finding) {
            Some((rule, dismiss)) => {
                dismissed.push(DismissedFinding {
                    reason: dismiss.reason.clone(),
                    rule,
                    finding,
                });
                None
            }
            None => Some(finding),
        })
        .collect();
    let findings: Vec<String> = finding_details.iter().map(format_finding).collect();
    warnings.extend(config.unused_rules(&routes, &dismissed));
    if !unjudged.is_empty() {
        let mut counts: Vec<(UnjudgedReason, usize)> = Vec::new();
        for route in &unjudged {
            match counts.iter_mut().find(|(reason, _)| *reason == route.reason) {
                Some((_, count)) => *count += 1,
                None => counts.push((route.reason, 1)),
            }
        }
        counts.sort();
        warnings.push(format!(
            "{} of {} routes were not compared with any peers ({}); see `unjudged` for each route's reason",
            unjudged.len(),
            routes.len(),
            counts
                .iter()
                .map(|(reason, count)| format!("{count} {reason}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let mut coverage = coverage(&index, &routes);
    coverage.unregistered_attribute_routes = unregistered.len();
    coverage.macro_registrations = macro_registrations(
        parsed_files.iter().map(|(_, _, syntax)| syntax),
        &coverage.unrouted_names,
    );
    for (name, handlers) in &coverage.macro_registrations {
        warnings.push(format!(
            "{handlers} unrouted handler(s) are named inside macro `{name}`; routes registered by macros are not analyzed"
        ));
    }
    if coverage.routed_handlers < coverage.likely_handlers {
        warnings.push(format!(
            "{} of {} functions that look like handlers are not reached by any route, for example {}",
            coverage.likely_handlers - coverage.routed_handlers,
            coverage.likely_handlers,
            coverage.unrouted_examples.join(", ")
        ));
    }
    if coverage.likely_handlers >= 10
        && coverage.routed_handlers * 2 < coverage.likely_handlers
    {
        warnings.push(format!(
            "only {} of {} functions that look like request handlers are reached by a route Archer could read; routes may be registered in a way it cannot follow (such as a custom routing macro), so a clean report says little",
            coverage.routed_handlers, coverage.likely_handlers
        ));
    }

    Ok(Report {
        files_scanned,
        parse_errors,
        warnings,
        routes,
        peer_groups,
        invariants,
        coverage,
        findings,
        finding_details,
        unjudged,
        config: config.source.clone(),
        dismissed,
    })
}

/// Targets of `(caller, target)` expansion edges that are reachable from a
/// caller which is not itself a target.
fn reachable_from_roots(edges: &[(Option<usize>, usize)]) -> HashSet<usize> {
    let targets: HashSet<usize> = edges.iter().map(|&(_, target)| target).collect();
    let mut reached: HashSet<usize> = HashSet::new();
    let mut pending: Vec<usize> = edges
        .iter()
        .filter(|(caller, _)| caller.is_none_or(|caller| !targets.contains(&caller)))
        .map(|&(_, target)| target)
        .collect();
    while let Some(target) = pending.pop() {
        if reached.insert(target) {
            pending.extend(
                edges
                    .iter()
                    .filter(|(caller, _)| *caller == Some(target))
                    .map(|&(_, next)| next),
            );
        }
    }
    reached
}

/// The library crates among the scanned crate directories, by the name other
/// crates import them under: `[lib] name`, else `[package] name` with `-`
/// read as `_`. A name two crates share resolves to neither.
fn workspace_crates<'p>(crate_keys: impl IntoIterator<Item = &'p PathBuf>) -> HashMap<String, PathBuf> {
    let mut seen: HashSet<&PathBuf> = HashSet::new();
    let mut crates: HashMap<String, Option<PathBuf>> = HashMap::new();
    for crate_key in crate_keys {
        if !seen.insert(crate_key) {
            continue;
        }
        let Ok(manifest) = fs::read_to_string(crate_key.join("Cargo.toml")) else {
            continue;
        };
        let Some(name) = library_name(&manifest) else {
            continue;
        };
        crates
            .entry(name)
            .and_modify(|existing| {
                if existing.as_ref() != Some(crate_key) {
                    *existing = None;
                }
            })
            .or_insert_with(|| Some(crate_key.clone()));
    }
    crates
        .into_iter()
        .filter_map(|(name, key)| Some((name, key?)))
        .collect()
}

/// The crate name a manifest's library is imported under, read from the
/// `name` keys of its `[lib]` and `[package]` tables.
pub(crate) fn library_name(manifest: &str) -> Option<String> {
    let mut section = String::new();
    let mut package = None;
    let mut lib = None;
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            section = line.trim_matches(|c| c == '[' || c == ']').trim().to_owned();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "name" {
            continue;
        }
        let value = value.trim().trim_matches('"').to_owned();
        match section.as_str() {
            "package" => package = Some(value),
            "lib" => lib = Some(value),
            _ => {}
        }
    }
    lib.or(package).map(|name| name.replace('-', "_"))
}

/// Removes items compiled only for tests (`#[cfg(test)] mod tests`, test
/// helpers): their routes are test fixtures, not the application's.
fn strip_test_items(items: &mut Vec<syn::Item>) {
    items.retain(|item| !item_attributes(item).iter().any(is_test_only_cfg));
    for item in items {
        match item {
            syn::Item::Mod(module) => {
                if let Some((_, content)) = &mut module.content {
                    strip_test_items(content);
                }
            }
            syn::Item::Impl(implementation) => implementation.items.retain(|item| match item {
                syn::ImplItem::Fn(function) => !function.attrs.iter().any(is_test_only_cfg),
                _ => true,
            }),
            _ => {}
        }
    }
}

fn item_attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        _ => &[],
    }
}

/// `#[cfg(test)]`, or an `all(..)` that requires `test`.
fn is_test_only_cfg(attribute: &syn::Attribute) -> bool {
    if !attribute.path().is_ident("cfg") {
        return false;
    }
    let Ok(list) = attribute.meta.require_list() else {
        return false;
    };
    let predicate: String = list
        .tokens
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    predicate == "test"
        || (predicate.starts_with("all(")
            && predicate[4..predicate.len().saturating_sub(1)]
                .split(',')
                .any(|part| part == "test"))
}

/// Free functions that look like request handlers, and how many a route reaches.
fn coverage(index: &HandlerIndex, routes: &[Route]) -> Coverage {
    let routed: HashSet<usize> = routes
        .iter()
        .filter_map(|route| route.origin.definition)
        .collect();
    let routed_names: HashSet<&str> = routes
        .iter()
        .filter_map(|route| route.handler.as_deref())
        .collect();
    let mut coverage = Coverage::default();
    for (index_position, item) in index.items.iter().enumerate() {
        if !looks_like_handler(item) {
            continue;
        }
        coverage.likely_handlers += 1;
        let definition = &index.definitions[index_position];
        if routed.contains(&index_position) || routed_names.contains(definition.name.as_str()) {
            coverage.routed_handlers += 1;
        } else {
            coverage.unrouted_names.insert(definition.name.clone());
            if coverage.unrouted_examples.len() < 5 {
                coverage.unrouted_examples.push(format!(
                    "{}:{} {}",
                    definition.file.display(),
                    item.sig.ident.span().start().line,
                    definition.name
                ));
            }
        }
    }
    coverage.unresolved_handlers = routes
        .iter()
        .filter(|route| {
            matches!(
                route.handler_resolution,
                Some(HandlerResolution::Unresolved | HandlerResolution::Ambiguous { .. })
            )
        })
        .count();
    coverage.unresolved_paths = routes
        .iter()
        .filter(|route| has_unresolved_segment(&route.path))
        .count();
    coverage
}

/// Macros (function-like or attribute) whose tokens name unrouted handlers,
/// with how many distinct handlers each names: routes such a macro may
/// register are invisible to Archer. Macros that only document handlers
/// (`#[openapi(paths(..))]`) are counted too; the warning says "may".
fn macro_registrations<'a>(
    files: impl IntoIterator<Item = &'a syn::File>,
    unrouted: &HashSet<String>,
) -> Vec<(String, usize)> {
    use quote::ToTokens;
    use syn::visit::Visit;
    struct MacroVisitor<'u> {
        unrouted: &'u HashSet<String>,
        named: HashMap<String, HashSet<String>>,
    }
    // Standard, logging, test, and JSON macros never register routes.
    const NON_REGISTERING: [&str; 33] = [
        "format", "format_args", "print", "println", "eprint", "eprintln", "write", "writeln",
        "panic", "assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq",
        "debug_assert_ne", "vec", "matches", "todo", "unimplemented", "unreachable", "dbg",
        "macro_rules", "cfg", "cfg_select", "concat", "stringify", "json", "select", "trace",
        "debug", "info", "warn", "error",
    ];
    impl MacroVisitor<'_> {
        fn scan(&mut self, path: &syn::Path, tokens: proc_macro2::TokenStream) {
            if path
                .segments
                .last()
                .is_some_and(|segment| NON_REGISTERING.contains(&segment.ident.to_string().as_str()))
            {
                return;
            }
            fn idents(tokens: proc_macro2::TokenStream, out: &mut Vec<String>) {
                for token in tokens {
                    match token {
                        proc_macro2::TokenTree::Ident(ident) => out.push(ident.to_string()),
                        proc_macro2::TokenTree::Group(group) => idents(group.stream(), out),
                        _ => {}
                    }
                }
            }
            let mut found = Vec::new();
            idents(tokens, &mut found);
            let name = path.to_token_stream().to_string().replace(' ', "");
            for ident in found {
                if self.unrouted.contains(&ident) {
                    self.named.entry(name.clone()).or_default().insert(ident);
                }
            }
        }
    }
    impl<'ast> Visit<'ast> for MacroVisitor<'_> {
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            self.scan(&node.path, node.tokens.clone());
        }
        fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
            if let syn::Meta::List(list) = &node.meta {
                self.scan(&list.path, list.tokens.clone());
            }
        }
    }
    if unrouted.is_empty() {
        return Vec::new();
    }
    let mut visitor = MacroVisitor { unrouted, named: HashMap::new() };
    for file in files {
        visitor.visit_file(file);
    }
    let mut named: Vec<(String, usize)> = visitor
        .named
        .into_iter()
        .map(|(name, handlers)| (name, handlers.len()))
        .collect();
    named.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    named
}

/// An async free function taking an Actix extractor or returning a response.
fn looks_like_handler(item: &syn::ItemFn) -> bool {
    use quote::ToTokens;
    if item.sig.asyncness.is_none() {
        return false;
    }
    const EXTRACTORS: [&str; 9] = [
        "Json", "Path", "Query", "Form", "Data", "ReqData", "Payload", "HttpRequest", "Bytes",
    ];
    let extractor = item.sig.inputs.iter().any(|input| match input {
        syn::FnArg::Typed(typed) => match &*typed.ty {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .is_some_and(|segment| EXTRACTORS.contains(&segment.ident.to_string().as_str())),
            _ => false,
        },
        syn::FnArg::Receiver(_) => false,
    });
    let output = item.sig.output.to_token_stream().to_string();
    extractor || output.contains("HttpResponse") || output.contains("Responder")
}

/// Names of out-of-line modules (`mod tests;`) declared only for tests.
fn test_only_module_declarations(items: &[syn::Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module)
                if module.content.is_none() && module.attrs.iter().any(is_test_only_cfg) =>
            {
                Some(module.ident.to_string())
            }
            _ => None,
        })
        .collect()
}
