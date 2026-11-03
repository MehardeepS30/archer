//! Repository analysis: file discovery, parsing, and the extraction and inference pipeline.

mod drift;
mod evidence;
mod handlers;
mod model;
mod routes;
#[cfg(test)]
mod tests;

pub use drift::format_finding;
pub use model::*;

use anyhow::Result;
use std::{
    collections::HashSet,
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
            Ok(syntax) => syntax,
            Err(error) => {
                parse_errors.push(format!("{}: {}", file_path.display(), error));
                continue;
            }
        };
        parsed_files.push((module_location(root, &file_path), file_path, syntax));
    }

    // Index every handler definition before extracting routes so that route
    // registrations can resolve handlers defined in other files.
    let index = HandlerIndex::build(
        parsed_files
            .iter()
            .map(|(location, file_path, syntax)| (file_path.as_path(), location.clone(), syntax)),
    );
    let mut registrations = Vec::new();
    let mut warnings = Vec::new();
    let mut configured = Vec::new();
    for (_, file_path, syntax) in &parsed_files {
        let mut visitor = RouteVisitor::new(file_path.clone(), &index);
        visitor.visit_file(syntax);
        routes.extend(visitor.routes);
        registrations.extend(visitor.registrations);
        configured.extend(visitor.configured);
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
    let mut routes = apply_registrations(routes, &registrations);
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
    }

    let (peer_groups, invariants, finding_details, findings) =
        build_analysis_layers_with(&routes, options);

    Ok(Report {
        files_scanned,
        parse_errors,
        warnings,
        routes,
        peer_groups,
        invariants,
        findings,
        finding_details,
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
