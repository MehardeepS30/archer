//! Handler index: every free function in the repository and Rust-style path resolution to it.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use syn::{Item, ItemFn, UseTree};

use super::{evidence::*, model::*, routes::*};

pub(crate) type ModuleKey = (PathBuf, Vec<String>);

pub(crate) const MAX_RESOLUTION_DEPTH: usize = 16;

/// How many calls deep a handler's helpers are searched for evidence.
pub(crate) const MAX_HELPER_DEPTH: usize = 3;

#[derive(Debug, Clone)]
pub(crate) struct HandlerDefinition {
    pub(crate) file: PathBuf,
    pub(crate) crate_key: PathBuf,
    pub(crate) module: Vec<String>,
    pub(crate) name: String,
    /// The function's own evidence combined with its helpers'.
    pub(crate) evidence: Vec<AuthEvidence>,
    /// The function's own evidence and calls, before helpers are combined.
    pub(crate) own: FunctionEvidence,
}

/// Resolved calls of one function: `(callee, enforced)` for its body, and
/// the callees in its returned predicate.
#[derive(Debug, Default)]
pub(crate) struct ResolvedCalls {
    pub(crate) calls: Vec<(usize, bool)>,
    pub(crate) predicate_calls: Vec<usize>,
}

impl HandlerDefinition {
    pub(crate) fn rust_path(&self) -> String {
        std::iter::once("crate")
            .chain(self.module.iter().map(String::as_str))
            .chain(std::iter::once(self.name.as_str()))
            .collect::<Vec<_>>()
            .join("::")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UsePath {
    pub(crate) segments: Vec<String>,
    pub(crate) leading_colon: bool,
}

#[derive(Debug, Default)]
pub(crate) struct ModuleScope {
    pub(crate) imports: HashMap<String, Vec<UsePath>>,
    pub(crate) globs: Vec<UsePath>,
}

pub(crate) enum Lookup {
    Found(usize, HandlerResolution),
    Ambiguous(Vec<usize>),
    /// `explicit` marks lookups that an explicit import or an unresolvable
    /// path already pinned to something outside the index; these never fall
    /// back to unique-name matching.
    NotFound {
        explicit: bool,
    },
}

/// Every free function in the scanned repository, keyed by crate and module
/// path, together with each module's `use` declarations.
#[derive(Default)]
pub(crate) struct HandlerIndex<'a> {
    pub(crate) definitions: Vec<HandlerDefinition>,
    /// The syntax of each definition, parallel to `definitions`, so that
    /// `.configure(f)` can visit `f`'s body.
    pub(crate) items: Vec<&'a ItemFn>,
    /// `const NAME: &str = "..."` items, keyed by crate, module, and name.
    pub(crate) consts: HashMap<(PathBuf, Vec<String>, String), String>,
    pub(crate) by_name: HashMap<String, Vec<usize>>,
    pub(crate) scopes: HashMap<ModuleKey, ModuleScope>,
    pub(crate) modules: HashSet<ModuleKey>,
    pub(crate) file_modules: HashMap<PathBuf, ModuleKey>,
}

impl<'a> HandlerIndex<'a> {
    pub(crate) fn build(
        files: impl IntoIterator<Item = (&'a Path, ModuleKey, &'a syn::File)>,
    ) -> Self {
        let mut index = Self::default();
        for (file, (crate_key, mut module), syntax) in files {
            for depth in 0..=module.len() {
                index
                    .modules
                    .insert((crate_key.clone(), module[..depth].to_vec()));
            }
            index
                .file_modules
                .insert(file.to_path_buf(), (crate_key.clone(), module.clone()));
            index.add_items(file, &crate_key, &mut module, &syntax.items);
        }
        index.add_helper_evidence();
        index
    }

    /// Adds to each function the evidence of the repository functions it
    /// calls, up to `MAX_HELPER_DEPTH` calls deep, so that a handler whose
    /// check sits in a wrapper (`ensure_can_manage(&user)` calling
    /// `require_admin`) is not reported as unauthorized. A helper's own
    /// enforced checks count wherever it is called; the predicate a `bool`
    /// helper returns (`fn can_edit(u) -> bool { u.role == Role::Admin }`)
    /// counts only where the caller enforces it. Only calls that resolve by
    /// Rust's scoping rules count; a unique-name guess does not, since wrongly
    /// added evidence would hide a finding. The evidence keeps the callee's
    /// location; its symbol names the call path.
    pub(crate) fn add_helper_evidence(&mut self) {
        let resolved: Vec<ResolvedCalls> = (0..self.definitions.len())
            .map(|definition| self.resolved_calls(definition))
            .collect();
        let combined: Vec<Vec<AuthEvidence>> = (0..self.definitions.len())
            .map(|definition| {
                let mut evidence = self.definitions[definition].own.evidence.clone();
                let mut stack = vec![definition];
                self.gather(
                    definition,
                    definition,
                    String::new(),
                    false,
                    0,
                    &resolved,
                    &mut stack,
                    &mut evidence,
                );
                evidence
            })
            .collect();
        for (definition, evidence) in self.definitions.iter_mut().zip(combined) {
            definition.evidence = evidence;
        }
    }

    /// Adds the evidence that `current`, reached from `root` through `via`,
    /// contributes: its own enforced checks, its returned predicate when the
    /// caller enforces it, and its callees' in turn.
    #[allow(clippy::too_many_arguments)]
    fn gather(
        &self,
        root: usize,
        current: usize,
        via: String,
        predicate: bool,
        depth: usize,
        resolved: &[ResolvedCalls],
        stack: &mut Vec<usize>,
        out: &mut Vec<AuthEvidence>,
    ) {
        let own = &self.definitions[current].own;
        let contributed = (current != root)
            .then_some(own.evidence.iter())
            .into_iter()
            .flatten()
            .chain(
                predicate
                    .then_some(own.predicate_evidence.iter())
                    .into_iter()
                    .flatten(),
            );
        for found in contributed {
            let mut found = found.clone();
            found.handler = Some(self.definitions[root].name.clone());
            found.symbol = Some(format!(
                "{via} -> {}",
                found.symbol.as_deref().unwrap_or(&found.mechanism)
            ));
            if !out.iter().any(|existing| {
                existing.kind == found.kind
                    && existing.file == found.file
                    && existing.line == found.line
            }) {
                out.push(found);
            }
        }
        if depth == MAX_HELPER_DEPTH {
            return;
        }
        let calls = &resolved[current];
        let next: Vec<(usize, bool)> = calls
            .calls
            .iter()
            .copied()
            .chain(
                predicate
                    .then_some(calls.predicate_calls.iter().map(|&callee| (callee, true)))
                    .into_iter()
                    .flatten(),
            )
            .collect();
        for (callee, enforced) in next {
            if stack.contains(&callee) {
                continue;
            }
            stack.push(callee);
            let name = &self.definitions[callee].name;
            let via = if via.is_empty() {
                name.clone()
            } else {
                format!("{via} -> {name}")
            };
            self.gather(root, callee, via, enforced, depth + 1, resolved, stack, out);
            stack.pop();
        }
    }

    /// Repository functions that a function's body calls by path, with
    /// whether the call's result is enforced.
    fn resolved_calls(&self, definition: usize) -> ResolvedCalls {
        let caller = &self.definitions[definition];
        let resolve = |target: &HandlerTarget| match self.resolve_handler_index(
            &caller.crate_key,
            &caller.module,
            target,
        ) {
            (Some(callee), resolution)
                if !matches!(resolution, HandlerResolution::UniqueName) && callee != definition =>
            {
                Some(callee)
            }
            _ => None,
        };
        let mut resolved = ResolvedCalls::default();
        for call in &caller.own.calls {
            if let Some(callee) = resolve(&call.target) {
                let enforced = call.use_ == Use::Enforcing;
                match resolved
                    .calls
                    .iter_mut()
                    .find(|(existing, _)| *existing == callee)
                {
                    Some((_, existing)) => *existing |= enforced,
                    None => resolved.calls.push((callee, enforced)),
                }
            }
        }
        for target in &caller.own.predicate_calls {
            if let Some(callee) = resolve(target)
                && !resolved.predicate_calls.contains(&callee)
            {
                resolved.predicate_calls.push(callee);
            }
        }
        resolved
    }

    #[cfg(test)]
    pub(crate) fn single_file(file: &'a Path, syntax: &'a syn::File) -> Self {
        Self::build([(file, (file.to_path_buf(), Vec::new()), syntax)])
    }

    pub(crate) fn add_items(
        &mut self,
        file: &Path,
        crate_key: &Path,
        module: &mut Vec<String>,
        items: &'a [Item],
    ) {
        for item in items {
            match item {
                Item::Fn(function) => {
                    let name = function.sig.ident.to_string();
                    self.by_name
                        .entry(name.clone())
                        .or_default()
                        .push(self.definitions.len());
                    self.items.push(function);
                    self.definitions.push(HandlerDefinition {
                        file: file.to_path_buf(),
                        crate_key: crate_key.to_path_buf(),
                        module: module.clone(),
                        name,
                        evidence: Vec::new(),
                        own: function_evidence(file, function),
                    });
                }
                Item::Mod(item_mod) => {
                    module.push(item_mod.ident.to_string());
                    self.modules
                        .insert((crate_key.to_path_buf(), module.clone()));
                    if let Some((_, items)) = &item_mod.content {
                        self.add_items(file, crate_key, module, items);
                    }
                    module.pop();
                }
                Item::Const(item_const) => {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(value),
                        ..
                    }) = &*item_const.expr
                    {
                        self.consts.insert(
                            (
                                crate_key.to_path_buf(),
                                module.clone(),
                                item_const.ident.to_string(),
                            ),
                            value.value(),
                        );
                    }
                }
                Item::Use(item_use) => {
                    let scope = self
                        .scopes
                        .entry((crate_key.to_path_buf(), module.clone()))
                        .or_default();
                    collect_use_tree(
                        &item_use.tree,
                        &mut Vec::new(),
                        item_use.leading_colon.is_some(),
                        scope,
                    );
                }
                _ => {}
            }
        }
    }

    pub(crate) fn is_module(&self, crate_key: &Path, module: &[String]) -> bool {
        self.modules
            .contains(&(crate_key.to_path_buf(), module.to_vec()))
    }

    pub(crate) fn scope(&self, crate_key: &Path, module: &[String]) -> Option<&ModuleScope> {
        self.scopes.get(&(crate_key.to_path_buf(), module.to_vec()))
    }

    pub(crate) fn definitions_named<'s>(
        &'s self,
        crate_key: &'s Path,
        name: &str,
    ) -> impl Iterator<Item = usize> + 's {
        self.by_name
            .get(name)
            .into_iter()
            .flatten()
            .copied()
            .filter(move |&index| self.definitions[index].crate_key == crate_key)
    }

    /// Resolves a handler expression from the module that registers the route.
    pub(crate) fn resolve_handler(
        &self,
        crate_key: &Path,
        module: &[String],
        target: &HandlerTarget,
    ) -> (Option<&HandlerDefinition>, HandlerResolution) {
        let (index, resolution) = self.resolve_handler_index(crate_key, module, target);
        (index.map(|index| &self.definitions[index]), resolution)
    }

    /// The value of a string constant named by `segments` as written in
    /// `module`: defined there, brought in by one explicit `use`, or
    /// module-qualified.
    pub(crate) fn resolve_const(
        &self,
        crate_key: &Path,
        module: &[String],
        segments: &[String],
    ) -> Option<String> {
        let (name, qualifier) = segments.split_last()?;
        let lookup = |module: &[String]| {
            self.consts
                .get(&(crate_key.to_path_buf(), module.to_vec(), name.clone()))
                .cloned()
        };
        if !qualifier.is_empty() {
            let qualifier = UsePath {
                segments: qualifier.to_vec(),
                leading_colon: false,
            };
            return lookup(&self.resolve_module(crate_key, module, &qualifier, 0)?);
        }
        if let Some(value) = lookup(module) {
            return Some(value);
        }
        let [import] = self.scope(crate_key, module)?.imports.get(name)?.as_slice() else {
            return None;
        };
        let (_, prefix) = import.segments.split_last()?;
        let prefix = UsePath {
            segments: prefix.to_vec(),
            leading_colon: import.leading_colon,
        };
        lookup(&self.resolve_module(crate_key, module, &prefix, 0)?)
    }

    /// The top-level function `name` defined directly in `module`, if exactly one is.
    pub(crate) fn definition_in(
        &self,
        crate_key: &Path,
        module: &[String],
        name: &str,
    ) -> Option<usize> {
        let mut matches = self
            .definitions_named(crate_key, name)
            .filter(|&index| self.definitions[index].module == module);
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }

    /// Like `resolve_handler`, returning the definition's index.
    pub(crate) fn resolve_handler_index(
        &self,
        crate_key: &Path,
        module: &[String],
        target: &HandlerTarget,
    ) -> (Option<usize>, HandlerResolution) {
        let HandlerTarget::Path {
            segments,
            leading_colon,
        } = target
        else {
            return (None, HandlerResolution::Unresolved);
        };
        if *leading_colon {
            return (None, HandlerResolution::Unresolved);
        }
        let Some((name, qualifier)) = segments.split_last() else {
            return (None, HandlerResolution::Unresolved);
        };

        let (lookup, qualifier_module) = if qualifier.is_empty() {
            let lookup = self.resolve_item(crate_key, module, name, &mut HashSet::new(), 0);
            (lookup, None)
        } else {
            let qualifier_path = UsePath {
                segments: qualifier.to_vec(),
                leading_colon: false,
            };
            let Some(qualifier_module) = self.resolve_module(crate_key, module, &qualifier_path, 0)
            else {
                return (None, HandlerResolution::Unresolved);
            };
            let mut visited = HashSet::new();
            let lookup =
                match self.resolve_item(crate_key, &qualifier_module, name, &mut visited, 0) {
                    Lookup::Found(index, _) => Lookup::Found(index, HandlerResolution::Qualified),
                    other => other,
                };
            (lookup, Some(qualifier_module))
        };

        match lookup {
            Lookup::Found(index, resolution) => (Some(index), resolution),
            Lookup::Ambiguous(candidates) => (None, self.ambiguous(candidates)),
            Lookup::NotFound { explicit: true } => (None, HandlerResolution::Unresolved),
            Lookup::NotFound { explicit: false } => {
                let candidates: Vec<usize> = self
                    .definitions_named(crate_key, name)
                    .filter(|&index| {
                        qualifier_module.as_ref().is_none_or(|qualifier| {
                            self.definitions[index].module.starts_with(qualifier)
                        })
                    })
                    .collect();
                match candidates.as_slice() {
                    [] => (None, HandlerResolution::Unresolved),
                    [index] => (Some(*index), HandlerResolution::UniqueName),
                    _ => (None, self.ambiguous(candidates)),
                }
            }
        }
    }

    pub(crate) fn ambiguous(&self, candidates: Vec<usize>) -> HandlerResolution {
        let mut candidates: Vec<String> = candidates
            .into_iter()
            .map(|index| self.definitions[index].rust_path())
            .collect();
        candidates.sort();
        HandlerResolution::Ambiguous { candidates }
    }

    /// Resolves `name` as seen from `module`: local definitions first, then
    /// explicit imports, then glob imports, mirroring Rust's shadowing order.
    pub(crate) fn resolve_item(
        &self,
        crate_key: &Path,
        module: &[String],
        name: &str,
        visited: &mut HashSet<(Vec<String>, String)>,
        depth: usize,
    ) -> Lookup {
        if depth > MAX_RESOLUTION_DEPTH || !visited.insert((module.to_vec(), name.to_owned())) {
            return Lookup::NotFound { explicit: true };
        }

        let local: Vec<usize> = self
            .definitions_named(crate_key, name)
            .filter(|&index| self.definitions[index].module == module)
            .collect();
        match local.as_slice() {
            [index] => return Lookup::Found(*index, HandlerResolution::Local),
            [_, _, ..] => return Lookup::Ambiguous(local),
            [] => {}
        }

        let Some(scope) = self.scope(crate_key, module) else {
            return Lookup::NotFound { explicit: false };
        };
        if let Some(imports) = scope.imports.get(name) {
            let lookups = imports
                .iter()
                .map(|path| self.resolve_use_item(crate_key, module, path, visited, depth + 1))
                .collect();
            return combine_lookups(lookups, HandlerResolution::Imported)
                .unwrap_or(Lookup::NotFound { explicit: true });
        }

        let lookups = scope
            .globs
            .iter()
            .filter_map(|glob| self.resolve_module(crate_key, module, glob, depth + 1))
            .map(|glob_module| self.resolve_item(crate_key, &glob_module, name, visited, depth + 1))
            .collect();
        combine_lookups(lookups, HandlerResolution::GlobImported)
            .unwrap_or(Lookup::NotFound { explicit: false })
    }

    pub(crate) fn resolve_use_item(
        &self,
        crate_key: &Path,
        module: &[String],
        path: &UsePath,
        visited: &mut HashSet<(Vec<String>, String)>,
        depth: usize,
    ) -> Lookup {
        let Some((name, prefix)) = path.segments.split_last() else {
            return Lookup::NotFound { explicit: true };
        };
        if prefix.is_empty() {
            return Lookup::NotFound { explicit: true };
        }
        let prefix = UsePath {
            segments: prefix.to_vec(),
            leading_colon: path.leading_colon,
        };
        match self.resolve_module(crate_key, module, &prefix, depth) {
            Some(target) => match self.resolve_item(crate_key, &target, name, visited, depth) {
                Lookup::NotFound { .. } => Lookup::NotFound { explicit: true },
                lookup => lookup,
            },
            None => Lookup::NotFound { explicit: true },
        }
    }

    /// Resolves a module path written in `module` to an absolute module path
    /// within the crate. Paths into other crates return `None`.
    pub(crate) fn resolve_module(
        &self,
        crate_key: &Path,
        module: &[String],
        path: &UsePath,
        depth: usize,
    ) -> Option<Vec<String>> {
        if path.leading_colon || depth > MAX_RESOLUTION_DEPTH {
            return None;
        }
        let segments = &path.segments;
        let (mut resolved, rest): (Vec<String>, &[String]) =
            match segments.first().map(String::as_str) {
                None => return Some(module.to_vec()),
                Some("crate") => (Vec::new(), &segments[1..]),
                Some("self") => (module.to_vec(), &segments[1..]),
                Some("super") => {
                    let supers = segments
                        .iter()
                        .take_while(|segment| *segment == "super")
                        .count();
                    if supers > module.len() {
                        return None;
                    }
                    (
                        module[..module.len() - supers].to_vec(),
                        &segments[supers..],
                    )
                }
                Some(first) => {
                    let mut child = module.to_vec();
                    child.push(first.to_owned());
                    if self.is_module(crate_key, &child) {
                        (child, &segments[1..])
                    } else {
                        let imports = self.scope(crate_key, module)?.imports.get(first)?;
                        let [import] = imports.as_slice() else {
                            return None;
                        };
                        (
                            self.resolve_module(crate_key, module, import, depth + 1)?,
                            &segments[1..],
                        )
                    }
                }
            };
        resolved.extend(rest.iter().cloned());
        self.is_module(crate_key, &resolved).then_some(resolved)
    }
}

/// Merges lookups through several imports. Distinct definitions, or any
/// ambiguous branch, make the whole lookup ambiguous; evidence is never merged.
pub(crate) fn combine_lookups(
    lookups: Vec<Lookup>,
    resolution: HandlerResolution,
) -> Option<Lookup> {
    let mut found = Vec::new();
    let mut ambiguous = false;
    for lookup in lookups {
        let indices = match lookup {
            Lookup::Found(index, _) => vec![index],
            Lookup::Ambiguous(indices) => {
                ambiguous = true;
                indices
            }
            Lookup::NotFound { .. } => continue,
        };
        for index in indices {
            if !found.contains(&index) {
                found.push(index);
            }
        }
    }
    match found.as_slice() {
        [] => None,
        [index] if !ambiguous => Some(Lookup::Found(*index, resolution)),
        _ => Some(Lookup::Ambiguous(found)),
    }
}

pub(crate) fn collect_use_tree(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    leading_colon: bool,
    scope: &mut ModuleScope,
) {
    let mut import = |alias: String, ident: String, prefix: &Vec<String>| {
        if alias == "_" {
            return;
        }
        let mut segments = prefix.clone();
        if ident != "self" {
            segments.push(ident);
        }
        scope.imports.entry(alias).or_default().push(UsePath {
            segments,
            leading_colon,
        });
    };
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_tree(&path.tree, prefix, leading_colon, scope);
            prefix.pop();
        }
        UseTree::Name(name) => {
            let ident = name.ident.to_string();
            let alias = if ident == "self" {
                match prefix.last() {
                    Some(last) => last.clone(),
                    None => return,
                }
            } else {
                ident.clone()
            };
            import(alias, ident, prefix);
        }
        UseTree::Rename(rename) => {
            import(rename.rename.to_string(), rename.ident.to_string(), prefix);
        }
        UseTree::Glob(_) => scope.globs.push(UsePath {
            segments: prefix.clone(),
            leading_colon,
        }),
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(item, prefix, leading_colon, scope);
            }
        }
    }
}

/// Maps a scanned file to its crate and module path using Cargo's
/// conventional layout. Files outside `src/` (tests, examples, build
/// scripts) and binaries under `src/bin/` get their own isolated namespace.
pub(crate) fn module_location(root: &Path, file: &Path) -> ModuleKey {
    let isolated = || (file.to_path_buf(), Vec::new());
    let crate_dir = file
        .ancestors()
        .skip(1)
        .take_while(|directory| directory.starts_with(root))
        .find(|directory| directory.join("Cargo.toml").is_file())
        .unwrap_or(root);
    let source_dir = crate_dir.join("src");
    let relative = if source_dir.is_dir() {
        file.strip_prefix(&source_dir)
    } else {
        file.strip_prefix(crate_dir)
    };
    let Ok(relative) = relative else {
        return isolated();
    };
    let mut segments: Vec<String> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    let Some(file_name) = segments.pop() else {
        return isolated();
    };
    if segments.first().is_some_and(|segment| segment == "bin") {
        return isolated();
    }
    let stem = file_name.strip_suffix(".rs").unwrap_or(&file_name);
    let crate_root = segments.is_empty() && (stem == "main" || stem == "lib");
    if !crate_root && stem != "mod" {
        segments.push(stem.to_owned());
    }
    (crate_dir.to_path_buf(), segments)
}
