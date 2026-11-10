//! Handler index: every free function in the repository and Rust-style path resolution to it.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use std::borrow::Cow;
use syn::{ImplItem, Item, ItemFn, Type, UseTree};

use super::{caller_use::block_rejects, evidence::*, model::*, routes::*};

pub(crate) type ModuleKey = (PathBuf, Vec<String>);

pub(crate) const MAX_RESOLUTION_DEPTH: usize = 16;


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
    /// Its `#[cfg(..)]` attributes, as written, so that a call can pick the
    /// variant compiled with the caller (`#[cfg(feature = "v1")]`).
    pub(crate) cfg: Vec<String>,
    /// Its body is only a placeholder (`todo!()`, `unimplemented!()`).
    pub(crate) stub: bool,
    /// For a method or associated function, the type of its `impl` block.
    /// Methods are reached through calls only, never as route handlers.
    pub(crate) owner: Option<String>,
}

/// Resolved calls of one function: `(callee, enforced)` for its body, and
/// the callees in its returned predicate.
#[derive(Debug, Default)]
pub(crate) struct ResolvedCalls {
    pub(crate) calls: Vec<(usize, bool)>,
    pub(crate) predicate_calls: Vec<usize>,
    /// Callees passed a caller value: a binding of an identity type, or
    /// `self` in a method of one. A check a callee makes on its own caller
    /// parameter is about this request's caller only for these.
    pub(crate) passes_caller: HashSet<usize>,
}

/// Request types: the caller's credentials travel in them.
const REQUEST_TYPES: &[&str] = &["HttpRequest", "ServiceRequest"];

/// Evidence a callee holds about a caller value it was handed: a branch on
/// it, its presence, a query scoped to it, or where it is passed on. It
/// holds for a caller only if that caller passes its own caller value; a
/// record loaded for another user, or no user at all, is not the caller.
/// Role and permission checks hold wherever the callee runs.
fn is_about_passed_caller(found: &AuthEvidence) -> bool {
    found.mechanism.starts_with(super::evidence::STRUCTURAL_CHECK)
        || matches!(
            found.kind,
            AuthEvidenceKind::IdentityExtraction
                | AuthEvidenceKind::OwnershipCheck
                | AuthEvidenceKind::Delegated
        )
}

impl HandlerDefinition {
    pub(crate) fn rust_path(&self) -> String {
        std::iter::once("crate")
            .chain(self.module.iter().map(String::as_str))
            .chain(self.owner.as_deref())
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
    /// `.configure(f)` can visit `f`'s body. A method is copied into a free
    /// function's shape.
    pub(crate) items: Vec<Cow<'a, ItemFn>>,
    /// Methods and associated functions by `(type, name)`, from inherent
    /// and trait `impl` blocks.
    pub(crate) methods: HashMap<(String, String), Vec<usize>>,
    /// Struct fields by struct name: named fields, or `0`, `1`.. for a
    /// tuple struct.
    pub(crate) structs: HashMap<String, Vec<Vec<(String, Type)>>>,
    /// `type Name = ..;` aliases, and `Deref` targets of the crate's types.
    pub(crate) aliases: HashMap<String, Vec<Type>>,
    pub(crate) deref_targets: HashMap<String, Vec<Type>>,
    /// The types of each definition's named values, computed when a
    /// method call in it is resolved.
    pub(crate) local_types: std::cell::RefCell<HashMap<usize, std::rc::Rc<HashMap<String, Type>>>>,
    /// `const NAME: &str = "..."` items, keyed by crate, module, and name.
    pub(crate) consts: HashMap<(PathBuf, Vec<String>, String), String>,
    /// Other `const` and `static` items, by the same key, with the
    /// expression that gives their value (`Routes::new()`), for path
    /// evaluation.
    pub(crate) const_exprs: HashMap<(PathBuf, Vec<String>, String), &'a syn::Expr>,
    pub(crate) by_name: HashMap<String, Vec<usize>>,
    pub(crate) scopes: HashMap<ModuleKey, ModuleScope>,
    pub(crate) modules: HashSet<ModuleKey>,
    pub(crate) file_modules: HashMap<PathBuf, ModuleKey>,
    /// Library crates of the scanned workspace by the name other crates use
    /// for them (`lemmy_api` for package `lemmy_api` or `lemmy-api`), so that
    /// `use lemmy_api::site::purge` resolves into that crate.
    pub(crate) crates: HashMap<String, PathBuf>,
    /// Set while a glob import's own path is resolved, so that resolution
    /// does not search globs again: modules re-exporting each other's globs
    /// would otherwise branch at every level.
    pub(crate) resolving_glob: std::cell::Cell<bool>,
}

impl<'a> HandlerIndex<'a> {
    pub(crate) fn build(
        files: impl IntoIterator<Item = (&'a Path, ModuleKey, &'a syn::File)>,
        crates: HashMap<String, PathBuf>,
    ) -> Self {
        let mut index = Self {
            crates,
            ..Self::default()
        };
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
    /// calls, however deep, so that a handler whose check sits in a wrapper
    /// (`ensure_can_manage(&user)` calling `require_admin`), a method of the
    /// caller's type (`principal.validate()`), or a service function in
    /// another module is not reported as unauthorized. A helper's own
    /// enforced checks count wherever it is called; the predicate a `bool`
    /// helper returns (`fn can_edit(u) -> bool { u.role == Role::Admin }`)
    /// counts only where the caller enforces it. Only calls that resolve by
    /// Rust's scoping rules or by a value's declared type count; a
    /// unique-name guess does not, since wrongly added evidence would hide a
    /// finding. The evidence keeps the callee's location; its symbol names
    /// the call chain.
    ///
    /// Each function gets a summary, computed bottom-up and repeated until
    /// nothing changes, so call cycles are safe: what its body enforces
    /// wherever it is called, and what its returned predicate enforces where
    /// a caller enforces it.
    pub(crate) fn add_helper_evidence(&mut self) {
        let count = self.definitions.len();
        let resolved: Vec<ResolvedCalls> = (0..count)
            .map(|definition| self.resolved_calls(definition))
            .collect();
        let mut callers: Vec<Vec<usize>> = vec![Vec::new(); count];
        for (caller, calls) in resolved.iter().enumerate() {
            for callee in calls
                .calls
                .iter()
                .map(|(callee, _)| *callee)
                .chain(calls.predicate_calls.iter().copied())
            {
                if !callers[callee].contains(&caller) {
                    callers[callee].push(caller);
                }
            }
        }
        let own = |select: fn(&FunctionEvidence) -> &Vec<AuthEvidence>| -> Vec<Vec<AuthEvidence>> {
            self.definitions
                .iter()
                .map(|definition| select(&definition.own).clone())
                .collect()
        };
        let (first_body, _) = self.summarize(
            &resolved,
            &callers,
            own(|own| &own.body_evidence),
            own(|own| &own.predicate_evidence),
        );
        // A method call recorded as "not analyzed" is analyzed once it
        // resolves. The callee's checks replace the note; a callee that
        // checks nothing (a getter) drops it; a callee that can reject but
        // makes no check Archer recognizes keeps it, saying where it is.
        let rejecting = self.can_reject(&resolved, &callers);
        let notes: Vec<HashMap<String, Option<String>>> = (0..count)
            .map(|definition| {
                self.resolved_methods(definition)
                    .into_iter()
                    .map(|(symbol, callee)| {
                        let recognized = first_body[callee].iter().any(|found| {
                            !matches!(found.kind, AuthEvidenceKind::Delegated | AuthEvidenceKind::Unknown)
                        });
                        let note = (!recognized && rejecting[callee]).then(|| {
                            let target = &self.definitions[callee];
                            format!(
                                "`{symbol}` runs `{}` ({}:{}), which can reject the request by a check Archer cannot classify",
                                target.rust_path().trim_start_matches("crate::"),
                                target.file.display(),
                                self.items[callee].sig.ident.span().start().line
                            )
                        });
                        (symbol, note)
                    })
                    .collect()
            })
            .collect();
        let annotate = |definition: usize, evidence: &[AuthEvidence]| -> Vec<AuthEvidence> {
            evidence
                .iter()
                .filter_map(|found| {
                    let Some(note) = (found.kind == AuthEvidenceKind::Delegated)
                        .then(|| found.symbol.as_ref().and_then(|symbol| notes[definition].get(symbol)))
                        .flatten()
                    else {
                        return Some(found.clone());
                    };
                    let mut found = found.clone();
                    found.mechanism = note.clone()?;
                    Some(found)
                })
                .collect()
        };
        let (body, _) = self.summarize(
            &resolved,
            &callers,
            (0..count)
                .map(|definition| annotate(definition, &self.definitions[definition].own.body_evidence))
                .collect(),
            (0..count)
                .map(|definition| {
                    annotate(definition, &self.definitions[definition].own.predicate_evidence)
                })
                .collect(),
        );
        let combined: Vec<Vec<AuthEvidence>> = (0..count)
            .map(|definition| {
                let own_body = annotate(definition, &self.definitions[definition].own.body_evidence);
                let mut evidence = annotate(definition, &self.definitions[definition].own.evidence);
                let name = &self.definitions[definition].name;
                for found in &body[definition] {
                    if own_body.iter().any(|own| same_evidence(own, found)) {
                        continue;
                    }
                    let mut found = found.clone();
                    found.handler = Some(name.clone());
                    merge_evidence(&mut evidence, found);
                }
                evidence
            })
            .collect();
        for (definition, evidence) in self.definitions.iter_mut().zip(combined) {
            definition.evidence = evidence;
        }
    }

    /// Bottom-up summaries: what each function's body enforces wherever it
    /// is called, and what its returned predicate enforces where a caller
    /// enforces it, grown from its callees' until nothing changes.
    fn summarize(
        &self,
        resolved: &[ResolvedCalls],
        callers: &[Vec<usize>],
        mut body: Vec<Vec<AuthEvidence>>,
        mut predicate: Vec<Vec<AuthEvidence>>,
    ) -> (Vec<Vec<AuthEvidence>>, Vec<Vec<AuthEvidence>>) {
        let count = body.len();
        let mut queued: Vec<bool> = vec![false; count];
        // Functions whose summary grew: their callers are recomputed.
        let mut grown: Vec<usize> = (0..count)
            .filter(|&definition| !body[definition].is_empty() || !predicate[definition].is_empty())
            .collect();
        while !grown.is_empty() {
            let mut next = Vec::new();
            for callee in grown {
                for &caller in &callers[callee] {
                    if !queued[caller] {
                        queued[caller] = true;
                        next.push(caller);
                    }
                }
            }
            let mut changed = Vec::new();
            for caller in next {
                queued[caller] = false;
                let mut added = false;
                for &(callee, enforced) in &resolved[caller].calls {
                    let passes = resolved[caller].passes_caller.contains(&callee);
                    let inherited: Vec<AuthEvidence> = body[callee]
                        .iter()
                        .chain(enforced.then_some(predicate[callee].iter()).into_iter().flatten())
                        .filter(|found| passes || !is_about_passed_caller(found))
                        .map(|found| self.through(callee, found))
                        .collect();
                    for found in inherited {
                        added |= merge_evidence(&mut body[caller], found);
                    }
                }
                for &callee in &resolved[caller].predicate_calls {
                    let passes = resolved[caller].passes_caller.contains(&callee);
                    let inherited: Vec<AuthEvidence> = body[callee]
                        .iter()
                        .chain(predicate[callee].iter())
                        .filter(|found| passes || !is_about_passed_caller(found))
                        .map(|found| self.through(callee, found))
                        .collect();
                    for found in inherited {
                        added |= merge_evidence(&mut predicate[caller], found);
                    }
                }
                if added {
                    changed.push(caller);
                }
            }
            grown = changed;
        }
        (body, predicate)
    }

    /// Whether each function can reject a request: it builds an error or a
    /// 401/403 response itself, or propagates one from a callee it enforces.
    fn can_reject(&self, resolved: &[ResolvedCalls], callers: &[Vec<usize>]) -> Vec<bool> {
        let mut rejecting: Vec<bool> = self
            .items
            .iter()
            .map(|item| block_rejects(&item.block))
            .collect();
        let mut pending: Vec<usize> = (0..rejecting.len()).filter(|&index| rejecting[index]).collect();
        while let Some(callee) = pending.pop() {
            for &caller in &callers[callee] {
                if !rejecting[caller]
                    && resolved[caller]
                        .calls
                        .iter()
                        .any(|&(called, enforced)| called == callee && enforced)
                {
                    rejecting[caller] = true;
                    pending.push(caller);
                }
            }
        }
        rejecting
    }

    /// The method calls in a definition's body that resolve, written as
    /// the delegation note writes them (`principal.validate()`), with
    /// their callee.
    fn resolved_methods(&self, definition: usize) -> HashMap<String, usize> {
        self.definitions[definition]
            .own
            .calls
            .iter()
            .filter_map(|call| match &call.target {
                HandlerTarget::Method { receiver, method } => self
                    .resolve_callee(definition, &call.target)
                    .map(|callee| (format!("{receiver}.{method}()"), callee)),
                _ => None,
            })
            .collect()
    }

    /// Evidence a caller inherits through a call of `callee`: its symbol
    /// gains the callee's name, `validate -> is_admin`.
    fn through(&self, callee: usize, found: &AuthEvidence) -> AuthEvidence {
        let mut found = found.clone();
        found.symbol = Some(format!(
            "{} -> {}",
            self.definitions[callee].name,
            found.symbol.as_deref().unwrap_or(&found.mechanism)
        ));
        found
    }

    /// Repository functions that a function's body calls, by path or as a
    /// method of a typed value, with whether the call's result is enforced.
    pub(crate) fn resolved_calls(&self, definition: usize) -> ResolvedCalls {
        let caller = &self.definitions[definition];
        let mut resolved = ResolvedCalls::default();
        for call in &caller.own.calls {
            if let Some(callee) = self.resolve_callee(definition, &call.target) {
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
        let types = self.local_types(definition);
        for (target, roots) in &caller.own.call_roots {
            if roots
                .iter()
                .any(|root| types.get(root).is_some_and(|ty| self.holds_caller(ty)))
                && let Some(callee) = self.resolve_callee(definition, target)
            {
                resolved.passes_caller.insert(callee);
            }
        }
        for target in &caller.own.predicate_calls {
            if let Some(callee) = self.resolve_callee(definition, target)
                && !resolved.predicate_calls.contains(&callee)
            {
                resolved.predicate_calls.push(callee);
            }
        }
        resolved
    }

    #[cfg(test)]
    pub(crate) fn single_file(file: &'a Path, syntax: &'a syn::File) -> Self {
        Self::build(
            [(file, (file.to_path_buf(), Vec::new()), syntax)],
            HashMap::new(),
        )
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
                    self.items.push(Cow::Borrowed(function));
                    self.definitions.push(HandlerDefinition {
                        file: file.to_path_buf(),
                        crate_key: crate_key.to_path_buf(),
                        module: module.clone(),
                        name,
                        evidence: Vec::new(),
                        own: function_evidence(file, function),
                        cfg: cfg_attributes(&function.attrs),
                        stub: is_stub_body(&function.block),
                        owner: None,
                    });
                }
                Item::Impl(implementation) => {
                    let Some(owner) = type_name(&implementation.self_ty) else {
                        continue;
                    };
                    let is_deref = implementation.trait_.as_ref().is_some_and(|(path, _)| {
                        path.segments.last().is_some_and(|segment| segment.ident == "Deref")
                    });
                    for impl_item in &implementation.items {
                        match impl_item {
                            ImplItem::Type(target) if is_deref && target.ident == "Target" => {
                                self.deref_targets
                                    .entry(owner.clone())
                                    .or_default()
                                    .push(target.ty.clone());
                            }
                            ImplItem::Fn(method) => {
                                let function = ItemFn {
                                    attrs: method.attrs.clone(),
                                    vis: method.vis.clone(),
                                    modifiers: method.modifiers.clone(),
                                    sig: method.sig.clone(),
                                    block: Box::new(method.block.clone()),
                                };
                                let name = method.sig.ident.to_string();
                                self.methods
                                    .entry((owner.clone(), name.clone()))
                                    .or_default()
                                    .push(self.definitions.len());
                                let mut attrs = cfg_attributes(&implementation.attrs);
                                attrs.extend(cfg_attributes(&method.attrs));
                                self.definitions.push(HandlerDefinition {
                                    file: file.to_path_buf(),
                                    crate_key: crate_key.to_path_buf(),
                                    module: module.clone(),
                                    name,
                                    evidence: Vec::new(),
                                    own: function_evidence_in(file, &function, Some(&owner)),
                                    cfg: attrs,
                                    stub: is_stub_body(&function.block),
                                    owner: Some(owner.clone()),
                                });
                                self.items.push(Cow::Owned(function));
                            }
                            _ => {}
                        }
                    }
                }
                Item::Struct(item_struct) => {
                    let fields = item_struct
                        .fields
                        .iter()
                        .enumerate()
                        .map(|(position, field)| {
                            let name = field
                                .ident
                                .as_ref()
                                .map_or_else(|| position.to_string(), ToString::to_string);
                            (name, field.ty.clone())
                        })
                        .collect();
                    self.structs
                        .entry(item_struct.ident.to_string())
                        .or_default()
                        .push(fields);
                }
                Item::Type(alias) => {
                    self.aliases
                        .entry(alias.ident.to_string())
                        .or_default()
                        .push((*alias.ty).clone());
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
                    } else {
                        self.const_exprs.insert(
                            (crate_key.to_path_buf(), module.clone(), item_const.ident.to_string()),
                            &item_const.expr,
                        );
                    }
                }
                Item::Static(item_static) => {
                    self.const_exprs.insert(
                        (crate_key.to_path_buf(), module.clone(), item_static.ident.to_string()),
                        &item_static.expr,
                    );
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

    /// The value of a string constant named by `segments` as written in
    /// `module`: defined there, brought in by one explicit `use`, or
    /// module-qualified.
    pub(crate) fn resolve_const(
        &self,
        crate_key: &Path,
        module: &[String],
        segments: &[String],
    ) -> Option<String> {
        self.resolve_const_with(crate_key, module, segments, |key| self.consts.get(key).cloned())
    }

    /// The `const` or `static` item `segments` names, as written in
    /// `module`, whose value is an expression: the module that defines it
    /// and that expression.
    pub(crate) fn resolve_const_expr(
        &self,
        crate_key: &Path,
        module: &[String],
        segments: &[String],
    ) -> Option<(ModuleKey, &'a syn::Expr)> {
        self.resolve_const_with(crate_key, module, segments, |key| {
            self.const_exprs
                .get(key)
                .map(|expr| ((key.0.clone(), key.1.clone()), *expr))
        })
    }

    fn resolve_const_with<T>(
        &self,
        crate_key: &Path,
        module: &[String],
        segments: &[String],
        get: impl Fn(&(PathBuf, Vec<String>, String)) -> Option<T>,
    ) -> Option<T> {
        let (name, qualifier) = segments.split_last()?;
        if super::path_eval::enabled() {
            let start = if qualifier.is_empty() {
                (crate_key.to_path_buf(), module.to_vec())
            } else {
                let qualifier = UsePath {
                    segments: qualifier.to_vec(),
                    leading_colon: false,
                };
                self.resolve_module(crate_key, module, &qualifier, 0)?
            };
            return self.const_in(&start, name, &get, 0);
        }
        let lookup = |(crate_key, module): &ModuleKey| get(&(crate_key.clone(), module.clone(), name.clone()));
        if !qualifier.is_empty() {
            let qualifier = UsePath {
                segments: qualifier.to_vec(),
                leading_colon: false,
            };
            return lookup(&self.resolve_module(crate_key, module, &qualifier, 0)?);
        }
        if let Some(value) = lookup(&(crate_key.to_path_buf(), module.to_vec())) {
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

    /// The constant `name` as seen in `module`: defined there, or brought
    /// in by one `use`, followed through re-exports and renames
    /// (`pub use api::ROUTES as API_ROUTES`).
    fn const_in<T>(
        &self,
        (crate_key, module): &ModuleKey,
        name: &str,
        get: &impl Fn(&(PathBuf, Vec<String>, String)) -> Option<T>,
        depth: usize,
    ) -> Option<T> {
        if depth > MAX_RESOLUTION_DEPTH {
            return None;
        }
        if let Some(value) = get(&(crate_key.clone(), module.clone(), name.to_owned())) {
            return Some(value);
        }
        let [import] = self.scope(crate_key, module)?.imports.get(name)?.as_slice() else {
            return None;
        };
        let (original, prefix) = import.segments.split_last()?;
        let prefix = UsePath {
            segments: prefix.to_vec(),
            leading_colon: import.leading_colon,
        };
        let target = self.resolve_module(crate_key, module, &prefix, 0)?;
        self.const_in(&target, original, get, depth + 1)
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
        self.resolve_handler_index_for(None, crate_key, module, target)
    }

    /// Resolves a call that `caller` makes. Among same-named functions that
    /// differ only by `#[cfg(..)]`, the one compiled with the caller is
    /// called; see `pick_variant`.
    pub(crate) fn resolve_call(
        &self,
        caller: usize,
        target: &HandlerTarget,
    ) -> (Option<usize>, HandlerResolution) {
        let definition = &self.definitions[caller];
        self.resolve_handler_index_for(
            Some(&definition.cfg),
            &definition.crate_key,
            &definition.module,
            target,
        )
    }

    /// One of several definitions a path names, when they are build
    /// variants of one function: all in one module, told apart by
    /// `#[cfg(..)]`. The variant whose conditions the caller also has is
    /// the one compiled with it; otherwise placeholders (`todo!()`) are set
    /// aside, and a single remaining variant is taken.
    fn pick_variant(&self, candidates: &[usize], caller_cfg: Option<&[String]>) -> Option<usize> {
        let first = &self.definitions[*candidates.first()?];
        let variants = candidates.iter().all(|&index| {
            let definition = &self.definitions[index];
            definition.crate_key == first.crate_key
                && definition.module == first.module
                && !definition.cfg.is_empty()
        });
        if !variants {
            return None;
        }
        let single = |found: Vec<usize>| match found.as_slice() {
            [index] => Some(*index),
            _ => None,
        };
        if let Some(caller_cfg) = caller_cfg.filter(|cfg| !cfg.is_empty()) {
            let matching: Vec<usize> = candidates
                .iter()
                .copied()
                .filter(|&index| {
                    self.definitions[index]
                        .cfg
                        .iter()
                        .all(|condition| caller_cfg.contains(condition))
                })
                .collect();
            if let Some(index) = single(matching) {
                return Some(index);
            }
        }
        single(
            candidates
                .iter()
                .copied()
                .filter(|&index| !self.definitions[index].stub)
                .collect(),
        )
    }

    fn resolve_handler_index_for(
        &self,
        caller_cfg: Option<&[String]>,
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
                match self.resolve_item(&qualifier_module.0, &qualifier_module.1, name, &mut visited, 0) {
                    Lookup::Found(index, _) => Lookup::Found(index, HandlerResolution::Qualified),
                    other => other,
                };
            (lookup, Some(qualifier_module))
        };

        match lookup {
            Lookup::Found(index, resolution) => (Some(index), resolution),
            Lookup::Ambiguous(candidates) => match self.pick_variant(&candidates, caller_cfg) {
                Some(index) => (
                    Some(index),
                    if qualifier.is_empty() {
                        HandlerResolution::Local
                    } else {
                        HandlerResolution::Qualified
                    },
                ),
                None => (None, self.ambiguous(candidates)),
            },
            Lookup::NotFound { explicit: true } => (None, HandlerResolution::Unresolved),
            Lookup::NotFound { explicit: false } => {
                let search_crate = qualifier_module
                    .as_ref()
                    .map_or(crate_key, |(qualifier_crate, _)| qualifier_crate.as_path());
                let candidates: Vec<usize> = self
                    .definitions_named(search_crate, name)
                    .filter(|&index| {
                        qualifier_module.as_ref().is_none_or(|(_, qualifier)| {
                            self.definitions[index].module.starts_with(qualifier)
                        })
                    })
                    .collect();
                match candidates.as_slice() {
                    [] => (None, HandlerResolution::Unresolved),
                    [index] => (Some(*index), HandlerResolution::UniqueName),
                    _ => match self.pick_variant(&candidates, caller_cfg) {
                        Some(index) => (Some(index), HandlerResolution::UniqueName),
                        None => (None, self.ambiguous(candidates)),
                    },
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
        visited: &mut HashSet<(PathBuf, Vec<String>, String)>,
        depth: usize,
    ) -> Lookup {
        if depth > MAX_RESOLUTION_DEPTH
            || !visited.insert((crate_key.to_path_buf(), module.to_vec(), name.to_owned()))
        {
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
            .map(|(glob_crate, glob_module)| {
                self.resolve_item(&glob_crate, &glob_module, name, visited, depth + 1)
            })
            .collect();
        combine_lookups(lookups, HandlerResolution::GlobImported)
            .unwrap_or(Lookup::NotFound { explicit: false })
    }

    pub(crate) fn resolve_use_item(
        &self,
        crate_key: &Path,
        module: &[String],
        path: &UsePath,
        visited: &mut HashSet<(PathBuf, Vec<String>, String)>,
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
            Some((target_crate, target)) => match self.resolve_item(
                &target_crate,
                &target,
                name,
                visited,
                depth,
            ) {
                Lookup::NotFound { .. } => Lookup::NotFound { explicit: true },
                lookup => lookup,
            },
            None => Lookup::NotFound { explicit: true },
        }
    }

    /// Resolves a module path written in `module` to an absolute module:
    /// its crate and its path within that crate. A path whose first segment
    /// names another library crate of the workspace resolves into that
    /// crate; paths into crates outside the scan return `None`.
    pub(crate) fn resolve_module(
        &self,
        crate_key: &Path,
        module: &[String],
        path: &UsePath,
        depth: usize,
    ) -> Option<ModuleKey> {
        if depth > MAX_RESOLUTION_DEPTH {
            return None;
        }
        let segments = &path.segments;
        let external = |name: &str| self.crates.get(name).map(|key| (key.clone(), Vec::new()));
        let ((target_crate, mut resolved), rest): (ModuleKey, &[String]) = if path.leading_colon {
            ((external(segments.first()?)?), &segments[1..])
        } else {
            match segments.first().map(String::as_str) {
                None => return Some((crate_key.to_path_buf(), module.to_vec())),
                Some("crate") => ((crate_key.to_path_buf(), Vec::new()), &segments[1..]),
                Some("self") => ((crate_key.to_path_buf(), module.to_vec()), &segments[1..]),
                Some("super") => {
                    let supers = segments
                        .iter()
                        .take_while(|segment| *segment == "super")
                        .count();
                    if supers > module.len() {
                        return None;
                    }
                    (
                        (
                            crate_key.to_path_buf(),
                            module[..module.len() - supers].to_vec(),
                        ),
                        &segments[supers..],
                    )
                }
                Some(first) => {
                    let mut child = module.to_vec();
                    child.push(first.to_owned());
                    if self.is_module(crate_key, &child) {
                        ((crate_key.to_path_buf(), child), &segments[1..])
                    } else if let Some(imports) = self
                        .scope(crate_key, module)
                        .and_then(|scope| scope.imports.get(first))
                    {
                        let [import] = imports.as_slice() else {
                            return None;
                        };
                        (
                            self.resolve_module(crate_key, module, import, depth + 1)?,
                            &segments[1..],
                        )
                    } else if let Some(found) = self.glob_module(crate_key, module, first, depth) {
                        // `use crate::api::*;` then `ping_controller::ping`:
                        // the module came in through exactly one glob.
                        (found, &segments[1..])
                    } else {
                        // Since the 2018 edition, a dependency's name is in
                        // scope in every module.
                        (external(first)?, &segments[1..])
                    }
                }
            }
        };
        resolved.extend(rest.iter().cloned());
        self.is_module(&target_crate, &resolved)
            .then_some((target_crate, resolved))
    }
}

impl HandlerIndex<'_> {
    /// The module named `name` that one of `module`'s glob imports brings
    /// into scope, if exactly one does.
    fn glob_module(
        &self,
        crate_key: &Path,
        module: &[String],
        name: &str,
        depth: usize,
    ) -> Option<ModuleKey> {
        if self.resolving_glob.get() {
            return None;
        }
        let scope = self.scope(crate_key, module)?;
        let mut found: Option<ModuleKey> = None;
        for glob in &scope.globs {
            self.resolving_glob.set(true);
            let resolved = self.resolve_module(crate_key, module, glob, depth + 1);
            self.resolving_glob.set(false);
            let Some((glob_crate, mut glob_module)) = resolved else {
                continue;
            };
            glob_module.push(name.to_owned());
            if self.is_module(&glob_crate, &glob_module) {
                if found.as_ref().is_some_and(|existing| *existing != (glob_crate.clone(), glob_module.clone())) {
                    return None;
                }
                found = Some((glob_crate, glob_module));
            }
        }
        found
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

/// A function's `#[cfg(..)]` attributes as token text.
pub(crate) fn cfg_attributes(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .map(|attr| quote::ToTokens::to_token_stream(&attr.meta).to_string())
        .collect()
}

/// A body that is only a placeholder macro: `todo!()`, `unimplemented!()`.
pub(crate) fn is_stub_body(block: &syn::Block) -> bool {
    let [statement] = block.stmts.as_slice() else {
        return false;
    };
    let mac = match statement {
        syn::Stmt::Macro(stmt) => &stmt.mac,
        syn::Stmt::Expr(syn::Expr::Macro(expr), _) => &expr.mac,
        _ => return false,
    };
    mac.path
        .get_ident()
        .is_some_and(|name| name == "todo" || name == "unimplemented")
}

/// The last name of a type path, through references: `Principal` for
/// `&Principal`, `ReqData` for `web::ReqData<Principal>`.
pub(crate) fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Reference(reference) => type_name(&reference.elem),
        Type::Paren(paren) => type_name(&paren.elem),
        Type::Group(group) => type_name(&group.elem),
        Type::Path(path) if path.qself.is_none() => {
            path.path.segments.last().map(|segment| segment.ident.to_string())
        }
        _ => None,
    }
}

/// The type arguments of a type path's last segment.
fn type_arguments(ty: &Type) -> Vec<&Type> {
    match ty {
        Type::Reference(reference) => type_arguments(&reference.elem),
        Type::Paren(paren) => type_arguments(&paren.elem),
        Type::Group(group) => type_arguments(&group.elem),
        Type::Path(path) => match path.path.segments.last().map(|segment| &segment.arguments) {
            Some(syn::PathArguments::AngleBracketed(arguments)) => arguments
                .args
                .iter()
                .filter_map(|argument| match argument {
                    syn::GenericArgument::Type(inner) => Some(inner),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// How deep type aliases, `Deref` targets and wrappers are followed.
const MAX_TYPE_DEPTH: usize = 8;

impl HandlerIndex<'_> {
    /// The types a value of type `ty` can be used as: the type itself, then
    /// what it stands for or dereferences to: an alias's definition, a
    /// `Deref` target from the crate, or the one type argument of a wrapper
    /// (`ReqData<T>`, `Arc<T>`, `Data<T>`), as method calls auto-deref.
    fn deref_chain(&self, ty: &Type) -> Vec<Type> {
        let mut chain = vec![ty.clone()];
        let mut current = ty.clone();
        for _ in 0..MAX_TYPE_DEPTH {
            let Some(name) = type_name(&current) else {
                break;
            };
            let next = if let Some([alias]) = self.aliases.get(&name).map(Vec::as_slice) {
                alias.clone()
            } else if let Some([target]) = self.deref_targets.get(&name).map(Vec::as_slice) {
                target.clone()
            } else if let [inner] = type_arguments(&current).as_slice() {
                (*inner).clone()
            } else {
                break;
            };
            chain.push(next.clone());
            current = next;
        }
        chain
    }

    /// Definitions of `method` for a receiver of type `ty`: on the first
    /// type in its deref chain that has a method of that name.
    fn methods_of(&self, ty: &Type, method: &str) -> Vec<usize> {
        for candidate in self.deref_chain(ty) {
            if let Some(name) = type_name(&candidate)
                && let Some(found) = self.methods.get(&(name, method.to_owned()))
            {
                return found.clone();
            }
        }
        Vec::new()
    }

    /// The type of field `field` (a name, or a tuple index) of a value of
    /// type `ty`, from the one struct of that name in the scan.
    pub(crate) fn field_type(&self, ty: &Type, field: &str) -> Option<Type> {
        for candidate in self.deref_chain(ty) {
            let Some(name) = type_name(&candidate) else {
                continue;
            };
            if let Some([fields]) = self.structs.get(&name).map(Vec::as_slice) {
                return fields
                    .iter()
                    .find(|(name, _)| name == field)
                    .map(|(_, ty)| ty.clone());
            }
        }
        None
    }

    /// The declared types of a definition's named values: its parameters
    /// (`self` included), and locals and closure parameters with a written
    /// type or one Archer can read off the initializer. A name bound with
    /// two different types has none.
    pub(crate) fn local_types(&self, definition: usize) -> std::rc::Rc<HashMap<String, Type>> {
        if let Some(found) = self.local_types.borrow().get(&definition) {
            return found.clone();
        }
        let mut collector = LocalTypes {
            index: self,
            owner: self.definitions[definition].owner.clone(),
            types: HashMap::new(),
            conflicted: HashSet::new(),
        };
        let item = &self.items[definition];
        for input in &item.sig.inputs {
            match input {
                syn::FnArg::Receiver(_) => {
                    if let Some(owner) = &collector.owner
                        && let Ok(ty) = syn::parse_str::<Type>(owner)
                    {
                        collector.insert("self".to_owned(), ty);
                    }
                }
                syn::FnArg::Typed(typed) => collector.bind(&typed.pat, &typed.ty),
            }
        }
        syn::visit::Visit::visit_block(&mut collector, &item.block);
        let types = std::rc::Rc::new(collector.types);
        self.local_types
            .borrow_mut()
            .insert(definition, types.clone());
        types
    }

    /// Whether a value of this type carries the caller: an identity type,
    /// the request whose credentials name it, or a reference, alias or
    /// wrapper of either.
    fn holds_caller(&self, ty: &Type) -> bool {
        match ty {
            Type::Reference(reference) => self.holds_caller(&reference.elem),
            Type::Paren(inner) => self.holds_caller(&inner.elem),
            Type::Group(inner) => self.holds_caller(&inner.elem),
            _ => {
                let carries = |ty: &Type| {
                    super::evidence::identity_type(ty)
                        || type_name(ty).is_some_and(|name| REQUEST_TYPES.contains(&name.as_str()))
                };
                carries(ty) || self.deref_chain(ty).iter().any(carries)
            }
        }
    }

    /// The type of a receiver written as a binding and fields.
    fn receiver_type(&self, definition: usize, receiver: &str) -> Option<Type> {
        let mut parts = receiver.split('.');
        let mut ty = self.local_types(definition).get(parts.next()?)?.clone();
        for field in parts {
            ty = self.field_type(&ty, field)?;
        }
        Some(ty)
    }

    /// The single definition a set of candidates names, or the build
    /// variant compiled with the caller.
    fn single(&self, candidates: &[usize], caller: usize) -> Option<usize> {
        match candidates {
            [] => None,
            [only] => Some(*only),
            _ => self.pick_variant(candidates, Some(&self.definitions[caller].cfg)),
        }
    }

    /// The repository function a call in `caller`'s body reaches, if Rust's
    /// rules pin it down: a path by scoping (a unique-name guess does not
    /// count), `Type::f` and `Self::f` by the `impl` blocks of that type,
    /// and `value.method()` by the type of `value`. Anything else stays
    /// unresolved.
    pub(crate) fn resolve_callee(&self, caller: usize, target: &HandlerTarget) -> Option<usize> {
        let found = match target {
            HandlerTarget::Method { receiver, method } => {
                let ty = self.receiver_type(caller, receiver)?;
                self.single(&self.methods_of(&ty, method), caller)
            }
            HandlerTarget::Path { segments, .. } => {
                match self.resolve_call(caller, target) {
                    (Some(callee), resolution) if !matches!(resolution, HandlerResolution::UniqueName) => {
                        Some(callee)
                    }
                    _ => {
                        let [.., owner, name] = segments.as_slice() else {
                            return None;
                        };
                        let owner = if owner == "Self" {
                            self.definitions[caller].owner.clone()?
                        } else if owner.starts_with(char::is_uppercase) {
                            owner.clone()
                        } else {
                            return None;
                        };
                        let ty = syn::parse_str::<Type>(&owner).ok()?;
                        self.single(&self.methods_of(&ty, name), caller)
                    }
                }
            }
            HandlerTarget::Other => None,
        };
        found.filter(|&callee| callee != caller)
    }
}

/// Collects the declared types of a function's named values.
struct LocalTypes<'i, 'a> {
    index: &'i HandlerIndex<'a>,
    owner: Option<String>,
    types: HashMap<String, Type>,
    conflicted: HashSet<String>,
}

impl LocalTypes<'_, '_> {
    fn insert(&mut self, name: String, ty: Type) {
        if self.conflicted.contains(&name) {
            return;
        }
        match self.types.get(&name) {
            Some(existing)
                if quote::ToTokens::to_token_stream(existing).to_string()
                    != quote::ToTokens::to_token_stream(&ty).to_string() =>
            {
                self.types.remove(&name);
                self.conflicted.insert(name);
            }
            Some(_) => {}
            None => {
                self.types.insert(name, ty);
            }
        }
    }

    /// Binds the names of `pattern`, matched against a value of type `ty`:
    /// `ActixAuth(auth): ActixAuth` gives `auth` the type of the struct's
    /// field `0`.
    fn bind(&mut self, pattern: &syn::Pat, ty: &Type) {
        match pattern {
            syn::Pat::Ident(ident) => {
                self.insert(ident.ident.to_string(), ty.clone());
                if let Some((_, inner)) = &ident.subpat {
                    self.bind(inner, ty);
                }
            }
            syn::Pat::Reference(reference) => self.bind(&reference.pat, ty),
            syn::Pat::Paren(paren) => self.bind(&paren.pat, ty),
            syn::Pat::Type(typed) => self.bind(&typed.pat, &typed.ty),
            syn::Pat::TupleStruct(tuple) => {
                for (position, element) in tuple.elems.iter().enumerate() {
                    if let Some(field) = self.index.field_type(ty, &position.to_string()) {
                        self.bind(element, &field);
                    }
                }
            }
            syn::Pat::Struct(structure) => {
                for field in &structure.fields {
                    if let syn::Member::Named(name) = &field.member
                        && let Some(field_ty) = self.index.field_type(ty, &name.to_string())
                    {
                        self.bind(&field.pat, &field_ty);
                    }
                }
            }
            _ => {}
        }
    }

    /// The type of an initializer Archer can read without inference: a
    /// struct literal, or `Type::f(..)` with `f`'s declared return type,
    /// through `?` and `.await`.
    fn initializer_type(&self, expr: &syn::Expr) -> Option<Type> {
        match expr {
            syn::Expr::Struct(literal) if literal.qself.is_none() => {
                let name = literal.path.segments.last()?.ident.to_string();
                let name = if name == "Self" { self.owner.clone()? } else { name };
                syn::parse_str::<Type>(&name).ok()
            }
            syn::Expr::Await(inner) => self.initializer_type(&inner.base),
            syn::Expr::Try(inner) => {
                let ty = self.initializer_type(&inner.expr)?;
                match type_name(&ty).as_deref() {
                    Some(name) if name.ends_with("Result") || name == "Option" => {
                        type_arguments(&ty).first().map(|inner| (*inner).clone())
                    }
                    _ => Some(ty),
                }
            }
            syn::Expr::Call(call) => {
                let syn::Expr::Path(path) = &*call.func else {
                    return None;
                };
                let segments: Vec<String> = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect();
                let [.., owner, name] = segments.as_slice() else {
                    return None;
                };
                let owner = if owner == "Self" { self.owner.clone()? } else { owner.clone() };
                if !owner.starts_with(char::is_uppercase) {
                    return None;
                }
                let [callee] = self.index.methods.get(&(owner.clone(), name.clone()))?.as_slice() else {
                    return None;
                };
                let syn::ReturnType::Type(_, returned) = &self.index.items[*callee].sig.output else {
                    return None;
                };
                Some(replace_self(returned, &owner))
            }
            _ => None,
        }
    }
}

/// `ty` with `Self` written as `owner`: `Result<Self, E>` read in
/// `impl Session` is `Result<Session, E>`.
fn replace_self(ty: &Type, owner: &str) -> Type {
    let written = quote::ToTokens::to_token_stream(ty).to_string();
    let replaced: Vec<String> = written
        .split(' ')
        .map(|token| if token == "Self" { owner.to_owned() } else { token.to_owned() })
        .collect();
    syn::parse_str::<Type>(&replaced.join(" ")).unwrap_or_else(|_| ty.clone())
}

impl<'ast> syn::visit::Visit<'ast> for LocalTypes<'_, '_> {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        match &node.pat {
            syn::Pat::Type(typed) => self.bind(&typed.pat, &typed.ty),
            pattern => {
                if let Some(init) = &node.init
                    && init.diverge.is_none()
                    && let Some(ty) = self.initializer_type(&init.expr)
                {
                    self.bind(pattern, &ty);
                }
            }
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        for input in &node.inputs {
            if let syn::Pat::Type(typed) = input {
                self.bind(&typed.pat, &typed.ty);
            }
        }
        syn::visit::visit_expr_closure(self, node);
    }

    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
    fn visit_item_impl(&mut self, _: &'ast syn::ItemImpl) {}
}

fn same_evidence(left: &AuthEvidence, right: &AuthEvidence) -> bool {
    left.kind == right.kind && left.file == right.file && left.line == right.line
}

/// Adds `found` unless the same check (kind and location) is there; the
/// first, shortest chain is kept.
fn merge_evidence(evidence: &mut Vec<AuthEvidence>, found: AuthEvidence) -> bool {
    if evidence.iter().any(|existing| same_evidence(existing, &found)) {
        return false;
    }
    evidence.push(found);
    true
}
