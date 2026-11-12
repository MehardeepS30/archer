//! Handler index: every free function in the repository and Rust-style path resolution to it.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use std::borrow::Cow;
use syn::{FnArg, Pat, ImplItem, Item, ItemFn, Type, UseTree};

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
    /// Callees whose failure this function discards at every call (see
    /// `reach`): their checks do not restrict the request here.
    pub(crate) swallowed: HashSet<usize>,
    /// For each callee, the argument positions every call here passes
    /// `None` or `false` at.
    pub(crate) absent: HashMap<usize, Vec<usize>>,
    /// Callees called only when a parameter of this function is given,
    /// with that parameter's position.
    pub(crate) conditional: HashMap<usize, usize>,
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

/// Whether associated-function handlers (`.to(Handlers::users)`) are
/// resolved: `ARCHER_P9=0` turns it off.
pub(crate) fn associated_enabled() -> bool {
    std::env::var("ARCHER_P9").map_or(true, |value| value != "0")
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
    /// The crate of each struct in `structs`, in the same order.
    pub(crate) struct_crates: HashMap<String, Vec<PathBuf>>,
    /// Type names that two or more crates of the scan define (`Service`
    /// in `kernel` and in `files`), with the crates that do. A type of
    /// such a name is told apart by the crate it is written in.
    pub(crate) contested: HashMap<String, Vec<PathBuf>>,
    /// `type Name = ..;` aliases, and `Deref` targets of the crate's types.
    pub(crate) aliases: HashMap<String, Vec<Type>>,
    pub(crate) deref_targets: HashMap<String, Vec<Type>>,
    /// The type parameters a `Deref` impl names its own type with:
    /// `impl<T> Deref for Data<T> { type Target = Arc<T>; }` gives
    /// `Data -> [T]`, so that `Data<Arc<Context>>` derefs to
    /// `Arc<Arc<Context>>` and not to `Arc<T>`.
    pub(crate) deref_params: HashMap<String, Vec<String>>,
    /// The types of each definition's named values, computed when a
    /// method call in it is resolved.
    pub(crate) local_types: std::cell::RefCell<HashMap<usize, std::rc::Rc<HashMap<String, Type>>>>,
    /// Traits defined in the scan, and the types that implement each
    /// trait name, for calls on `dyn Trait`, `impl Trait` and bounded
    /// type parameters.
    pub(crate) traits: HashSet<String>,
    pub(crate) implementors: HashMap<String, Vec<String>>,
    /// Copies of generic functions with a type parameter, or an `impl
    /// Trait`/`dyn Trait` parameter, replaced by the type one call site
    /// passes, by `(caller, generic callee)`: `execute(usecase)` with
    /// `usecase: RenameUseCase` calls the copy of `execute<U>` whose
    /// `usecase.run()` is `RenameUseCase::run`. `None` when one caller
    /// passes two different types.
    pub(crate) instances: HashMap<(usize, usize), Option<usize>>,
    /// For a copy, the generic function it was made from.
    pub(crate) instance_of: HashMap<usize, usize>,
    /// Every type name that has an `impl` block in the scan.
    pub(crate) owners: std::cell::RefCell<Option<std::rc::Rc<HashSet<String>>>>,
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
        index.find_contested();
        index.instantiate_generics();
        index.add_helper_evidence();
        index.debug_calls();
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
        // Calls that resolve, as a delegation note names them: the method
        // (`share`) or the path as written (`Board::rename`). A name that
        // also has a call that does not resolve is left out.
        let handed: Vec<HashSet<String>> = (0..count)
            .map(|definition| {
                if !super::rc::enabled("READARGS") {
                    return HashSet::new();
                }
                let mut resolving = HashSet::new();
                let mut failing = HashSet::new();
                for call in &self.definitions[definition].own.calls {
                    let name = match &call.target {
                        HandlerTarget::Method { method, .. } => method.clone(),
                        HandlerTarget::Path { segments, .. } if segments.len() >= 2 => segments.join("::"),
                        _ => continue,
                    };
                    if self.resolve_callee(definition, &call.target).is_some() {
                        resolving.insert(name);
                    } else {
                        failing.insert(name);
                    }
                }
                resolving.retain(|name| !failing.contains(name));
                resolving
            })
            .collect();
        // A parameter whose type may hold no caller (`actor: Actor`, with
        // `Actor::None`): handing it on shows nothing until something
        // narrows it, and Archer reads what does. A definite caller handed
        // to read code stays a hand-over: the code may filter by it.
        let maybe_absent = |definition: usize, binding: &str| -> bool {
            self.items[definition].sig.inputs.iter().any(|input| match input {
                FnArg::Typed(typed) => {
                    matches!(&*typed.pat, Pat::Ident(ident) if ident.ident == binding)
                        && type_name(&typed.ty).is_some_and(|name| super::structural::optional_caller(&name))
                }
                FnArg::Receiver(_) => false,
            })
        };
        let annotate = |definition: usize, evidence: &[AuthEvidence]| -> Vec<AuthEvidence> {
            evidence
                .iter()
                .filter_map(|found| {
                    // `notes.share(actor, id)`: the caller handed as an
                    // argument to a function Archer reads. What that
                    // function does with it, a hand-over to code Archer
                    // cannot read included, is inherited from it.
                    if found.kind == AuthEvidenceKind::Delegated
                        && found
                            .symbol
                            .as_ref()
                            .and_then(|symbol| symbol.split_once('('))
                            .is_some_and(|(callee, binding)| {
                                handed[definition].contains(callee)
                                    && maybe_absent(definition, binding.trim_end_matches(')'))
                            })
                    {
                        // `fn subscribe(&self, _actor: Actor, ..)`: the
                        // function names the caller as unused, so no
                        // caller is needed by design.
                        let callee = found.symbol.as_deref().and_then(|symbol| symbol.split_once('(')).map(|(callee, _)| callee);
                        let unused = self.definitions[definition].own.calls.iter().find_map(|call| {
                            let name = match &call.target {
                                HandlerTarget::Method { method, .. } => method.clone(),
                                HandlerTarget::Path { segments, .. } => segments.join("::"),
                                HandlerTarget::Other => return None,
                            };
                            (Some(name.as_str()) == callee).then_some(())?;
                            let target = self.resolve_callee(definition, &call.target)?;
                            self.items[target].sig.inputs.iter().find_map(|input| match input {
                                FnArg::Typed(typed) => match &*typed.pat {
                                    Pat::Ident(ident)
                                        if ident.ident.to_string().starts_with('_')
                                            && type_name(&typed.ty)
                                                .is_some_and(|name| super::structural::optional_caller(&name)) =>
                                    {
                                        Some(ident.ident.to_string())
                                    }
                                    Pat::Wild(_)
                                        if type_name(&typed.ty)
                                            .is_some_and(|name| super::structural::optional_caller(&name)) =>
                                    {
                                        Some("_".to_owned())
                                    }
                                    _ => None,
                                },
                                FnArg::Receiver(_) => None,
                            })
                        });
                        return unused.map(|parameter| {
                            let mut found = found.clone();
                            found.mechanism = format!(
                                "`{}` takes the caller as `{parameter}`, unused by name: no caller is needed by design",
                                callee.unwrap_or_default()
                            );
                            found
                        });
                    }
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
                // `check_access(&user, &note, None)?`: a check read by its
                // name, whose function Archer read too and found to check
                // only when given the argument this call leaves out.
                if super::rc::enabled("ABSENT") {
                    evidence.retain(|found| {
                        !(resolved[definition].absent.iter().any(|(&callee, absent)| {
                                let target = &self.definitions[callee];
                                (found.mechanism == target.name || found.symbol.as_deref() == Some(target.name.as_str()))
                                    && !body[callee].is_empty()
                                    && body[callee].iter().all(|inner| {
                                        inner.file == target.file
                                            && target
                                                .own
                                                .reach
                                                .condition_at(inner.line)
                                                .is_some_and(|parameter| absent.contains(&parameter))
                                    })
                            }))
                    });
                }
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
        // Evidence a function has only when one of its parameters is
        // given, by the evidence's location: its own checks inside `if
        // let Some(x) = parameter { .. }`, and what it inherits through
        // calls made only there. A caller that passes `None` or `false`
        // for that parameter does not inherit it.
        let mut conditions: Vec<HashMap<(PathBuf, usize), usize>> = (0..count)
            .map(|definition| {
                let own = &self.definitions[definition];
                body[definition]
                    .iter()
                    .filter(|found| found.file == own.file)
                    .filter_map(|found| {
                        own.own
                            .reach
                            .condition_at(found.line)
                            .map(|parameter| ((found.file.clone(), found.line), parameter))
                    })
                    .collect()
            })
            .collect();
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
                    // The caller goes on when this callee fails.
                    if resolved[caller].swallowed.contains(&callee) {
                        continue;
                    }
                    let passes = resolved[caller].passes_caller.contains(&callee);
                    let absent = resolved[caller].absent.get(&callee);
                    let via = resolved[caller].conditional.get(&callee).copied();
                    let inherited: Vec<AuthEvidence> = body[callee]
                        .iter()
                        .chain(enforced.then_some(predicate[callee].iter()).into_iter().flatten())
                        .filter(|found| passes || !is_about_passed_caller(found))
                        .filter(|found| {
                            match conditions[callee].get(&(found.file.clone(), found.line)) {
                                Some(parameter) => !absent.is_some_and(|absent| absent.contains(parameter)),
                                None => true,
                            }
                        })
                        .map(|found| self.through(callee, found))
                        .collect();
                    for found in inherited {
                        let key = (found.file.clone(), found.line);
                        if merge_evidence(&mut body[caller], found) {
                            added = true;
                            if let Some(parameter) = via {
                                conditions[caller].insert(key, parameter);
                            }
                        } else if via.is_none() && conditions[caller].remove(&key).is_some() {
                            // Also reached without the condition.
                            added = true;
                        }
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
        // A parameter that holds the caller, by its declared type: a name
        // bound again with another type (`let actor =
        // self.current_user(actor)?`) has no one type in `types`.
        let parameters: HashSet<String> = if super::rc::enabled("NARROWS") {
            self.items[definition]
                .sig
                .inputs
                .iter()
                .filter_map(|input| match input {
                    syn::FnArg::Typed(typed) => match &*typed.pat {
                        syn::Pat::Ident(ident) if self.holds_caller(&typed.ty) => Some(ident.ident.to_string()),
                        _ => None,
                    },
                    syn::FnArg::Receiver(_) => None,
                })
                .collect()
        } else {
            HashSet::new()
        };
        for (target, roots) in &caller.own.call_roots {
            if roots.iter().any(|root| {
                parameters.contains(root) || types.get(root).is_some_and(|ty| self.holds_caller(ty))
            }) && let Some(callee) = self.resolve_callee(definition, target)
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
        // What every call site of a callee agrees on.
        let mut sites: HashMap<usize, Vec<&super::reach::CallShape>> = HashMap::new();
        for shape in &caller.own.reach.shapes {
            if let Some(callee) = self.resolve_callee(definition, &shape.target) {
                sites.entry(callee).or_default().push(shape);
            }
        }
        for (callee, shapes) in sites {
            let enforced = resolved
                .calls
                .iter()
                .any(|(called, enforced)| *called == callee && *enforced);
            if !enforced && shapes.iter().all(|shape| shape.swallowed) && self.fallible(callee) {
                resolved.swallowed.insert(callee);
            }
            let absent: Vec<usize> = shapes[0]
                .absent
                .iter()
                .copied()
                .filter(|position| shapes.iter().all(|shape| shape.absent.contains(position)))
                .collect();
            if !absent.is_empty() {
                resolved.absent.insert(callee, absent);
            }
            if let Some(parameter) = shapes[0].condition
                && shapes.iter().all(|shape| shape.condition == Some(parameter))
            {
                resolved.conditional.insert(callee, parameter);
            }
        }
        resolved
    }

    /// Whether a function reports failure in its returned value: a
    /// `Result` or an `Option`.
    fn fallible(&self, definition: usize) -> bool {
        returned_type(&self.items[definition].sig.output)
            .and_then(|ty| type_name(&ty))
            .is_some_and(|name| name.ends_with("Result") || name == "Option")
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
                    if let Some((path, _)) = &implementation.trait_
                        && let Some(segment) = path.segments.last()
                    {
                        let implementors = self.implementors.entry(segment.ident.to_string()).or_default();
                        if !implementors.contains(&owner) {
                            implementors.push(owner.clone());
                        }
                    }
                    for impl_item in &implementation.items {
                        match impl_item {
                            ImplItem::Type(target) if is_deref && target.ident == "Target" => {
                                let targets = self.deref_targets.entry(owner.clone()).or_default();
                                // The same impl seen twice (a vendored
                                // copy of a crate) is one target.
                                if !targets.iter().any(|known| {
                                    quote::ToTokens::to_token_stream(known).to_string() == quote::ToTokens::to_token_stream(&target.ty).to_string()
                                }) {
                                    targets.push(target.ty.clone());
                                }
                                self.deref_params.insert(
                                    owner.clone(),
                                    type_arguments(&implementation.self_ty)
                                        .iter()
                                        .filter_map(|argument| type_name(argument))
                                        .collect(),
                                );
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
                Item::Trait(item_trait) if super::rc::enabled("TRAITS") => {
                    // A trait's provided methods are reached through the
                    // trait's name when no implementor overrides them.
                    let owner = item_trait.ident.to_string();
                    self.traits.insert(owner.clone());
                    for trait_item in &item_trait.items {
                        let syn::TraitItem::Fn(method) = trait_item else {
                            continue;
                        };
                        let Some(block) = &method.default else {
                            continue;
                        };
                        let function = ItemFn {
                            attrs: method.attrs.clone(),
                            vis: syn::Visibility::Inherited,
                            modifiers: method.modifiers.clone(),
                            sig: method.sig.clone(),
                            block: Box::new(block.clone()),
                        };
                        let name = method.sig.ident.to_string();
                        self.methods
                            .entry((owner.clone(), name.clone()))
                            .or_default()
                            .push(self.definitions.len());
                        let mut attrs = cfg_attributes(&item_trait.attrs);
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
                    self.struct_crates
                        .entry(item_struct.ident.to_string())
                        .or_default()
                        .push(crate_key.to_path_buf());
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

    /// The single function `owner::name` defined in an `impl` block of
    /// this module.
    pub(crate) fn associated_in(
        &self,
        crate_key: &Path,
        module: &[String],
        owner: &str,
        name: &str,
    ) -> Option<usize> {
        let mut matches = self
            .methods
            .get(&(owner.to_owned(), name.to_owned()))?
            .iter()
            .copied()
            .filter(|&index| {
                let definition = &self.definitions[index];
                definition.crate_key == crate_key && definition.module == module
            });
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
                // Not a module: perhaps a type, as in `.to(Handlers::users)` (P9).
                return match self.resolve_associated(crate_key, module, qualifier, name) {
                    Some(index) => (Some(index), HandlerResolution::Qualified),
                    None => (None, HandlerResolution::Unresolved),
                };
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

    /// The associated function `name` (no receiver) of the type that
    /// `qualifier` names as seen from `module`: a type defined there,
    /// `handlers::H`, or `H` brought in by one explicit `use` or by exactly
    /// one glob import. `Self` is not resolved here.
    pub(crate) fn resolve_associated(
        &self,
        crate_key: &Path,
        module: &[String],
        qualifier: &[String],
        name: &str,
    ) -> Option<usize> {
        if !associated_enabled() {
            return None;
        }
        let (type_name, prefix) = qualifier.split_last()?;
        if type_name == "Self" {
            return None;
        }
        let lookup = |(key_crate, key_module): ModuleKey, owner: &str| -> Option<usize> {
            let candidates: Vec<usize> = self
                .methods
                .get(&(owner.to_owned(), name.to_owned()))?
                .iter()
                .copied()
                .filter(|&index| {
                    let definition = &self.definitions[index];
                    definition.crate_key == key_crate
                        && definition.module == key_module
                        && self.items[index].sig.receiver().is_none()
                })
                .collect();
            match candidates.as_slice() {
                [index] => Some(*index),
                _ => None,
            }
        };
        if !prefix.is_empty() {
            let path = UsePath {
                segments: prefix.to_vec(),
                leading_colon: false,
            };
            return lookup(self.resolve_module(crate_key, module, &path, 0)?, type_name);
        }
        if let Some(found) = lookup((crate_key.to_path_buf(), module.to_vec()), type_name) {
            return Some(found);
        }
        let scope = self.scope(crate_key, module)?;
        if let Some(imports) = scope.imports.get(type_name) {
            let [import] = imports.as_slice() else {
                return None;
            };
            let (imported, import_prefix) = import.segments.split_last()?;
            let path = UsePath {
                segments: import_prefix.to_vec(),
                leading_colon: import.leading_colon,
            };
            return lookup(self.resolve_module(crate_key, module, &path, 0)?, imported);
        }
        let mut found = scope
            .globs
            .iter()
            .filter_map(|glob| self.resolve_module(crate_key, module, glob, 0))
            .filter_map(|key| lookup(key, type_name));
        let first = found.next()?;
        found.next().is_none().then_some(first)
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

/// Marks a contested type name with its crate: `__archer_crate_1::Service`
/// is the `Service` of the second crate listed for that name.
const CRATE_PREFIX: &str = "__archer_crate_";

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
                let mut target = target.clone();
                let arguments = type_arguments(&current);
                if super::rc::enabled("TYPES")
                    && let Some(parameters) = self.deref_params.get(&name)
                    && parameters.len() == arguments.len()
                    && !parameters.is_empty()
                {
                    let named: HashMap<String, String> = parameters
                        .iter()
                        .zip(&arguments)
                        .map(|(parameter, argument)| (parameter.clone(), quote::ToTokens::to_token_stream(argument).to_string()))
                        .collect();
                    syn::visit_mut::VisitMut::visit_type_mut(&mut Substitute { named: &named }, &mut target);
                }
                target
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
                && let Some(found) = self.methods.get(&(name.clone(), method.to_owned()))
            {
                // `Service::find_trash` of the crate the type is written
                // for, where several crates have a `Service`.
                if found.len() > 1
                    && let Some(wanted) = self.crate_of_type(&candidate)
                {
                    let narrowed: Vec<usize> = found
                        .iter()
                        .copied()
                        .filter(|&definition| self.definitions[definition].crate_key == wanted)
                        .collect();
                    if !narrowed.is_empty() {
                        return narrowed;
                    }
                }
                return found.clone();
            }
            // A method the type does not define itself: one a trait of
            // the scan provides to its implementors.
            if let Some(name) = type_name(&candidate) {
                let mut provided: Vec<usize> = Vec::new();
                for (trait_name, implementors) in &self.implementors {
                    if implementors.contains(&name)
                        && let Some(methods) = self.methods.get(&(trait_name.clone(), method.to_owned()))
                    {
                        provided.extend(methods.iter().copied());
                    }
                }
                if !provided.is_empty() {
                    provided.sort_unstable();
                    return provided;
                }
            }
            // `dyn Trait`, `impl Trait`, or the trait named as a type
            // (`Trait::method(..)`): the method of the trait's one
            // implementor in the scan, or the trait's provided method.
            let trait_name = trait_of(&candidate)
                .or_else(|| type_name(&candidate))
                .filter(|name| self.traits.contains(name));
            if let Some(trait_name) = trait_name {
                let mut found: Vec<usize> = Vec::new();
                for implementor in self.implementors.get(&trait_name).into_iter().flatten() {
                    if let Some(methods) = self.methods.get(&(implementor.clone(), method.to_owned())) {
                        found.extend(methods.iter().copied());
                    }
                }
                if found.is_empty()
                    && let Some(provided) = self.methods.get(&(trait_name, method.to_owned()))
                {
                    found.extend(provided.iter().copied());
                }
                if !found.is_empty() {
                    return found;
                }
            }
        }
        Vec::new()
    }

    /// The trait a provided method's `self` stands for, seen from one
    /// implementor: a call `self.check()` inside trait `T`'s provided
    /// method resolves like a call on `dyn T`.
    fn known_type(&self, name: &str) -> bool {
        self.structs.contains_key(name) || self.method_owners().contains(name)
    }

    fn method_owners(&self) -> std::rc::Rc<HashSet<String>> {
        if let Some(found) = self.owners.borrow().as_ref() {
            return found.clone();
        }
        let owners: HashSet<String> = self.methods.keys().map(|(owner, _)| owner.clone()).collect();
        let owners = std::rc::Rc::new(owners);
        *self.owners.borrow_mut() = Some(owners.clone());
        owners
    }

    /// Records the type names more than one crate defines.
    fn find_contested(&mut self) {
        if !super::rc::enabled("CRATES") {
            return;
        }
        let mut crates: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let mut add = |name: &str, key: &Path| {
            let known = crates.entry(name.to_owned()).or_default();
            if !known.iter().any(|existing| existing == key) {
                known.push(key.to_path_buf());
            }
        };
        for (name, keys) in &self.struct_crates {
            for key in keys {
                add(name, key);
            }
        }
        for definition in &self.definitions {
            if let Some(owner) = &definition.owner {
                add(owner, &definition.crate_key);
            }
        }
        crates.retain(|_, keys| keys.len() > 1);
        self.contested = crates;
    }

    /// The crate a type is written for: `kernel::Service` names it, and
    /// `qualify` writes it into a contested name.
    fn crate_of_type(&self, ty: &Type) -> Option<PathBuf> {
        let Type::Path(path) = strip_reference(ty) else {
            return None;
        };
        let [first, _, ..] = path.path.segments.iter().collect::<Vec<_>>()[..] else {
            return None;
        };
        let first = first.ident.to_string();
        if let Some(position) = first.strip_prefix(CRATE_PREFIX) {
            let name = type_name(ty)?;
            return self.contested.get(&name)?.get(position.parse::<usize>().ok()?).cloned();
        }
        self.crates.get(&first).cloned()
    }

    /// `ty` as written in crate `context`, with each contested type name
    /// marked with the crate it means there: the crate's own type of that
    /// name, else the one the crate imports (`use kernel::Service`). A
    /// path that names a crate already (`kernel::Service`) is left alone.
    pub(crate) fn qualify(&self, ty: &Type, context: &Path) -> Type {
        if self.contested.is_empty() {
            return ty.clone();
        }
        struct Qualify<'i, 'a> {
            index: &'i HandlerIndex<'a>,
            context: &'i Path,
        }
        impl syn::visit_mut::VisitMut for Qualify<'_, '_> {
            fn visit_type_path_mut(&mut self, node: &mut syn::TypePath) {
                syn::visit_mut::visit_type_path_mut(self, node);
                if node.qself.is_some() {
                    return;
                }
                let Some(last) = node.path.segments.last() else {
                    return;
                };
                let name = last.ident.to_string();
                let Some(crates) = self.index.contested.get(&name) else {
                    return;
                };
                if node.path.segments.len() >= 2 {
                    let first = node.path.segments[0].ident.to_string();
                    if first.starts_with(CRATE_PREFIX) || self.index.crates.contains_key(&first) {
                        return;
                    }
                }
                let position = crates
                    .iter()
                    .position(|key| key == self.context)
                    .or_else(|| self.index.imported_from(self.context, &name, crates));
                if let Some(position) = position {
                    let last = node.path.segments.last().cloned();
                    let marker = syn::Ident::new(&format!("{CRATE_PREFIX}{position}"), proc_macro2::Span::call_site());
                    let mut segments = syn::punctuated::Punctuated::new();
                    segments.push(syn::PathSegment::from(marker));
                    segments.extend(last);
                    node.path = syn::Path {
                        leading_colon: None,
                        segments,
                    };
                }
            }
        }
        let mut ty = ty.clone();
        syn::visit_mut::VisitMut::visit_type_mut(&mut Qualify { index: self, context }, &mut ty);
        ty
    }

    /// Which of `crates` the modules of crate `context` import `name`
    /// from, if they all import it from one.
    fn imported_from(&self, context: &Path, name: &str, crates: &[PathBuf]) -> Option<usize> {
        let mut found: Option<usize> = None;
        for ((crate_key, _), scope) in &self.scopes {
            if crate_key != context {
                continue;
            }
            for import in scope.imports.get(name).into_iter().flatten() {
                let from = import
                    .segments
                    .first()
                    .and_then(|first| self.crates.get(first))
                    .and_then(|key| crates.iter().position(|known| known == key));
                match (found, from) {
                    (_, None) => {}
                    (None, Some(position)) => found = Some(position),
                    (Some(existing), Some(position)) if existing != position => return None,
                    _ => {}
                }
            }
        }
        found
    }

    /// The type a call of `callee` returns, as written in its crate.
    fn returned(&self, callee: usize, self_type: Option<&str>) -> Option<Type> {
        let returned = returned_type(&self.items[callee].sig.output)?;
        let returned = match self_type.or(self.definitions[callee].owner.as_deref()) {
            Some(owner) => replace_self(&returned, owner),
            None => returned,
        };
        Some(self.qualify(&returned, &self.definitions[callee].crate_key))
    }

    /// The type of field `field` (a name, or a tuple index) of a value of
    /// type `ty`, from the one struct of that name in the scan.
    pub(crate) fn field_type(&self, ty: &Type, field: &str) -> Option<Type> {
        for candidate in self.deref_chain(ty) {
            let Some(name) = type_name(&candidate) else {
                continue;
            };
            let Some(structs) = self.structs.get(&name) else {
                continue;
            };
            // The one struct of that name, or the one in the crate the
            // type is written for.
            let position = match structs.as_slice() {
                [_] => Some(0),
                _ => self.crate_of_type(&candidate).and_then(|wanted| {
                    let crates = self.struct_crates.get(&name)?;
                    let mut found = crates.iter().enumerate().filter(|(_, key)| **key == wanted);
                    let first = found.next()?;
                    found.next().is_none().then_some(first.0)
                }),
            };
            if let Some(position) = position {
                let context = self.struct_crates.get(&name).and_then(|crates| crates.get(position));
                return structs[position]
                    .iter()
                    .find(|(name, _)| name == field)
                    .map(|(_, ty)| match context {
                        Some(context) => self.qualify(ty, context),
                        None => ty.clone(),
                    });
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
        let item = &self.items[definition];
        let mut collector = LocalTypes {
            index: self,
            definition,
            owner: self.definitions[definition].owner.clone(),
            types: HashMap::new(),
            conflicted: HashSet::new(),
            bounds: self.trait_bounds(&item.sig),
            inferring: super::rc::enabled("TYPES"),
        };
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
            if std::env::var("ARCHER_DEBUG_TYPES").is_ok() {
                eprintln!(
                    "   chain {receiver} .{field}: {:?} structs {:?}",
                    self.deref_chain(&ty).iter().map(|ty| quote::ToTokens::to_token_stream(ty).to_string()).collect::<Vec<_>>(),
                    self.deref_chain(&ty).iter().map(|ty| type_name(ty).and_then(|name| self.structs.get(&name).map(Vec::len))).collect::<Vec<_>>()
                );
            }
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
        let found = self.resolve_generic(caller, target)?;
        // The copy made for the type this caller passes, if it passes one.
        Some(match self.instances.get(&(caller, found)) {
            Some(Some(instance)) => *instance,
            _ => found,
        })
    }

    /// `resolve_callee` before a generic function is exchanged for the
    /// copy made for this caller.
    fn resolve_generic(&self, caller: usize, target: &HandlerTarget) -> Option<usize> {
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
                        let ty = self.qualify(&ty, &self.definitions[caller].crate_key);
                        self.single(&self.methods_of(&ty, name), caller)
                    }
                }
            }
            HandlerTarget::Other => None,
        };
        found.filter(|&callee| callee != caller && self.instance_of.get(&caller) != Some(&callee))
    }
}

/// Collects the declared types of a function's named values.
struct LocalTypes<'i, 'a> {
    index: &'i HandlerIndex<'a>,
    definition: usize,
    owner: Option<String>,
    types: HashMap<String, Type>,
    conflicted: HashSet<String>,
    /// The function's type parameters bounded by a trait of the scan, as
    /// `impl Trait`: a value of type `U: UseCase` is used as the trait.
    bounds: HashMap<String, Type>,
    /// Whether types are read off calls, fields and patterns (the
    /// root-cause round), or only off struct literals and `Type::f(..)`.
    inferring: bool,
}

impl LocalTypes<'_, '_> {
    fn insert(&mut self, name: String, ty: Type) {
        if self.conflicted.contains(&name) {
            return;
        }
        // A value of a bounded type parameter is used as its trait.
        let ty = match type_name(&ty).and_then(|name| self.bounds.get(&name)) {
            Some(bound) => bound.clone(),
            None => ty,
        };
        let ty = self.index.qualify(&ty, &self.index.definitions[self.definition].crate_key);
        let written = |ty: &Type| quote::ToTokens::to_token_stream(strip_reference(ty)).to_string();
        match self.types.get(&name) {
            Some(existing) if written(existing) != written(&ty) => {
                // `let user = find(id).await; let user = user.ok_or(..)?;`:
                // one value, wrapped and unwrapped. Method calls reach the
                // inner type from either; the inner one is kept.
                if self.inferring {
                    let inside = |outer: &Type, inner: &Type| {
                        self.index
                            .deref_chain(outer)
                            .iter()
                            .skip(1)
                            .any(|link| written(link) == written(inner))
                    };
                    if inside(existing, &ty) {
                        self.types.insert(name, ty);
                        return;
                    }
                    if inside(&ty, existing) {
                        return;
                    }
                }
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
            syn::Pat::Guard(guarded) => self.bind(&guarded.pat, ty),
            syn::Pat::TupleStruct(tuple)
                if self.inferring
                    && tuple.path.segments.last().is_some_and(|segment| {
                        segment.ident == "Some" || segment.ident == "Ok"
                    }) =>
            {
                // `Some(user)` or `Ok(user)` against `Option<User>`.
                if let Some(element) = tuple.elems.first()
                    && let Some(inner) = carried(ty)
                {
                    self.bind(element, &inner);
                }
            }
            syn::Pat::TupleStruct(tuple) => {
                for (position, element) in tuple.elems.iter().enumerate() {
                    if let Some(field) = self.index.field_type(ty, &position.to_string()) {
                        self.bind(element, &field);
                    }
                }
            }
            syn::Pat::Tuple(tuple) if self.inferring => {
                if let Type::Tuple(types) = strip_reference(ty) {
                    for (element, ty) in tuple.elems.iter().zip(&types.elems) {
                        self.bind(element, ty);
                    }
                }
            }
            syn::Pat::Or(cases) if self.inferring => {
                if let Some(first) = cases.cases.first() {
                    self.bind(first, ty);
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

    /// The type of an initializer: a struct literal or `Type::f(..)` with
    /// `f`'s declared return type, through `?` and `.await`; and, in the
    /// root-cause round, whatever `HandlerIndex::expr_type` reads.
    fn initializer_type(&self, expr: &syn::Expr) -> Option<Type> {
        if self.inferring {
            return self
                .index
                .expr_type(self.definition, self.owner.as_deref(), &self.types, expr, 0);
        }
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
        if self.inferring {
            // The initializer first: `let user = match found { Some(u) =>
            // u, .. }` has the type its arm's binding has.
            syn::visit::visit_local(self, node);
        }
        match &node.pat {
            syn::Pat::Type(typed) => self.bind(&typed.pat, &typed.ty),
            pattern => {
                if let Some(init) = &node.init
                    && (init.diverge.is_none() || self.inferring)
                    && let Some(ty) = self.initializer_type(&init.expr)
                {
                    self.bind(pattern, &ty);
                }
            }
        }
        if !self.inferring {
            syn::visit::visit_local(self, node);
        }
    }

    fn visit_expr_let(&mut self, node: &'ast syn::ExprLet) {
        if self.inferring
            && let Some(ty) = self.initializer_type(&node.expr)
        {
            self.bind(&node.pat, &ty);
        }
        syn::visit::visit_expr_let(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if self.inferring
            && let Some(ty) = self.initializer_type(&node.expr)
        {
            for arm in &node.arms {
                self.bind(&arm.pat, &ty);
            }
        }
        syn::visit::visit_expr_match(self, node);
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

/// A type without its references and parentheses.
pub(crate) fn strip_reference(ty: &Type) -> &Type {
    match ty {
        Type::Reference(reference) => strip_reference(&reference.elem),
        Type::Paren(paren) => strip_reference(&paren.elem),
        Type::Group(group) => strip_reference(&group.elem),
        _ => ty,
    }
}

/// The trait of `dyn Trait` or `impl Trait`: its first bound that is not a
/// marker (`Send`, `Sync`, `Debug`..).
fn trait_of(ty: &Type) -> Option<String> {
    let bounds = match strip_reference(ty) {
        Type::TraitObject(object) => &object.bounds,
        Type::ImplTrait(implemented) => &implemented.bounds,
        _ => return None,
    };
    bounds.iter().find_map(|bound| match bound {
        syn::TypeParamBound::Trait(found) => found
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .filter(|name| !MARKER_TRAITS.contains(&name.as_str())),
        _ => None,
    })
}

/// Traits that say nothing about which methods a value has.
const MARKER_TRAITS: &[&str] = &[
    "Send", "Sync", "Sized", "Unpin", "Debug", "Clone", "Copy", "Default", "Serialize", "Deserialize",
    "DeserializeOwned", "Display", "PartialEq", "Eq", "Hash",
];

/// What `?`, `.unwrap()`, `Some(x)` or `Ok(x)` take out of a value of type
/// `ty`: the first type argument of an `Option` or a `..Result`.
fn carried(ty: &Type) -> Option<Type> {
    let ty = strip_reference(ty);
    match type_name(ty).as_deref() {
        Some(name) if name.ends_with("Result") || name == "Option" => {
            type_arguments(ty).first().map(|inner| (*inner).clone())
        }
        _ => None,
    }
}

/// The value type of a function's declared return type: `T` for `-> T`,
/// and for `-> impl Future<Output = T>`.
fn returned_type(output: &syn::ReturnType) -> Option<Type> {
    let syn::ReturnType::Type(_, ty) = output else {
        return None;
    };
    if let Type::ImplTrait(implemented) = &**ty {
        for bound in &implemented.bounds {
            if let syn::TypeParamBound::Trait(found) = bound
                && let Some(segment) = found.path.segments.last()
                && segment.ident == "Future"
                && let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments
            {
                for argument in &arguments.args {
                    if let syn::GenericArgument::AssocType(output) = argument
                        && output.ident == "Output"
                    {
                        return Some(output.ty.clone());
                    }
                }
            }
        }
        return None;
    }
    Some((**ty).clone())
}

/// Methods and functions whose result is the value they are given, perhaps
/// wrapped or unwrapped: its type reaches the same methods.
const SAME_VALUE: &[&str] = &[
    "clone", "cloned", "copied", "to_owned", "as_ref", "as_mut", "as_deref", "as_deref_mut", "borrow",
    "borrow_mut", "deref", "deref_mut", "into_inner", "get_ref", "get_mut", "map_err", "ok", "ok_or",
    "ok_or_else", "or_else", "context", "with_context", "inspect_err", "inspect", "unwrap_or",
    "unwrap_or_else", "unwrap_or_default", "lock", "read", "write", "take", "into", "iter", "into_iter",
    "first", "last", "next", "pop", "get", "peekable", "as_slice", "to_vec",
];
const UNWRAPS: &[&str] = &["unwrap", "expect", "unwrap_unchecked"];
/// Functions that wrap or move their one argument.
const WRAPPERS: &[&str] = &["Some", "Ok", "new", "from", "take", "replace", "pin"];
const WRAPPER_TYPES: &[&str] = &["Box", "Arc", "Rc", "Data", "Json", "Mutex", "RwLock", "RefCell", "Cell", "mem", "Pin"];

/// How deep an expression's type is read.
const MAX_EXPR_DEPTH: usize = 24;

impl HandlerIndex<'_> {
    /// A function's type parameters bounded by a trait defined in the scan,
    /// as `impl Trait`.
    fn trait_bounds(&self, signature: &syn::Signature) -> HashMap<String, Type> {
        let mut bounds: HashMap<String, Type> = HashMap::new();
        if self.traits.is_empty() {
            return bounds;
        }
        let mut bound = |name: String, found: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>| {
            for candidate in found {
                if let syn::TypeParamBound::Trait(candidate) = candidate
                    && let Some(segment) = candidate.path.segments.last()
                    && self.traits.contains(&segment.ident.to_string())
                    && let Ok(ty) = syn::parse_str::<Type>(&format!("impl {}", segment.ident))
                {
                    bounds.entry(name).or_insert(ty);
                    return;
                }
            }
        };
        for parameter in &signature.generics.params {
            if let syn::GenericParam::Type(parameter) = parameter {
                bound(parameter.ident.to_string(), &parameter.bounds);
            }
        }
        if let Some(clause) = &signature.generics.where_clause {
            for predicate in &clause.predicates {
                if let syn::WherePredicate::Type(predicate) = predicate
                    && let Type::Path(path) = &predicate.bounded_ty
                    && let Some(ident) = path.path.get_ident()
                    && signature.generics.params.iter().any(|parameter| {
                        matches!(parameter, syn::GenericParam::Type(parameter) if parameter.ident == *ident)
                    })
                {
                    bound(ident.to_string(), &predicate.bounds);
                }
            }
        }
        bounds
    }

    /// The type of an expression in `definition`'s body, read without
    /// solving anything: a named value's type, a field's declared type, a
    /// call's declared return type, through `?`, `.await`, references and
    /// calls that hand their value on. `None` where that is not enough.
    pub(crate) fn expr_type(
        &self,
        definition: usize,
        owner: Option<&str>,
        types: &HashMap<String, Type>,
        expr: &syn::Expr,
        depth: usize,
    ) -> Option<Type> {
        use syn::Expr;
        if depth > MAX_EXPR_DEPTH {
            return None;
        }
        let of = |inner: &Expr| self.expr_type(definition, owner, types, inner, depth + 1);
        match expr {
            Expr::Struct(literal) if literal.qself.is_none() => {
                let name = literal.path.segments.last()?.ident.to_string();
                let written = if name == "Self" {
                    syn::parse_str::<Type>(owner?).ok()?
                } else {
                    Type::Path(syn::TypePath {
                        attrs: Vec::new(),
                        qself: None,
                        path: literal.path.clone(),
                    })
                };
                Some(self.qualify(&written, &self.definitions[definition].crate_key))
            }
            Expr::Await(inner) => of(&inner.base),
            Expr::Try(inner) => {
                let ty = of(&inner.expr)?;
                match type_name(&ty).as_deref() {
                    Some(name) if name.ends_with("Result") || name == "Option" => carried(&ty),
                    _ => Some(ty),
                }
            }
            Expr::Paren(inner) => of(&inner.expr),
            Expr::Group(inner) => of(&inner.expr),
            Expr::Reference(inner) => of(&inner.expr),
            Expr::Unary(inner) if matches!(inner.op, syn::UnOp::Deref(_)) => of(&inner.expr),
            Expr::Cast(cast) => Some(self.qualify(&cast.ty, &self.definitions[definition].crate_key)),
            Expr::Path(path) if path.qself.is_none() => {
                let ident = path.path.get_ident()?;
                types.get(&ident.to_string()).cloned()
            }
            Expr::Field(field) => {
                let base = of(&field.base)?;
                let member = match &field.member {
                    syn::Member::Named(name) => name.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };
                self.field_type(&base, &member)
            }
            Expr::Block(block) => match block.block.stmts.last() {
                Some(syn::Stmt::Expr(tail, None)) => of(tail),
                _ => None,
            },
            Expr::Match(matched) => matched.arms.iter().find_map(|arm| of(&arm.body)),
            Expr::If(branch) => match branch.then_branch.stmts.last() {
                Some(syn::Stmt::Expr(tail, None)) => of(tail),
                _ => None,
            },
            Expr::Call(call) => {
                let Expr::Path(path) = &*call.func else {
                    return None;
                };
                let segments: Vec<String> = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect();
                let target = HandlerTarget::Path {
                    segments: segments.clone(),
                    leading_colon: path.path.leading_colon.is_some(),
                };
                if let Some(callee) = self.resolve_generic(definition, &target) {
                    return self.returned(callee, None);
                }
                // `Some(user)`, `Arc::new(service)`, `mem::take(&mut id)`.
                let wraps = match segments.as_slice() {
                    [name] => name == "Some" || name == "Ok",
                    [.., qualifier, name] => {
                        WRAPPER_TYPES.contains(&qualifier.as_str()) && WRAPPERS.contains(&name.as_str())
                    }
                    [] => false,
                };
                if wraps {
                    return call.args.first().and_then(of);
                }
                None
            }
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                let receiver = of(&call.receiver);
                if let Some(receiver) = &receiver
                    && let Some(callee) = self.single(&self.methods_of(receiver, &method), definition)
                {
                    // A provided method's `Self` is the receiver.
                    let provided = self.definitions[callee]
                        .owner
                        .as_ref()
                        .is_some_and(|owner| self.traits.contains(owner));
                    let receiver_written = provided
                        .then(|| quote::ToTokens::to_token_stream(strip_reference(receiver)).to_string());
                    return self.returned(callee, receiver_written.as_deref());
                }
                if UNWRAPS.contains(&method.as_str()) {
                    let receiver = receiver?;
                    return carried(&receiver).or(Some(receiver));
                }
                if SAME_VALUE.contains(&method.as_str()) {
                    return receiver;
                }
                None
            }
            _ => None,
        }
    }

    /// The type a call site passes for a parameter, as a type of the scan:
    /// the first type in the argument's deref chain that has a struct or an
    /// `impl` block here.
    fn concrete(&self, ty: &Type, generic: &HashSet<String>) -> Option<String> {
        self.deref_chain(strip_reference(ty)).iter().find_map(|link| {
            let name =
                type_name(strip_reference(link)).filter(|name| !generic.contains(name) && self.known_type(name))?;
            // A contested name keeps the crate it is written for.
            if self.contested.contains_key(&name)
                && self.crate_of_type(link).is_some()
                && let Type::Path(path) = strip_reference(link)
                && let Some(first) = path.path.segments.first()
            {
                return Some(format!("{}::{name}", first.ident));
            }
            Some(name)
        })
    }

    /// Makes a copy of each generic function for each type its callers
    /// pass, however deep (`execute(usecase)` -> `run(usecase)` ->
    /// `usecase.execute()`), so that both the evidence and the caller-use
    /// layers read the method the call reaches. A parameter is replaced
    /// when its declared type is a type parameter (`U`, `&U`), `impl
    /// Trait`, or a trait object, and the argument's type is a type of the
    /// scan.
    fn instantiate_generics(&mut self) {
        if !super::rc::enabled("GENERICS") {
            return;
        }
        let originals = self.definitions.len();
        let limit = originals + originals.max(4000);
        let mut made: HashMap<(usize, Vec<(String, String)>), usize> = HashMap::new();
        let mut pending: Vec<(usize, usize)> = (0..originals).rev().map(|definition| (definition, 0)).collect();
        while let Some((caller, depth)) = pending.pop() {
            let types = self.local_types(caller);
            let owner = self.definitions[caller].owner.clone();
            let generic: HashSet<String> = self.items[caller]
                .sig
                .generics
                .params
                .iter()
                .filter_map(|parameter| match parameter {
                    syn::GenericParam::Type(parameter) => Some(parameter.ident.to_string()),
                    _ => None,
                })
                .collect();
            let mut sites = CallSites::default();
            syn::visit::Visit::visit_block(&mut sites, &self.items[caller].block);
            for (target, arguments) in sites.found {
                let Some(callee) = self.resolve_generic(caller, &target) else {
                    continue;
                };
                let passed: Vec<Option<String>> = arguments
                    .iter()
                    .map(|argument| {
                        self.expr_type(caller, owner.as_deref(), &types, argument, 0)
                            .and_then(|ty| self.concrete(&ty, &generic))
                    })
                    .collect();
                let replaced = self.replacements(callee, &passed);
                if replaced.is_empty() {
                    continue;
                }
                let key = (callee, replaced.clone());
                let instance = match made.get(&key) {
                    Some(instance) => *instance,
                    None => {
                        if self.definitions.len() >= limit || depth >= MAX_INSTANCE_DEPTH {
                            continue;
                        }
                        let instance = self.instantiate(callee, &replaced);
                        made.insert(key, instance);
                        pending.push((instance, depth + 1));
                        instance
                    }
                };
                match self.instances.get(&(caller, callee)) {
                    None => {
                        self.instances.insert((caller, callee), Some(instance));
                    }
                    Some(Some(existing)) if *existing != instance => {
                        self.instances.insert((caller, callee), None);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Which of `callee`'s parameters a call replaces, given the scan type
    /// each argument has: `("U", "RenameUseCase")` for a type parameter,
    /// `("#2", "JwtAuth")` for the `impl Trait` or `dyn Trait` parameter at
    /// position 2.
    fn replacements(&self, callee: usize, passed: &[Option<String>]) -> Vec<(String, String)> {
        let item = &self.items[callee];
        let generic: HashSet<String> = item
            .sig
            .generics
            .params
            .iter()
            .filter_map(|parameter| match parameter {
                syn::GenericParam::Type(parameter) => Some(parameter.ident.to_string()),
                _ => None,
            })
            .collect();
        let mut replaced: Vec<(String, String)> = Vec::new();
        for (position, input) in item.sig.inputs.iter().enumerate() {
            let syn::FnArg::Typed(typed) = input else {
                continue;
            };
            let Some(Some(concrete)) = passed.get(position) else {
                continue;
            };
            let declared = strip_reference(&typed.ty);
            let key = match declared {
                Type::Path(path) => match path.path.get_ident() {
                    Some(ident) if generic.contains(&ident.to_string()) => ident.to_string(),
                    // `Box<dyn Policy>`, `Arc<dyn Policy>`.
                    _ => match type_arguments(declared).as_slice() {
                        [inner] if trait_of(inner).is_some() => format!("#{position}"),
                        _ => continue,
                    },
                },
                Type::ImplTrait(_) | Type::TraitObject(_) => {
                    // Closures are not types of the scan; a trait of the
                    // scan, or one whose implementor is, is.
                    if trait_of(declared).is_none() {
                        continue;
                    }
                    format!("#{position}")
                }
                _ => continue,
            };
            if !replaced.iter().any(|(existing, _)| *existing == key) {
                replaced.push((key, concrete.clone()));
            }
        }
        replaced
    }

    /// A copy of `callee` with `replaced` applied; returns its index.
    fn instantiate(&mut self, callee: usize, replaced: &[(String, String)]) -> usize {
        let mut item: ItemFn = self.items[callee].clone().into_owned();
        let named: HashMap<String, String> = replaced
            .iter()
            .filter(|(key, _)| !key.starts_with('#'))
            .cloned()
            .collect();
        for (key, concrete) in replaced {
            if let Some(position) = key.strip_prefix('#').and_then(|position| position.parse::<usize>().ok())
                && let Some(syn::FnArg::Typed(typed)) = item.sig.inputs.iter_mut().nth(position)
                && let Ok(ty) = syn::parse_str::<Type>(concrete)
            {
                *typed.ty = ty;
            }
        }
        if !named.is_empty() {
            let mut substitute = Substitute { named: &named };
            syn::visit_mut::VisitMut::visit_item_fn_mut(&mut substitute, &mut item);
            item.sig.generics.params = item
                .sig
                .generics
                .params
                .iter()
                .filter(|parameter| {
                    !matches!(parameter, syn::GenericParam::Type(parameter) if named.contains_key(&parameter.ident.to_string()) || named.values().any(|concrete| parameter.ident == concrete))
                })
                .cloned()
                .collect();
        }
        let mut definition = self.definitions[callee].clone();
        definition.evidence = Vec::new();
        definition.own = function_evidence_in(&definition.file, &item, definition.owner.as_deref());
        let instance = self.definitions.len();
        self.definitions.push(definition);
        self.items.push(Cow::Owned(item));
        self.instance_of.insert(instance, callee);
        instance
    }

    /// `ARCHER_DEBUG_CALLS=name`: prints, for each function of that name,
    /// the types Archer read for its values and where each call resolves.
    fn debug_calls(&self) {
        let Ok(wanted) = std::env::var("ARCHER_DEBUG_CALLS") else {
            return;
        };
        for (definition, found) in self.definitions.iter().enumerate() {
            if found.name != wanted {
                continue;
            }
            eprintln!(
                "== #{definition} {} ({}){}",
                found.rust_path(),
                found.file.display(),
                self.instance_of
                    .get(&definition)
                    .map(|generic| format!(" copy of #{generic}"))
                    .unwrap_or_default()
            );
            let types = self.local_types(definition);
            let mut names: Vec<&String> = types.keys().collect();
            names.sort();
            for name in names {
                eprintln!("   {name}: {}", quote::ToTokens::to_token_stream(&types[name]));
            }
            let mut sites = CallSites::default();
            syn::visit::Visit::visit_block(&mut sites, &self.items[definition].block);
            for (target, _) in sites.found {
                let written = target.written().unwrap_or_default();
                match self.resolve_callee(definition, &target) {
                    Some(callee) => eprintln!(
                        "   call {written} -> #{callee} {}{}",
                        self.definitions[callee].rust_path(),
                        if self.instance_of.contains_key(&callee) { " (copy)" } else { "" }
                    ),
                    None => eprintln!("   call {written} -> ?"),
                }
            }
            for found in &found.evidence {
                eprintln!("   evidence {:?} {} {:?}", found.kind, found.mechanism, found.symbol);
            }
        }
    }
}

/// How deep copies of generic functions call further copies.
const MAX_INSTANCE_DEPTH: usize = 6;

/// The calls in a body with their argument expressions; a method call's
/// receiver is argument 0, as the method's `self` is its first input.
#[derive(Default)]
struct CallSites {
    found: Vec<(HandlerTarget, Vec<syn::Expr>)>,
}

impl<'ast> syn::visit::Visit<'ast> for CallSites {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(target @ HandlerTarget::Path { .. }) = handler_target(&node.func) {
            self.found.push((target, node.args.iter().cloned().collect()));
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if let Some(receiver) = receiver_path(&node.receiver) {
            self.found.push((
                HandlerTarget::Method {
                    receiver,
                    method: node.method.to_string(),
                },
                std::iter::once((*node.receiver).clone())
                    .chain(node.args.iter().cloned())
                    .collect(),
            ));
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
    fn visit_item_impl(&mut self, _: &'ast syn::ItemImpl) {}
}

/// Writes a concrete type for a type parameter: `U` becomes the type, and
/// `U::Response`, `U::subscribers()` name it.
struct Substitute<'n> {
    named: &'n HashMap<String, String>,
}

impl syn::visit_mut::VisitMut for Substitute<'_> {
    fn visit_type_mut(&mut self, node: &mut Type) {
        if let Type::Path(path) = node
            && path.qself.is_none()
            && let Some(ident) = path.path.get_ident()
            && let Some(concrete) = self.named.get(&ident.to_string())
            && let Ok(ty) = syn::parse_str::<Type>(concrete)
        {
            *node = ty;
            return;
        }
        syn::visit_mut::visit_type_mut(self, node);
    }

    fn visit_path_mut(&mut self, node: &mut syn::Path) {
        if node.segments.len() >= 2
            && let Some(first) = node.segments.first_mut()
            && first.arguments.is_none()
            && let Some(concrete) = self.named.get(&first.ident.to_string())
            && let Ok(written) = syn::parse_str::<syn::Path>(concrete)
            && written.segments.iter().all(|segment| segment.arguments.is_none())
        {
            // `U::run()` for `U = kernel::Service`: `kernel::Service::run()`.
            let rest: Vec<syn::PathSegment> = node.segments.iter().skip(1).cloned().collect();
            node.segments = written.segments.into_iter().chain(rest).collect();
        }
        syn::visit_mut::visit_path_mut(self, node);
    }
}
