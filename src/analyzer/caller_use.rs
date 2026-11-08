//! How a handler treats its caller: which identity values it takes, which of
//! their fields it reads, which calls it hands them to, and whether it
//! compares them with something else.
//!
//! These facts are recorded without deciding what they mean. A route is
//! later compared with peers that take the same identity type: when nearly
//! all of them hand it to the same call (`check_private_instance`), read the
//! same field (`auth.profile`), or compare it with a record, a route that
//! does not is reported (see `drift::peer_checks`). The vocabulary comes from
//! the scanned application, not from a list of names.
//!
//! Features are strings of the form `kind:Type` or `kind:Type:detail`:
//! - `takes:T`: a handler or a closure inside it binds a parameter of
//!   identity type `T` to a name it can use (not `_` or `_name`);
//! - `reads:T:field`: it reads `binding.field` of such a parameter;
//! - `checks:T:callee`: it passes the parameter, a field of it, or a value
//!   computed from it to `callee` (as an argument or the receiver), where
//!   the call decides something: its value is discarded after `?`
//!   (`check_private_instance(&user, &site)?;`) or it is a branch condition
//!   (`if !is_mod_or_admin(..)`). A call whose result is kept is a fetch
//!   (`let post = Post::read(&mut pool, id, &user)?`), not a check;
//! - `scheme:Name`: it names an authentication scheme value
//!   (`&auth::AdminApiAuth`, `auth::JWTAuth { .. }`), as handlers that pass
//!   their scheme to a wrapper do;
//! - `acts:T`: it makes a deciding call with the caller that is not a check
//!   (`update_profile(&auth.profile)?;`);
//! - `auths:f()`: it calls `f`, a function that yields the caller, whether
//!   or not it keeps the result;
//! - `calls:f` and `requires:f#i:arg`: it calls the identity source `f`,
//!   passing `arg` (not `None`) as argument `i`
//!   (`authorize_session(&req, Some(&origin), Some(Maintainer))`);
//! - `compares:T`: it compares a value derived from the parameter with a
//!   value that is not (a record's owner field, an id from the path);
//! - `binds:K:p`: it holds request value `p` to the caller, where `K` is
//!   `path` (a `Path` extractor's parameter) or `body` (a `Json`, `Query`
//!   or `Form` field): a comparison of the two, a check given both, or a
//!   load scoped by both. `p` is the name the request gives the value, so
//!   it can be matched with the route template's parameter;
//! - `mentions:body:p`: it reads field `p` of the body, query or form.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use syn::{
    BinOp, Expr, ExprClosure, FnArg, GenericArgument, ItemFn, Pat, PathArguments, Type,
    visit::{self, Visit},
};

use super::{
    evidence::{identity_type, names_authentication, receiver_path},
    handlers::HandlerIndex,
    model::Route,
    routes::{HandlerTarget, handler_target},
};

/// Calls that only convert, copy, or unwrap a value; passing an identity
/// through them passes the identity.
const TRANSPARENT_CALLS: [&str; 22] = [
    "clone",
    "as_ref",
    "as_mut",
    "into_inner",
    "to_owned",
    "to_string",
    "borrow",
    "into",
    "deref",
    "as_deref",
    "map",
    "and_then",
    "unwrap",
    "unwrap_or",
    "unwrap_or_default",
    "expect",
    "ok",
    "ok_or",
    "ok_or_else",
    "get_id",
    "Some",
    "Ok",
];

/// The label of an identity whose type Archer cannot see.
pub(crate) const UNKNOWN_TYPE: &str = "?";

/// Methods that probe a value's shape (`user.is_none()`), not the caller's
/// rights; presence of an identity is authentication, judged elsewhere.
const PROBES: [&str; 7] = [
    "is_none",
    "is_some",
    "is_ok",
    "is_err",
    "is_empty",
    "is_some_and",
    "is_none_or",
];

/// Caller-use features for each route, parallel to `routes`.
///
/// A handler's features include those of the repository functions it
/// calls, however deep: free functions, methods of a typed value
/// (`principal.validate()`), associated functions (`Type::check(..)`), and
/// service functions in other modules. A callee's parameter counts as the
/// caller's identity when its type is an identity type or when the call
/// passes it a value derived from one (`delete_evidence(state,
/// auth.profile_id, ..)`, or the receiver of `principal.validate()`), so a
/// check made in a service function is the handler's check. Summaries are
/// memoized per function and identity-bound parameters, and recomputed
/// until they stop changing when calls form a cycle.
pub(crate) fn caller_use<'f>(
    index: &HandlerIndex,
    files: impl IntoIterator<Item = &'f syn::File>,
    routes: &[Route],
) -> Vec<Vec<String>> {
    let mut walker = Walker {
        index,
        shapes: return_shapes(files),
        sources: std::rc::Rc::new(identity_sources(index, routes)),
        analyzed: HashMap::new(),
        summaries: HashMap::new(),
        previous: HashMap::new(),
        in_progress: HashSet::new(),
        cycle: false,
        shapes_of: HashMap::new(),
    };
    let roots: Vec<usize> = {
        let mut seen = HashSet::new();
        routes
            .iter()
            .filter_map(|route| route.origin.definition)
            .filter(|definition| seen.insert(*definition))
            .collect()
    };
    let mut combined: HashMap<usize, Vec<String>> = HashMap::new();
    for _ in 0..MAX_ROUNDS {
        walker.cycle = false;
        for &definition in &roots {
            let summary = walker.summary(definition, &[]);
            let name = &index.definitions[definition].name;
            let mut features: Vec<String> = summary.features.into_iter().collect();
            features.extend(
                summary
                    .sites
                    .iter()
                    .map(|(feature, site)| format!("{SITE}{feature}{SITE_SEPARATOR}{name} -> {site}")),
            );
            combined.insert(definition, features);
        }
        if !walker.cycle || walker.summaries == walker.previous {
            break;
        }
        walker.previous = std::mem::take(&mut walker.summaries);
    }
    routes
        .iter()
        .map(|route| {
            route
                .origin
                .definition
                .and_then(|definition| combined.get(&definition).cloned())
                .unwrap_or_default()
        })
        .collect()
}

/// Not a feature: where a route's check `feature` is made, written
/// `site:feature\u{1f}chain`. `peer_checks` cites it in findings.
pub(crate) const SITE: &str = "site:";
pub(crate) const SITE_SEPARATOR: char = '\u{1f}';

/// The last three components of a path, for evidence text.
fn short_path(path: &std::path::Path) -> String {
    let components: Vec<String> = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    components[components.len().saturating_sub(3)..].join("/")
}

/// How many times summaries are recomputed when calls form a cycle.
const MAX_ROUNDS: usize = 4;

/// A function, with the positions of its parameters bound to the caller's
/// identity and that identity's label.
type SummaryKey = (usize, Vec<(usize, String)>);

#[derive(Clone, Default, PartialEq)]
struct Summary {
    features: BTreeSet<String>,
    /// It can reject the request, in a branch that depends on the caller:
    /// `if !self.is_admin() { return Err(..) }`, or a check call under `?`.
    rejects: bool,
    /// Where each check is made, by compared feature: the call chain from
    /// this function and the check call's location.
    sites: BTreeMap<String, String>,
}

struct Walker<'i, 'a> {
    index: &'i HandlerIndex<'a>,
    shapes: HashMap<String, Vec<bool>>,
    sources: std::rc::Rc<HashSet<String>>,
    analyzed: HashMap<SummaryKey, Analysis>,
    summaries: HashMap<SummaryKey, Summary>,
    /// The last round's summaries, used for a function met again while its
    /// own summary is being computed.
    previous: HashMap<SummaryKey, Summary>,
    in_progress: HashSet<SummaryKey>,
    cycle: bool,
    /// How each function that takes a closure hands it its parameters.
    shapes_of: HashMap<usize, Option<WrapperShape>>,
}

impl Walker<'_, '_> {
    fn analysis(&mut self, definition: usize, bound: &[(usize, String)]) -> Analysis {
        let key = (definition, bound.to_vec());
        if let Some(found) = self.analyzed.get(&key) {
            return found.clone();
        }
        let mut analysis =
            analyze_function(&self.index.items[definition], bound, &self.sources, &HashMap::new());
        // Closures handed to a wrapper that passes them the request data:
        // bind those inputs and read the function again.
        let mut inputs: HashMap<ClosureKey, Vec<(usize, Option<Origin>)>> = HashMap::new();
        for call in analysis.wrapper_calls.clone() {
            let Some(wrapper) = self.index.resolve_callee(definition, &call.target) else {
                continue;
            };
            let Some(shape) = self.wrapper_shape(wrapper, 0) else {
                continue;
            };
            let Some((_, closure)) = call.closures.iter().find(|(position, _)| *position == shape.closure) else {
                continue;
            };
            for (argument, input) in &shape.passes {
                if let Some((_, origin)) = call.requested.iter().find(|(position, _)| position == argument) {
                    inputs.entry(*closure).or_default().push((*input, origin.clone()));
                }
            }
        }
        if !inputs.is_empty() {
            analysis = analyze_function(&self.index.items[definition], bound, &self.sources, &inputs);
        }
        self.analyzed.insert(key, analysis.clone());
        analysis
    }

    /// How a function that takes a closure parameter (`func: F` with
    /// `F: Fn(..)`, or `impl Fn(..)`) calls it: which of its parameters
    /// reach which closure input, directly or through functions it hands
    /// the closure on to, up to three deep.
    fn wrapper_shape(&mut self, definition: usize, depth: usize) -> Option<WrapperShape> {
        if let Some(found) = self.shapes_of.get(&definition) {
            return found.clone();
        }
        if depth > 3 {
            return None;
        }
        self.shapes_of.insert(definition, None);
        let item = self.index.items[definition].clone();
        let callable = callable_generics(&item.sig);
        let names: Vec<Option<String>> = item
            .sig
            .inputs
            .iter()
            .map(|input| match input {
                FnArg::Typed(typed) => match &*typed.pat {
                    Pat::Ident(ident) => Some(ident.ident.to_string()),
                    _ => None,
                },
                FnArg::Receiver(_) => None,
            })
            .collect();
        let closure = item.sig.inputs.iter().position(|input| {
            matches!(input, FnArg::Typed(typed) if is_callable(&typed.ty, &callable))
        })?;
        let function = names[closure].clone()?;
        struct Calls<'n> {
            function: &'n str,
            direct: Vec<Vec<Expr>>,
            handed: Vec<(HandlerTarget, usize, Vec<Expr>)>,
        }
        impl<'ast> Visit<'ast> for Calls<'_> {
            fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
                let arguments: Vec<Expr> = node.args.iter().cloned().collect();
                if matches!(&*node.func, Expr::Path(path) if path.path.is_ident(self.function)) {
                    self.direct.push(arguments);
                } else if let Some(position) = node.args.iter().position(|argument| {
                    matches!(strip_transparent(argument), Expr::Path(path) if path.path.is_ident(self.function))
                }) && let Some(target) = handler_target(&node.func)
                {
                    self.handed.push((target, position, arguments));
                }
                visit::visit_expr_call(self, node);
            }
        }
        let mut calls = Calls {
            function: &function,
            direct: Vec::new(),
            handed: Vec::new(),
        };
        calls.visit_block(&item.block);
        let reaches = |argument: &Expr| -> Vec<usize> {
            names
                .iter()
                .enumerate()
                .filter(|(position, name)| {
                    *position != closure
                        && name.as_ref().is_some_and(|name| mentions_any(argument, |found| found == name))
                })
                .map(|(position, _)| position)
                .collect()
        };
        let mut passes: Vec<(usize, usize)> = Vec::new();
        for arguments in &calls.direct {
            for (input, argument) in arguments.iter().enumerate() {
                passes.extend(reaches(argument).into_iter().map(|own| (own, input)));
            }
        }
        for (target, position, arguments) in &calls.handed {
            let Some(inner) = self.index.resolve_callee(definition, target) else {
                continue;
            };
            let Some(shape) = self.wrapper_shape(inner, depth + 1) else {
                continue;
            };
            if shape.closure != *position {
                continue;
            }
            for (theirs, input) in &shape.passes {
                if let Some(argument) = arguments.get(*theirs) {
                    passes.extend(reaches(argument).into_iter().map(|own| (own, *input)));
                }
            }
        }
        passes.sort();
        passes.dedup();
        let shape = (!passes.is_empty()).then_some(WrapperShape { closure, passes });
        self.shapes_of.insert(definition, shape.clone());
        shape
    }

    /// Whether a deciding call is a check, and whether it makes the calling
    /// function a check too: when Archer resolved it, or it is outside the
    /// scan. A resolved call is a check when that function
    /// returns `bool` or can reject on the identity it is given (a branch on
    /// it rejects, or it makes such a check itself); a `Result<()>` that only
    /// propagates other errors (`update_profile(..)?;`) is a side effect,
    /// not a check. A call Archer cannot resolve stays a check when its name
    /// returns a verdict somewhere, or nowhere is known.
    fn is_check(&mut self, caller: usize, candidate: &CheckCandidate) -> (bool, bool) {
        if let Some(target) = &candidate.target
            && let Some(callee) = self.index.resolve_callee(caller, target)
        {
            let predicate = returns_bool(&self.index.items[callee].sig.output);
            return (predicate || self.summary(callee, &candidate.bound).rejects, true);
        }
        match self.shapes.get(&candidate.name) {
            // Defined in the scan but not resolved: its shape is a guess.
            Some(verdicts) if !verdicts.is_empty() => (verdicts.iter().any(|verdict| *verdict), false),
            // Outside the scan (a library's `authorize(&user)?`): a check
            // whose code Archer cannot read.
            _ => (true, true),
        }
    }

    fn summary(&mut self, definition: usize, bound: &[(usize, String)]) -> Summary {
        let key = (definition, bound.to_vec());
        if let Some(found) = self.summaries.get(&key) {
            return found.clone();
        }
        if self.in_progress.contains(&key) {
            self.cycle = true;
            return self.previous.get(&key).cloned().unwrap_or_default();
        }
        self.in_progress.insert(key.clone());
        let analysis = self.analysis(definition, bound);
        let mut summary = Summary {
            features: analysis.features.clone(),
            rejects: analysis.rejects,
            sites: BTreeMap::new(),
        };
        for candidate in &analysis.checks {
            let (check, resolved) = self.is_check(definition, candidate);
            if check {
                summary.features.insert(candidate.feature.clone());
                // A record handed with the caller to a call under `?` is
                // held to the caller only by a check Archer read; a call it
                // cannot read (`Flag::open(&pool, user.id, note.key)`)
                // more often records the two together. In a branch
                // condition the call decides.
                let guards = candidate.condition
                    || candidate.target.as_ref().is_some_and(|target| {
                        self.index.resolve_callee(definition, target).is_some()
                    });
                for key in candidate.records.iter().filter(|_| guards) {
                    summary
                        .features
                        .insert(format!("{GUARDS}{key}:checks it with `{}`", candidate.name));
                }
                // A check given the caller and a request value holds the
                // value to the caller.
                if resolved || candidate.condition {
                    for tag in candidate.requested.iter().filter(|tag| tag.starts_with("path:")) {
                        summary.features.insert(format!("{BINDS}{tag}"));
                    }
                }
                // A check Archer followed, or library code, makes this
                // function a check; a guess from a name defined in the scan
                // does not.
                summary.rejects |= resolved;
                summary
                    .sites
                    .entry(super::peer_checks::compared(&candidate.feature))
                    .or_insert_with(|| {
                        format!(
                            "`{}` at {}:{}",
                            candidate.name,
                            short_path(&self.index.definitions[definition].file),
                            candidate.line
                        )
                    });
            } else if let Some(label) = candidate
                .feature
                .strip_prefix("checks:")
                .and_then(|rest| rest.split_once(':'))
                .map(|(label, _)| label)
            {
                // Not a check, but the handler acts on the caller
                // deliberately; see `peer_checks`.
                summary.features.insert(format!("acts:{label}"));
            }
        }
        let mut callees: Vec<(usize, Vec<(usize, String)>)> = Vec::new();
        for (target, bound) in &analysis.flows {
            if let Some(callee) = self.index.resolve_callee(definition, target) {
                callees.push((callee, bound.clone()));
            }
        }
        for (callee, _) in self.index.resolved_calls(definition).calls {
            callees.push((callee, Vec::new()));
        }
        // An identity source's own checks are compared through what its
        // callers pass it (`calls:`, `requires:`), not credited to every
        // caller.
        callees.retain(|(callee, _)| !self.sources.contains(&self.index.definitions[*callee].name));
        let mut seen = HashSet::new();
        for (callee, bound) in callees {
            if !seen.insert((callee, bound.clone())) {
                continue;
            }
            let helper = self.summary(callee, &bound);
            let name = &self.index.definitions[callee].name;
            for (feature, site) in &helper.sites {
                summary
                    .sites
                    .entry(feature.clone())
                    .or_insert_with(|| format!("{name} -> {site}"));
            }
            // A record handed to a helper together with the caller is
            // checked by that helper, whatever it does inside: a policy
            // some routes follow, as when the handler calls a check
            // function with both (see `peer_checks::unguarded_record`).
            let handed: HashSet<&str> = bound
                .iter()
                .filter_map(|(_, label)| label.strip_prefix(RECORD_LABEL))
                .collect();
            let caller_too = bound.iter().any(|(_, label)| !label.starts_with('\u{1}'));
            // A helper's parameters are values handed to it, not
            // extractors: only what it reads, checks, and compares is the
            // handler's doing.
            summary.features.extend(
                helper
                    .features
                    .iter()
                    .filter(|feature| {
                        !feature.starts_with("takes:")
                            && !feature.starts_with("scheme:")
                            && !feature.starts_with("auths:")
                    })
                    .map(|feature| {
                        match feature.strip_prefix(GUARDS).and_then(super::peer_checks::split_guard) {
                            Some((key, how))
                                if handed.contains(key) && caller_too && how != "loaded with the caller" =>
                            {
                                format!("{GUARDS}{key}:checks it with `{name}`")
                            }
                            _ => feature.clone(),
                        }
                    }),
            );
        }
        self.in_progress.remove(&key);
        self.summaries.insert(key, summary.clone());
        summary
    }
}

/// A call that decides something with the caller's identity, before Archer
/// knows whether the called function returns a verdict.
#[derive(Clone)]
struct CheckCandidate {
    target: Option<HandlerTarget>,
    /// The call's identity-derived arguments, by parameter position (the
    /// receiver of a method call is position 0).
    bound: Vec<(usize, String)>,
    /// The function or method name, for lookup when the path does not resolve.
    name: String,
    feature: String,
    /// The line of the call.
    line: usize,
    /// Records loaded from request data that the call also receives: a
    /// check of the caller against them (`ensure_member(&group, &user)?`).
    records: Vec<String>,
    /// Made in a branch condition (`if !may_edit(&note, &user) { .. }`),
    /// not as a statement under `?`.
    condition: bool,
    /// Named request values the call also receives, as `K:p`: a check of
    /// the caller against them binds them (`ensure_self(&user, &id)?`).
    requested: Vec<String>,
}

#[derive(Clone, Default)]
struct Analysis {
    features: BTreeSet<String>,
    checks: Vec<CheckCandidate>,
    /// Calls that receive identity-derived arguments: the target, and each
    /// such argument's position and identity label.
    flows: Vec<(HandlerTarget, Vec<(usize, String)>)>,
    rejects: bool,
    /// Calls that pass request data and a closure (see `WrapperShape`).
    wrapper_calls: Vec<WrapperCall>,
}

/// A call such as `wrap(flow, &req, payload, |state, auth, req| ..)`,
/// whose closure the called function may hand the request data to.
#[derive(Clone)]
struct WrapperCall {
    target: HandlerTarget,
    /// Closure arguments, by position, with where each closure starts.
    closures: Vec<(usize, ClosureKey)>,
    /// Arguments that are request data, by position, with their origin.
    requested: Vec<(usize, Option<Origin>)>,
}

/// Where a closure starts in the source: stable across visits of the same
/// syntax tree.
type ClosureKey = (usize, usize);

/// Where request data comes from (`path` or `body`) and the name the
/// request gives it; empty for a whole extractor, whose fields have names.
type Origin = (&'static str, String);

/// How a function that takes a closure calls it: which of its own
/// parameters reach which closure parameter, directly
/// (`func(state, auth, payload)`) or through another such function it
/// hands the closure to.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct WrapperShape {
    closure: usize,
    passes: Vec<(usize, usize)>,
}

/// Whether a rule of the missed-drift round is on: `ARCHER_P10_<name>=0`
/// turns it off, for measuring what each one adds.
pub(crate) fn rule_on(name: &str) -> bool {
    std::env::var(format!("ARCHER_P10_{name}")).map_or(true, |value| value != "0")
}

/// A callee parameter bound to request data, as `\u{1}request:K:p`, or to
/// a loaded record, as `\u{1}record:key`, beside the caller's identity
/// positions.
const REQUEST_LABEL: &str = "\u{1}request:";
const RECORD_LABEL: &str = "\u{1}record:";

fn request_label(origin: &Option<Origin>) -> String {
    match origin {
        Some((kind, name)) => format!("{REQUEST_LABEL}{kind}:{name}"),
        None => format!("{REQUEST_LABEL}body:"),
    }
}

/// One function's features, with `bound` naming parameters (by position)
/// that hold the caller's identity whatever their type.
fn analyze_function(
    item: &ItemFn,
    bound: &[(usize, String)],
    sources: &std::rc::Rc<HashSet<String>>,
    closure_inputs: &HashMap<ClosureKey, Vec<(usize, Option<Origin>)>>,
) -> Analysis {
    let mut visitor = CallerUseVisitor {
        sources: sources.clone(),
        closure_inputs: closure_inputs.clone(),
        ..CallerUseVisitor::default()
    };
    for (position, input) in item.sig.inputs.iter().enumerate() {
        let typed = match input {
            FnArg::Typed(typed) => typed,
            FnArg::Receiver(_) => {
                if let Some((_, label)) = bound
                    .iter()
                    .find(|(index, label)| *index == position && !label.starts_with('\u{1}'))
                {
                    visitor.bindings.insert("self".to_owned(), label.clone());
                }
                continue;
            }
        };
        match bound.iter().find(|(index, _)| *index == position) {
            Some((_, label)) if label.starts_with(REQUEST_LABEL) => {
                let (kind, name) = label[REQUEST_LABEL.len()..].split_once(':').unwrap_or(("body", ""));
                let kind = if kind == "path" { "path" } else { "body" };
                visitor.bind_request(&typed.pat, Some((kind, name.to_string())));
            }
            Some((_, label)) if label.starts_with(RECORD_LABEL) => {
                let mut names = HashSet::new();
                super::routes::pattern_bindings(&typed.pat, &mut names);
                for name in names.into_iter().filter(|name| !name.starts_with('_')) {
                    visitor.records.insert(name, label[RECORD_LABEL.len()..].to_string());
                }
            }
            Some((_, label)) => {
                visitor.bind_names(&typed.pat, label);
            }
            None => visitor.bind_parameter(&typed.pat, &typed.ty),
        }
    }
    visitor.visit_block(&item.block);
    let loaded: BTreeSet<String> = visitor.records.values().cloned().collect();
    for key in loaded {
        let guarded = visitor
            .features
            .iter()
            .any(|feature| feature.strip_prefix(GUARDS).is_some_and(|rest| rest.starts_with(&format!("{key}:"))));
        if guarded || visitor.used_records.contains(&key) {
            visitor.features.insert(format!("{LOADS}{key}"));
        }
    }
    // A `Result` returned as the body's value is the caller's to
    // propagate: `fn rename(..) -> Result<..> { ensure_owner(caller, &b) }`
    // decides with the caller like `ensure_owner(..)?;` does.
    if let syn::ReturnType::Type(_, ty) = &item.sig.output
        && super::handlers::type_name(ty).is_some_and(|name| name.ends_with("Result"))
        && let Some(syn::Stmt::Expr(tail, None)) = item.block.stmts.last()
    {
        visitor.decides(tail);
    }
    Analysis {
        features: visitor.features,
        checks: visitor.checks,
        flows: visitor.flows,
        rejects: visitor.rejects,
        wrapper_calls: visitor.wrapper_calls,
    }
}

#[derive(Default)]
struct CallerUseVisitor {
    /// Names bound to an identity value, with the identity type's label.
    bindings: HashMap<String, String>,
    features: BTreeSet<String>,
    checks: Vec<CheckCandidate>,
    flows: Vec<(HandlerTarget, Vec<(usize, String)>)>,
    /// Functions whose returned value is the caller (see `identity_sources`).
    sources: std::rc::Rc<HashSet<String>>,
    /// A branch that depends on the caller rejects the request.
    rejects: bool,
    /// Names bound to data the request supplies: a `Json`, `Path`, `Query`
    /// or `Form` extractor, or a value read from one. The request itself is
    /// left out: what is read from it is mostly credentials and headers.
    requested: HashSet<String>,
    /// Names bound to a record loaded with request data, with the record's
    /// key: the loading call (`PrivateNote::read`, `find_note`).
    records: HashMap<String, String>,
    /// Record keys whose loaded value the function reads a field of, or
    /// hands to a check: a loaded record, not a converted string.
    used_records: HashSet<String>,
    /// Visiting a branch condition.
    in_condition: bool,
    /// Where each request-data name comes from (see `Origin`).
    origins: HashMap<String, Origin>,
    /// Closure inputs to bind as request data: what a wrapper hands them.
    closure_inputs: HashMap<ClosureKey, Vec<(usize, Option<Origin>)>>,
    wrapper_calls: Vec<WrapperCall>,
}

impl CallerUseVisitor {
    fn bind_parameter(&mut self, pattern: &Pat, ty: &Type) {
        if let Some(kind) = request_kind(ty) {
            self.bind_request(pattern, Some((kind, String::new())));
        }
        if !identity_type(ty) {
            return;
        }
        let label = type_label(ty);
        if self.bind_names(pattern, &label) {
            self.features.insert(format!("takes:{label}"));
        }
    }

    /// Binds a pattern's names to request data. A plain name holds the
    /// whole value, and keeps the origin's name (empty for an extractor);
    /// a destructuring pattern names each part (`Path((team, id))`).
    fn bind_request(&mut self, pattern: &Pat, origin: Option<Origin>) {
        let mut names = HashSet::new();
        super::routes::pattern_bindings(pattern, &mut names);
        let whole = matches!(pattern, Pat::Ident(_)) || matches!(pattern, Pat::Type(typed) if matches!(&*typed.pat, Pat::Ident(_)));
        for name in names {
            if name.starts_with('_') {
                continue;
            }
            if let Some((kind, given)) = &origin {
                let given = if whole { given.clone() } else { name.clone() };
                self.origins.insert(name.clone(), (kind, given));
            }
            self.requested.insert(name);
        }
    }

    /// A path value handed to a call that may act on it (`find(&pool, id)`),
    /// not one that only builds a value (`Page::new(.., id)`): the route
    /// uses its path (`mentions:path:p`, `p` empty for a whole value).
    fn path_passed<'e>(&mut self, callee: &str, arguments: impl Iterator<Item = &'e Expr>) {
        if NOT_LOADERS.contains(&callee) {
            return;
        }
        for argument in arguments {
            for (kind, name) in self.request_names(argument) {
                if kind == "path" {
                    self.features.insert(format!("{MENTIONS}path:{name}"));
                }
            }
        }
    }

    /// The origin of a request value an expression reads: `connector_id`,
    /// `path.into_inner()`, `data.note_id` (the field names it).
    fn origin_of(&self, expr: &Expr) -> Option<Origin> {
        origin_in(&self.origins, expr)
    }

    /// The named request values an expression reads, outside closures.
    fn request_names(&self, expr: &Expr) -> Vec<Origin> {
        struct Names<'o> {
            origins: &'o HashMap<String, Origin>,
            found: Vec<Origin>,
        }
        impl<'ast> Visit<'ast> for Names<'_> {
            fn visit_expr(&mut self, node: &'ast Expr) {
                // A whole path value has no name of its own: it is the
                // template's one parameter, if it has one.
                if matches!(node, Expr::Path(_) | Expr::Field(_) | Expr::MethodCall(_))
                    && let Some(origin) = origin_in(self.origins, node)
                    && (!origin.1.is_empty() || origin.0 == "path")
                {
                    self.found.push(origin);
                    return;
                }
                visit::visit_expr(self, node);
            }
            fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
        }
        let mut names = Names {
            origins: &self.origins,
            found: Vec::new(),
        };
        names.visit_expr(expr);
        names.found.sort();
        names.found.dedup();
        names.found
    }

    /// Call arguments that are not the caller, as callee bindings: a loaded
    /// record (`\u{1}record:key`) or request data (`\u{1}request:K:p`).
    fn data_bound<'e>(&self, arguments: impl Iterator<Item = &'e Expr>, bound: &[(usize, String)]) -> Vec<(usize, String)> {
        if !rule_on("R1") {
            return Vec::new();
        }
        arguments
            .enumerate()
            .filter(|(position, _)| bound.iter().all(|(taken, _)| taken != position))
            .filter_map(|(position, argument)| {
                if let Some(key) = self.record_of(argument) {
                    return Some((position, format!("{RECORD_LABEL}{key}")));
                }
                let whole = strip_transparent(argument);
                if matches!(whole, Expr::Path(_) | Expr::Field(_)) && self.mentions_requested(whole) {
                    return Some((position, request_label(&self.origin_of(whole))));
                }
                None
            })
            .collect()
    }

    /// `Ok(session)` or `Some(user)` matched against an identity value binds
    /// the caller; `Err(e)` does not.
    fn bind_success(&mut self, pattern: &Pat, label: &str) {
        let success = match pattern {
            Pat::TupleStruct(tuple) => tuple
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Ok" || segment.ident == "Some"),
            Pat::Ident(_) => true,
            _ => false,
        };
        if success && self.bind_names(pattern, label) && label.ends_with("()") {
            self.features.insert(format!("takes:{label}"));
        }
    }

    /// Binds the names a pattern introduces to `label`; false when it binds
    /// none that the code can use (`_`, `_auth`).
    fn bind_names(&mut self, pattern: &Pat, label: &str) -> bool {
        let mut names = HashSet::new();
        super::routes::pattern_bindings(pattern, &mut names);
        let mut bound = false;
        for name in names {
            if name.starts_with('_') {
                continue;
            }
            self.bindings.insert(name, label.to_string());
            bound = true;
        }
        bound
    }

    /// The identity type an expression is derived from: a binding, a field
    /// or method chain on one, a reference or conversion of one.
    fn derived(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Path(path) if path.qself.is_none() => {
                let ident = path.path.get_ident()?;
                self.bindings.get(&ident.to_string()).cloned()
            }
            Expr::Field(field) => self.derived(&field.base),
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                if self.sources.contains(&method) {
                    return Some(format!("{method}()"));
                }
                self.derived(&call.receiver)
            }
            // `match authorize_session(&req) { Ok(session) => session.id(), .. }`
            Expr::Match(matched) => self.derived(&matched.expr),
            Expr::Reference(reference) => self.derived(&reference.expr),
            Expr::Paren(paren) => self.derived(&paren.expr),
            Expr::Group(group) => self.derived(&group.expr),
            Expr::Unary(unary) => self.derived(&unary.expr),
            Expr::Try(inner) => self.derived(&inner.expr),
            Expr::Await(inner) => self.derived(&inner.base),
            Expr::Cast(cast) => self.derived(&cast.expr),
            Expr::Call(call) => match &*call.func {
                Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment| {
                        TRANSPARENT_CALLS.contains(&segment.ident.to_string().as_str())
                    }) =>
                {
                    call.args.iter().find_map(|argument| self.derived(argument))
                }
                Expr::Path(path) => {
                    let name = path.path.segments.last()?.ident.to_string();
                    self.sources.contains(&name).then(|| format!("{name}()"))
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// The first field read on an identity binding: `auth.profile` in
    /// `auth.profile.map(..)`, `person` in `local_user_view.person.id`.
    fn first_field(&self, expr: &Expr) -> Option<(String, String)> {
        let Expr::Field(field) = expr else {
            return None;
        };
        match &*field.base {
            Expr::Path(path) if path.qself.is_none() => {
                let ident = path.path.get_ident()?;
                let label = self.bindings.get(&ident.to_string())?;
                let member = match &field.member {
                    syn::Member::Named(name) => name.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };
                Some((label.clone(), member))
            }
            _ => None,
        }
    }

    /// Records the identity values a deciding call receives.
    fn decides(&mut self, expr: &Expr) {
        match expr {
            Expr::Try(inner) => self.decides(&inner.expr),
            Expr::Await(inner) => self.decides(&inner.base),
            Expr::Paren(inner) => self.decides(&inner.expr),
            Expr::Group(inner) => self.decides(&inner.expr),
            Expr::Unary(inner) => self.decides(&inner.expr),
            Expr::Let(inner) => self.decides(&inner.expr),
            Expr::Binary(binary) if matches!(binary.op, BinOp::And(_) | BinOp::Or(_)) => {
                self.decides(&binary.left);
                self.decides(&binary.right);
            }
            Expr::Call(call) => {
                let Expr::Path(path) = &*call.func else {
                    return;
                };
                let Some(callee) = callee_name(&path.path) else {
                    return;
                };
                let name = path
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_default();
                let line = syn::spanned::Spanned::span(&call.func).start().line;
                self.checks(&callee, handler_target(&call.func), name, line, call.args.iter());
            }
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                if TRANSPARENT_CALLS.contains(&method.as_str()) {
                    // `check(..).await.map_err(..)?`: the check is inside.
                    self.decides(&call.receiver);
                    return;
                }
                let target = receiver_path(&call.receiver).map(|receiver| HandlerTarget::Method {
                    receiver,
                    method: method.clone(),
                });
                self.checks(
                    &method,
                    target,
                    method.clone(),
                    call.method.span().start().line,
                    std::iter::once(&*call.receiver).chain(call.args.iter()),
                );
            }
            // `if !user.map(|u| u.local_user.admin).unwrap_or_default()`:
            // a branch on the caller's own fields is a decision about it.
            other => {
                if let Some(label) = self.derived(other) {
                    self.features.insert(format!("acts:{label}"));
                }
            }
        }
    }

    fn checks<'e>(
        &mut self,
        callee: &str,
        target: Option<HandlerTarget>,
        name: String,
        line: usize,
        arguments: impl Iterator<Item = &'e Expr>,
    ) {
        if TRANSPARENT_CALLS.contains(&callee) || PROBES.contains(&callee) {
            return;
        }
        let arguments: Vec<&Expr> = arguments.collect();
        let bound: Vec<(usize, String)> = arguments
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(position, argument)| self.derived(argument).map(|label| (position, label)))
            .collect();
        let records: Vec<String> = arguments
            .iter()
            .filter_map(|argument| self.record_of(argument))
            .collect();
        self.used_records.extend(records.iter().cloned());
        let requested: Vec<String> = arguments
            .iter()
            .flat_map(|argument| self.request_names(argument))
            .map(|(kind, name)| format!("{kind}:{name}"))
            .collect();
        let mut labels: Vec<&String> = bound.iter().map(|(_, label)| label).collect();
        labels.dedup();
        for label in labels {
            self.checks.push(CheckCandidate {
                target: target.clone(),
                bound: bound.clone(),
                name: name.clone(),
                feature: format!("checks:{label}:{callee}"),
                line,
                records: records.clone(),
                requested: requested.clone(),
                condition: self.in_condition,
            });
        }
    }

    /// Whether an expression reads a name bound to request data.
    fn mentions_requested(&self, expr: &Expr) -> bool {
        mentions_any(expr, |name| self.requested.contains(name))
    }

    /// The record an expression reads (`note`, `note.owner`, `&note`).
    fn record_in(&self, expr: &Expr) -> Option<String> {
        let mut found = None;
        let _ = mentions_any(expr, |name| {
            if let Some(key) = self.records.get(name) {
                found.get_or_insert_with(|| key.clone());
                true
            } else {
                false
            }
        });
        found
    }

    /// A loaded record passed whole or by a field (`&note`, `note.group_id`).
    fn record_of(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Reference(inner) => self.record_of(&inner.expr),
            Expr::Paren(inner) => self.record_of(&inner.expr),
            Expr::Field(field) => self.record_of(&field.base),
            Expr::MethodCall(call) if TRANSPARENT_CALLS.contains(&call.method.to_string().as_str()) => {
                self.record_of(&call.receiver)
            }
            Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|ident| self.records.get(&ident.to_string()).cloned()),
            _ => None,
        }
    }

    /// A call that loads a record with request data: `Note::read(&pool,
    /// data.note_id)`, `repo.find_note(&id)`, through `.await`, `?` and
    /// error adapters. Also whether it passes the caller, which scopes the
    /// load to the caller (`find_note(id, user.id)`).
    fn loader(&self, expr: &Expr) -> Option<(String, bool)> {
        match expr {
            Expr::Try(inner) => self.loader(&inner.expr),
            Expr::Await(inner) => self.loader(&inner.base),
            Expr::Paren(inner) => self.loader(&inner.expr),
            Expr::Reference(inner) => self.loader(&inner.expr),
            Expr::Call(call) => {
                let Expr::Path(path) = &*call.func else {
                    return None;
                };
                let key = callee_name(&path.path)?;
                let last = path.path.segments.last()?.ident.to_string();
                if TRANSPARENT_CALLS.contains(&last.as_str()) || NOT_LOADERS.contains(&last.as_str()) {
                    return None;
                }
                let requested = call.args.iter().any(|argument| self.mentions_requested(argument));
                let scoped = call.args.iter().any(|argument| self.derived(argument).is_some());
                requested.then_some((key, scoped))
            }
            Expr::MethodCall(call) => {
                // `Note::read(..).await.map_err(..)`: the adapter wraps the load.
                if let Some(found) = self.loader(&call.receiver) {
                    return Some(found);
                }
                let method = call.method.to_string();
                if TRANSPARENT_CALLS.contains(&method.as_str())
                    || NOT_LOADERS.contains(&method.as_str())
                    || self.mentions_requested(&call.receiver)
                    || self.derived(&call.receiver).is_some()
                {
                    return None;
                }
                let requested = call.args.iter().any(|argument| self.mentions_requested(argument));
                let scoped = call.args.iter().any(|argument| self.derived(argument).is_some());
                requested.then_some((method, scoped))
            }
            _ => None,
        }
    }

    /// Whether an expression reads a name bound to the caller.
    fn mentions_caller(&self, expr: &Expr) -> bool {
        struct Mentions<'b> {
            bindings: &'b HashMap<String, String>,
            found: bool,
        }
        impl<'ast> Visit<'ast> for Mentions<'_> {
            fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
                if node
                    .path
                    .get_ident()
                    .is_some_and(|ident| self.bindings.contains_key(&ident.to_string()))
                {
                    self.found = true;
                }
            }
            fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
        }
        let mut mentions = Mentions {
            bindings: &self.bindings,
            found: false,
        };
        mentions.visit_expr(expr);
        mentions.found
    }
}

/// Whether code rejects the request: it builds an `Err`, or an
/// `HttpResponse::Unauthorized()`/`Forbidden()`, or calls `bail!`.
fn rejects(visit: impl FnOnce(&mut Rejects)) -> bool {
    let mut found = Rejects(false);
    visit(&mut found);
    found.0
}

pub(crate) struct Rejects(pub(crate) bool);

/// Whether an expression rejects a request anywhere outside closures.
pub(crate) fn rejects_in(expr: &Expr) -> bool {
    rejects(|found| found.visit_expr(expr))
}

pub(crate) fn rejects_in_block(block: &syn::Block) -> bool {
    rejects(|found| found.visit_block(block))
}

/// Whether a function body rejects a request anywhere outside closures.
pub(crate) fn block_rejects(block: &syn::Block) -> bool {
    rejects(|found| found.visit_block(block))
}

impl<'ast> Visit<'ast> for Rejects {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        let segments: Vec<String> = node
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let last = segments.last().map(String::as_str);
        if last == Some("Err")
            || matches!(last, Some("ErrorUnauthorized" | "ErrorForbidden"))
            || (segments.iter().any(|segment| segment == "HttpResponse")
                && matches!(last, Some("Unauthorized" | "Forbidden")))
        {
            self.0 = true;
        }
    }
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.segments.last().is_some_and(|segment| segment.ident == "bail") {
            self.0 = true;
        }
    }
    fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
}

impl CallerUseVisitor {
    /// A unit or struct value named for authentication: `AdminApiAuth`,
    /// `NoAuth`, `JWTAuthProfileFromRoute`.
    fn scheme(&mut self, path: &syn::Path) {
        let Some(last) = path.segments.last() else {
            return;
        };
        let name = last.ident.to_string();
        if name.chars().next().is_some_and(char::is_uppercase)
            && name.chars().any(char::is_lowercase)
            && names_authentication(&name)
        {
            self.features.insert(format!("scheme:{name}"));
        }
    }
}

/// `Type::function` keeps its type, `Post::read` and `Comment::read` being
/// different calls; a free function is named by its last segment.
fn callee_name(path: &syn::Path) -> Option<String> {
    let segments: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let last = segments.last()?;
    let associated = segments.len() >= 2
        && segments[segments.len() - 2]
            .chars()
            .next()
            .is_some_and(char::is_uppercase);
    Some(if associated {
        segments[segments.len() - 2..].join("::")
    } else {
        last.clone()
    })
}

impl<'ast> Visit<'ast> for CallerUseVisitor {
    // `matches!(caller.role, ..)` and `ensure!(caller.active)` read the
    // caller like any expression; other macros' tokens stay opaque.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let Some(name) = node.path.segments.last().map(|segment| segment.ident.to_string()) else {
            return;
        };
        if name != "matches" && !super::evidence::ENFORCING_MACROS.contains(&name.as_str()) {
            return;
        }
        let scrutinee = node.parse_body_with(|input: syn::parse::ParseStream| {
            let expr: Expr = input.parse()?;
            let _: proc_macro2::TokenStream = input.parse()?;
            Ok(expr)
        });
        if let Ok(expr) = scrutinee {
            self.visit_expr(&expr);
        }
    }

    fn visit_expr_closure(&mut self, node: &'ast ExprClosure) {
        // Inputs a wrapper hands request data to.
        if let Some(inputs) = self.closure_inputs.get(&closure_key(node)).cloned() {
            for (position, origin) in inputs {
                if let Some(input) = node.inputs.iter().nth(position) {
                    self.bind_request(input, origin.or(Some(("body", String::new()))));
                }
            }
        }
        for input in &node.inputs {
            match input {
                Pat::Type(typed) => self.bind_parameter(&typed.pat, &typed.ty),
                // `|state, auth, req, _|`: the type is inferred from the
                // wrapper. A name that says authentication is taken as an
                // identity of unknown type, so the route is not reported
                // for ignoring the caller, and not compared on its uses.
                Pat::Ident(ident) if names_authentication(&ident.ident.to_string()) => {
                    if self.bind_names(input, UNKNOWN_TYPE) {
                        self.features.insert(format!("takes:{UNKNOWN_TYPE}"));
                    }
                }
                _ => {}
            }
        }
        visit::visit_expr_closure(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        // `let Some(user) = caller.user() else { return Err(..) };`
        if let Some(init) = &node.init
            && let Some((_, diverge)) = &init.diverge
            && self.mentions_caller(&init.expr)
            && rejects(|found| found.visit_expr(diverge))
        {
            self.rejects = true;
        }
        // `let note = Note::read(&pool, data.note_id).await?`: a record
        // loaded with request data. Loaded with the caller too
        // (`find_note(id, user.id)`), it is scoped to the caller already.
        if let Some(init) = &node.init
            && self.derived(&init.expr).is_none()
        {
            let mut names = HashSet::new();
            super::routes::pattern_bindings(&node.pat, &mut names);
            names.retain(|name| !name.starts_with('_'));
            if let Some((key, scoped)) = self.loader(&init.expr) {
                if scoped {
                    self.features.insert(format!("{GUARDS}{key}:loaded with the caller"));
                    for (kind, name) in self.request_names(&init.expr).into_iter().filter(|(kind, _)| *kind == "path") {
                        self.features.insert(format!("{BINDS}{kind}:{name}"));
                    }
                }
                for name in names {
                    self.records.insert(name, key.clone());
                }
            } else if self.mentions_requested(&init.expr) {
                // `let id = path.into_inner();`, `let note_id = data.note_id;`
                let origin = self.origin_of(&init.expr);
                match origin {
                    Some(origin) => self.bind_request(&node.pat, Some(origin)),
                    None => self.requested.extend(names),
                }
            }
        }
        // `let profile_id = auth.profile.map(..)` carries the identity on.
        if let Some(init) = &node.init
            && let Some(label) = self.derived(&init.expr)
        {
            let mut names = HashSet::new();
            super::routes::pattern_bindings(&node.pat, &mut names);
            let mut bound = false;
            for name in names {
                if !name.starts_with('_') {
                    self.bindings.entry(name).or_insert_with(|| label.clone());
                    bound = true;
                }
            }
            // `let user = get_current_user(&req)?`: the handler takes the
            // caller from a call rather than an extractor.
            if bound && label.ends_with("()") {
                self.features.insert(format!("takes:{label}"));
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if let Some(label) = self.derived(&node.expr) {
            for arm in &node.arms {
                self.bind_success(&arm.pat, &label);
            }
        }
        if self.mentions_caller(&node.expr)
            && rejects(|found| {
                for arm in &node.arms {
                    found.visit_expr(&arm.body);
                }
            })
        {
            self.rejects = true;
        }
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_let(&mut self, node: &'ast syn::ExprLet) {
        if let Some(label) = self.derived(&node.expr) {
            self.bind_success(&node.pat, &label);
        }
        visit::visit_expr_let(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        if let Expr::Path(base) = &*node.base
            && let Some(ident) = base.path.get_ident()
            && let Some(key) = self.records.get(&ident.to_string())
        {
            self.used_records.insert(key.clone());
        }
        if let Some((label, field)) = self.first_field(&Expr::Field(node.clone())) {
            self.features.insert(format!("reads:{label}:{field}"));
        }
        if let Some(("body", name)) = self.origin_of(&Expr::Field(node.clone())).as_ref().map(|(kind, name)| (*kind, name.as_str()))
            && !name.is_empty()
        {
            self.features.insert(format!("{MENTIONS}body:{name}"));
        }
        visit::visit_expr_field(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func
            && let Some(last) = path.path.segments.last()
        {
            self.path_passed(&last.ident.to_string(), node.args.iter());
        }
        // `constant_time_eq(invite.stored.as_bytes(), given.as_bytes())`
        if let Expr::Path(path) = &*node.func
            && path.path.segments.last().is_some_and(|segment| {
                super::evidence::SECRET_COMPARISONS.contains(&segment.ident.to_string().as_str())
            })
            && node.args.iter().any(|argument| self.mentions_requested(argument))
            && let Some(key) = node.args.iter().find_map(|argument| self.record_in(argument))
        {
            let name = path.path.segments.last().map(|segment| segment.ident.to_string()).unwrap_or_default();
            self.features.insert(format!("{GUARDS}{key}:compares it with a secret the request presents (`{name}`)"));
            self.used_records.insert(key);
        }
        // A call that yields the caller, made with no requirement beyond
        // the request (`authorize_session(&req, None, None)`). One that
        // names a requirement (`Some(&origin), Some(Maintainer)`) is a check
        // in itself and counts as the route's own means.
        if let Expr::Path(path) = &*node.func
            && let Some(last) = path.path.segments.last()
            && self.sources.contains(&last.ident.to_string())
            && node
                .args
                .iter()
                .skip(1)
                .all(|argument| matches!(argument, Expr::Path(path) if path.path.is_ident("None")))
        {
            self.features.insert(format!("auths:{}()", last.ident));
        }
        // Which requirement arguments a call to an identity source passes,
        // for comparison with the peers' calls of the same source.
        if let Expr::Path(path) = &*node.func
            && let Some(last) = path.path.segments.last()
            && self.sources.contains(&last.ident.to_string())
        {
            let name = last.ident.to_string();
            self.features.insert(format!("calls:{name}"));
            for (position, argument) in node.args.iter().enumerate().skip(1) {
                if matches!(argument, Expr::Path(path) if path.path.is_ident("None")) {
                    continue;
                }
                let mut written = quote::ToTokens::to_token_stream(argument)
                    .to_string()
                    .replace(' ', "");
                if written.len() > 60 {
                    written.truncate(written.floor_char_boundary(57));
                    written.push_str("...");
                }
                self.features
                    .insert(format!("requires:{name}#{position}:{written}"));
            }
        }
        let bound: Vec<(usize, String)> = node
            .args
            .iter()
            .enumerate()
            .filter_map(|(position, argument)| {
                self.derived(argument).map(|label| (position, label))
            })
            .collect();
        let mut bound = bound;
        let data = self.data_bound(node.args.iter(), &bound);
        bound.extend(data);
        if !bound.is_empty()
            && let Some(target) = handler_target(&node.func)
        {
            self.flows.push((target, bound));
        }
        // `wrap(.., payload, |state, auth, req| ..)`: the wrapper may hand
        // the payload to the closure; the walker reads how.
        if rule_on("R1")
            && let Some(target) = handler_target(&node.func)
        {
            let closures: Vec<(usize, ClosureKey)> = node
                .args
                .iter()
                .enumerate()
                .filter_map(|(position, argument)| match argument {
                    Expr::Closure(closure) => Some((position, closure_key(closure))),
                    _ => None,
                })
                .collect();
            let requested: Vec<(usize, Option<Origin>)> = node
                .args
                .iter()
                .enumerate()
                .filter(|(_, argument)| {
                    let whole = strip_transparent(argument);
                    matches!(whole, Expr::Path(_) | Expr::Field(_)) && self.mentions_requested(whole)
                })
                .map(|(position, argument)| (position, self.origin_of(strip_transparent(argument))))
                .collect();
            if !closures.is_empty() && !requested.is_empty() {
                self.wrapper_calls.push(WrapperCall {
                    target,
                    closures,
                    requested,
                });
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if let syn::Stmt::Expr(expr, Some(_)) = node {
            self.decides(expr);
        }
        visit::visit_stmt(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.in_condition = true;
        self.decides(&node.cond);
        self.in_condition = false;
        if self.mentions_caller(&node.cond)
            && rejects(|found| {
                found.visit_block(&node.then_branch);
                if let Some((_, otherwise)) = &node.else_branch {
                    found.visit_expr(otherwise);
                }
            })
        {
            self.rejects = true;
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.path_passed(&node.method.to_string(), node.args.iter());
        // `note.readers.contains(&user.id)`: the caller in a loaded record.
        if self.derived(&node.receiver).is_none()
            && node.args.iter().any(|argument| self.derived(argument).is_some())
            && let Some(key) = self.record_of(&node.receiver)
        {
            let written = short_written(&Expr::MethodCall(node.clone()));
            self.features.insert(format!("{GUARDS}{key}:checks `{written}`"));
        }
        // `principal.validate()` hands the caller to the method as `self`.
        if let Some(receiver) = receiver_path(&node.receiver) {
            let mut bound: Vec<(usize, String)> = std::iter::once(&*node.receiver)
                .chain(node.args.iter())
                .enumerate()
                .filter_map(|(position, argument)| {
                    self.derived(argument).map(|label| (position, label))
                })
                .collect();
            // Request data and records as arguments; a receiver that is
            // request data is converted, not handed over.
            let data: Vec<(usize, String)> = self
                .data_bound(std::iter::once(&*node.receiver).chain(node.args.iter()), &bound)
                .into_iter()
                .filter(|(position, _)| *position > 0)
                .collect();
            bound.extend(data);
            if !bound.is_empty() {
                self.flows.push((
                    HandlerTarget::Method {
                        receiver,
                        method: node.method.to_string(),
                    },
                    bound,
                ));
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            let left = self.derived(&node.left);
            let right = self.derived(&node.right);
            let literal = |expr: &Expr| matches!(expr, Expr::Lit(_));
            match (&left, &right) {
                (Some(label), None) if !literal(&node.right) && !is_variant(&node.right) => {
                    self.features.insert(format!("compares:{label}"));
                }
                (None, Some(label)) if !literal(&node.left) && !is_variant(&node.left) => {
                    self.features.insert(format!("compares:{label}"));
                }
                _ => {}
            }
            // `auth.user_id != principal`: a request value held to the caller.
            let request_side = match (&left, &right) {
                (Some(_), None) => Some(&*node.right),
                (None, Some(_)) => Some(&*node.left),
                _ => None,
            };
            if let Some(side) = request_side {
                for (kind, name) in self.request_names(side) {
                    self.features.insert(format!("{BINDS}{kind}:{name}"));
                }
            }
            // `note.recipient_id != user.person.id`: a loaded record held to
            // the caller, whatever its field is called.
            let record_side = match (&left, &right) {
                (Some(_), None) => Some(&*node.right),
                (None, Some(_)) => Some(&*node.left),
                _ => None,
            };
            if let Some(side) = record_side
                && let Some(key) = self.record_in(side)
            {
                let written = short_written(side);
                self.features.insert(format!("{GUARDS}{key}:compares `{written}` with the caller"));
            }
            // `invite.join_secret != query.secret`: the stored secret of a
            // loaded record matched with one the request presents.
            if left.is_none() && right.is_none() {
                for (stored, presented) in [(&*node.left, &*node.right), (&*node.right, &*node.left)] {
                    if names_secret(stored)
                        && self.mentions_requested(presented)
                        && let Some(key) = self.record_of(stored)
                    {
                        let written = short_written(stored);
                        self.features.insert(format!("{GUARDS}{key}:compares `{written}` with a secret the request presents"));
                    }
                }
            }
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.scheme(&node.path);
        if let Some(ident) = node.path.get_ident()
            && let Some(("body", name)) = self.origins.get(&ident.to_string()).map(|(kind, name)| (*kind, name.as_str()))
            && !name.is_empty()
        {
            self.features.insert(format!("{MENTIONS}body:{name}"));
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        self.scheme(&node.path);
        visit::visit_expr_struct(self, node);
    }

    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
}

/// An enum variant or constant (`Role::Admin`, `MAX`): comparing the caller
/// with one checks a role or a setting, not ownership.
fn is_variant(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
            segment
                .ident
                .to_string()
                .chars()
                .next()
                .is_some_and(char::is_uppercase)
        }),
        Expr::Reference(reference) => is_variant(&reference.expr),
        Expr::Paren(paren) => is_variant(&paren.expr),
        _ => false,
    }
}

/// A short, stable name for an identity type: its last path segment, with
/// the wrapper kept for `Option` (an optional caller is handled differently
/// from a required one) and dropped for `Box`, `Arc`, and references.
fn type_label(ty: &Type) -> String {
    match ty {
        Type::Reference(reference) => type_label(&reference.elem),
        Type::Paren(paren) => type_label(&paren.elem),
        Type::Group(group) => type_label(&group.elem),
        Type::Path(path) => {
            let Some(segment) = path.path.segments.last() else {
                return String::new();
            };
            let name = segment.ident.to_string();
            let inner = match &segment.arguments {
                PathArguments::AngleBracketed(arguments) => {
                    arguments.args.iter().find_map(|argument| match argument {
                        GenericArgument::Type(inner) if identity_type(inner) => {
                            Some(type_label(inner))
                        }
                        _ => None,
                    })
                }
                _ => None,
            };
            match (name.as_str(), inner) {
                ("Option", Some(inner)) => format!("Option<{inner}>"),
                ("Box" | "Arc" | "Rc", Some(inner)) => inner,
                (_, Some(inner)) => format!("{name}<{inner}>"),
                (_, None) => name,
            }
        }
        _ => String::new(),
    }
}

/// Whether a function's return type is a verdict: `bool`, or a wrapper
/// whose value is `()` (`Result<()>`, `LemmyResult<()>`, `Option<()>`).
fn returns_verdict(output: &syn::ReturnType) -> bool {
    let syn::ReturnType::Type(_, ty) = output else {
        return false;
    };
    verdict_type(ty)
}

fn verdict_type(ty: &Type) -> bool {
    match ty {
        Type::Paren(paren) => verdict_type(&paren.elem),
        Type::Group(group) => verdict_type(&group.elem),
        Type::Path(path) => {
            let Some(segment) = path.path.segments.last() else {
                return false;
            };
            if segment.ident == "bool" {
                return true;
            }
            match &segment.arguments {
                PathArguments::AngleBracketed(arguments) => matches!(
                    arguments.args.first(),
                    Some(GenericArgument::Type(Type::Tuple(tuple))) if tuple.elems.is_empty()
                ),
                _ => false,
            }
        }
        // `impl Future<Output = Result<()>>`.
        Type::ImplTrait(bounds) => bounds.bounds.iter().any(|bound| match bound {
            syn::TypeParamBound::Trait(trait_bound) => trait_bound
                .path
                .segments
                .last()
                .is_some_and(|segment| match &segment.arguments {
                    PathArguments::AngleBracketed(arguments) => {
                        arguments.args.iter().any(|argument| match argument {
                            GenericArgument::AssocType(assoc) => verdict_type(&assoc.ty),
                            _ => false,
                        })
                    }
                    _ => false,
                }),
            _ => false,
        }),
        _ => false,
    }
}

/// For every function and method name in the scanned files, whether each
/// definition by that name returns a verdict.
fn return_shapes<'f>(files: impl IntoIterator<Item = &'f syn::File>) -> HashMap<String, Vec<bool>> {
    #[derive(Default)]
    struct Shapes(HashMap<String, Vec<bool>>);
    impl<'ast> Visit<'ast> for Shapes {
        fn visit_signature(&mut self, node: &'ast syn::Signature) {
            self.0
                .entry(node.ident.to_string())
                .or_default()
                .push(returns_verdict(&node.output));
            visit::visit_signature(self, node);
        }
    }
    let mut shapes = Shapes::default();
    for file in files {
        shapes.visit_file(file);
    }
    shapes.0
}

/// Functions that hand the caller back: they take the request and return a
/// value rather than a verdict, and either establish who the caller is
/// (their evidence reaches identity) or are named for it
/// (`authorize_session(&req, ..) -> Result<Session>`,
/// `get_user_from_request(&req) -> Result<String>`). The value they return
/// is treated like an identity extractor's. Route handlers are excluded:
/// their evidence comes from what they call.
fn identity_sources(index: &HandlerIndex, routes: &[Route]) -> HashSet<String> {
    let handlers: HashSet<usize> = routes
        .iter()
        .filter_map(|route| route.origin.definition)
        .collect();
    index
        .definitions
        .iter()
        .zip(&index.items)
        .enumerate()
        .filter(|(position, (definition, item))| {
            !handlers.contains(position)
                && definition.owner.is_none()
                && matches!(item.sig.output, syn::ReturnType::Type(..))
                && !returns_verdict(&item.sig.output)
                && item
                    .sig
                    .inputs
                    .iter()
                    .any(|input| matches!(input, FnArg::Typed(typed) if takes_request(&typed.ty)))
                && (names_caller(&definition.name)
                    || definition.evidence.iter().any(|evidence| {
                        !matches!(
                            evidence.kind,
                            super::model::AuthEvidenceKind::Delegated
                                | super::model::AuthEvidenceKind::Unknown
                        ) && super::model::EvidenceTier::of(&evidence.kind)
                            >= super::model::EvidenceTier::Identity
                    }))
        })
        .map(|(_, (definition, _))| definition.name.clone())
        .collect()
}

/// `HttpRequest`, `&HttpRequest`, `ServiceRequest`.
fn takes_request(ty: &Type) -> bool {
    match ty {
        Type::Reference(reference) => takes_request(&reference.elem),
        Type::Path(path) => path.path.segments.last().is_some_and(|segment| {
            segment.ident == "HttpRequest" || segment.ident == "ServiceRequest"
        }),
        _ => false,
    }
}

/// A function name that says it yields the caller: `authorize_session`,
/// `get_current_user`, `extract_claims`, `principal_from_req`.
fn names_caller(name: &str) -> bool {
    names_authentication(name)
        || name.split('_').any(|word| {
            [
                "session",
                "user",
                "principal",
                "claims",
                "identity",
                "authorize",
                "authorization",
                "caller",
                "account",
            ]
            .contains(&word)
        })
}

fn returns_bool(output: &syn::ReturnType) -> bool {
    matches!(output, syn::ReturnType::Type(_, ty) if matches!(&**ty, Type::Path(path) if path.path.is_ident("bool")))
}

/// Type parameters bounded by a closure trait (`F: Fn(..) -> R`), in the
/// generics or a `where` clause.
fn callable_generics(signature: &syn::Signature) -> HashSet<String> {
    let callable_bound = |bound: &syn::TypeParamBound| {
        matches!(bound, syn::TypeParamBound::Trait(found) if found.path.segments.last().is_some_and(|segment| {
            segment.ident == "Fn" || segment.ident == "FnMut" || segment.ident == "FnOnce"
        }))
    };
    let mut names = HashSet::new();
    for parameter in &signature.generics.params {
        if let syn::GenericParam::Type(ty) = parameter
            && ty.bounds.iter().any(callable_bound)
        {
            names.insert(ty.ident.to_string());
        }
    }
    if let Some(clause) = &signature.generics.where_clause {
        for predicate in &clause.predicates {
            if let syn::WherePredicate::Type(found) = predicate
                && found.bounds.iter().any(callable_bound)
                && let Type::Path(path) = &found.bounded_ty
                && let Some(ident) = path.path.get_ident()
            {
                names.insert(ident.to_string());
            }
        }
    }
    names
}

/// A parameter type that is a closure: a callable type parameter, or
/// `impl Fn(..)`.
fn is_callable(ty: &Type, callable: &HashSet<String>) -> bool {
    match ty {
        Type::Path(path) => path.path.get_ident().is_some_and(|ident| callable.contains(&ident.to_string())),
        Type::ImplTrait(bounds) => bounds.bounds.iter().any(|bound| {
            matches!(bound, syn::TypeParamBound::Trait(found) if found.path.segments.last().is_some_and(|segment| {
                segment.ident == "Fn" || segment.ident == "FnMut" || segment.ident == "FnOnce"
            }))
        }),
        Type::Reference(reference) => is_callable(&reference.elem, callable),
        _ => false,
    }
}

/// Feature prefix: the route holds a named request value to the caller,
/// as `binds:K:p` (see the module documentation).
pub(crate) const BINDS: &str = "binds:";
/// Feature prefix: the route reads a named field of its body or query.
pub(crate) const MENTIONS: &str = "mentions:";

/// Where a closure starts, as its key across visits.
fn closure_key(closure: &ExprClosure) -> ClosureKey {
    let start = syn::spanned::Spanned::span(closure).start();
    (start.line, start.column)
}

/// An expression without references, parentheses and converting calls.
fn strip_transparent(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(inner) => strip_transparent(&inner.expr),
        Expr::Paren(inner) => strip_transparent(&inner.expr),
        Expr::Group(inner) => strip_transparent(&inner.expr),
        Expr::MethodCall(call)
            if call.args.is_empty()
                && (TRANSPARENT_CALLS.contains(&call.method.to_string().as_str())
                    || call.method == "as_str"
                    || call.method == "as_bytes") =>
        {
            strip_transparent(&call.receiver)
        }
        _ => expr,
    }
}

fn origin_in(origins: &HashMap<String, Origin>, expr: &Expr) -> Option<Origin> {
    match strip_transparent(expr) {
        Expr::Path(path) if path.qself.is_none() => origins.get(&path.path.get_ident()?.to_string()).cloned(),
        Expr::Field(field) => {
            let (kind, given) = origin_in(origins, &field.base)?;
            match &field.member {
                syn::Member::Named(name) => Some((kind, name.to_string())),
                syn::Member::Unnamed(_) => Some((kind, given)),
            }
        }
        Expr::Unary(unary) => origin_in(origins, &unary.expr),
        // `path.into_inner()`, `id.clone()`: the same value, unwrapped or
        // copied.
        Expr::MethodCall(call) if call.args.is_empty() && rule_on("R2") => origin_in(origins, &call.receiver),
        Expr::Try(inner) => origin_in(origins, &inner.expr),
        Expr::Await(inner) => origin_in(origins, &inner.base),
        _ => None,
    }
}

/// Feature prefix: the route loads a record with request data, keyed by the
/// loading call. Not compared by `peer_checks`' consensus on caller use; see
/// `peer_checks::unguarded_record`.
pub(crate) const LOADS: &str = "loads:";
/// Feature prefix: the route holds a loaded record to the caller, as
/// `guards:<key>:<how>`.
pub(crate) const GUARDS: &str = "guards:";

/// Calls that parse, convert or build a value rather than load a record.
const NOT_LOADERS: [&str; 24] = [
    "from", "new", "parse", "parse_str", "try_from", "from_str", "format", "trim", "len",
    "to_lowercase", "to_uppercase", "split", "join", "push", "insert", "contains", "get",
    "iter", "collect", "as_str", "Json", "Err", "Box", "Arc",
];

/// Extractor types that carry data the request supplies: ids and fields
/// the client chose, from the path or from the body, query or form.
fn request_kind(ty: &Type) -> Option<&'static str> {
    match ty {
        Type::Reference(reference) => request_kind(&reference.elem),
        Type::Path(path) => {
            let name = path.path.segments.last()?.ident.to_string();
            match name.as_str() {
                "Path" => Some("path"),
                "Json" | "Query" | "Form" | "QsQuery" | "QsForm" => Some("body"),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether an expression reads a name the predicate accepts; stops at the
/// first one. Closures are left out: they run elsewhere.
fn mentions_any(expr: &Expr, mut accept: impl FnMut(&str) -> bool) -> bool {
    struct Mentions<'p> {
        accept: &'p mut dyn FnMut(&str) -> bool,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Mentions<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if !self.found
                && let Some(ident) = node.path.get_ident()
                && (self.accept)(&ident.to_string())
            {
                self.found = true;
            }
        }
        fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
    }
    let mut mentions = Mentions {
        accept: &mut accept,
        found: false,
    };
    mentions.visit_expr(expr);
    mentions.found
}

/// An expression as written, without spaces, cut to 60 characters.
fn short_written(expr: &Expr) -> String {
    let mut written = quote::ToTokens::to_token_stream(expr)
        .to_string()
        .replace(' ', "");
    if written.len() > 60 {
        written.truncate(written.floor_char_boundary(57));
        written.push_str("...");
    }
    written
}

/// Whether a record field is named as a secret (`join_secret`, `token_hash`).
fn names_secret(expr: &Expr) -> bool {
    let name = match expr {
        Expr::Field(field) => match &field.member {
            syn::Member::Named(name) => name.to_string(),
            syn::Member::Unnamed(_) => return false,
        },
        Expr::Reference(inner) => return names_secret(&inner.expr),
        Expr::MethodCall(call) if TRANSPARENT_CALLS.contains(&call.method.to_string().as_str()) || call.method == "as_bytes" || call.method == "as_str" => {
            return names_secret(&call.receiver);
        }
        _ => return false,
    };
    let flat = name.to_ascii_lowercase().replace('_', "");
    super::evidence::SECRET_WORDS.iter().any(|word| flat.contains(word))
}
