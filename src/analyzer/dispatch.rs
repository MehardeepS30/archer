//! Checks dispatched through a type parameter (P13).
//!
//! ```rust,ignore
//! pub struct Require<T: Requirement>(PhantomData<T>);
//!
//! impl<T: Requirement> FromRequest for Require<T> {
//!     fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
//!         let user = ..;
//!         T::enforce(authorizer, user)?;
//!         ..
//!     }
//! }
//!
//! impl Requirement for ReadSbom {
//!     fn enforce(authorizer: &Authorizer, user: &User) -> Result<(), Error> {
//!         Ok(authorizer.require(user, Permission::ReadSbom)?)
//!     }
//! }
//! ```
//!
//! `Require<T>` does nothing itself: what it checks is decided by its type
//! argument. Such an extractor is a permission check whose requirement is
//! that argument, so `Require<ReadSbom>` and `Require<DeleteSbom>` can be
//! compared between peer routes. The requirement of an argument is read
//! from its `impl` of the dispatched method: the constants it passes
//! (`Permission::ReadSbom`), and the requirements of other types whose same
//! method it calls (`ReadSbom::enforce(..)?; ReadAdvisory::enforce(..)?`).
//! Impls written by the project's own `macro_rules!` macros are expanded
//! first. Nothing here reads a name's words.

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap},
};
use syn::{
    Expr, GenericArgument, GenericParam, ImplItem, Item, PathArguments, Type,
    visit::{self, Visit},
};

use super::macros::Rule;

#[derive(Default)]
struct State {
    /// Extractor type name to the position of the type argument it
    /// dispatches on and the method it calls on it. `None`: impls disagree.
    gates: HashMap<String, Option<(usize, String)>>,
    /// `(type, method)` to the requirement keys that impl checks.
    requirements: HashMap<(String, String), Vec<String>>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// `ReadSbom` as `read_sbom`.
fn key(name: &str) -> String {
    let mut out = String::new();
    for (index, c) in name.chars().enumerate() {
        if c.is_uppercase() && index > 0 && !out.ends_with('_') {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) if path.qself.is_none() => {
            path.path.segments.last().map(|segment| segment.ident.to_string())
        }
        Type::Reference(reference) => type_name(&reference.elem),
        Type::Paren(paren) => type_name(&paren.elem),
        Type::Group(group) => type_name(&group.elem),
        _ => None,
    }
}

/// Calls of the form `T::method(..)` where `T` is a type parameter in scope.
struct ParameterCalls {
    parameters: Vec<String>,
    found: Vec<(String, String)>,
}

impl<'ast> Visit<'ast> for ParameterCalls {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        // A helper declared inside `from_request` names its own parameter.
        let before = self.parameters.len();
        self.parameters.extend(type_parameters(&node.sig.generics));
        visit::visit_item_fn(self, node);
        self.parameters.truncate(before);
    }
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func
            && path.qself.is_none()
            && path.path.segments.len() == 2
        {
            let owner = path.path.segments[0].ident.to_string();
            if self.parameters.contains(&owner) {
                self.found.push((owner, path.path.segments[1].ident.to_string()));
            }
        }
        visit::visit_expr_call(self, node);
    }
}

fn type_parameters(generics: &syn::Generics) -> Vec<String> {
    generics
        .params
        .iter()
        .filter_map(|parameter| match parameter {
            GenericParam::Type(ty) => Some(ty.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// What one `impl .. for Type` method checks: constants it passes to calls,
/// and other types whose method of the same name it calls.
struct ImplBody {
    method: String,
    constants: BTreeSet<String>,
    delegates: Vec<String>,
}

impl<'ast> Visit<'ast> for ImplBody {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func
            && path.qself.is_none()
            && path.path.segments.len() >= 2
            && path.path.segments.last().is_some_and(|last| last.ident == self.method)
        {
            let owner = &path.path.segments[path.path.segments.len() - 2].ident;
            self.delegates.push(owner.to_string());
        }
        for argument in &node.args {
            self.constant(argument);
        }
        visit::visit_expr_call(self, node);
    }
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        for argument in &node.args {
            self.constant(argument);
        }
        visit::visit_expr_method_call(self, node);
    }
}

impl ImplBody {
    /// `Permission::ReadSbom` passed as an argument: an enum variant or an
    /// associated constant, written `Type::Name`.
    fn constant(&mut self, argument: &Expr) {
        let argument = match argument {
            Expr::Reference(reference) => &*reference.expr,
            other => other,
        };
        if let Expr::Path(path) = argument
            && path.qself.is_none()
            && path.path.segments.len() >= 2
            && let Some(last) = path.path.segments.last()
            && last.ident.to_string().chars().next().is_some_and(char::is_uppercase)
            && matches!(last.arguments, PathArguments::None)
        {
            self.constants.insert(key(&last.ident.to_string()));
        }
    }
}

#[derive(Default)]
struct Collected {
    gates: HashMap<String, Option<(usize, String)>>,
    /// `(type, method)` to its constants and delegates.
    bodies: HashMap<(String, String), (BTreeSet<String>, Vec<String>)>,
}

impl Collected {
    fn items(&mut self, items: &[Item], macros: &HashMap<String, Vec<Rule>>, depth: usize) {
        for item in items {
            match item {
                Item::Impl(node) => self.implementation(node),
                Item::Mod(module) => {
                    if let Some((_, items)) = &module.content {
                        self.items(items, macros, depth);
                    }
                }
                // `permission! { .. }`, `all!(Name -> A, B)`: the project's
                // own macro, read as the items it produces.
                Item::Macro(invocation) if depth < 4 => {
                    let Some(name) = invocation.mac.path.segments.last() else {
                        continue;
                    };
                    let Some(rules) = macros.get(&name.ident.to_string()) else {
                        continue;
                    };
                    if let Some(tokens) = super::macros::expand(rules, &invocation.mac.tokens)
                        && let Ok(file) = syn::parse2::<syn::File>(tokens)
                    {
                        self.items(&file.items, macros, depth + 1);
                    }
                }
                _ => {}
            }
        }
    }

    fn implementation(&mut self, node: &syn::ItemImpl) {
        let Some((trait_path, _)) = &node.trait_ else {
            return;
        };
        let Some(owner) = type_name(&node.self_ty) else {
            return;
        };
        let is_extractor =
            trait_path.segments.last().is_some_and(|last| last.ident == "FromRequest");
        let parameters = type_parameters(&node.generics);
        if is_extractor && !parameters.is_empty() {
            self.gate(node, &owner, &parameters);
            return;
        }
        if !parameters.is_empty() {
            return;
        }
        for item in &node.items {
            let ImplItem::Fn(function) = item else {
                continue;
            };
            let mut body = ImplBody {
                method: function.sig.ident.to_string(),
                constants: BTreeSet::new(),
                delegates: Vec::new(),
            };
            body.visit_block(&function.block);
            self.bodies
                .insert((owner.clone(), body.method.clone()), (body.constants, body.delegates));
        }
    }

    /// `impl<T: Bound> FromRequest for Owner<T>` whose `from_request` calls
    /// `T::method(..)` and can fail.
    fn gate(&mut self, node: &syn::ItemImpl, owner: &str, parameters: &[String]) {
        // Position of each impl parameter among the self type's arguments.
        let Type::Path(self_path) = &*node.self_ty else {
            return;
        };
        let Some(PathArguments::AngleBracketed(arguments)) =
            self_path.path.segments.last().map(|segment| &segment.arguments)
        else {
            return;
        };
        let positions: Vec<(String, usize)> = arguments
            .args
            .iter()
            .enumerate()
            .filter_map(|(position, argument)| match argument {
                GenericArgument::Type(ty) => {
                    let name = type_name(ty)?;
                    parameters.contains(&name).then_some((name, position))
                }
                _ => None,
            })
            .collect();
        if positions.is_empty() {
            return;
        }
        for item in &node.items {
            let ImplItem::Fn(function) = item else {
                continue;
            };
            if function.sig.ident != "from_request" {
                continue;
            }
            let mut calls = ParameterCalls { parameters: parameters.to_vec(), found: Vec::new() };
            calls.visit_block(&function.block);
            let Some((parameter, method)) = calls.found.first().cloned() else {
                continue;
            };
            // The extractor must be able to reject the request.
            let fails = super::extractor_flow::block_rejects(&function.block);
            if !fails {
                continue;
            }
            // A nested helper may rename the parameter; with one candidate
            // position the mapping is still unambiguous.
            let position = positions
                .iter()
                .find(|(name, _)| *name == parameter)
                .map(|(_, position)| *position)
                .or_else(|| (positions.len() == 1).then(|| positions[0].1));
            let Some(position) = position else {
                continue;
            };
            let found = Some((position, method));
            self.gates
                .entry(owner.to_string())
                .and_modify(|known| {
                    if *known != found {
                        *known = None;
                    }
                })
                .or_insert(found);
        }
    }
}

/// Indexes parameter-dispatched extractors and the impls they dispatch to.
pub(crate) fn index<'a>(
    files: impl IntoIterator<Item = &'a syn::File>,
    macros: &HashMap<String, Vec<Rule>>,
) {
    let mut collected = Collected::default();
    if super::p13::enabled("DISPATCH") {
        for file in files {
            collected.items(&file.items, macros, 0);
        }
    }
    let mut requirements: HashMap<(String, String), Vec<String>> = HashMap::new();
    let dispatched: Vec<&String> =
        collected.gates.values().flatten().map(|(_, method)| method).collect();
    for (owner, method) in collected.bodies.keys() {
        if !dispatched.contains(&method) {
            continue;
        }
        let mut keys = BTreeSet::new();
        let mut seen = vec![owner.clone()];
        resolve(&collected, owner, method, &mut keys, &mut seen, 0);
        if !keys.is_empty() {
            requirements.insert((owner.clone(), method.clone()), keys.into_iter().collect());
        }
    }
    if std::env::var_os("ARCHER_DEBUG_DISPATCH").is_some() {
        let mut gates: Vec<_> = collected.gates.iter().collect();
        gates.sort();
        for (name, gate) in gates {
            eprintln!("dispatch gate {name}: {gate:?}");
        }
        let mut all: Vec<_> = requirements.iter().collect();
        all.sort();
        for ((owner, method), keys) in all {
            eprintln!("dispatch {owner}::{method}: {keys:?}");
        }
    }
    STATE.with(|state| {
        *state.borrow_mut() = State { gates: collected.gates, requirements };
    });
}

fn resolve(
    collected: &Collected,
    owner: &str,
    method: &str,
    keys: &mut BTreeSet<String>,
    seen: &mut Vec<String>,
    depth: usize,
) {
    let Some((constants, delegates)) = collected.bodies.get(&(owner.to_string(), method.to_string()))
    else {
        return;
    };
    keys.extend(constants.iter().cloned());
    if depth >= 6 {
        return;
    }
    for delegate in delegates {
        if seen.contains(delegate) {
            continue;
        }
        seen.push(delegate.clone());
        resolve(collected, delegate, method, keys, seen, depth + 1);
    }
}

/// The requirements of `Name<..>` when `Name` is an extractor that
/// dispatches its check to a type argument: what that argument's impl
/// checks, or the argument's own name when its impl is not in the scanned
/// code. `None` when `Name` is not such an extractor.
pub(crate) fn gate_requirements(name: &str, arguments: &PathArguments) -> Option<Vec<String>> {
    let PathArguments::AngleBracketed(arguments) = arguments else {
        return None;
    };
    STATE.with(|state| {
        let state = state.borrow();
        let (position, method) = state.gates.get(name)?.clone()?;
        let GenericArgument::Type(argument) = arguments.args.iter().nth(position)? else {
            return None;
        };
        let argument = type_name(argument)?;
        Some(
            state
                .requirements
                .get(&(argument.clone(), method))
                .cloned()
                .unwrap_or_else(|| vec![key(&argument)]),
        )
    })
}

/// How the routes of the application use one dispatched requirement.
#[derive(Default)]
struct Usage {
    reads: usize,
    writes: usize,
    resources: BTreeSet<String>,
}

thread_local! {
    static USAGE: RefCell<HashMap<String, Usage>> = RefCell::new(HashMap::new());
}

fn is_gate(name: &str) -> bool {
    STATE.with(|state| state.borrow().gates.get(name).is_some_and(Option::is_some))
}

/// The requirement keys a route gets from dispatched extractors, when all
/// of its privilege requirements come from them.
fn gate_keys(route: &super::model::Route) -> Option<Vec<&str>> {
    let mut keys: Vec<&str> = route
        .authorization
        .iter()
        .filter(|evidence| is_gate(&evidence.mechanism))
        .flat_map(|evidence| evidence.requirements.iter().map(String::as_str))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    (!keys.is_empty() && keys == route.privilege_requirements()).then_some(keys)
}

/// Counts, per dispatched requirement, the read and write routes that
/// carry it and the resources they belong to.
pub(crate) fn index_usage(routes: &[super::model::Route]) {
    let mut usage: HashMap<String, Usage> = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for route in routes {
        if !seen.insert((route.method.as_str(), route.path.as_str())) {
            continue;
        }
        let Some(keys) = gate_keys(route) else {
            continue;
        };
        let class = super::drift::route_class(route);
        let resource = super::drift::placement(route).resource;
        for key in keys {
            let entry = usage.entry(key.to_string()).or_default();
            if class == super::model::MethodClass::Write {
                entry.writes += 1;
            } else {
                entry.reads += 1;
            }
            entry.resources.insert(resource.clone());
        }
    }
    USAGE.with(|map| *map.borrow_mut() = usage);
}

/// What a route's dispatched requirement differing from its peers' means.
pub(crate) enum Difference {
    /// The requirement is carried only by routes of the route's own
    /// resource: one permission per action, which differs by design.
    OwnAction,
    /// A write requires a permission that mostly reads require.
    ReadOnWrite(String),
    /// The requirement belongs to other resources too: no direction.
    Elsewhere(String),
}

/// Judges a requirement difference for a route whose privilege
/// requirements all come from dispatched extractors. Permissions written as
/// one constant per action (`CreateSbom`, `ReadSbom`, `DeleteSbom`) differ
/// between routes by design, and nothing orders them, so a difference alone
/// says little. `None` for any other route.
pub(crate) fn difference(route: &super::model::Route) -> Option<Difference> {
    if !super::p13::enabled("DISPATCH") {
        return None;
    }
    let keys = gate_keys(route)?;
    let class = super::drift::route_class(route);
    let resource = super::drift::placement(route).resource;
    USAGE.with(|usage| {
        let usage = usage.borrow();
        if class == super::model::MethodClass::Write {
            // Every permission the write requires is one reads require.
            let read_keys: Vec<(&str, &Usage)> = keys
                .iter()
                .filter_map(|key| usage.get(*key).map(|found| (*key, found)))
                .filter(|(_, found)| found.reads >= 2 && found.reads > found.writes)
                .collect();
            if read_keys.len() == keys.len() {
                let listed = read_keys
                    .iter()
                    .map(|(key, found)| {
                        format!("`{key}` ({} read routes, {} write)", found.reads, found.writes)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                return Some(Difference::ReadOnWrite(format!(
                    " This write requires only what read routes require: {listed}."
                )));
            }
        }
        let elsewhere: Vec<String> = keys
            .iter()
            .filter_map(|key| {
                let found = usage.get(*key)?;
                let others: Vec<&String> =
                    found.resources.iter().filter(|other| **other != resource).collect();
                (!others.is_empty()).then(|| {
                    format!(
                        "`{key}` is also required under {}",
                        others.iter().take(3).map(|other| other.as_str()).collect::<Vec<_>>().join(", ")
                    )
                })
            })
            .collect();
        if elsewhere.is_empty() {
            Some(Difference::OwnAction)
        } else {
            Some(Difference::Elsewhere(format!(
                " The permissions are separate constants with no order between them, so this only shows that the route follows another resource's permission: {}.",
                elsewhere.join("; ")
            )))
        }
    })
}

/// A write whose dispatched permissions are all ones that read routes
/// require, while the other writes of its resource require permissions no
/// read route does: `DELETE /books/{id}` taking `Gate<ReadBook>` beside
/// `POST /books` with `Gate<CreateBook>` and `PUT /books/{id}` with
/// `Gate<UpdateBook>`. At least two such write peers are needed.
pub(crate) fn writes_with_read_permission(
    routes: &[super::model::Route],
    peer_groups: &mut Vec<super::model::PeerGroup>,
    invariants: &mut Vec<super::model::AuthorizationInvariant>,
    finding_details: &mut Vec<super::model::Finding>,
) {
    use super::model::*;
    if !super::p13::enabled("DISPATCH") {
        return;
    }
    let routes = super::drift::unique_routes(routes.iter());
    let reported: std::collections::HashSet<_> = finding_details
        .iter()
        .map(|finding| (finding.suspicious_route.method.clone(), finding.suspicious_route.path.clone()))
        .collect();
    let writes: Vec<(&Route, Vec<&str>, String)> = routes
        .iter()
        .filter(|route| super::drift::route_class(route) == MethodClass::Write)
        .filter_map(|route| {
            // A record (`/books/{}`) belongs with its collection (`/books`).
            let resource = super::drift::placement(route).resource;
            let collection = resource.trim_end_matches("/{}").to_string();
            Some((*route, gate_keys(route)?, collection))
        })
        .collect();
    let mut found = Vec::new();
    USAGE.with(|usage| {
        let usage = usage.borrow();
        let read_majority = |key: &str| {
            usage.get(key).is_some_and(|found| found.reads >= 2 && found.reads > found.writes)
        };
        let write_only = |key: &str| usage.get(key).is_some_and(|found| found.reads == 0);
        for (route, keys, resource) in &writes {
            if reported.contains(&(route.method.clone(), route.path.clone()))
                || !keys.iter().all(|key| read_majority(key))
            {
                continue;
            }
            let peers: Vec<&Route> = writes
                .iter()
                .filter(|(other, theirs, place)| {
                    place == resource
                        && other.handler != route.handler
                        && theirs.iter().any(|key| write_only(key))
                })
                .map(|(other, _, _)| *other)
                .collect();
            if peers.len() >= 2 {
                let counts: Vec<String> = keys
                    .iter()
                    .map(|key| {
                        let found = &usage[*key];
                        format!("`{key}` ({} read routes, {} write)", found.reads, found.writes)
                    })
                    .collect();
                found.push((*route, resource.clone(), peers, counts));
            }
        }
    });
    for (route, resource, peers, counts) in found {
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut members: Vec<RouteReference> = vec![route.into()];
        members.extend(peers.iter().map(|peer| (*peer).into()));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!("write routes of {resource} and the permissions they require"),
            prefix: resource.clone(),
            level: GroupLevel::Linked,
            method_class: MethodClass::Write,
            routes: members,
        });
        let mut peer_keys: Vec<String> = peers
            .iter()
            .flat_map(|peer| peer.privilege_requirements().into_iter().map(str::to_owned))
            .collect();
        peer_keys.sort();
        peer_keys.dedup();
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "Writes of {resource} require a permission that no read route requires."
            ),
            total_routes: peers.len() + 1,
            routes_with_authorization: peers.len(),
            routes_without_authorization: 1,
            evidence_patterns: peer_keys.clone(),
            strength: AuthStrength::Medium,
            expected_tier: Some(EvidenceTier::Privilege),
            dominant_requirement: None,
        };
        invariants.push(invariant.clone());
        let listed: Vec<String> = peers
            .iter()
            .take(4)
            .map(|peer| {
                format!(
                    "{} {} ({})",
                    peer.method,
                    peer.path,
                    peer.privilege_requirements()
                        .iter()
                        .map(|key| format!("`{key}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .collect();
        finding_details.push(Finding {
            peer_group_id: id,
            category: FindingCategory::WeakerAuthorization,
            severity: Severity::Medium,
            rationale: format!(
                "This write requires only what read routes require: {}. The other writes of {resource} require permissions no read route does: {}. Dismiss if the difference is intended.",
                counts.join(", "),
                listed.join(", "),
            ),
            invariant,
            suspicious_route: route.into(),
            suspicious_route_tier: route.best_tier(),
            expected_tier: EvidenceTier::Privilege,
            suspicious_route_evidence: route.authorization.clone(),
            evidence: Default::default(),
            authorized_peer_routes: peers.iter().map(|peer| (*peer).into()).collect(),
        });
    }
}
