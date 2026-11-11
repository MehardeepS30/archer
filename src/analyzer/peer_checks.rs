//! Checks a route skips that its peers make, learned from the peers.
//!
//! Each route carries caller-use features (see `caller_use`): the identity
//! types it takes, and what it does with them. A route is compared with its
//! peers of the same method class, narrowest group first: routes linked to
//! it by shared data, its resource, its namespace, the scope trees above
//! it, the whole application. For each feature, the narrowest group with
//! enough routes that could have it decides. When nearly all of them have it
//! and the route does not, the route is reported, with the peers that do.
//!
//! The checks are not named in advance. `check_private_instance` in Lemmy
//! and `validate_profile_id_from_auth_layer` in Hyperswitch are found
//! because the application's own handlers use them consistently.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use super::{
    caller_use::{BINDS, GRANTS, GUARDS, KEYED, LOADS, MENTIONS, SITE, SITE_SEPARATOR, UNKNOWN_TYPE},
    drift::{
        is_authentication_route, is_generic_segment, is_well_known_public_route, link_strength,
        placement, route_identity, unique_routes,
    },
    evidence::camel_case_words,
    model::*,
    routes::has_unresolved_inner_segment as has_unresolved_segment,
};

/// Routes, besides the route itself, that must be able to have a feature
/// before a group can decide on it.
const MIN_POPULATION: usize = 3;
/// The whole application is a loose group: it needs more routes.
const MIN_APP_POPULATION: usize = 6;
/// The share of that population that must have the feature.
const CONSENSUS: f64 = 0.75;
const APPLICATION: &str = "the application";
/// How many skipped features a finding names.
const NAMED: usize = 3;

/// A feature as peers are compared on it. A call's identity label is
/// dropped: a helper that takes `&LocalUserView` and a handler that holds
/// `Option<LocalUserView>` make the same check.
pub(crate) fn compared(feature: &str) -> String {
    match feature.strip_prefix("checks:") {
        // The label has no `:`; the callee can (`Post::read`).
        Some(rest) => match rest.split_once(':') {
            Some((_, callee)) => format!("checks:{callee}"),
            None => feature.to_string(),
        },
        None => feature.to_string(),
    }
}

struct Features {
    takes: BTreeSet<String>,
    uses: BTreeSet<String>,
    schemes: BTreeSet<String>,
    /// Calls that yield the caller (`authorize_session()`), bound or not.
    auths: BTreeSet<String>,
    /// Identity sources the route calls.
    calls: BTreeSet<String>,
    /// Requirement arguments it passes them, as `f#i`, with what it passes.
    requires: BTreeMap<String, String>,
    /// Where each compared check is made (see `caller_use::SITE`).
    sites: BTreeMap<String, String>,
    /// Records the route loads with request data, by loading call.
    loads: BTreeSet<String>,
    /// How the route holds each loaded record to the caller.
    guards: BTreeMap<String, Vec<String>>,
    /// Request values it holds to the caller, as `K:p` (see
    /// `caller_use::BINDS`).
    binds: BTreeSet<String>,
    /// Body or query fields it reads, as `body:p`.
    mentions: BTreeSet<String>,
    /// Constants its auth objects are built with (`caller_use::GRANTS`).
    grants: BTreeSet<String>,
}

impl Features {
    /// It checks the caller by its own call or comparison.
    fn checks_itself(&self) -> bool {
        self.uses
            .iter()
            .any(|feature| feature.starts_with("checks:") || feature.starts_with("compares:"))
    }
}

fn features(route: &Route) -> Features {
    let mut takes = BTreeSet::new();
    let mut uses = BTreeSet::new();
    let mut schemes = BTreeSet::new();
    let mut auths = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut requires = BTreeMap::new();
    let mut sites = BTreeMap::new();
    let mut loads = BTreeSet::new();
    let mut guards: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut binds = BTreeSet::new();
    let mut mentions = BTreeSet::new();
    let mut grants = BTreeSet::new();
    for feature in &route.caller_use {
        if let Some(value) = feature.strip_prefix(GRANTS) {
            grants.insert(value.to_string());
        } else if feature.starts_with(KEYED) {
            // Bookkeeping for `public::likely_public`, not a check.
        } else if let Some(tag) = feature.strip_prefix(BINDS) {
            binds.insert(tag.to_string());
        } else if let Some(tag) = feature.strip_prefix(MENTIONS) {
            mentions.insert(tag.to_string());
        } else if let Some(key) = feature.strip_prefix(LOADS) {
            loads.insert(key.to_string());
        } else if let Some(rest) = feature.strip_prefix(GUARDS) {
            // The key can hold `::` (`Note::read`); the way it is guarded
            // follows the first `:` after it.
            if let Some((key, how)) = split_guard(rest) {
                guards.entry(key.to_string()).or_default().push(how.to_string());
            }
        } else if let Some(site) = feature.strip_prefix(SITE) {
            if let Some((feature, chain)) = site.split_once(SITE_SEPARATOR) {
                sites.insert(feature.to_string(), chain.to_string());
            }
        } else if let Some(label) = feature.strip_prefix("takes:") {
            takes.insert(label.to_string());
        } else if let Some(name) = feature.strip_prefix("scheme:") {
            schemes.insert(name.to_string());
        } else if let Some(call) = feature.strip_prefix("auths:") {
            auths.insert(call.to_string());
        } else if let Some(source) = feature.strip_prefix("calls:") {
            calls.insert(source.to_string());
        } else if let Some(rest) = feature.strip_prefix("requires:") {
            if let Some((key, written)) = rest.split_once(':') {
                requires
                    .entry(key.to_string())
                    .or_insert_with(|| written.to_string());
            }
        } else {
            uses.insert(compared(feature));
        }
    }
    Features {
        takes,
        uses,
        schemes,
        auths,
        calls,
        requires,
        sites,
        loads,
        guards,
        binds,
        mentions,
        grants,
    }
}

/// Rank of a caller-use feature, most specific first: an object-level
/// comparison, a check call, the caller taken, a decision on the caller's
/// own value, a field read.
fn specificity(feature: &str) -> u8 {
    if feature.starts_with("compares:") {
        0
    } else if feature.starts_with("checks:") {
        1
    } else if feature.starts_with("takes:") {
        2
    } else if feature.starts_with("acts:") {
        3
    } else {
        4
    }
}

/// How a peer guards a record it loads together with the caller.
const SCOPED_LOAD: &str = "loaded with the caller";

/// `Note::read:compares ..` → (`Note::read`, `compares ..`).
pub(crate) fn split_guard(rest: &str) -> Option<(&str, &str)> {
    let mut start = 0;
    while let Some(offset) = rest[start..].find(':') {
        let at = start + offset;
        if rest[at + 1..].starts_with(':') {
            start = at + 2;
            continue;
        }
        return Some((&rest[..at], &rest[at + 1..]));
    }
    None
}

/// The object-level check: the route loads a record with data from the
/// request (`Note::read(&pool, data.note_id)`), and does not hold it to the
/// caller, where the peers of its method class that load the same record
/// do: they compare one of its fields with the caller, pass it with the
/// caller to a check, or load it with the caller. Peers are found by the
/// record, not by path, so a route is compared with every route that
/// touches the same data.
///
/// A peer that loads it together with the caller (`find_note(id, user.id)`)
/// may scope the query or only shape the view, so it is left out. A guard
/// seen as a comparison of a record field with the caller is direct
/// evidence; a check function that receives both is a policy that only
/// some routes follow (moderators' actions beside a user's own follow), so
/// alone it must be unanimous. At least 3 peers, 75% of them guarding with
/// a comparison among them, or all of them guarding; or 2 that both do. A
/// finding backed by a comparison with 3 or more peers is Medium, else Low.
#[allow(clippy::too_many_arguments)]
fn unguarded_record(
    route: &Route,
    own: &Features,
    index: usize,
    featured: &[Features],
    eligible: &[&Route],
    class: MethodClass,
    classes: &[MethodClass],
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
) -> Option<Finding> {
    let scoped = |features: &Features, key: &str| {
        features.guards.get(key).is_some_and(|ways| ways.iter().any(|how| how == SCOPED_LOAD))
    };
    let direct = |features: &Features, key: &str| {
        features.guards.get(key).is_some_and(|ways| {
            ways.iter().any(|how| how.starts_with("compares ") || how.starts_with("checks `"))
        })
    };
    for key in &own.loads {
        if own.guards.contains_key(key) {
            continue;
        }
        let support = |any_class: bool| {
            let population: Vec<usize> = (0..eligible.len())
                .filter(|&other| {
                    other != index
                        && (any_class || classes[other] == class)
                        && featured[other].loads.contains(key)
                        && !scoped(&featured[other], key)
                        && route_identity(eligible[other]) != route_identity(route)
                        && eligible[other].origin.definition != route.origin.definition
                })
                .collect::<Vec<usize>>();
            let having: Vec<usize> = population
                .iter()
                .copied()
                .filter(|&other| featured[other].guards.contains_key(key))
                .collect();
            let compared = having
                .iter()
                .filter(|&&other| direct(&featured[other], key))
                .count();
            let share = having.len() as f64 / population.len().max(1) as f64;
            let enough = (population.len() >= MIN_POPULATION
                && ((share + 1e-9 >= CONSENSUS && compared > 0) || having.len() == population.len()))
                || (population.len() == 2 && having.len() == 2);
            (population, having, compared, enough)
        };
        // Too few routes of its own method class load the record: the routes
        // of any class that load it are a lead, at Low.
        let (population, having, compared, enough) = support(false);
        let (population, having, compared, across) = if !enough
            && population.len() < MIN_POPULATION
            && super::caller_use::rule_on("R1")
        {
            let (population, having, compared, enough) = support(true);
            if !enough {
                continue;
            }
            (population, having, compared, true)
        } else if enough {
            (population, having, compared, false)
        } else {
            continue;
        };
        let peers_named = if across { "routes of any method".to_owned() } else { format!("{class} routes") };
        // A route with a role or permission check where the peers that
        // guard the record have none follows a different policy (an
        // administrator may act on any record).
        if route.best_tier() == EvidenceTier::Privilege
            && having
                .iter()
                .any(|&other| eligible[other].best_tier() != EvidenceTier::Privilege)
        {
            continue;
        }
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut group_routes: Vec<RouteReference> = vec![route.into()];
        group_routes.extend(having.iter().map(|&other| eligible[other].into()));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!("{peers_named} that load the record `{key}` with request data"),
            prefix: format!("record `{key}`"),
            level: GroupLevel::Linked,
            method_class: class,
            routes: group_routes,
        });
        let feature = format!("{GUARDS}{key}");
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "{peers_named} that load `{key}` with request data hold it to the caller."
            ),
            total_routes: population.len() + 1,
            routes_with_authorization: having.len(),
            routes_without_authorization: population.len() - having.len() + 1,
            evidence_patterns: vec![feature.clone()],
            strength: AuthStrength::Medium,
            expected_tier: Some(EvidenceTier::Resource),
            dominant_requirement: Some(feature),
        };
        invariants.push(invariant.clone());
        let examples: Vec<String> = having
            .iter()
            .take(NAMED)
            .map(|&other| {
                let ways = &featured[other].guards[key];
                let how = ways
                    .iter()
                    .find(|how| how.starts_with("compares "))
                    .or_else(|| ways.first())
                    .cloned()
                    .unwrap_or_default();
                format!("{} {} {how}", eligible[other].method, eligible[other].path)
            })
            .collect();
        // A route that names an authentication scheme none of the guarding
        // peers name (an operator key beside user sessions) follows another
        // policy more often than it forgets one.
        let other_scheme = !own.schemes.is_empty()
            && having
                .iter()
                .all(|&other| featured[other].schemes.is_disjoint(&own.schemes));
        return Some(Finding {
            peer_group_id: id,
            category: FindingCategory::SkipsPeerCheck,
            severity: if population.len() >= MIN_POPULATION && compared > 0 && !other_scheme && !across {
                Severity::Medium
            } else {
                Severity::Low
            },
            rationale: format!(
                "Loads `{key}` with data from the request but never holds the result to the caller (or to a secret the request presents). {} of {} {peers_named} that load it do: {}.{} Dismiss if the difference is intended.",
                having.len(),
                population.len(),
                examples.join("; "),
                if across {
                    format!(" Fewer than {MIN_POPULATION} {class} routes load it, so routes of every method are compared and the finding is capped at Low.")
                } else {
                    String::new()
                }
            ),
            invariant,
            suspicious_route: route.into(),
            suspicious_route_tier: route.best_tier(),
            expected_tier: EvidenceTier::Resource,
            suspicious_route_evidence: route.authorization.clone(),
            evidence: Default::default(),
            authorized_peer_routes: having.iter().map(|&other| eligible[other].into()).collect(),
        });
    }
    None
}

/// A requirement argument that names a fixed requirement, a variant,
/// constant, or literal (`Some(OriginMemberRole::Maintainer)`, `"admin"`),
/// not a value from the request (`Some(&origin)`), which scopes the call to
/// the route's own data and is not comparable across routes.
fn is_constant_requirement(written: &str) -> bool {
    let mut value = written;
    while let Some(inner) = value
        .strip_prefix("Some(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        value = inner;
    }
    let value = value.trim_start_matches('&');
    if value.starts_with('"') || value.parse::<f64>().is_ok() || value == "true" || value == "false" {
        return true;
    }
    let segments: Vec<&str> = value.split("::").collect();
    let simple = segments.iter().all(|segment| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|character| character.is_alphanumeric() || character == '_')
    });
    let last = segments.last().copied().unwrap_or_default();
    simple
        && (last.chars().all(|character| character.is_ascii_uppercase() || character == '_' || character.is_ascii_digit())
            || (segments.len() >= 2 && last.starts_with(|character: char| character.is_ascii_uppercase())))
}

/// Names of a path's parameters: `origin` and `id` for `/o/{origin}/x/{id:\\d+}`.
fn path_parameters(path: &str) -> Vec<String> {
    path.split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .map(|inner| inner.split(':').next().unwrap_or(inner).to_string())
        .collect()
}

/// Lowercase identifiers in written code: `origin` in `Some(&origin)`.
fn identifiers(written: &str) -> Vec<String> {
    written
        .split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .filter(|word| word.starts_with(|character: char| character.is_ascii_lowercase()))
        .map(str::to_string)
        .collect()
}

/// A scheme value whose name says it requires no credential: `NoAuth`,
/// `PublicAuth`, `AnonymousAuth`.
fn admits_anyone(scheme: &str) -> bool {
    camel_case_words(scheme).iter().any(|word| {
        [
            "no",
            "none",
            "public",
            "anonymous",
            "anon",
            "unauthenticated",
        ]
        .contains(&word.as_str())
    })
}

/// The open-scheme check: every scheme the route names admits anyone, and at
/// its narrowest group with enough scheme-naming peers, a dominant share of
/// them names one credential scheme the route lacks.
#[allow(clippy::too_many_arguments)]
fn open_scheme(
    route: &Route,
    own: &Features,
    levels: &[(String, Vec<usize>, usize)],
    featured: &[Features],
    eligible: &[&Route],
    class: MethodClass,
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
) -> Option<Finding> {
    if own.schemes.is_empty() || !own.schemes.iter().all(|scheme| admits_anyone(scheme)) {
        return None;
    }
    for (scope, members, minimum) in levels {
        let population: Vec<usize> = members
            .iter()
            .copied()
            .filter(|&other| !featured[other].schemes.is_empty())
            .collect();
        if population.len() < *minimum {
            continue;
        }
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for &other in &population {
            for scheme in &featured[other].schemes {
                if !admits_anyone(scheme) {
                    *counts.entry(scheme.as_str()).or_default() += 1;
                }
            }
        }
        let (scheme, count) = counts
            .into_iter()
            .max_by_key(|(name, count)| (*count, std::cmp::Reverse(*name)))?;
        if (count as f64) / (population.len() as f64) + 1e-9 < CONSENSUS {
            // The narrowest group with enough peers decides.
            return None;
        }
        let having: Vec<usize> = population
            .iter()
            .copied()
            .filter(|&other| featured[other].schemes.contains(scheme))
            .collect();
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut group_routes: Vec<RouteReference> = vec![route.into()];
        group_routes.extend(having.iter().map(|&other| eligible[other].into()));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!(
                "{class} routes under {scope} compared on the auth scheme they name"
            ),
            prefix: scope.clone(),
            level: GroupLevel::Linked,
            method_class: class,
            routes: group_routes,
        });
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!("{class} routes under {scope} authenticate with `{scheme}`."),
            total_routes: population.len() + 1,
            routes_with_authorization: having.len(),
            routes_without_authorization: population.len() - having.len() + 1,
            evidence_patterns: vec![format!("scheme:{scheme}")],
            strength: AuthStrength::Medium,
            expected_tier: None,
            dominant_requirement: Some(format!("scheme:{scheme}")),
        };
        invariants.push(invariant.clone());
        let named: Vec<String> = own
            .schemes
            .iter()
            .map(|scheme| format!("`{scheme}`"))
            .collect();
        return Some(Finding {
            peer_group_id: id,
            category: FindingCategory::SkipsPeerCheck,
            // An open scheme on a route whose code still expects a caller
            // is a contradiction; on one that takes none it is often a
            // public endpoint by design.
            severity: if own.takes.is_empty() {
                Severity::Low
            } else {
                Severity::Medium
            },
            rationale: format!(
                "Uses {} where {} of {} {class} peers under {scope} use `{scheme}`; this route admits callers they would refuse. Dismiss if the difference is intended.",
                named.join(", "),
                having.len(),
                population.len()
            ),
            invariant,
            suspicious_route: route.into(),
            suspicious_route_tier: route.best_tier(),
            expected_tier: route.best_tier(),
            suspicious_route_evidence: route.authorization.clone(),
            evidence: Default::default(),
            authorized_peer_routes: having.iter().map(|&other| eligible[other].into()).collect(),
        });
    }
    None
}

/// The requirement check: the route calls an identity source
/// (`authorize_session`) without an argument that, at its narrowest group
/// with enough peers calling the same source, a dominant share of them
/// pass (`Some(OriginMemberRole::Maintainer)`). Such an argument is the
/// requirement the source enforces; leaving it `None` admits any caller.
#[allow(clippy::too_many_arguments)]
fn missing_requirement(
    route: &Route,
    own: &Features,
    levels: &[(String, Vec<usize>, usize)],
    featured: &[Features],
    eligible: &[&Route],
    class: MethodClass,
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
) -> Option<Finding> {
    for source in &own.calls {
        for (scope, members, minimum) in levels {
            let prefix = format!("{source}#");
            // Peers whose call is scoped to request data (`Some(&origin)`)
            // compare only when this route has that data in its path: a
            // role in an origin means nothing to a route with no origin.
            let parameters = path_parameters(&route.path);
            let population: Vec<usize> = members
                .iter()
                .copied()
                .filter(|&other| featured[other].calls.contains(source))
                .filter(|&other| {
                    featured[other]
                        .requires
                        .iter()
                        .filter(|(key, written)| key.starts_with(&prefix) && !is_constant_requirement(written))
                        .all(|(_, written)| {
                            identifiers(written).iter().any(|name| parameters.contains(name))
                        })
                })
                .collect();
            if population.len() < *minimum {
                continue;
            }
            let positions: BTreeSet<&String> = population
                .iter()
                .flat_map(|&other| featured[other].requires.iter())
                .filter(|(key, written)| key.starts_with(&prefix) && is_constant_requirement(written))
                .map(|(key, _)| key)
                .collect();
            let mut missing: Vec<(&String, Vec<usize>, usize)> = positions
                .into_iter()
                .filter(|key| !own.requires.contains_key(*key))
                .map(|key| {
                    let passes = |other: usize| {
                        featured[other]
                            .requires
                            .get(key)
                            .is_some_and(|written| is_constant_requirement(written))
                    };
                    // A peer that omits the requirement but checks the
                    // caller itself (`if session.id() != owner`) is not a
                    // counterexample: it authorizes by other means.
                    let population: Vec<usize> = population
                        .iter()
                        .copied()
                        .filter(|&other| passes(other) || !featured[other].checks_itself())
                        .collect();
                    let having: Vec<usize> = population
                        .iter()
                        .copied()
                        .filter(|&other| passes(other))
                        .collect();
                    (key, having, population.len())
                })
                .filter(|(_, _, total)| *total >= *minimum)
                .collect();
            if missing.is_empty() {
                continue;
            }
            // The narrowest group with enough callers decides.
            missing.retain(|(_, having, total)| {
                having.len() as f64 / *total as f64 + 1e-9 >= CONSENSUS
            });
            if missing.is_empty() {
                break;
            }
            missing.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
            let (key, having, total) = &missing[0];
            let position: usize = key[prefix.len()..].parse().unwrap_or(0);
            let mut examples: Vec<&str> = having
                .iter()
                .filter_map(|&other| featured[other].requires.get(*key).map(String::as_str))
                .collect();
            examples.sort_unstable();
            examples.dedup();
            let shown: Vec<String> = examples
                .iter()
                .take(NAMED)
                .map(|example| format!("`{example}`"))
                .collect();
            let scoped = own
                .requires
                .iter()
                .any(|(key, written)| key.starts_with(&prefix) && !is_constant_requirement(written));
            let id = format!("peer-group-{:03}", peer_groups.len() + 1);
            let mut group_routes: Vec<RouteReference> = vec![route.into()];
            group_routes.extend(having.iter().map(|&other| eligible[other].into()));
            peer_groups.push(PeerGroup {
                id: id.clone(),
                description: format!(
                    "{class} routes under {scope} compared on what they pass `{source}`"
                ),
                prefix: scope.clone(),
                level: GroupLevel::Linked,
                method_class: class,
                routes: group_routes,
            });
            let invariant = AuthorizationInvariant {
                peer_group_id: id.clone(),
                description: format!(
                    "{class} routes under {scope} that call `{source}` pass it a requirement as argument {}.",
                    position + 1
                ),
                total_routes: total + 1,
                routes_with_authorization: having.len(),
                routes_without_authorization: total - having.len() + 1,
                evidence_patterns: vec![format!("requires:{key}")],
                strength: AuthStrength::Medium,
                expected_tier: None,
                dominant_requirement: Some(format!("requires:{key}")),
            };
            invariants.push(invariant.clone());
            return Some(Finding {
                peer_group_id: id,
                category: FindingCategory::SkipsPeerCheck,
                // A call already scoped to the route's data (`Some(&origin),
                // None`: any member) is a lighter requirement more often
                // than a missing one.
                severity: if scope == APPLICATION || scoped {
                    Severity::Low
                } else {
                    Severity::Medium
                },
                rationale: format!(
                    "Calls `{source}` with no requirement as argument {}, where {} of {} {class} peers under {scope} that call it pass one ({}). Dismiss if the difference is intended.",
                    position + 1,
                    having.len(),
                    total,
                    shown.join(", ")
                ),
                invariant,
                suspicious_route: route.into(),
                suspicious_route_tier: route.best_tier(),
                expected_tier: route.best_tier(),
                suspicious_route_evidence: route.authorization.clone(),
                evidence: Default::default(),
                authorized_peer_routes: having.iter().map(|&other| eligible[other].into()).collect(),
            });
        }
    }
    None
}

/// The leading generic segments of a namespace, when they include a version:
/// `/api/v4` for `/api/v4/multi_community`.
fn version_prefix(namespace: &str) -> Option<String> {
    let generic: Vec<&str> = namespace
        .split('/')
        .filter(|segment| !segment.is_empty())
        .take_while(|segment| is_generic_segment(segment))
        .collect();
    let versioned = generic.iter().any(|segment| {
        segment.len() > 1
            && segment.starts_with(['v', 'V'])
            && segment[1..]
                .chars()
                .all(|character| character.is_ascii_digit())
    });
    versioned.then(|| format!("/{}", generic.join("/")))
}

/// `/` and `/{_:.*}`: a root page or a fallback, not a peer of the API.
fn is_catch_all(path: &str) -> bool {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .all(|segment| {
            segment.starts_with('{')
                && (segment.contains(".*") || segment.contains(".+") || segment.starts_with("{_"))
        })
}

/// Peers take the caller as `Option<X>`, so they serve anonymous callers
/// too; a route whose extractor requires `X` (bound to `_` or not) rejects
/// them, which is stricter than its peers, not a skipped check.
fn requires_what_peers_allow(route: &Route, label: &str) -> bool {
    let Some(base) = label
        .strip_prefix("Option<")
        .and_then(|rest| rest.strip_suffix('>'))
    else {
        return false;
    };
    route.authorization.iter().any(|evidence| {
        evidence.kind == AuthEvidenceKind::IdentityExtraction
            && !evidence.mechanism.contains("Option<")
            && evidence.mechanism == base
            && evidence.symbol.as_deref().is_none_or(|symbol| !symbol.contains("Option<"))
    })
}

fn describe(feature: &str) -> String {
    if let Some(callee) = feature.strip_prefix("checks:") {
        format!("check the caller with `{callee}`")
    } else if let Some(label) = feature.strip_prefix("compares:") {
        format!("compare the caller (`{label}`) with a value from the request or a record")
    } else if let Some(rest) = feature.strip_prefix("reads:") {
        match rest.rsplit_once(':') {
            Some((label, field)) => format!("read `{field}` of the caller (`{label}`)"),
            None => format!("read {rest}"),
        }
    } else if let Some(label) = feature.strip_prefix("takes:") {
        format!("take the caller as `{label}`")
    } else {
        feature.to_string()
    }
}

pub(crate) fn skipped_peer_checks(
    routes: &[Route],
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
    finding_details: &mut Vec<Finding>,
) {
    let eligible: Vec<&Route> = unique_routes(routes.iter().filter(|route| {
        route.origin.definition.is_some()
            && route.unverified.is_empty()
            && !has_unresolved_segment(&route.path)
            && !is_authentication_route(route)
            && !is_well_known_public_route(route)
    }));
    // A route reported only for protection Archer cannot verify is still
    // checked for an open scheme: one it names itself outweighs code Archer
    // cannot follow, and that finding replaces the other.
    let unverified: HashSet<_> = finding_details
        .iter()
        .filter(|finding| is_unverified_only(finding))
        .map(|finding| {
            let route = &finding.suspicious_route;
            (route.method.clone(), route.path.clone(), route.handler.clone())
        })
        .collect();
    let reported: HashSet<_> = finding_details
        .iter()
        .filter(|finding| !is_unverified_only(finding))
        .map(|finding| {
            let route = &finding.suspicious_route;
            (
                route.method.clone(),
                route.path.clone(),
                route.handler.clone(),
            )
        })
        .collect();
    let placed: Vec<_> = eligible.iter().map(|route| placement(route)).collect();
    let featured: Vec<Features> = eligible.iter().map(|route| features(route)).collect();
    let classes: Vec<MethodClass> = placed.iter().map(|place| place.class).collect();

    // Routes for the grant check, which runs last: the reasons above are
    // more specific.
    let mut granted: Vec<usize> = Vec::new();
    for (index, route) in eligible.iter().enumerate() {
        if reported.contains(&(
            route.method.clone(),
            route.path.clone(),
            route.handler.clone(),
        )) || is_catch_all(&route.path)
        {
            continue;
        }
        let place = &placed[index];
        let own = &featured[index];
        // Peers: same method class, a different route and handler.
        let peers: Vec<usize> = (0..eligible.len())
            .filter(|&other| {
                other != index
                    && placed[other].class == place.class
                    && route_identity(eligible[other]) != route_identity(route)
                    && eligible[other].origin.definition != route.origin.definition
            })
            .collect();
        if peers.is_empty() {
            continue;
        }
        // Groups, narrowest first.
        let mut levels: Vec<(String, Vec<usize>, usize)> = Vec::new();
        let linked: Vec<usize> = peers
            .iter()
            .copied()
            .filter(|&other| {
                eligible[other].path != route.path && link_strength(route, eligible[other]) > 0
            })
            .collect();
        levels.push((
            format!("routes serving the same data as {}", route.path),
            linked,
            MIN_POPULATION,
        ));
        let resource: Vec<usize> = peers
            .iter()
            .copied()
            .filter(|&other| placed[other].resource == place.resource)
            .collect();
        levels.push((place.resource.clone(), resource, MIN_POPULATION));
        // Sibling resources (`/account/block/instance` beside
        // `/account/block/person`): each path prefix between the resource
        // and its namespace, narrowest first. A namespace can be too broad
        // to agree on a check that every route beside this one makes.
        let mut parent = place.resource.as_str();
        while let Some((above, _)) = parent.rsplit_once('/') {
            if above.len() <= place.namespace.len() || !above.starts_with(&place.namespace) {
                break;
            }
            let siblings: Vec<usize> = peers
                .iter()
                .copied()
                .filter(|&other| {
                    let resource = &placed[other].resource;
                    placed[other].namespace == place.namespace
                        && (resource == above || resource.starts_with(&format!("{above}/")))
                })
                .collect();
            levels.push((above.to_string(), siblings, MIN_POPULATION));
            parent = above;
        }
        let namespace: Vec<usize> = peers
            .iter()
            .copied()
            .filter(|&other| placed[other].namespace == place.namespace)
            .collect();
        levels.push((place.namespace.clone(), namespace, MIN_POPULATION));
        for prefix in place.subtrees() {
            let within: Vec<usize> = peers
                .iter()
                .copied()
                .filter(|&other| {
                    let namespace = &placed[other].namespace;
                    namespace == &prefix || namespace.starts_with(&format!("{prefix}/"))
                })
                .collect();
            levels.push((prefix, within, MIN_POPULATION));
        }
        // The API version the route belongs to (`/api/v4`): scope trees
        // skip generic prefixes, but a version is narrower than the whole
        // application, which also pools other versions and mounts.
        let version = version_prefix(&place.namespace);
        if let Some(version) = version.filter(|version| version != &place.namespace) {
            let within: Vec<usize> = peers
                .iter()
                .copied()
                .filter(|&other| {
                    let namespace = &placed[other].namespace;
                    namespace == &version || namespace.starts_with(&format!("{version}/"))
                })
                .collect();
            levels.push((version, within, MIN_APP_POPULATION));
        }
        levels.push((APPLICATION.to_string(), peers.clone(), MIN_APP_POPULATION));

        let only_unverified = unverified.contains(&(
            route.method.clone(),
            route.path.clone(),
            route.handler.clone(),
        ));
        // The most specific check first: a record the route loads and its
        // peers hold to the caller.
        if !only_unverified
            && let Some(finding) = unguarded_record(
            route,
            own,
            index,
            &featured,
            &eligible,
            place.class,
            &classes,
            peer_groups,
            invariants,
        ) {
            finding_details.push(finding);
            continue;
        }
        // A path parameter its peers hold to the caller, then a guard kind
        // the routes admitting its scheme make on what they load.
        if !only_unverified {
            if let Some(finding) =
                unbound_parameter(route, own, index, &featured, &eligible, peer_groups, invariants)
            {
                finding_details.push(finding);
                continue;
            }
            if let Some(finding) =
                mechanism_guard(route, own, index, &featured, &eligible, peer_groups, invariants)
            {
                finding_details.push(finding);
                continue;
            }
            granted.push(index);
        }
        // A route whose only auth schemes admit anyone (`NoAuth`) where its
        // peers pass a credential scheme to the same wrapper.
        if let Some(finding) = open_scheme(
            route,
            own,
            &levels,
            &featured,
            &eligible,
            place.class,
            peer_groups,
            invariants,
        ) {
            finding_details.push(finding);
            continue;
        }
        if only_unverified {
            continue;
        }
        // A route that calls the peers' identity source without the
        // requirement they pass it, and makes no check of its own.
        if !own.checks_itself()
            && let Some(finding) = missing_requirement(
                route,
                own,
                &levels,
                &featured,
                &eligible,
                place.class,
                peer_groups,
                invariants,
            )
        {
            finding_details.push(finding);
            continue;
        }

        // Item routes beneath a create still count for taking the caller,
        // the scope check, but not for their object-level checks.
        let existing_record = |other: usize| acts_on_existing_record(route, own, eligible[other], &featured[other]);
        // Every feature some peer has, decided at its narrowest level.
        let mut decided: BTreeMap<String, (String, usize, Vec<usize>)> = BTreeMap::new();
        let mut undecidable: HashSet<String> = HashSet::new();
        for (scope, members, minimum) in &levels {
            // Peers that could have a use feature take an identity the
            // route also takes; `takes:` is open to every peer.
            let sharing: Vec<usize> = members
                .iter()
                .copied()
                .filter(|&other| !featured[other].takes.is_disjoint(&own.takes) && !existing_record(other))
                .collect();
            let mut candidates: BTreeSet<String> = BTreeSet::new();
            if own.takes.is_empty() {
                for &other in members {
                    candidates.extend(
                        featured[other]
                            .takes
                            .iter()
                            .map(|label| format!("takes:{label}")),
                    );
                }
            } else {
                for &other in &sharing {
                    candidates.extend(
                        featured[other]
                            .uses
                            .iter()
                            .filter(|feature| !feature.starts_with("acts:"))
                            .cloned(),
                    );
                }
            }
            for feature in candidates {
                if decided.contains_key(&feature) || undecidable.contains(&feature) {
                    continue;
                }
                let population: &Vec<usize> = if feature.starts_with("takes:") {
                    members
                } else {
                    &sharing
                };
                if population.len() < *minimum {
                    continue;
                }
                let having: Vec<usize> = population
                    .iter()
                    .copied()
                    .filter(|&other| match feature.strip_prefix("takes:") {
                        Some(label) => featured[other].takes.contains(label),
                        None => featured[other].uses.contains(&feature),
                    })
                    .collect();
                let share = having.len() as f64 / population.len() as f64;
                // Reading a field is weaker evidence of a check than a call
                // or a comparison: it must be unanimous.
                let needed = if feature.starts_with("reads:") {
                    1.0
                } else {
                    CONSENSUS
                };
                if share + 1e-9 >= needed {
                    decided.insert(feature, (scope.clone(), population.len(), having));
                } else {
                    // The narrowest group that can decide has decided: a
                    // wider group must not overrule it.
                    undecidable.insert(feature);
                }
            }
        }
        // A route that establishes the caller by its own means (another
        // extractor, a guard, a role check) has not ignored the caller by
        // not taking the peers' identity type. An extractor of that very
        // type bound to `_` has.
        let own_identity = |label: &str| {
            // It makes the peers' own identity call and throws the caller
            // away (`Ok(_session) => ..`): the evidence that call carries
            // is not a different means.
            if own.auths.contains(label) {
                return false;
            }
            let base = label
                .strip_prefix("Option<")
                .and_then(|rest| rest.strip_suffix('>'))
                .unwrap_or(label);
            // An authentication object passed to a wrapper is where the
            // wrapper gets the caller it hands the handler: the peers pass
            // one too, so it is not a different means.
            route.authorization.iter().any(|evidence| {
                !matches!(
                    evidence.kind,
                    AuthEvidenceKind::Delegated | AuthEvidenceKind::Unknown
                ) && !super::auth_objects::is_learned(evidence)
                    && EvidenceTier::of(&evidence.kind) >= EvidenceTier::Identity
                    && !(evidence.kind == AuthEvidenceKind::IdentityExtraction
                        && evidence.mechanism.contains(base))
            })
        };
        let own_checks: Vec<&String> = own
            .uses
            .iter()
            .filter(|feature| {
                feature.starts_with("checks:")
                    || feature.starts_with("compares:")
                    || feature.starts_with("acts:")
            })
            .collect();
        let makes_variant = |feature: &str| {
            let Some(callee) = feature.strip_prefix("checks:") else {
                return false;
            };
            own_checks.iter().any(|check| {
                check.strip_prefix("checks:").is_some_and(|own_callee| {
                    own_callee != callee
                        && (own_callee.starts_with(callee) || callee.starts_with(own_callee))
                })
            })
        };
        // Its own checks are a different policy unless every peer in its
        // resource, sibling resources or namespace makes the skipped check,
        // and most of them make each of the route's checks too: then the
        // route does what they all do minus one check. Where only most
        // peers make it, the ones that do not show the check is optional.
        let own_policy = |scope: &str, total: usize, having: &[usize]| {
            let narrow = scope == place.namespace || scope.starts_with(&format!("{}/", place.namespace));
            !own_checks.is_empty()
                && (!narrow
                    || having.len() < total
                    || own_checks.iter().any(|check| {
                        2 * having
                            .iter()
                            .filter(|&&other| featured[other].uses.contains(*check))
                            .count()
                            < having.len()
                    }))
        };
        let mut skipped: Vec<(String, (String, usize, Vec<usize>))> = decided
            .into_iter()
            .filter(
                |(feature, (scope, total, having))| match feature.strip_prefix("takes:") {
                    // A route that names a scheme none of those peers use
                    // (`AdminApiAuth`, `NoAuth`) authenticates differently on
                    // purpose; its scheme yields no caller to take.
                    Some(label) => {
                        own.takes.is_empty()
                            && !own_identity(label)
                            && !requires_what_peers_allow(route, label)
                            && label != UNKNOWN_TYPE
                            && !own.schemes.iter().any(|scheme| {
                                having
                                    .iter()
                                    .all(|&other| !featured[other].schemes.contains(scheme))
                            })
                    }
                    // A route that makes checks of its own with the caller, only
                    // not all of its peers' checks, is a different policy more
                    // often than a forgotten one; a route that makes none has
                    // ignored the caller.
                    // A reading of a field is too weak to set aside the
                    // route's own checks; a call to a variant of the check
                    // (`validate_x_or_init` for `validate_x`) makes it.
                    None => {
                        !own.uses.contains(feature)
                            && (own_checks.is_empty()
                                || (!own_policy(scope, *total, having)
                                    && feature.starts_with("checks:")
                                    // Calling a method of the caller
                                    // (`acts:`) alone says too little of
                                    // what the route checks.
                                    && own_checks.iter().any(|check| !check.starts_with("acts:"))
                                    && !makes_variant(feature)))
                    }
                },
            )
            .collect();
        if skipped.is_empty() {
            continue;
        }
        // Strongest consensus first, then the most specific kind of check
        // (a comparison with data before a call, before taking the caller,
        // before a field read), then the most peers.
        skipped.sort_by(
            |(a_feature, (_, a_total, a_having)), (b_feature, (_, b_total, b_having))| {
                let a_share = a_having.len() as f64 / *a_total as f64;
                let b_share = b_having.len() as f64 / *b_total as f64;
                b_share
                    .partial_cmp(&a_share)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(specificity(a_feature).cmp(&specificity(b_feature)))
                    .then(b_having.len().cmp(&a_having.len()))
                    .then(a_feature.cmp(b_feature))
            },
        );
        let (top_feature, (top_scope, top_total, top_having)) = &skipped[0];
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut group_routes: Vec<RouteReference> = vec![(*route).into()];
        group_routes.extend(top_having.iter().map(|&other| eligible[other].into()));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!(
                "{} routes under {top_scope} compared on how they use the caller",
                place.class
            ),
            prefix: top_scope.clone(),
            level: GroupLevel::Linked,
            method_class: place.class,
            routes: group_routes,
        });
        let named: Vec<String> = skipped
            .iter()
            .take(NAMED)
            .map(|(feature, (scope, total, having))| {
                format!(
                    "{} of {total} under {scope} {}",
                    having.len(),
                    describe(feature)
                )
            })
            .collect();
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "{} routes under {top_scope} that take the caller {}.",
                place.class,
                describe(top_feature)
            ),
            total_routes: top_total + 1,
            routes_with_authorization: top_having.len(),
            routes_without_authorization: top_total - top_having.len() + 1,
            evidence_patterns: skipped
                .iter()
                .take(NAMED)
                .map(|(feature, _)| feature.clone())
                .collect(),
            strength: AuthStrength::Medium,
            expected_tier: None,
            dominant_requirement: Some(top_feature.clone()),
        };
        invariants.push(invariant.clone());
        // A route that gets the caller from an identity source those peers
        // do not call (a login step's `auth_finish(&req, ..)`) may
        // establish it by a different means.
        let own_source: Option<&String> = own.calls.iter().find(|source| {
            top_having
                .iter()
                .all(|&other| !featured[other].calls.contains(*source))
        });
        // Where one of those peers makes the check, so the finding can be
        // verified: the call chain from its handler to the check call.
        let example = top_having.iter().find_map(|&other| {
            featured[other].sites.get(top_feature).map(|site| {
                format!(
                    " For example, {} {} makes it as {site}.",
                    eligible[other].method, eligible[other].path
                )
            })
        });
        let rationale = format!(
            "Its {} peers make a check with the caller that this route does not: {}.{}{} Dismiss if the difference is intended.",
            place.class,
            named.join("; "),
            example.unwrap_or_default(),
            own_source
                .map(|source| format!(" It gets the caller through `{source}` instead, which they do not call."))
                .unwrap_or_default()
        );
        // A field the peers read and this route does not is a lead, not a
        // skipped check, unless a call or comparison backs it.
        // So is a consensus of the whole application, which pools routes
        // that were never meant to be alike, and a route whose own
        // protection Archer cannot evaluate.
        let app_wide = skipped
            .iter()
            .all(|(_, (scope, _, _))| scope == APPLICATION);
        // Unknown protection the peers share (CORS, metrics middleware)
        // says nothing about this difference.
        let unknown = route.authorization.iter().any(|evidence| {
            evidence.kind == AuthEvidenceKind::Unknown
                && !top_having.iter().all(|&other| {
                    eligible[other].authorization.iter().any(|theirs| {
                        theirs.kind == evidence.kind && theirs.mechanism == evidence.mechanism
                    })
                })
        });
        // P13: a write that takes no caller at all, where the writes of
        // the whole application take one almost without exception (at
        // least 10, and 95% of them): the consensus is too wide and too
        // even to be an accident of pooling. The same exception the
        // whole-app tier comparison makes for writes (`at_level`). A
        // handler that takes the raw request, a header, a cookie or a
        // session can authenticate the caller by itself (a signed webhook
        // or federation inbox), so it stays Low.
        let everyone_takes = super::p13::enabled("APPWIDE")
            && app_wide
            && !route.origin.sees_request
            && place.class == MethodClass::Write
            && route.best_tier() == EvidenceTier::None
            && top_feature.starts_with("takes:")
            && top_having.len() >= 10
            && top_having.len() as f64 >= 0.95 * *top_total as f64;
        let severity = if everyone_takes && !unknown && own_source.is_none() {
            Severity::Medium
        } else if app_wide
            || unknown
            || own_source.is_some()
            || skipped
                .iter()
                .all(|(feature, _)| feature.starts_with("reads:"))
        {
            Severity::Low
        } else {
            Severity::Medium
        };
        finding_details.push(Finding {
            peer_group_id: id,
            category: FindingCategory::SkipsPeerCheck,
            severity,
            rationale,
            invariant,
            suspicious_route: (*route).into(),
            suspicious_route_tier: route.best_tier(),
            expected_tier: route.best_tier(),
            suspicious_route_evidence: route.authorization.clone(),
            evidence: FindingEvidence {
                check: format!("{} routes under {top_scope} {}", place.class, describe(top_feature)),
                supporting: top_having.len(),
                compared: *top_total,
                peers: top_having
                    .iter()
                    .take(super::explain::PEERS_SHOWN)
                    .map(|&other| PeerCheck {
                        method: eligible[other].method.clone(),
                        path: eligible[other].path.clone(),
                        check: featured[other]
                            .sites
                            .get(top_feature)
                            .cloned()
                            .unwrap_or_else(|| describe(top_feature)),
                        file: eligible[other].file.clone(),
                        line: eligible[other].line,
                    })
                    .collect(),
                ..Default::default()
            },
            authorized_peer_routes: top_having
                .iter()
                .map(|&other| eligible[other].into())
                .collect(),
        });
    }
    for index in granted {
        let route = eligible[index];
        if finding_details
            .iter()
            .any(|finding| finding.suspicious_route.method == route.method && finding.suspicious_route.path == route.path)
        {
            continue;
        }
        if let Some(finding) = same_grant(route, &featured[index], index, &featured, &eligible, peer_groups, invariants) {
            finding_details.push(finding);
        }
    }
    drop_superseded_unverified(finding_details);
}

/// A finding that says only that the route has protection Archer cannot
/// verify.
fn is_unverified_only(finding: &Finding) -> bool {
    finding.category == FindingCategory::UnverifiedProtection && finding.severity == Severity::Low
}

/// Drops an unverified-only finding for a route that has another one.
pub(crate) fn drop_superseded_unverified(finding_details: &mut Vec<Finding>) {
    let key = |finding: &Finding| {
        let route = &finding.suspicious_route;
        (route.method.clone(), route.path.clone(), route.handler.clone())
    };
    let other: HashSet<_> = finding_details
        .iter()
        .filter(|finding| !is_unverified_only(finding))
        .map(key)
        .collect();
    finding_details.retain(|finding| !is_unverified_only(finding) || !other.contains(&key(finding)));
}

/// A path template's segments, with each parameter written `{}` and its
/// name alongside: `/u/{user}/c/{cal}` → (`["u", "{}", "c", "{}"]`,
/// `[None, Some("user"), None, Some("cal")]`).
fn template(path: &str) -> (Vec<String>, Vec<Option<String>>) {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.strip_prefix('{').and_then(|inner| inner.strip_suffix('}')) {
            Some(inner) => ("{}".to_string(), Some(inner.split(':').next().unwrap_or(inner).to_string())),
            None => (segment.to_string(), None),
        })
        .unzip()
}

/// Whether a route holds the request value `name` to the caller: it binds
/// it in its code, or passes an authentication object scoped to it.
fn binds(route: &Route, features: &Features, kind: &str, name: &str) -> bool {
    features.binds.contains(&format!("{kind}:{name}"))
        // The whole path value, on a template with that one parameter.
        || (kind == "path"
            && features.binds.contains("path:")
            && matches!(template(&route.path).1.iter().flatten().collect::<Vec<_>>().as_slice(), [only] if *only == name))
        || route
            .authorization
            .iter()
            .any(|evidence| evidence.requirements.iter().any(|key| key == &format!("scope:{name}")))
}

/// The path-parameter binding check (`caller_use::BINDS`): routes that
/// take a parameter at the same place in the same template hold it to the
/// caller (`auth.user_id != principal`), and this route does not. Peers of
/// any method count, since binding a principal or tenant does not depend
/// on the method. In order:
/// - at least 3 routes share the template prefix up to the parameter and
///   at least 75% of them bind it: Medium;
/// - every other route on the exact template binds it, 2 or more: Medium;
/// - one other route on the exact template binds it: Low;
/// - the route whose template ends at the parameter (`/x/{p}`) binds it and
///   this route under it does not: Low, however many routes under it skip.
///   When several methods share that template, more than half of them must
///   bind it.
///
/// Low instead of Medium when the route checks a role or permission (the
/// binding may be how callers without it get in) or names a scheme none of
/// the binders name.
///
/// Not reported: a route with a role or permission check where the binding
/// routes have none, a route that loads with the caller, and a route that
/// never passes its path to a call, or one whose middleware names the
/// parameter. A
/// route that passes an authentication object gives
/// way to `auth_objects::unscoped_objects`, which names that object.
#[allow(clippy::too_many_arguments)]
fn unbound_parameter(
    route: &Route,
    own: &Features,
    index: usize,
    featured: &[Features],
    eligible: &[&Route],
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
) -> Option<Finding> {
    if !super::caller_use::rule_on("R2") {
        return None;
    }
    if own.guards.values().flatten().any(|how| how == SCOPED_LOAD) {
        return None;
    }
    // A handler that never hands its path parameters to a call acts on
    // nothing they name (a page that only shows the id in a form).
    let reads_path = own.mentions.iter().any(|mention| mention.starts_with("path:"));
    let (shape, names) = template(&route.path);
    let templates: Vec<(Vec<String>, Vec<Option<String>>)> = eligible.iter().map(|other| template(&other.path)).collect();
    for (position, name) in names.iter().enumerate() {
        let Some(name) = name else {
            continue;
        };
        if binds(route, own, "path", name) || !reads_path || middleware_names(route, name) {
            continue;
        }
        let prefix = &shape[..=position];
        let population: Vec<usize> = (0..eligible.len())
            .filter(|&other| {
                other != index
                    && route_identity(eligible[other]) != route_identity(route)
                    && eligible[other].origin.definition != route.origin.definition
                    && templates[other].0.len() > position
                    && templates[other].0[..=position] == *prefix
            })
            .collect();
        let binding = |other: usize| {
            templates[other].1[position]
                .as_ref()
                .is_some_and(|theirs| binds(eligible[other], &featured[other], "path", theirs))
        };
        let having: Vec<usize> = population.iter().copied().filter(|&other| binding(other)).collect();
        if having.is_empty() {
            continue;
        }
        if route.best_tier() == EvidenceTier::Privilege
            && having.iter().all(|&other| eligible[other].best_tier() != EvidenceTier::Privilege)
        {
            continue;
        }
        let same: Vec<usize> = population.iter().copied().filter(|&other| templates[other].0 == shape).collect();
        let same_binding = same.iter().filter(|&&other| binding(other)).count();
        let owners: Vec<usize> = having
            .iter()
            .copied()
            .filter(|&other| templates[other].0.len() == position + 1)
            .collect();
        // The owner template must bind it on most of its methods, or which
        // route is "the owner" is a matter of which handler the walker could
        // follow.
        let owner_routes = population
            .iter()
            .filter(|&&other| templates[other].0.len() == position + 1)
            .count();
        let owners: Vec<usize> = if 2 * owners.len() > owner_routes { owners } else { Vec::new() };
        let share = having.len() as f64 / population.len() as f64;
        let (severity, why) = if population.len() >= MIN_POPULATION && share + 1e-9 >= CONSENSUS {
            (
                Severity::Medium,
                format!("{} of {} routes that take `{{{name}}}` at this place hold it to the caller", having.len(), population.len()),
            )
        } else if same.len() >= 2 && same_binding == same.len() {
            (Severity::Medium, format!("every other route on this template ({}) holds `{{{name}}}` to the caller", same.len()))
        } else if same_binding >= 1 && 2 * same_binding >= same.len() {
            (Severity::Low, format!("{same_binding} of {} other routes on this template hold `{{{name}}}` to the caller", same.len()))
        } else if !owners.is_empty() && shape.len() > position + 1 {
            let under = population
                .iter()
                .filter(|&&other| templates[other].0.len() > position + 1 && !binding(other))
                .count()
                + 1;
            (
                Severity::Low,
                format!("the route that names `{{{name}}}` holds it to the caller; {under} route(s) under it do not"),
            )
        } else {
            continue;
        };
        let having: Vec<usize> = if severity == Severity::Low && !owners.is_empty() && same_binding == 0 {
            owners
        } else {
            having
        };
        // A role or permission check beside binders that also check one: the
        // binding may be the way in for callers without the role.
        let elevated = route.best_tier() == EvidenceTier::Privilege;
        let severity = if other_scheme(own, &having, featured) || elevated { Severity::Low } else { severity };
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut group_routes: Vec<RouteReference> = vec![route.into()];
        group_routes.extend(having.iter().map(|&other| eligible[other].into()));
        let at = format!("/{}", prefix.join("/"));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!("routes that take a path parameter at {at}"),
            prefix: at.clone(),
            level: GroupLevel::Linked,
            method_class: MethodClass::of(&route.method),
            routes: group_routes,
        });
        let feature = format!("{BINDS}path:{name}");
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!("Routes that take the parameter at {at} hold it to the caller."),
            total_routes: population.len() + 1,
            routes_with_authorization: having.len(),
            routes_without_authorization: population.len() + 1 - having.len(),
            evidence_patterns: vec![feature.clone()],
            strength: AuthStrength::Medium,
            expected_tier: Some(EvidenceTier::Resource),
            dominant_requirement: Some(feature),
        };
        invariants.push(invariant.clone());
        let listed: Vec<String> = having
            .iter()
            .take(NAMED)
            .map(|&other| format!("{} {}", eligible[other].method, eligible[other].path))
            .collect();
        return Some(Finding {
            peer_group_id: id,
            category: FindingCategory::SkipsPeerCheck,
            severity,
            rationale: format!(
                "Takes `{{{name}}}` from the path but never holds it to the caller, where {why} ({}). Dismiss if the difference is intended.",
                listed.join(", ")
            ),
            invariant,
            suspicious_route: route.into(),
            suspicious_route_tier: route.best_tier(),
            expected_tier: EvidenceTier::Resource,
            suspicious_route_evidence: route.authorization.clone(),
            evidence: FindingEvidence {
                check: format!("holds the path parameter at {at} to the caller"),
                supporting: having.len(),
                compared: population.len(),
                peers: having
                    .iter()
                    .take(super::explain::PEERS_SHOWN)
                    .map(|&other| PeerCheck {
                        method: eligible[other].method.clone(),
                        path: eligible[other].path.clone(),
                        check: format!(
                            "holds `{{{}}}` to the caller",
                            templates[other].1[position].as_deref().unwrap_or(name)
                        ),
                        file: eligible[other].file.clone(),
                        line: eligible[other].line,
                    })
                    .collect(),
                ..Default::default()
            },
            authorized_peer_routes: having.iter().map(|&other| eligible[other].into()).collect(),
        });
    }
    // The same binding through the body or query: routes of the namespace
    // hold path parameter `{p}` to the caller, and this route reads a body
    // or query field `p` it never holds to the caller.
    let place = placement(route);
    for mention in &own.mentions {
        let Some(name) = mention.strip_prefix("body:") else {
            continue;
        };
        if binds(route, own, "body", name)
            || binds(route, own, "path", name)
            || names.iter().flatten().any(|own_name| own_name == name)
            || !names_one_entity(name, &templates)
        {
            continue;
        }
        let having: Vec<usize> = (0..eligible.len())
            .filter(|&other| {
                other != index
                    && eligible[other].origin.definition != route.origin.definition
                    && templates[other].1.iter().flatten().any(|theirs| theirs == name)
                    && binds(eligible[other], &featured[other], "path", name)
            })
            .collect();
        if having.is_empty() {
            continue;
        }
        if route.best_tier() == EvidenceTier::Privilege
            && having.iter().all(|&other| eligible[other].best_tier() != EvidenceTier::Privilege)
        {
            continue;
        }
        // Peers across the application are a lead; three in its own
        // namespace are a pattern.
        let near = having
            .iter()
            .filter(|&&other| placement(eligible[other]).namespace == place.namespace)
            .count();
        let severity = if near >= MIN_POPULATION
            && !other_scheme(own, &having, featured)
            && route.best_tier() != EvidenceTier::Privilege
        {
            Severity::Medium
        } else {
            Severity::Low
        };
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut group_routes: Vec<RouteReference> = vec![route.into()];
        group_routes.extend(having.iter().map(|&other| eligible[other].into()));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!("routes that hold `{{{name}}}` to the caller"),
            prefix: place.namespace.clone(),
            level: GroupLevel::Linked,
            method_class: MethodClass::of(&route.method),
            routes: group_routes,
        });
        let feature = format!("{BINDS}body:{name}");
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!("Routes that take `{{{name}}}` hold it to the caller."),
            total_routes: having.len() + 1,
            routes_with_authorization: having.len(),
            routes_without_authorization: 1,
            evidence_patterns: vec![feature.clone()],
            strength: AuthStrength::Medium,
            expected_tier: Some(EvidenceTier::Resource),
            dominant_requirement: Some(feature),
        };
        invariants.push(invariant.clone());
        let listed: Vec<String> = having
            .iter()
            .take(NAMED)
            .map(|&other| format!("{} {}", eligible[other].method, eligible[other].path))
            .collect();
        return Some(Finding {
            peer_group_id: id,
            category: FindingCategory::SkipsPeerCheck,
            severity,
            rationale: format!(
                "Reads `{name}` from the request body or query and never holds it to the caller, where {} route(s) that take `{{{name}}}` in the path do, {near} of them under {} ({}). Dismiss if the difference is intended.",
                having.len(),
                place.namespace,
                listed.join(", ")
            ),
            invariant,
            suspicious_route: route.into(),
            suspicious_route_tier: route.best_tier(),
            expected_tier: EvidenceTier::Resource,
            suspicious_route_evidence: route.authorization.clone(),
            evidence: FindingEvidence {
                check: format!("holds `{name}` to the caller"),
                supporting: having.len(),
                compared: having.len(),
                peers: having
                    .iter()
                    .take(super::explain::PEERS_SHOWN)
                    .map(|&other| PeerCheck {
                        method: eligible[other].method.clone(),
                        path: eligible[other].path.clone(),
                        check: format!("holds `{{{name}}}` to the caller"),
                        file: eligible[other].file.clone(),
                        line: eligible[other].line,
                    })
                    .collect(),
                ..Default::default()
            },
            authorized_peer_routes: having.iter().map(|&other| eligible[other].into()).collect(),
        });
    }
    None
}

/// Middleware or a guard on the route (evidence outside the handler) that
/// names the parameter: it may hold it to the caller before the handler
/// runs, which this check cannot see.
fn middleware_names(route: &Route, name: &str) -> bool {
    route.authorization.iter().any(|evidence| {
        evidence.handler.is_none()
            && (evidence.mechanism.contains(&format!("`{name}`"))
                || evidence.mechanism.contains(&format!("\"{name}\""))
                || evidence.requirements.iter().any(|key| key == name))
    })
}

/// The route names an authentication scheme that none of the given peers
/// name (an operator key beside user sessions): another policy more often
/// than a forgotten check.
fn other_scheme(own: &Features, having: &[usize], featured: &[Features]) -> bool {
    !own.schemes.is_empty()
        && having
            .iter()
            .all(|&other| featured[other].schemes.is_disjoint(&own.schemes))
}

/// A parameter name that stands for one kind of entity in the application:
/// wherever a template takes `{p}`, at least 75% of them name the same
/// static segment before it (`business_profile/{profile_id}`), unlike a
/// generic `{id}` under users, clients and groups alike.
fn names_one_entity(name: &str, templates: &[(Vec<String>, Vec<Option<String>>)]) -> bool {
    let mut before: BTreeMap<&str, usize> = BTreeMap::new();
    let mut total = 0;
    for (shape, names) in templates {
        for (position, found) in names.iter().enumerate() {
            if found.as_deref() == Some(name) {
                total += 1;
                let previous = shape[..position].iter().rev().find(|segment| *segment != "{}");
                *before.entry(previous.map_or("", String::as_str)).or_default() += 1;
            }
        }
    }
    total > 0 && before.values().max().is_some_and(|&most| most as f64 / total as f64 + 1e-9 >= CONSENSUS)
}

/// How a route holds a loaded record, by kind: a secret the request
/// presents, a field compared with the caller, or a named check function
/// given the record and the caller. A load scoped to the caller is no
/// guard kind: it scopes, it does not check.
fn guard_kinds(features: &Features) -> BTreeSet<String> {
    features
        .guards
        .values()
        .flatten()
        .filter_map(|how| {
            if how.contains("secret the request presents") {
                Some("a secret the request presents".to_string())
            } else if how.starts_with("compares ") {
                Some("a field compared with the caller".to_string())
            } else {
                how.strip_prefix("checks it with `").map(|rest| format!("`{}`", rest.trim_end_matches('`')))
            }
        })
        .collect()
}

/// The mechanism invariant: among the routes that admit authentication
/// scheme `T` and load a record with request data, at least 3, of which at
/// least 75% hold some loaded record by the same kind of guard (see
/// `guard_kinds`), whatever the record. A route that admits `T`, loads a
/// record and has no guard of that kind is reported. Medium with at least
/// 5 such peers and a secret or field comparison; otherwise Low.
#[allow(clippy::too_many_arguments)]
fn mechanism_guard(
    route: &Route,
    own: &Features,
    index: usize,
    featured: &[Features],
    eligible: &[&Route],
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
) -> Option<Finding> {
    if !super::caller_use::rule_on("R3") || own.loads.is_empty() {
        return None;
    }
    let mine = guard_kinds(own);
    let mut best: Option<(String, String, Vec<usize>, usize)> = None;
    for scheme in own.schemes.iter().filter(|scheme| !admits_anyone(scheme)) {
        let population: Vec<usize> = (0..eligible.len())
            .filter(|&other| {
                other != index
                    && route_identity(eligible[other]) != route_identity(route)
                    && eligible[other].origin.definition != route.origin.definition
                    && featured[other].schemes.contains(scheme)
                    && !featured[other].loads.is_empty()
            })
            .collect();
        if population.len() < MIN_POPULATION {
            continue;
        }
        let kinds: Vec<BTreeSet<String>> = population.iter().map(|&other| guard_kinds(&featured[other])).collect();
        let mut counted: BTreeMap<&String, usize> = BTreeMap::new();
        for found in &kinds {
            for kind in found {
                *counted.entry(kind).or_default() += 1;
            }
        }
        for (kind, count) in counted {
            if mine.contains(kind) || (count as f64) / (population.len() as f64) + 1e-9 < CONSENSUS {
                continue;
            }
            let having: Vec<usize> = population
                .iter()
                .zip(&kinds)
                .filter(|(_, found)| found.contains(kind))
                .map(|(&other, _)| other)
                .collect();
            if best.as_ref().is_none_or(|(_, _, theirs, _)| having.len() > theirs.len()) {
                best = Some((scheme.clone(), kind.clone(), having, population.len()));
            }
        }
    }
    let (scheme, kind, having, total) = best?;
    if route.best_tier() == EvidenceTier::Privilege
        && having.iter().all(|&other| eligible[other].best_tier() != EvidenceTier::Privilege)
    {
        return None;
    }
    let severity = if having.len() >= 5
        && (kind.starts_with("a secret") || kind.starts_with("a field"))
        && !other_scheme(own, &having, featured)
    {
        Severity::Medium
    } else {
        Severity::Low
    };
    let id = format!("peer-group-{:03}", peer_groups.len() + 1);
    let mut group_routes: Vec<RouteReference> = vec![route.into()];
    group_routes.extend(having.iter().map(|&other| eligible[other].into()));
    peer_groups.push(PeerGroup {
        id: id.clone(),
        description: format!("routes that admit `{scheme}` and load a record with request data"),
        prefix: format!("scheme `{scheme}`"),
        level: GroupLevel::Linked,
        method_class: MethodClass::of(&route.method),
        routes: group_routes,
    });
    let feature = format!("{GUARDS}{kind}");
    let invariant = AuthorizationInvariant {
        peer_group_id: id.clone(),
        description: format!("Routes that admit `{scheme}` and load a record hold it by {kind}."),
        total_routes: total + 1,
        routes_with_authorization: having.len(),
        routes_without_authorization: total + 1 - having.len(),
        evidence_patterns: vec![feature.clone()],
        strength: AuthStrength::Medium,
        expected_tier: Some(EvidenceTier::Resource),
        dominant_requirement: Some(feature),
    };
    invariants.push(invariant.clone());
    let listed: Vec<String> = having
        .iter()
        .take(NAMED)
        .map(|&other| format!("{} {}", eligible[other].method, eligible[other].path))
        .collect();
    Some(Finding {
        peer_group_id: id,
        category: FindingCategory::SkipsPeerCheck,
        severity,
        rationale: format!(
            "Admits `{scheme}` and loads a record with request data, but never holds a loaded record by {kind}, where {} of {total} routes that admit `{scheme}` and load records do ({}). Dismiss if the difference is intended.",
            having.len(),
            listed.join(", ")
        ),
        invariant,
        suspicious_route: route.into(),
        suspicious_route_tier: route.best_tier(),
        expected_tier: EvidenceTier::Resource,
        suspicious_route_evidence: route.authorization.clone(),
        evidence: FindingEvidence {
            check: format!("holds a loaded record by {kind}"),
            supporting: having.len(),
            compared: total,
            peers: having
                .iter()
                .take(super::explain::PEERS_SHOWN)
                .map(|&other| PeerCheck {
                    method: eligible[other].method.clone(),
                    path: eligible[other].path.clone(),
                    check: featured[other]
                        .guards
                        .iter()
                        .find_map(|(key, ways)| ways.first().map(|how| format!("`{key}`: {how}")))
                        .unwrap_or_default(),
                    file: eligible[other].file.clone(),
                    line: eligible[other].line,
                })
                .collect(),
            ..Default::default()
        },
        authorized_peer_routes: having.iter().map(|&other| eligible[other].into()).collect(),
    })
}

/// The grant, the caller field `(label, field)`, the peers reading it and
/// the population size.
type GrantSupport = (String, (String, String), Vec<usize>, usize);

/// A create on a collection (`POST /notes`) has no record yet: an item
/// route beneath it (`/notes/{id}`) that holds a record it loads to the
/// caller makes an object-level check the create cannot make.
fn acts_on_existing_record(route: &Route, own: &Features, other: &Route, theirs: &Features) -> bool {
    super::public::rule_on("S3")
        && route.method == "POST"
        && !route.path.ends_with('}')
        && other.path.starts_with(&format!("{}/{{", route.path.trim_end_matches('/')))
        && theirs.guards.keys().any(|key| !own.loads.contains(key))
}

/// The caller's fields a route reads, by identity label: `team` for
/// `reads:AccountUser:team`.
fn caller_reads(features: &Features) -> BTreeSet<(&str, &str)> {
    features
        .uses
        .iter()
        .filter_map(|feature| feature.strip_prefix("reads:")?.split_once(':'))
        .filter(|(label, _)| *label != UNKNOWN_TYPE)
        .collect()
}

/// The grant invariant: routes that build their auth object with the same
/// constant (`Grant::NotesRead`) are granted the same
/// operation, and read the same part of the caller to scope it. Among at
/// least 3 other routes with that grant, of any method, at least 75% read
/// the caller's field `f`; a route with the grant and the same caller type
/// that never reads `f` is reported. Only fields named like an entity of
/// the application's own templates count (`team` beside `{team_id}`).
/// Peers come from the same API version root (`/v2/..` apart from
/// unversioned routes), whose callers can differ in shape. It runs after
/// the other checks, for routes none of them reported.
/// Medium with at least 5 such peers,
/// unless the route names a scheme none of them name; otherwise Low.
#[allow(clippy::too_many_arguments)]
fn same_grant(
    route: &Route,
    own: &Features,
    index: usize,
    featured: &[Features],
    eligible: &[&Route],
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
) -> Option<Finding> {
    if !super::caller_use::rule_on("R5") || own.grants.is_empty() {
        return None;
    }
    let mine = caller_reads(own);
    // A field that names an entity of the application's own templates
    // (`team` beside `{team_id}`): the part of the caller that scopes.
    let entities: BTreeSet<String> = eligible
        .iter()
        .flat_map(|other| path_parameters(&other.path))
        .collect();
    let scopes = |field: &str| {
        entities.contains(field) || entities.contains(&format!("{field}_id")) || entities.contains(&format!("{field}Id"))
    };
    let labels: BTreeSet<&str> = own.takes.iter().map(String::as_str).chain(mine.iter().map(|(label, _)| *label)).collect();
    let mut best: Option<GrantSupport> = None;
    let version = placement(route).version;
    for grant in &own.grants {
        let population: Vec<usize> = (0..eligible.len())
            .filter(|&other| {
                other != index
                    && placement(eligible[other]).version == version
                    && route_identity(eligible[other]) != route_identity(route)
                    && eligible[other].origin.definition != route.origin.definition
                    && featured[other].grants.contains(grant)
                    && !acts_on_existing_record(route, own, eligible[other], &featured[other])
            })
            .collect();
        if population.len() < MIN_POPULATION {
            continue;
        }
        let reads: Vec<BTreeSet<(&str, &str)>> = population.iter().map(|&other| caller_reads(&featured[other])).collect();
        let mut counted: BTreeMap<(&str, &str), usize> = BTreeMap::new();
        for found in &reads {
            for read in found {
                *counted.entry(*read).or_default() += 1;
            }
        }
        for (read, count) in counted {
            if mine.contains(&read)
                || !labels.contains(read.0)
                || !scopes(read.1)
                || (count as f64) / (population.len() as f64) + 1e-9 < CONSENSUS
            {
                continue;
            }
            let having: Vec<usize> = population
                .iter()
                .zip(&reads)
                .filter(|(_, found)| found.contains(&read))
                .map(|(&other, _)| other)
                .collect();
            if best.as_ref().is_none_or(|(_, _, theirs, _)| having.len() > theirs.len()) {
                best = Some((grant.clone(), (read.0.to_string(), read.1.to_string()), having, population.len()));
            }
        }
    }
    let (grant, (label, field), having, total) = best?;
    let severity = if having.len() >= 5 && !other_scheme(own, &having, featured) {
        Severity::Medium
    } else {
        Severity::Low
    };
    let id = format!("peer-group-{:03}", peer_groups.len() + 1);
    let mut group_routes: Vec<RouteReference> = vec![route.into()];
    group_routes.extend(having.iter().map(|&other| eligible[other].into()));
    peer_groups.push(PeerGroup {
        id: id.clone(),
        description: format!("routes whose auth object is built with `{grant}`"),
        prefix: format!("grant `{grant}`"),
        level: GroupLevel::Linked,
        method_class: MethodClass::of(&route.method),
        routes: group_routes,
    });
    let feature = format!("reads:{label}:{field}");
    let invariant = AuthorizationInvariant {
        peer_group_id: id.clone(),
        description: format!("Routes granted `{grant}` read the caller's `{field}`."),
        total_routes: total + 1,
        routes_with_authorization: having.len(),
        routes_without_authorization: total + 1 - having.len(),
        evidence_patterns: vec![feature.clone()],
        strength: AuthStrength::Medium,
        expected_tier: Some(EvidenceTier::Resource),
        dominant_requirement: Some(feature),
    };
    invariants.push(invariant.clone());
    let listed: Vec<String> = having
        .iter()
        .take(NAMED)
        .map(|&other| format!("{} {}", eligible[other].method, eligible[other].path))
        .collect();
    Some(Finding {
        peer_group_id: id,
        category: FindingCategory::SkipsPeerCheck,
        severity,
        rationale: format!(
            "Builds its auth object with `{grant}` but never reads the caller's `{field}`, where {} of {total} routes granted `{grant}` do ({}); routes granted the same operation usually scope it by the same part of the caller. Dismiss if the difference is intended.",
            having.len(),
            listed.join(", ")
        ),
        invariant,
        suspicious_route: route.into(),
        suspicious_route_tier: route.best_tier(),
        expected_tier: EvidenceTier::Resource,
        suspicious_route_evidence: route.authorization.clone(),
        evidence: FindingEvidence {
            check: format!("reads the caller's `{field}`"),
            supporting: having.len(),
            compared: total,
            peers: having
                .iter()
                .take(super::explain::PEERS_SHOWN)
                .map(|&other| PeerCheck {
                    method: eligible[other].method.clone(),
                    path: eligible[other].path.clone(),
                    check: format!("reads `{label}.{field}`"),
                    file: eligible[other].file.clone(),
                    line: eligible[other].line,
                })
                .collect(),
            ..Default::default()
        },
        authorized_peer_routes: having.iter().map(|&other| eligible[other].into()).collect(),
    })
}
