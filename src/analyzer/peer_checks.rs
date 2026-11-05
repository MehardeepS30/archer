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
    caller_use::UNKNOWN_TYPE,
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
fn compared(feature: &str) -> String {
    match feature.strip_prefix("checks:") {
        Some(rest) => match rest.rsplit_once(':') {
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
    for feature in &route.caller_use {
        if let Some(label) = feature.strip_prefix("takes:") {
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
    }
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
    let reported: HashSet<_> = finding_details
        .iter()
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

        // Every feature some peer has, decided at its narrowest level.
        let mut decided: BTreeMap<String, (String, usize, Vec<usize>)> = BTreeMap::new();
        let mut undecidable: HashSet<String> = HashSet::new();
        for (scope, members, minimum) in &levels {
            // Peers that could have a use feature take an identity the
            // route also takes; `takes:` is open to every peer.
            let sharing: Vec<usize> = members
                .iter()
                .copied()
                .filter(|&other| !featured[other].takes.is_disjoint(&own.takes))
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
            route.authorization.iter().any(|evidence| {
                !matches!(
                    evidence.kind,
                    AuthEvidenceKind::Delegated | AuthEvidenceKind::Unknown
                ) && EvidenceTier::of(&evidence.kind) >= EvidenceTier::Identity
                    && !(evidence.kind == AuthEvidenceKind::IdentityExtraction
                        && evidence.mechanism.contains(base))
            })
        };
        let makes_checks = own.uses.iter().any(|feature| {
            feature.starts_with("checks:")
                || feature.starts_with("compares:")
                || feature.starts_with("acts:")
        });
        let mut skipped: Vec<(String, (String, usize, Vec<usize>))> = decided
            .into_iter()
            .filter(
                |(feature, (_, _, having))| match feature.strip_prefix("takes:") {
                    // A route that names a scheme none of those peers use
                    // (`AdminApiAuth`, `NoAuth`) authenticates differently on
                    // purpose; its scheme yields no caller to take.
                    Some(label) => {
                        own.takes.is_empty()
                            && !own_identity(label)
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
                    None => !own.uses.contains(feature) && !makes_checks,
                },
            )
            .collect();
        if skipped.is_empty() {
            continue;
        }
        // Strongest consensus first, then the most specific feature.
        skipped.sort_by(
            |(a_feature, (_, a_total, a_having)), (b_feature, (_, b_total, b_having))| {
                let a_share = a_having.len() as f64 / *a_total as f64;
                let b_share = b_having.len() as f64 / *b_total as f64;
                b_share
                    .partial_cmp(&a_share)
                    .unwrap_or(std::cmp::Ordering::Equal)
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
        let rationale = format!(
            "Its {} peers make a check with the caller that this route does not: {}. Dismiss if the difference is intended.",
            place.class,
            named.join("; ")
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
        let severity = if app_wide
            || unknown
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
            authorized_peer_routes: top_having
                .iter()
                .map(|&other| eligible[other].into())
                .collect(),
        });
    }
}
