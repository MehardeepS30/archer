//! Peer grouping, invariant inference, and drift findings.

use std::collections::{HashMap, HashSet};

use super::{model::*, routes::has_unresolved_inner_segment as has_unresolved_segment};

/// Analysis layers with default options.
#[cfg(test)]
pub(crate) fn build_analysis_layers(
    routes: &[Route],
) -> (
    Vec<PeerGroup>,
    Vec<AuthorizationInvariant>,
    Vec<Finding>,
    Vec<String>,
) {
    build_analysis_layers_with(routes, &AnalysisOptions::default())
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_analysis_layers_with(
    routes: &[Route],
    options: &AnalysisOptions,
) -> (
    Vec<PeerGroup>,
    Vec<AuthorizationInvariant>,
    Vec<Finding>,
    Vec<String>,
) {
    let (groups, invariants, details, findings, _) = build_analysis_layers_full(routes, options);
    (groups, invariants, details, findings)
}

/// A route to judge: its index, its group, for a write the reads it is held
/// to, the levels passed over, and whether it is compared as the class its
/// handler acts as rather than its method's.
type Judged = (usize, GroupKey, Option<GroupKey>, Vec<String>, bool);

/// The analysis layers, and every route that no comparison judged, with why.
pub(crate) fn build_analysis_layers_full(
    routes: &[Route],
    options: &AnalysisOptions,
) -> (
    Vec<PeerGroup>,
    Vec<AuthorizationInvariant>,
    Vec<Finding>,
    Vec<String>,
    Vec<UnjudgedRoute>,
) {
    let mut unjudged: Vec<UnjudgedRoute> = Vec::new();
    let mut seen_identities = HashSet::new();
    for route in routes {
        if !seen_identities.insert(route_identity(route)) {
            continue;
        }
        let reason = if is_authentication_route(route) {
            Some(UnjudgedReason::AuthenticationEndpoint)
        } else if is_well_known_public_route(route) {
            Some(UnjudgedReason::WellKnownPublic)
        } else if has_unresolved_segment(&route.path) {
            Some(UnjudgedReason::UnresolvedPath)
        } else {
            None
        };
        if let Some(reason) = reason {
            unjudged.push(UnjudgedRoute::new(route, reason, String::new()));
        }
    }
    let mut pending: Vec<(&Route, UnjudgedReason, String)> = Vec::new();
    let candidates: Vec<&Route> = unique_routes(routes.iter().filter(|route| {
        !is_authentication_route(route)
            && !is_well_known_public_route(route)
            && !has_unresolved_segment(&route.path)
    }));
    let placed: Vec<Placement> = candidates.iter().map(|route| placement(route)).collect();

    // Routes of each (level, prefix, class), in order of first appearance.
    let mut members: HashMap<GroupKey, Vec<usize>> = HashMap::new();
    for (index, place) in placed.iter().enumerate() {
        for key in [
            place.key(GroupLevel::Resource),
            place.key(GroupLevel::Namespace),
        ]
        .into_iter()
        .chain(place.subtrees().map(|prefix| place.subtree_key(prefix)))
        .chain(place.fallbacks())
        {
            members.entry(key).or_default().push(index);
        }
    }
    let class_size = |key: &GroupKey| members.get(key).map_or(0, Vec::len);

    let mut stats: HashMap<GroupKey, GroupStats> = HashMap::new();
    let mut order: Vec<GroupKey> = Vec::new();
    let mut judged: Vec<Judged> = Vec::new();
    let compute = |key: &GroupKey| {
        let indices: Vec<usize> = members.get(key).cloned().unwrap_or_default();
        let peers: Vec<&Route> = indices.iter().map(|&member| candidates[member]).collect();
        // Across a namespace, each resource counts once: a resource
        // with many routes must not outvote its single-route siblings.
        let weights: Vec<f64> = indices
            .iter()
            .map(|&member| match key.level {
                GroupLevel::Resource | GroupLevel::Handler | GroupLevel::Linked => 1.0,
                GroupLevel::Namespace
                | GroupLevel::Subtree
                | GroupLevel::Version
                | GroupLevel::App => {
                    1.0 / class_size(&placed[member].key(GroupLevel::Resource)).max(1) as f64
                }
            })
            .collect();
        GroupStats::of(peers, weights, options)
    };
    for (index, place) in placed.iter().enumerate() {
        // A route whose handler acts against its method (a POST that only
        // queries, a GET that writes) is held to the class it acts as, when
        // that class has routes to hold it to; it still counts among the
        // routes of its method's class as a peer.
        let (acts_as, class_reason) = route_class_with_reason(candidates[index]);
        let as_other = Placement {
            class: acts_as,
            ..place.clone()
        };
        let switched = acts_as != place.class
            && comparison_key(&as_other, &class_size).is_some_and(|key| class_size(&key) >= 2);
        let place = if switched { &as_other } else { place };
        // The levels tried before the one chosen, with why each was passed
        // over; they go into the finding or the unjudged reason.
        let mut trail: Vec<String> = Vec::new();
        if switched && let Some(reason) = &class_reason {
            trail.push(format!("compared as a {acts_as}: {reason}"));
        }
        let resource_key = place.key(GroupLevel::Resource);
        let first = comparison_key(place, &class_size);
        if first.as_ref() != Some(&resource_key) {
            trail.push(format!(
                "resource {}: {} {} route(s)",
                resource_key.prefix,
                class_size(&resource_key),
                place.class
            ));
        }
        let holds_reads = |key: &GroupKey| {
            place.class == MethodClass::Write
                && class_size(&GroupKey {
                    class: MethodClass::Read,
                    ..key.clone()
                }) >= 2
        };
        let first = match first {
            // A lone write is still held to the reads beside it.
            Some(key) if class_size(&key) >= 2 || holds_reads(&key) => Some(key),
            Some(key) => {
                trail.push(format!(
                    "{} {}: no other {} route",
                    key.level.label(),
                    key.prefix,
                    place.class
                ));
                None
            }
            None => None,
        };
        // No scope the route is in holds a peer: fall back to its API
        // version root, then to the whole app.
        let first = first.or_else(|| {
            place.fallbacks().find(|key| {
                let size = class_size(key);
                if size < 2 {
                    trail.push(format!(
                        "{} {}: no other {} route",
                        key.level.label(),
                        key.prefix,
                        place.class
                    ));
                }
                size >= 2
            })
        });
        let Some(mut own) = first else {
            pending.push((
                candidates[index],
                UnjudgedReason::NoPeers,
                format!(
                    "no other {} route anywhere in the app (tried {})",
                    place.class,
                    trail.join("; ")
                ),
            ));
            continue;
        };
        // A resource whose few routes disagree (one authenticated, one not)
        // cannot say what it expects. Its namespace can: hold the route to
        // the wider group instead. A resource whose routes all lack auth
        // agrees that it is public and keeps its own verdict.
        // The same holds above: a namespace whose routes disagree, below
        // the support threshold, defers to the enclosing scope tree, then
        // the API version root, then the whole app.
        loop {
            let undecided = {
                let group = stats.entry(own.clone()).or_insert_with(|| compute(&own));
                let protected = group
                    .peers
                    .iter()
                    .filter(|peer| peer.best_tier() > EvidenceTier::None)
                    .count();
                let undecided = group.expected.is_none() && protected > 0;
                if undecided && group.peers.len() < 2 {
                    trail.push(format!(
                        "{} {}: its only {} route",
                        own.level.label(),
                        own.prefix,
                        own.class
                    ));
                } else if undecided {
                    trail.push(format!(
                        "{} {}: {protected} of {} {} routes protected, no pattern reaches support",
                        own.level.label(),
                        own.prefix,
                        group.peers.len(),
                        own.class
                    ));
                }
                undecided
            };
            if !undecided {
                break;
            }
            let next = match own.level {
                GroupLevel::Resource => wider_key(place, &class_size)
                    .filter(|key| class_size(key) >= 2)
                    .or_else(|| fallback_key(place, &own, &class_size)),
                GroupLevel::Namespace | GroupLevel::Subtree => {
                    parent_key(place, &own, &class_size)
                        .or_else(|| fallback_key(place, &own, &class_size))
                }
                GroupLevel::Version => fallback_key(place, &own, &class_size),
                GroupLevel::Handler | GroupLevel::Linked | GroupLevel::App => None,
            };
            match next {
                Some(next) if next != own => own = next,
                _ => break,
            }
        }
        // Separate top-level scopes of one app often serve different
        // callers by design (`/public` beside `/admin`), so the whole-app
        // group only judges root-level routes. Any other route that
        // reaches it is listed with the app-wide pattern for review.
        // A flat app's root-level routes (`/about`, `/users`, no scope
        // around them) form one root group: they are judged there.
        let root_level = place.namespace == "/"
            || (path_segments(without_mount_prefix(&candidates[index].scope_prefix)).is_empty()
                && path_segments(without_mount_prefix(&candidates[index].path)).len() == 1);
        if own.level == GroupLevel::App && !root_level {
            let group = stats.entry(own.clone()).or_insert_with(|| compute(&own));
            let protected = group
                .peers
                .iter()
                .filter(|peer| peer.best_tier() > EvidenceTier::None)
                .count();
            // Peers that disagree below support, or none at all.
            let disagree = trail
                .iter()
                .any(|step| !step.starts_with("whole app") && step.contains("routes protected"));
            pending.push((
                candidates[index],
                if disagree {
                    UnjudgedReason::BelowSupport
                } else {
                    UnjudgedReason::NoPeers
                },
                format!(
                    "{} under {} or a scope above it; the whole app ({protected} of {} {} routes protected) is not used for a route inside a top-level scope, since separate scopes often serve different callers (tried {})",
                    if disagree {
                        format!("no group of {} routes reaches a verdict", place.class)
                    } else {
                        format!("no other {} route", place.class)
                    },
                    place.namespace,
                    group.peers.len(),
                    place.class,
                    trail.join("; ")
                ),
            ));
            continue;
        }
        let reads = (place.class == MethodClass::Write).then(|| GroupKey {
            class: MethodClass::Read,
            ..own.clone()
        });
        for key in std::iter::once(&own).chain(reads.as_ref()) {
            let group = stats.entry(key.clone()).or_insert_with(|| compute(key));
            // Every group of two or more is formed, an unprotected one too
            // (tier None, public by design).
            if !order.contains(key) && group.peers.len() >= 2 {
                order.push(key.clone());
            }
        }
        let by_behaviour = switched
            && class_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("whose handler"));
        judged.push((index, own, reads, trail, by_behaviour));
    }

    let mut peer_groups = Vec::new();
    let mut invariants = Vec::new();
    let mut ids: HashMap<&GroupKey, String> = HashMap::new();
    for (position, key) in order.iter().enumerate() {
        let id = format!("peer-group-{:03}", position + 1);
        let group = &stats[key];
        let unprotected = group
            .peers
            .iter()
            .all(|peer| peer.best_tier() == EvidenceTier::None);
        // Routes whose protection Archer could not evaluate (an unknown
        // middleware, a path rule it could not decide) are not "public".
        let unevaluated = group
            .peers
            .iter()
            .filter(|peer| {
                peer.authorization.iter().any(|evidence| {
                    evidence.kind == AuthEvidenceKind::Unknown
                        || (evidence.kind == AuthEvidenceKind::Delegated
                            && evidence.mechanism.contains("checks the caller"))
                })
            })
            .count();
        let note = if !unprotected {
            String::new()
        } else if unevaluated > 0 {
            format!(
                " (no recognised protection, tier None; {unevaluated} of {} routes carry protection Archer cannot evaluate)",
                group.peers.len()
            )
        } else if key.class == MethodClass::Write {
            " (no route carries protection, tier None; it holds writes, so check that they are meant to be public)".to_string()
        } else {
            " (no route carries protection, tier None)".to_string()
        };
        let description = format!("{} routes of {} {}{note}", key.class, key.level.label(), key.prefix);
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description,
            prefix: key.prefix.clone(),
            level: key.level,
            method_class: key.class,
            routes: group.peers.iter().map(|route| (*route).into()).collect(),
        });
        invariants.push(group.invariant(&id, key));
        ids.insert(key, id);
    }

    let mut finding_details = Vec::new();
    // Findings from a fallback level, kept until every narrower check has
    // had its say: a route another check reports is reported by that one.
    let mut fallback_details: Vec<Finding> = Vec::new();
    for (index, own, reads, trail, switched) in judged {
        let tried = if trail.is_empty() {
            String::new()
        } else {
            format!(" (grouping: {})", trail.join("; "))
        };
        let route = candidates[index];
        // The groups this route is held to: its own class, and for a write
        // the reads of the same resource. Writes are never less protected.
        // Across a whole namespace, reads say less about an unrelated
        // resource's writes; they are only held to reads that require a
        // privilege (an `/admin` namespace), not to merely authenticated
        // reads, where public writes such as webhooks are common.
        let entries: Vec<(&GroupStats, &GroupKey, &String)> = std::iter::once(&own)
            .chain(reads.as_ref())
            .filter_map(|key| ids.get(key).map(|id| (&stats[key], key, id)))
            .filter(|(group, key, _)| {
                key.class == own.class
                    || (key.level == GroupLevel::Resource && targets_record(route))
                    || (group.expected == Some(EvidenceTier::Privilege)
                        && own_undecided(&stats, &own))
            })
            .collect();
        let Some(&(basis, basis_key, basis_id)) = entries.iter().max_by_key(|(group, key, _)| {
            (
                group.expected,
                std::cmp::Reverse(key.class != MethodClass::of(&route.method)),
            )
        }) else {
            let group = &stats[&own];
            let (reason, detail) = if group.peers.len() < 2 {
                (
                    UnjudgedReason::NoPeers,
                    format!("the only {} route under {}{tried}", own.class, own.prefix),
                )
            } else {
                (
                    UnjudgedReason::PeersUnprotected,
                    format!(
                        "none of its {} {} peers under {} carries protection; read as public by design{tried}",
                        group.peers.len() - 1,
                        own.class,
                        own.prefix
                    ),
                )
            };
            pending.push((route, reason, detail));
            continue;
        };
        let Some(mut expected) = basis.expected else {
            let protected = basis
                .peers
                .iter()
                .filter(|peer| peer.best_tier() > EvidenceTier::None)
                .count();
            // An unprotected group judges its routes: none is expected to
            // carry protection, and none falls short.
            if protected == 0 {
                continue;
            }
            pending.push((
                route,
                UnjudgedReason::BelowSupport,
                format!(
                    "{protected} of {} {} routes under {} carry protection, below the {} routes and {:.0}% a pattern needs{tried}",
                    basis.peers.len(),
                    basis_key.class,
                    basis_key.prefix,
                    options.min_support,
                    options.dominance_threshold * 100.0
                ),
            ));
            continue;
        };
        // Ownership is checked against the record a route serves, so it is
        // expected only of the routes of one resource. Across a namespace
        // (`/admin/password`, `/admin/logout`), peers' ownership checks say
        // that their callers are identified, not that every route has a
        // record to own.
        if expected == EvidenceTier::Resource && basis_key.level != GroupLevel::Resource {
            expected = EvidenceTier::Identity;
        }
        // A create (`POST /messages`) makes the record its caller will own;
        // there is nothing to own yet. Peers' ownership checks on edits and
        // deletes say only that the caller must be identified.
        if expected == EvidenceTier::Resource
            && route.method == "POST"
            && !basis.peers.iter().any(|peer| {
                peer.method == "POST"
                    && peer.best_tier() >= EvidenceTier::Resource
                    // An action on one record beneath the collection
                    // (`POST /boards/{id}/archive`) is not another create.
                    && !(super::public::rule_on("S3")
                        && !route.path.ends_with('}')
                        && peer.path.starts_with(&format!("{}/{{", route.path.trim_end_matches('/'))))
            })
        {
            expected = EvidenceTier::Identity;
        }
        let tier = route.best_tier();
        let category = if tier < expected {
            if unverified_beyond_peers(route, basis, expected) {
                FindingCategory::UnverifiedProtection
            } else {
                match (expected, tier) {
                    (EvidenceTier::Identity, _) => FindingCategory::MissingAuthentication,
                    (_, EvidenceTier::None | EvidenceTier::Identity) => {
                        FindingCategory::MissingAuthorization
                    }
                    _ => FindingCategory::WeakerAuthorization,
                }
            }
        } else if expected == EvidenceTier::Privilege && tier == EvidenceTier::Privilege {
            // Compare the role sets, not just the tier.
            let requirement = Requirement::of(route);
            let mismatch = entries.iter().copied().find_map(|(group, key, id)| {
                role_mismatch(route, &requirement, group, options).map(|category| (category, group, key, id))
            });
            let Some((category, group, key, id)) = mismatch else {
                continue;
            };
            let mut reported = finding(route, category, expected, group, key, id, options);
            if category == FindingCategory::WeakerAuthorization {
                let mut extra: Vec<String> = refused_roles(route, &requirement, group, options);
                if extra.is_empty() {
                    extra = requirement.roles.iter().filter(|role| !group.dominant_roles.contains(role)).cloned().collect();
                }
                let extra: Vec<String> = extra.iter().map(|role| format!("`{role}`")).collect();
                reported.rationale = format!(
                    "Admits any of {} where its {} peers under {} admit only {}; it also lets in {}.",
                    requirement.roles.iter().map(|role| format!("`{role}`")).collect::<Vec<_>>().join(", "),
                    key.class,
                    key.prefix,
                    group.dominant_roles.iter().map(|role| format!("`{role}`")).collect::<Vec<_>>().join(", "),
                    extra.join(", "),
                );
            } else if category == FindingCategory::DifferentAuthorization
                && is_allow_list(route, &requirement)
                && peers_allow_lists(route, group)
            {
                // Two allow-lists, neither containing the other: some callers
                // each admits the other refuses. No direction, so Low.
                let list = |roles: &[String]| roles.iter().map(|role| format!("`{role}`")).collect::<Vec<_>>().join(", ");
                let extra: Vec<String> = refused_roles(route, &requirement, group, options);
                reported.severity = Severity::Low;
                reported.rationale = format!(
                    "Admits {} where its {} peers under {} admit {}: it lets in {} they refuse, and refuses some they admit. Neither allow-list contains the other; check which is intended.",
                    list(&requirement.roles),
                    key.class,
                    key.prefix,
                    list(&group.dominant_roles),
                    list(&extra),
                );
            }
            let reported = at_level(reported, key, &tried, switched);
            if key.level.is_fallback() {
                fallback_details.push(reported);
            } else {
                finding_details.push(reported);
            }
            continue;
        } else {
            continue;
        };
        let reported = at_level(
            finding(route, category, expected, basis, basis_key, basis_id, options),
            basis_key,
            &tried,
            switched,
        );
        if basis_key.level.is_fallback() {
            fallback_details.push(reported);
        } else {
            finding_details.push(reported);
        }
    }
    inconsistent_registrations(routes, &mut peer_groups, &mut invariants, &mut finding_details);
    writes_below_resource(&candidates, &mut peer_groups, &mut invariants, &mut finding_details);
    let linked = same_resource_weaker(routes, &mut peer_groups, &mut invariants, &mut finding_details, options);
    super::peer_checks::skipped_peer_checks(routes, &mut peer_groups, &mut invariants, &mut finding_details);
    super::auth_objects::unscoped_objects(routes, &mut peer_groups, &mut invariants, &mut finding_details);
    super::roles::delete_admits_more(routes, &mut peer_groups, &mut invariants, &mut finding_details);
    per_route_permissions(routes, &mut finding_details);
    for fallback in fallback_details {
        let route = &fallback.suspicious_route;
        if !finding_details.iter().any(|finding| {
            finding.suspicious_route.method == route.method
                && finding.suspicious_route.path == route.path
                && finding.suspicious_route.handler == route.handler
        }) {
            finding_details.push(fallback);
        }
    }
    // A route its groups could not judge falls back to the routes linked to
    // it by data; if those judged it, it is not left unjudged.
    let reported: HashSet<_> = finding_details
        .iter()
        .map(|finding| {
            let route = &finding.suspicious_route;
            (route.method.clone(), route.path.clone(), route.handler.clone())
        })
        .collect();
    for (route, reason, detail) in pending {
        let identity = (route.method.clone(), route.path.clone(), route.handler.clone());
        if reported.contains(&identity) || linked.contains(&identity) {
            continue;
        }
        unjudged.push(UnjudgedRoute::new(
            route,
            reason,
            format!("{detail}; no routes are linked to it by shared data"),
        ));
    }
    let findings = finding_details.iter().map(format_finding).collect();
    (peer_groups, invariants, finding_details, findings, unjudged)
}

/// A write on a resource's collection or record that requires less than
/// every other route of that resource, its reads included:
/// `POST /org/api_key` open to any logged-in user beside an admin-only
/// `GET /org/api_key` and `DELETE /org/api_key/{id}`. The class-split
/// groups miss it when the resource has too few routes of each class to
/// reach support. Every other route must agree (at least two, one of them
/// a read), so a resource with mixed protection says nothing.
fn writes_below_resource(
    candidates: &[&Route],
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
    finding_details: &mut Vec<Finding>,
) {
    let reported: HashSet<(String, String, Option<String>)> = finding_details
        .iter()
        .map(|finding| {
            let route = &finding.suspicious_route;
            (route.method.clone(), route.path.clone(), route.handler.clone())
        })
        .collect();
    let on_record: Vec<(&Route, String)> = candidates
        .iter()
        .copied()
        .filter(|route| targets_record(route))
        .map(|route| (route, placement(route).resource))
        .collect();
    for (route, resource) in &on_record {
        if route_class(route) != MethodClass::Write
            || reported.contains(&(route.method.clone(), route.path.clone(), route.handler.clone()))
        {
            continue;
        }
        let peers: Vec<&Route> = on_record
            .iter()
            .filter(|(other, theirs)| {
                theirs == resource && route_identity(other) != route_identity(route)
            })
            .map(|(other, _)| *other)
            .collect();
        if peers.len() < 2
            || !peers
                .iter()
                .any(|peer| MethodClass::of(&peer.method) == MethodClass::Read)
        {
            continue;
        }
        let tier = route.best_tier();
        let Some(mut expected) = peers.iter().map(|peer| peer.best_tier()).min() else {
            continue;
        };
        // A create makes the record its caller will own: nothing to own yet.
        if expected == EvidenceTier::Resource && route.method == "POST" {
            expected = EvidenceTier::Identity;
        }
        if expected <= tier {
            continue;
        }
        // Protection Archer cannot evaluate, which the peers do not share,
        // may close the gap: review, not a finding.
        let unverified = !route.unverified.is_empty()
            || route.authorization.iter().any(|evidence| {
                matches!(evidence.kind, AuthEvidenceKind::Unknown | AuthEvidenceKind::Delegated)
                    && !peers.iter().all(|peer| {
                        peer.authorization.iter().any(|theirs| {
                            theirs.kind == evidence.kind && theirs.mechanism == evidence.mechanism
                        })
                    })
            });
        let (category, severity) = if unverified {
            (FindingCategory::UnverifiedProtection, Severity::Low)
        } else {
            match (expected, tier) {
                (EvidenceTier::Identity, _) => (FindingCategory::MissingAuthentication, Severity::High),
                (EvidenceTier::Privilege, EvidenceTier::None | EvidenceTier::Identity) => {
                    (FindingCategory::MissingAuthorization, Severity::High)
                }
                (_, EvidenceTier::None | EvidenceTier::Identity) => {
                    (FindingCategory::MissingAuthorization, Severity::Medium)
                }
                _ => (FindingCategory::WeakerAuthorization, Severity::Medium),
            }
        };
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut members: Vec<RouteReference> = vec![(*route).into()];
        members.extend(peers.iter().map(|peer| (*peer).into()));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!("routes of resource {resource}, reads and writes"),
            prefix: resource.clone(),
            level: GroupLevel::Resource,
            method_class: MethodClass::Write,
            routes: members,
        });
        let listed = peers
            .iter()
            .map(|peer| format!("{} {} ({})", peer.method, peer.path, peer.best_tier()))
            .collect::<Vec<_>>()
            .join(", ");
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "Every other route of resource {resource} requires at least {expected}."
            ),
            total_routes: peers.len() + 1,
            routes_with_authorization: peers.iter().filter(|peer| peer.is_authorized()).count()
                + usize::from(route.is_authorized()),
            routes_without_authorization: peers.iter().filter(|peer| !peer.is_authorized()).count()
                + usize::from(!route.is_authorized()),
            evidence_patterns: Vec::new(),
            strength: AuthStrength::Medium,
            expected_tier: Some(expected),
            dominant_requirement: None,
        };
        invariants.push(invariant.clone());
        let mut rationale = format!(
            "Best evidence is {tier}, while every other route of {resource}, its reads included, reaches at least {expected}: {listed}. A write is rarely less protected than the reads of the same data."
        );
        if unverified {
            rationale.push_str(" It has protection Archer cannot verify. Review manually.");
        }
        finding_details.push(Finding {
            peer_group_id: id,
            category,
            severity,
            rationale,
            invariant,
            suspicious_route: (*route).into(),
            suspicious_route_tier: tier,
            expected_tier: expected,
            suspicious_route_evidence: route.authorization.clone(),
            evidence: Default::default(),
            authorized_peer_routes: peers.iter().map(|peer| (*peer).into()).collect(),
        });
    }
}

/// Fewest distinct permissions a mechanism must name across the application,
/// and the largest number of routes per permission, before it is read as
/// assigning one permission per operation.
const PER_ROUTE_PERMISSIONS: usize = 5;
const ROUTES_PER_PERMISSION: f64 = 3.0;

/// Lowers a different-requirement finding to Low when the application gives
/// each operation its own permission through the same mechanism
/// (`ActionPolicy<{ actions::DOCUMENTS_DELETE }>` next to `DOCUMENTS_ADD`):
/// there, a route naming another permission than its peers is the design,
/// and the permissions cannot be ranked against each other.
fn per_route_permissions(routes: &[Route], findings: &mut [Finding]) {
    let mut named: HashMap<&str, (HashSet<&str>, HashSet<(&str, &str)>)> = HashMap::new();
    for route in routes {
        for evidence in &route.authorization {
            if evidence.kind != AuthEvidenceKind::PermissionCheck || evidence.requirements.is_empty() {
                continue;
            }
            let (permissions, users) = named.entry(evidence.mechanism.as_str()).or_default();
            permissions.extend(evidence.requirements.iter().map(String::as_str));
            users.insert((route.method.as_str(), route.path.as_str()));
        }
    }
    for finding in findings {
        if finding.category != FindingCategory::DifferentAuthorization {
            continue;
        }
        let scheme = finding.suspicious_route_evidence.iter().find_map(|evidence| {
            let (permissions, users) = named.get(evidence.mechanism.as_str())?;
            (evidence.kind == AuthEvidenceKind::PermissionCheck
                && permissions.len() >= PER_ROUTE_PERMISSIONS
                && users.len() as f64 <= permissions.len() as f64 * ROUTES_PER_PERMISSION)
                .then(|| (evidence.mechanism.clone(), permissions.len(), users.len()))
        });
        if let Some((mechanism, permissions, users)) = scheme {
            finding.severity = Severity::Low;
            finding.rationale.push_str(&format!(
                " `{mechanism}` names {permissions} different permissions across {users} routes, so permissions look assigned per operation; check that this one is the intended permission."
            ));
        }
    }
}

/// One handler definition registered for the same method at several paths,
/// where one registration lacks guards or middleware that another carries:
/// `POST /newsletters` at the root next to `POST /admin/newsletters` inside
/// an authenticated scope. The handler's own evidence is the same in both,
/// so the difference is exactly what the scopes add. This needs no peer
/// group, so it also covers routes at the root, which are never grouped.
fn inconsistent_registrations(
    routes: &[Route],
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
    finding_details: &mut Vec<Finding>,
) {
    let key = |evidence: &AuthEvidence| {
        (
            format!("{:?}", evidence.kind),
            evidence.mechanism.clone(),
            evidence.file.clone(),
            evidence.line,
        )
    };
    let mut by_handler: Vec<((usize, &str), Vec<&Route>)> = Vec::new();
    for route in unique_routes(routes.iter().filter(|route| {
        !has_unresolved_segment(&route.path)
            && !is_authentication_route(route)
            && !is_well_known_public_route(route)
    })) {
        let Some(definition) = route.origin.definition else {
            continue;
        };
        let id = (definition, route.method.as_str());
        match by_handler.iter_mut().find(|(existing, _)| *existing == id) {
            Some((_, registered)) => registered.push(route),
            None => by_handler.push((id, vec![route])),
        }
    }
    for (_, registrations) in by_handler {
        let paths: HashSet<&str> = registrations.iter().map(|route| route.path.as_str()).collect();
        if paths.len() < 2 {
            continue;
        }
        for route in &registrations {
            let own: HashSet<_> = route.authorization.iter().map(key).collect();
            // The best other registration whose protection strictly includes
            // this one's and adds a recognized authentication or
            // authorization layer (an unknown component alone is not enough).
            let Some((stronger, missing)) = registrations
                .iter()
                .filter(|other| other.path != route.path)
                .filter_map(|other| {
                    let theirs: HashSet<_> = other.authorization.iter().map(key).collect();
                    if !own.is_subset(&theirs) {
                        return None;
                    }
                    let missing: Vec<&AuthEvidence> = other
                        .authorization
                        .iter()
                        .filter(|evidence| !own.contains(&key(evidence)))
                        .collect();
                    missing
                        .iter()
                        .any(|evidence| EvidenceTier::of(&evidence.kind) > EvidenceTier::None)
                        .then_some((*other, missing))
                })
                .max_by_key(|(other, _)| other.best_tier())
            else {
                continue;
            };
            let id = format!("peer-group-{:03}", peer_groups.len() + 1);
            let handler = route.handler.as_deref().unwrap_or("?");
            let mechanisms: Vec<String> = missing
                .iter()
                .map(|evidence| format!("`{}`", evidence.mechanism))
                .collect();
            peer_groups.push(PeerGroup {
                id: id.clone(),
                description: format!("{} registrations of handler {handler}", route.method),
                prefix: stronger.path.clone(),
                level: GroupLevel::Handler,
                method_class: MethodClass::of(&route.method),
                routes: registrations.iter().map(|route| (*route).into()).collect(),
            });
            let invariant = AuthorizationInvariant {
                peer_group_id: id.clone(),
                description: format!(
                    "Every registration of `{handler}` carries {}.",
                    mechanisms.join(", ")
                ),
                total_routes: registrations.len(),
                routes_with_authorization: registrations
                    .iter()
                    .filter(|route| route.is_authorized())
                    .count(),
                routes_without_authorization: registrations
                    .iter()
                    .filter(|route| !route.is_authorized())
                    .count(),
                evidence_patterns: mechanisms.clone(),
                strength: AuthStrength::Strong,
                expected_tier: Some(stronger.best_tier()),
                dominant_requirement: None,
            };
            let severity = if missing.iter().any(|evidence| {
                EvidenceTier::of(&evidence.kind) >= EvidenceTier::Identity
                    && evidence.symbol.as_deref().is_some_and(|symbol| {
                        symbol.starts_with(".wrap") || symbol.starts_with(".guard")
                    })
            }) || missing.iter().any(|evidence| evidence.is_authorization())
            {
                Severity::High
            } else {
                Severity::Medium
            };
            invariants.push(invariant.clone());
            finding_details.push(Finding {
                peer_group_id: id,
                category: FindingCategory::InconsistentRegistration,
                severity,
                rationale: format!(
                    "`{handler}` is also registered at {} {} behind {}, which this registration lacks.",
                    stronger.method,
                    stronger.path,
                    mechanisms.join(", ")
                ),
                invariant,
                suspicious_route: (*route).into(),
                suspicious_route_tier: route.best_tier(),
                expected_tier: stronger.best_tier(),
                suspicious_route_evidence: route.authorization.clone(),
                evidence: Default::default(),
                authorized_peer_routes: vec![stronger.into()],
            });
        }
    }
}

/// What `stronger` requires of a caller that `route` does not: a login, a
/// role, or an ownership check. A route that checks ownership is not held to
/// a linked route's role (owners reach their own records, admins every
/// record), and a route with a role is not held to ownership.
fn stronger_fields(route: &Requirement, stronger: &Requirement, same_handler: bool) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if stronger.authenticated && !route.authenticated {
        fields.push("a logged-in caller");
    }
    // Administrative routes act on everyone's records by design, so a role
    // carries over only between registrations of one handler.
    if same_handler && !stronger.roles.is_empty() && route.roles.is_empty() && !route.ownership {
        fields.push("a role");
    }
    if stronger.ownership && !route.ownership && route.roles.is_empty() && !route.relation {
        fields.push("an ownership check");
    }
    fields
}

/// How strongly two routes are linked: `usize::MAX` for one handler, else
/// the number of repository functions and model types both take request
/// data into. A single shared function or type (an error constructor, a
/// converter) is too weak a link to compare on, so it counts as none.
pub(crate) fn link_strength(route: &Route, other: &Route) -> usize {
    let shared: Vec<&String> = route
        .resource_keys
        .iter()
        .filter(|key| other.resource_keys.contains(key))
        .collect();
    if shared.iter().any(|key| key.starts_with("handler ")) {
        return usize::MAX;
    }
    if shared.len() >= 2 { shared.len() } else { 0 }
}

/// Routes that serve the same data as routes requiring more of the caller,
/// whatever their paths: the resource-link comparison. A route is reported
/// when a dominant share of the routes linked to it, of its method class,
/// require something it lacks. Routes already reported by peer groups are
/// left alone.
fn same_resource_weaker(
    routes: &[Route],
    peer_groups: &mut Vec<PeerGroup>,
    invariants: &mut Vec<AuthorizationInvariant>,
    finding_details: &mut Vec<Finding>,
    options: &AnalysisOptions,
) -> HashSet<(String, String, Option<String>)> {
    let mut compared = HashSet::new();
    let eligible: Vec<&Route> = unique_routes(routes.iter().filter(|route| {
        !route.resource_keys.is_empty()
            && !has_unresolved_segment(&route.path)
            && !is_authentication_route(route)
            && !is_well_known_public_route(route)
    }));
    let reported: HashSet<_> = finding_details
        .iter()
        .map(|finding| {
            let route = &finding.suspicious_route;
            (route.method.clone(), route.path.clone(), route.handler.clone())
        })
        .collect();
    for route in &eligible {
        if reported.contains(&(route.method.clone(), route.path.clone(), route.handler.clone())) {
            continue;
        }
        let class = MethodClass::of(&route.method);
        let linked: Vec<&Route> = eligible
            .iter()
            .copied()
            .filter(|other| {
                route_identity(other) != route_identity(route)
                    && MethodClass::of(&other.method) == class
                    && other.path != route.path
                    && link_strength(route, other) > 0
            })
            .collect();
        if linked.is_empty() {
            continue;
        }
        compared.insert((route.method.clone(), route.path.clone(), route.handler.clone()));
        let requirement = Requirement::of(route);
        let stronger: Vec<(&Route, Vec<&'static str>)> = linked
            .iter()
            .map(|other| {
                let same_handler = link_strength(route, other) == usize::MAX;
                (*other, stronger_fields(&requirement, &Requirement::of(other), same_handler))
            })
            .filter(|(_, fields)| !fields.is_empty())
            .collect();
        // Pairwise, one stronger link is support enough; the share must
        // still dominate the route's links.
        let share = stronger.len() as f64 / linked.len() as f64;
        if stronger.is_empty() || share + 1e-9 < options.dominance_threshold {
            continue;
        }
        let mut fields: Vec<&str> = stronger.iter().flat_map(|(_, fields)| fields.iter().copied()).collect();
        fields.sort();
        fields.dedup();
        let shared: Vec<String> = route
            .resource_keys
            .iter()
            .filter(|key| stronger.iter().any(|(other, _)| other.resource_keys.contains(key)))
            .cloned()
            .collect();
        // Protection that cannot be evaluated and that the stronger routes
        // do not share may close the gap: review, not a finding.
        let unverified_own = !route.unverified.is_empty()
            || route.authorization.iter().any(|evidence| {
                matches!(evidence.kind, AuthEvidenceKind::Unknown | AuthEvidenceKind::Delegated)
                    && !stronger.iter().all(|(other, _)| {
                        other.authorization.iter().any(|theirs| {
                            theirs.kind == evidence.kind && theirs.mechanism == evidence.mechanism
                        })
                    })
            });
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut members: Vec<RouteReference> = vec![(*route).into()];
        members.extend(linked.iter().map(|other| (*other).into()));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!("{class} routes linked to {} {} by {}", route.method, route.path, shared.join(", ")),
            prefix: route.path.clone(),
            level: GroupLevel::Linked,
            method_class: class,
            routes: members,
        });
        let expected = stronger
            .iter()
            .map(|(other, _)| other.best_tier())
            .max()
            .unwrap_or(EvidenceTier::Identity);
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "Routes serving the same data ({}) require {}.",
                shared.join(", "),
                fields.join(" and ")
            ),
            total_routes: linked.len() + 1,
            routes_with_authorization: linked.iter().filter(|other| other.is_authorized()).count()
                + usize::from(route.is_authorized()),
            routes_without_authorization: linked.iter().filter(|other| !other.is_authorized()).count()
                + usize::from(!route.is_authorized()),
            evidence_patterns: fields.iter().map(|field| field.to_string()).collect(),
            strength: AuthStrength::Medium,
            expected_tier: Some(expected),
            dominant_requirement: None,
        };
        invariants.push(invariant.clone());
        let (category, severity, rationale) = if unverified_own {
            (
                FindingCategory::UnverifiedProtection,
                Severity::Low,
                format!(
                    "Serves the same data as {} ({}), which require {}; it has protection Archer cannot verify. Review manually.",
                    stronger.iter().map(|(other, _)| format!("{} {}", other.method, other.path)).collect::<Vec<_>>().join(", "),
                    shared.join(", "),
                    fields.join(" and ")
                ),
            )
        } else {
            (
                FindingCategory::SameResourceWeakerProtection,
                Severity::Medium,
                format!(
                    "Serves the same data as {} ({}), which require {} that this route lacks.",
                    stronger.iter().map(|(other, _)| format!("{} {}", other.method, other.path)).collect::<Vec<_>>().join(", "),
                    shared.join(", "),
                    fields.join(" and ")
                ),
            )
        };
        finding_details.push(Finding {
            peer_group_id: id,
            category,
            severity,
            rationale,
            invariant,
            suspicious_route: (*route).into(),
            suspicious_route_tier: route.best_tier(),
            expected_tier: expected,
            suspicious_route_evidence: route.authorization.clone(),
            evidence: Default::default(),
            authorized_peer_routes: stronger.iter().map(|(other, _)| (*other).into()).collect(),
        });
    }
    compared
}

#[cfg(test)]
pub(crate) fn infer_prototype_drift(routes: &[Route]) -> Vec<String> {
    build_analysis_layers(routes).3
}

/// Where a route sits: its namespace (declared scope, or leading segments),
/// its resource within the namespace, and its method class.
#[derive(Debug, Clone)]
pub(crate) struct Placement {
    pub(crate) namespace: String,
    pub(crate) resource: String,
    pub(crate) class: MethodClass,
    /// The route's leading generic segments (`/api/v1`), if any.
    pub(crate) version: Option<String>,
}

impl Placement {
    pub(crate) fn key(&self, level: GroupLevel) -> GroupKey {
        GroupKey {
            level,
            prefix: match level {
                GroupLevel::Resource => self.resource.clone(),
                GroupLevel::Namespace
                | GroupLevel::Subtree
                | GroupLevel::Handler
                | GroupLevel::Linked
                | GroupLevel::Version
                | GroupLevel::App => {
                    self.namespace.clone()
                }
            },
            class: self.class,
        }
    }

    fn subtree_key(&self, prefix: String) -> GroupKey {
        GroupKey {
            level: GroupLevel::Subtree,
            prefix,
            class: self.class,
        }
    }

    /// The namespace and its enclosing prefixes, nearest first, that can
    /// head a scope tree: not the root, and not only generic segments
    /// (`/api/v4`), which would pool a whole API.
    pub(crate) fn subtrees(&self) -> impl Iterator<Item = String> + use<> {
        let segments: Vec<&str> = self
            .namespace
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        let prefixes: Vec<String> = (1..=segments.len())
            .rev()
            .filter(|&length| {
                segments[..length]
                    .iter()
                    .any(|segment| !is_generic_segment(segment) && !is_dynamic_segment(segment))
            })
            .map(|length| format!("/{}", segments[..length].join("/")))
            .collect();
        prefixes.into_iter()
    }
}

impl Placement {
    /// The last-resort groups, nearest first: the route's API version root
    /// (`/api/v1`, its leading generic segments) when that is wider than its
    /// namespace, then the whole app.
    pub(crate) fn fallbacks(&self) -> impl Iterator<Item = GroupKey> + use<> {
        let mut keys = Vec::new();
        if let Some(version) = &self.version
            && *version != self.namespace
        {
            keys.push(GroupKey {
                level: GroupLevel::Version,
                prefix: version.clone(),
                class: self.class,
            });
        }
        keys.push(GroupKey {
            level: GroupLevel::App,
            prefix: "/".into(),
            class: self.class,
        });
        keys.into_iter()
    }
}

/// The next fallback above `own` with more routes of its class.
fn fallback_key(
    place: &Placement,
    own: &GroupKey,
    class_size: &impl Fn(&GroupKey) -> usize,
) -> Option<GroupKey> {
    let size = class_size(own);
    place
        .fallbacks()
        .filter(|key| own.level != GroupLevel::Version || key.level == GroupLevel::App)
        .find(|key| *key != *own && class_size(key) > size)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct GroupKey {
    pub(crate) level: GroupLevel,
    pub(crate) prefix: String,
    pub(crate) class: MethodClass,
}

/// The level at which a route is compared. Its resource, when the resource
/// holds another route of its class (or, for a write, two reads); otherwise
/// its namespace, when that is wider than the resource and not the bare root.
/// A resource whose routes all lack evidence is thereby treated as public
/// by design, not escalated.
///
/// A namespace that holds no other route of the class gives way to the
/// nearest enclosing scope tree that does, so a lone read in
/// `/admin/tagline` is compared with the reads under `/admin`.
fn comparison_key(
    place: &Placement,
    class_size: &impl Fn(&GroupKey) -> usize,
) -> Option<GroupKey> {
    let resource = place.key(GroupLevel::Resource);
    let reads = GroupKey {
        class: MethodClass::Read,
        ..resource.clone()
    };
    let informative = class_size(&resource) >= 2
        || (place.class == MethodClass::Write && class_size(&reads) >= 2);
    if informative {
        return Some(resource);
    }
    wider_key(place, class_size)
}

/// Whether a route acts on its resource's collection or one of its records
/// (`/users`, `/users/{id}`), where writes are never less protected than
/// reads. A sub-action below a record (`/users/{id}/otp`,
/// `/users/{id}/self/delete`) is its own operation with its own policy.
fn targets_record(route: &Route) -> bool {
    let resource = placement(route).resource;
    let depth = path_segments(&resource).len();
    let segments = path_segments(without_mount_prefix(&route.path));
    // A catch-all (`/files/{tail:.*}`) serves any path below, not a record.
    !segments.iter().any(|segment| is_catch_all_segment(segment))
        && segments.iter().skip(depth).all(|segment| is_dynamic_segment(segment))
}

/// Whether a route's own-class group gives no verdict, so that a wider or
/// cross-class group has to speak for it. A namespace whose writes agree
/// among themselves (self-service writes beside admin-only reads) is judged
/// by those writes.
fn own_undecided(stats: &HashMap<GroupKey, GroupStats>, own: &GroupKey) -> bool {
    stats.get(own).is_none_or(|group| group.expected.is_none())
}

/// The group above a route's resource: its namespace, or the nearest
/// enclosing scope with more routes of its class.
fn wider_key(place: &Placement, class_size: &impl Fn(&GroupKey) -> usize) -> Option<GroupKey> {
    if place.namespace == "/" {
        return None;
    }
    // A collection that is its own namespace (`GET /api/users` beside
    // `GET /api/users/{id}`): its namespace group holds its records' routes.
    if place.namespace == place.resource {
        let namespace = place.key(GroupLevel::Namespace);
        return (class_size(&namespace) >= 2).then_some(namespace);
    }
    let namespace = place.key(GroupLevel::Namespace);
    let own_size = class_size(&namespace);
    if own_size >= 2 {
        return Some(namespace);
    }
    place
        .subtrees()
        .skip_while(|prefix| *prefix == place.namespace)
        .map(|prefix| place.subtree_key(prefix))
        .find(|key| class_size(key) > own_size.max(1))
        .or(Some(namespace))
}

/// The nearest enclosing scope tree above `own` that holds more routes of
/// its class.
fn parent_key(
    place: &Placement,
    own: &GroupKey,
    class_size: &impl Fn(&GroupKey) -> usize,
) -> Option<GroupKey> {
    let size = class_size(own);
    place
        .subtrees()
        .filter(|prefix| prefix.len() < own.prefix.len() && own.prefix.starts_with(prefix.as_str()))
        .map(|prefix| place.subtree_key(prefix))
        .find(|key| class_size(key) > size)
}

/// What a peer group establishes.
pub(crate) struct GroupStats<'a> {
    pub(crate) peers: Vec<&'a Route>,
    /// The highest tier that a dominant share of the group reaches.
    pub(crate) expected: Option<EvidenceTier>,
    /// A requirement carried by a dominant share of the group's
    /// privilege-tier routes that name one.
    pub(crate) dominant_requirement: Option<String>,
    /// Every role or permission that a dominant share of the group's
    /// role-naming routes requires, sorted.
    pub(crate) dominant_roles: Vec<String>,
    /// Most of those routes take their roles from one allow-list.
    pub(crate) roles_any_of: bool,
    /// Unrecognized components most of the group carries, such as a
    /// scope-wide middleware. They cannot explain why one route differs.
    pub(crate) common_unknowns: Vec<String>,
    pub(crate) authorized: usize,
}

impl<'a> GroupStats<'a> {
    fn of(peers: Vec<&'a Route>, weights: Vec<f64>, options: &AnalysisOptions) -> Self {
        let expected = group_tier(&peers, &weights, options);
        let mut counts: HashMap<&str, f64> = HashMap::new();
        let mut naming = 0.0;
        for (peer, weight) in peers.iter().zip(&weights) {
            if peer.best_tier() != EvidenceTier::Privilege {
                continue;
            }
            let requirements = peer.privilege_requirements();
            if requirements.is_empty() {
                continue;
            }
            naming += weight;
            for requirement in requirements {
                *counts.entry(requirement).or_default() += weight;
            }
        }
        let mut ranked: Vec<(&str, f64)> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(b.0)));
        let dominant_requirement = ranked
            .first()
            .filter(|(_, count)| is_dominant_weight(*count, naming, options))
            .map(|(requirement, _)| requirement.to_string());
        let mut dominant_roles: Vec<String> = ranked
            .iter()
            .filter(|(_, count)| is_dominant_weight(*count, naming, options))
            .map(|(requirement, _)| requirement.to_string())
            .collect();
        dominant_roles.sort();
        let any_of: f64 = peers
            .iter()
            .zip(&weights)
            .filter(|(peer, _)| peer.best_tier() == EvidenceTier::Privilege && Requirement::of(peer).roles_any_of)
            .map(|(_, weight)| weight)
            .sum();
        let roles_any_of = naming > 0.0 && any_of * 2.0 > naming;
        let total: f64 = weights.iter().sum();
        let mut unknown_counts: HashMap<&str, f64> = HashMap::new();
        for (peer, weight) in peers.iter().zip(&weights) {
            let mut seen = HashSet::new();
            for evidence in &peer.authorization {
                if is_shared_unknown(evidence) && seen.insert(evidence.mechanism.as_str())
                {
                    *unknown_counts
                        .entry(evidence.mechanism.as_str())
                        .or_default() += weight;
                }
            }
        }
        let mut common_unknowns: Vec<String> = unknown_counts
            .into_iter()
            .filter(|(_, count)| *count / total >= options.dominance_threshold)
            .map(|(name, _)| name.to_string())
            .collect();
        common_unknowns.sort();
        let authorized = peers.iter().filter(|peer| peer.is_authorized()).count();
        Self {
            peers,
            expected,
            dominant_requirement,
            dominant_roles,
            roles_any_of,
            common_unknowns,
            authorized,
        }
    }

    fn invariant(&self, id: &str, key: &GroupKey) -> AuthorizationInvariant {
        let mut evidence_patterns: Vec<String> = self
            .peers
            .iter()
            .flat_map(|route| {
                route
                    .authorization
                    .iter()
                    .map(|evidence| evidence.mechanism.clone())
            })
            .collect();
        evidence_patterns.sort();
        evidence_patterns.dedup();
        let reaching = self.expected.map_or(0, |tier| {
            self.peers
                .iter()
                .filter(|peer| peer.best_tier() >= tier)
                .count()
        });
        AuthorizationInvariant {
            peer_group_id: id.into(),
            description: match self.expected {
                Some(tier) => format!(
                    "{} routes under {} reach at least {} evidence ({} of {}){}.",
                    capitalized(&key.class.to_string()),
                    key.prefix,
                    tier,
                    reaching,
                    self.peers.len(),
                    self.dominant_requirement
                        .as_ref()
                        .map(|requirement| format!(", requiring `{requirement}`"))
                        .unwrap_or_default()
                ),
                None => format!(
                    "{} routes under {} share no dominant protection.",
                    capitalized(&key.class.to_string()),
                    key.prefix
                ),
            },
            total_routes: self.peers.len(),
            routes_with_authorization: self.authorized,
            routes_without_authorization: self.peers.len() - self.authorized,
            evidence_patterns,
            strength: invariant_strength(reaching, self.peers.len(), self.expected.is_some()),
            expected_tier: self.expected,
            dominant_requirement: self.dominant_requirement.clone(),
        }
    }
}

fn capitalized(text: &str) -> String {
    let mut characters = text.chars();
    characters
        .next()
        .map(|first| first.to_uppercase().chain(characters).collect())
        .unwrap_or_default()
}

/// Whether the route carries something Archer cannot judge that its peers
/// do not share: its own unrecognized guard or middleware, or a handler that
/// could not be analyzed.
/// Protection on the route that Archer cannot evaluate, which the peers do
/// not share and so could be the check the route lacks: an unanalyzed
/// handler, the caller handed to unanalyzed code, or a guard or middleware
/// only this route has. Only that lowers a finding to unverified; what the
/// peers share is listed as a note on the finding.
fn unverified_beyond_peers(route: &Route, group: &GroupStats, _expected: EvidenceTier) -> bool {
    !route.unverified.is_empty()
        || route.authorization.iter().any(|evidence| {
            match evidence.kind {
                AuthEvidenceKind::Unknown => {}
                AuthEvidenceKind::Delegated if is_shared_unknown(evidence) => {}
                AuthEvidenceKind::Delegated => return true,
                _ => return false,
            }
            !group.common_unknowns.contains(&evidence.mechanism)
        })
}

/// How a privileged route's roles differ from its group's, if they do:
/// an allow-list that admits roles the peers do not is weaker; lacking the
/// role the peers lead with is different. A route that requires more than
/// its peers, or allows a subset of their allow-list, is stricter and is
/// not reported.
/// A route admits callers by role from a set: role checks only (a named
/// permission is held, not chosen from a set), one role or several any of
/// which passes.
pub(crate) fn is_allow_list(route: &Route, requirement: &Requirement) -> bool {
    !requirement.roles.is_empty()
        && (requirement.roles_any_of || requirement.roles.len() == 1)
        && route.authorization.iter().any(|evidence| evidence.kind == AuthEvidenceKind::RoleCheck)
        && !route.authorization.iter().any(|evidence| evidence.kind == AuthEvidenceKind::PermissionCheck)
}

/// Most of the peers that name roles admit from allow-lists.
fn peers_allow_lists(route: &Route, group: &GroupStats) -> bool {
    let naming: Vec<(&Route, Requirement)> = group
        .peers
        .iter()
        .filter(|peer| route_identity(peer) != route_identity(route) && peer.best_tier() == EvidenceTier::Privilege)
        .map(|peer| (*peer, Requirement::of(peer)))
        .filter(|(_, requirement)| !requirement.roles.is_empty())
        .collect();
    let lists = naming.iter().filter(|(peer, requirement)| is_allow_list(peer, requirement)).count();
    !naming.is_empty() && lists * 2 > naming.len()
}

/// The roles a route's allow-list admits that most of its peers' allow-lists
/// (those that name roles) refuse.
pub(crate) fn refused_roles(
    route: &Route,
    requirement: &Requirement,
    group: &GroupStats,
    options: &AnalysisOptions,
) -> Vec<String> {
    let naming: Vec<Requirement> = group
        .peers
        .iter()
        .filter(|peer| route_identity(peer) != route_identity(route) && peer.best_tier() == EvidenceTier::Privilege)
        .map(|peer| Requirement::of(peer))
        .filter(|peer| !peer.roles.is_empty() && !peer.unverified)
        .collect();
    requirement
        .roles
        .iter()
        .filter(|role| {
            let refusing = naming.iter().filter(|peer| !peer.roles.contains(role)).count();
            is_dominant_weight(refusing as f64, naming.len() as f64, options)
        })
        .cloned()
        .collect()
}

fn role_mismatch(
    route: &Route,
    requirement: &Requirement,
    group: &GroupStats,
    options: &AnalysisOptions,
) -> Option<FindingCategory> {
    if requirement.roles.is_empty() || group.dominant_roles.is_empty() {
        return None;
    }
    let missing = group
        .dominant_roles
        .iter()
        .any(|role| !requirement.roles.contains(role));
    let extra = requirement
        .roles
        .iter()
        .any(|role| !group.dominant_roles.contains(role));
    // Both sides are sets of admitted roles: a route admitting only roles
    // the peers admit is as strict or stricter, and is not reported.
    if is_allow_list(route, requirement) && peers_allow_lists(route, group) {
        // A role it admits is extra when most peers that name roles refuse
        // it; only those make it weaker. Admitting none and refusing a role
        // most admit is stricter; doing both has no direction.
        if refused_roles(route, requirement, group, options).is_empty() {
            return None;
        }
        return Some(if missing {
            FindingCategory::DifferentAuthorization
        } else {
            FindingCategory::WeakerAuthorization
        });
    }
    if requirement.roles_any_of && extra && !missing {
        // Supported by other routes alone: peers that name roles and admit
        // none of the extra ones.
        let naming: Vec<Requirement> = group
            .peers
            .iter()
            .filter(|peer| route_identity(peer) != route_identity(route))
            .map(|peer| Requirement::of(peer))
            .filter(|peer| !peer.roles.is_empty())
            .collect();
        let narrower = naming
            .iter()
            .filter(|peer| {
                peer.roles
                    .iter()
                    .all(|role| !requirement.roles.contains(role) || group.dominant_roles.contains(role))
            })
            .count();
        if is_dominant_weight(narrower as f64, naming.len() as f64, options) {
            return Some(FindingCategory::WeakerAuthorization);
        }
        return None;
    }
    // Conjunctive checks are compared on the group's leading requirement
    // only: routes that name several checks rarely name the same set.
    let lacks_leading = group
        .dominant_requirement
        .as_ref()
        .is_some_and(|required| !requirement.roles.contains(required));
    if lacks_leading && !(group.roles_any_of && !extra) {
        return Some(FindingCategory::DifferentAuthorization);
    }
    None
}

/// Unanalyzed protection that can wrap many routes alike: an unrecognized
/// guard or middleware, or middleware that checks only some paths. When most
/// of a group carries it, it does not explain why one route falls short.
fn is_shared_unknown(evidence: &AuthEvidence) -> bool {
    evidence.kind == AuthEvidenceKind::Unknown
        || (evidence.kind == AuthEvidenceKind::Delegated
            && evidence
                .symbol
                .as_deref()
                .is_some_and(|symbol| symbol.starts_with(".wrap")))
}

fn finding(
    route: &Route,
    category: FindingCategory,
    expected: EvidenceTier,
    group: &GroupStats,
    key: &GroupKey,
    id: &str,
    _options: &AnalysisOptions,
) -> Finding {
    let tier = route.best_tier();
    let route_class = MethodClass::of(&route.method);
    let compared = if key.class != route_class {
        format!("the {} routes of {}", key.class, key.prefix)
    } else {
        format!("its {} peers under {}", key.class, key.prefix)
    };
    // Where a peer gets the expected tier through a call chain, cited so
    // the finding can be checked: a check deep in a service function is
    // not visible from the handler.
    let example = group
        .peers
        .iter()
        .filter(|peer| !std::ptr::eq(**peer, route))
        .find_map(|peer| {
            peer.authorization
                .iter()
                .filter(|evidence| EvidenceTier::of(&evidence.kind) >= expected.max(EvidenceTier::Identity))
                .filter(|evidence| evidence.symbol.as_deref().is_some_and(|symbol| symbol.contains(" -> ")))
                // The deepest link: the comparison itself, not the call to it.
                .max_by_key(|evidence| evidence.symbol.as_deref().map_or(0, |symbol| symbol.matches(" -> ").count()))
                .map(|evidence| {
                    format!(
                        " For example, {} {} reaches it as {} -> {} ({}:{}).",
                        peer.method,
                        peer.path,
                        peer.handler.as_deref().unwrap_or("its handler"),
                        evidence.symbol.as_deref().unwrap_or_default(),
                        short_file(&evidence.file),
                        evidence.line
                    )
                })
        })
        .unwrap_or_default();
    let (severity, rationale) = match category {
        FindingCategory::MissingAuthentication => (
            Severity::High,
            format!(
                "No authentication or authorization evidence, while {compared} at least authenticate the caller.{example}"
            ),
        ),
        FindingCategory::MissingAuthorization => (
            if expected == EvidenceTier::Privilege {
                Severity::High
            } else {
                Severity::Medium
            },
            format!("Best evidence is {tier}, while {compared} reach {expected}.{example}"),
        ),
        FindingCategory::WeakerAuthorization => (
            Severity::Medium,
            format!("Best evidence is {tier}, while {compared} reach {expected}.{example}"),
        ),
        FindingCategory::DifferentAuthorization => (
            Severity::Medium,
            format!(
                "Checks {} where {compared} require {}.",
                route
                    .privilege_requirements()
                    .iter()
                    .map(|requirement| format!("`{requirement}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
                group
                    .dominant_roles
                    .iter()
                    .map(|requirement| format!("`{requirement}`"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        ),
        FindingCategory::InconsistentRegistration => (
            Severity::Medium,
            "The same handler is registered elsewhere with protection this route lacks.".into(),
        ),
        FindingCategory::SameResourceWeakerProtection => (
            Severity::Medium,
            "Routes serving the same data require more of the caller than this route.".into(),
        ),
        FindingCategory::SkipsPeerCheck => (
            Severity::Medium,
            "Its peers make a check with the caller that this route does not.".into(),
        ),
        FindingCategory::UnverifiedProtection => (
            Severity::Low,
            format!(
                "Recognized evidence is {tier}, while {compared} reach {expected}; it also has protection Archer cannot verify ({}). Review manually.",
                route
                    .unverified
                    .iter()
                    .cloned()
                    .chain(
                        route
                            .authorization
                            .iter()
                            .filter(|evidence| {
                                matches!(
                                    evidence.kind,
                                    AuthEvidenceKind::Unknown | AuthEvidenceKind::Delegated
                                )
                            })
                            .map(|evidence| match evidence.kind {
                                AuthEvidenceKind::Delegated => evidence.mechanism.clone(),
                                _ => format!("unrecognized `{}`", evidence.mechanism),
                            })
                    )
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        ),
    };
    let invariant = group.invariant(id, key);
    Finding {
        peer_group_id: id.into(),
        category,
        severity,
        rationale,
        invariant,
        suspicious_route: route.into(),
        suspicious_route_tier: tier,
        expected_tier: expected,
        suspicious_route_evidence: route.authorization.clone(),
        evidence: Default::default(),
        authorized_peer_routes: group
            .peers
            .iter()
            .filter(|peer| route_identity(peer) != route_identity(route))
            .filter(|peer| match category {
                FindingCategory::DifferentAuthorization => group
                    .dominant_requirement
                    .as_deref()
                    .is_some_and(|required| peer.privilege_requirements().contains(&required)),
                _ => peer.best_tier() >= expected,
            })
            .map(|peer| (*peer).into())
            .collect(),
    }
}

/// Notes the level a finding was judged at. A finding from a fallback
/// level (API version root, whole app) compares unrelated routes, so it is
/// at most Low; one for a route compared as the class its handler acts as
/// is at most Medium.
fn at_level(mut finding: Finding, key: &GroupKey, tried: &str, switched: bool) -> Finding {
    // A class read from what the handler does is an inference: a finding
    // that rests on it is at most Medium.
    if switched && finding.severity == Severity::High {
        finding.severity = Severity::Medium;
    }
    if key.level.is_fallback() {
        // A whole-application group pools routes never meant to be alike,
        // so it supports little: Low, unless the route is a write and
        // nearly all writes of the application make the check. Reads are
        // often public by design; an unprotected write among protected
        // ones rarely is.
        let compared = finding.invariant.total_routes.saturating_sub(1);
        let supporting = finding.authorized_peer_routes.len();
        let strong = super::explain::strong_support(supporting, compared);
        finding.severity = if strong && MethodClass::of(&finding.suspicious_route.method) == MethodClass::Write {
            finding.severity.min(Severity::Medium)
        } else {
            Severity::Low
        };
        finding.rationale.push_str(&format!(
            " Compared at the {} level ({}), since no narrower group had peers that agree.",
            key.level.label(),
            key.prefix
        ));
    }
    finding.rationale.push_str(tried);
    finding
}

/// The highest tier that a dominant share of the group reaches, each route
/// counting with its weight.
pub(crate) fn group_tier(
    peers: &[&Route],
    weights: &[f64],
    options: &AnalysisOptions,
) -> Option<EvidenceTier> {
    let total: f64 = weights.iter().sum();
    [
        EvidenceTier::Privilege,
        EvidenceTier::Resource,
        EvidenceTier::Identity,
    ]
    .into_iter()
    .find(|tier| {
        let reaching: f64 = peers
            .iter()
            .zip(weights)
            .filter(|(peer, _)| peer.best_tier() >= *tier)
            .map(|(_, weight)| weight)
            .sum();
        is_dominant_weight(reaching, total, options)
    })
}

/// `is_dominant` for weighted counts.
fn is_dominant_weight(reaching: f64, total: f64, options: &AnalysisOptions) -> bool {
    const EPSILON: f64 = 1e-9;
    total > 0.0
        && reaching + EPSILON >= options.min_support as f64
        && reaching / total + EPSILON >= options.dominance_threshold
}

/// `Strong` for a unanimous group or a dominant one with three or more
/// routes reaching its tier, `Medium` for any other dominant group, `Weak`
/// for a pattern too rare to report on.
fn invariant_strength(reaching: usize, total: usize, dominant: bool) -> AuthStrength {
    if dominant && (reaching == total || reaching >= 3) {
        AuthStrength::Strong
    } else if dominant {
        AuthStrength::Medium
    } else {
        AuthStrength::Weak
    }
}

/// The text form of a finding, as printed by the CLI.
pub fn format_finding(finding: &Finding) -> String {
    let route = &finding.suspicious_route;
    let peer_lines = finding
        .authorized_peer_routes
        .iter()
        .map(|peer| {
            format!(
                "    - {} {}\n      {}",
                peer.method,
                peer.path,
                format_evidence(&peer.authorization)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let category = format!(
        "  Category: {} (severity {}; best evidence tier {}, peers reach {})\n  Why: {}\n",
        finding.category,
        finding.severity,
        finding.suspicious_route_tier,
        finding.expected_tier,
        finding.rationale
    );
    let evidence = &finding.evidence;
    if evidence.check.is_empty() {
        return format!(
            "{}  Suspicious route: {} {} ({}:{})\n\
  Inferred invariant: {}\n\
  Peer evidence ({} route(s)):\n{}\n\
  Suspicious route evidence: {}.",
            category,
            route.method,
            route.path,
            route.file.display(),
            route.line,
            finding.invariant.description,
            finding.authorized_peer_routes.len(),
            peer_lines,
            format_evidence(&finding.suspicious_route_evidence)
        );
    }
    // The case, short: up to five peers that make the check stand for the
    // rest, which the JSON report lists in full.
    let mut text = format!(
        "{}  Suspicious route: {} {} ({}:{})\n  Inferred invariant: {}",
        category,
        route.method,
        route.path,
        route.file.display(),
        route.line,
        finding.invariant.description,
    );
    {
        text.push_str(&format!(
            "\n  The check: {} ({} of {} compared peers make it)",
            evidence.check, evidence.supporting, evidence.compared
        ));
        for peer in &evidence.peers {
            text.push_str(&format!(
                "\n    - {} {}: {} ({}:{})",
                peer.method,
                peer.path,
                peer.check,
                peer.file.display(),
                peer.line
            ));
        }
        text.push_str(&format!("\n  This route has instead: {}", evidence.instead.join("; ")));
        for note in &evidence.notes {
            text.push_str(&format!("\n  Note: {note}"));
        }
        text.push_str("\n  If intended, add to archer.toml:");
        for line in evidence.dismiss.lines() {
            text.push_str(&format!("\n    {line}"));
        }
    }
    text
}

pub(crate) fn format_evidence(authorization: &[AuthEvidence]) -> String {
    if authorization.is_empty() {
        return "No recognized authorization evidence".into();
    }
    authorization
        .iter()
        .map(|evidence| {
            format!(
                "{:?}: {} at {}:{} ({:?})",
                evidence.kind,
                evidence.mechanism,
                evidence.file.display(),
                evidence.line,
                evidence.strength
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Whether two routes are compared with each other at the resource level:
/// both are analysed, share a resource, and share a method class.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn same_peer_group(route: &Route, candidate: &Route) -> bool {
    let analysed = |route: &Route| {
        !has_unresolved_segment(&route.path)
            && !is_authentication_route(route)
            && !is_well_known_public_route(route)
    };
    if !analysed(route) || !analysed(candidate) {
        return false;
    }
    let (left, right) = (placement(route), placement(candidate));
    left.resource == right.resource && left.class == right.class
}

/// Version and API-root segments that say nothing about what a route serves:
/// `api`, `rest`, `rpc`, `v1`, `v2beta`, `2024-01`.
pub(crate) fn is_generic_segment(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    ["api", "apis", "rest", "rpc", "json"].contains(&lower.as_str())
        || (lower.starts_with('v')
            && lower[1..].starts_with(|character: char| character.is_ascii_digit()))
        || lower
            .chars()
            .all(|character| character.is_ascii_digit() || character == '-' || character == '.')
}

/// A route's namespace and resource. The namespace is its declared scope;
/// outside any scope, its leading generic segments (`/api/v1`), or else its
/// first segment (`/admin`). The resource is the namespace plus the next
/// meaningful static segment: `/admin/users` for `/admin/users`,
/// `/admin/users/{id}`, and `/admin/users/{id}/roles`. Parameters are
/// normalized, so `/t/{id}/x` and `/t/{tenant}/x` share a resource.
pub(crate) fn placement(route: &Route) -> Placement {
    // A leading runtime mount prefix (`web::scope(&cfg.base_uri)`) is the
    // same for every route under it: place routes as if it were the root.
    let path = without_mount_prefix(&route.path);
    let scope_prefix = without_mount_prefix(&route.scope_prefix);
    let segments: Vec<&str> = path_segments(path);
    let scope_segments = path_segments(scope_prefix).len().min(segments.len());
    let namespace_length = if scope_segments > 0 {
        scope_segments
    } else {
        let generic = segments
            .iter()
            .take_while(|segment| is_generic_segment(segment))
            .count();
        if generic > 0 {
            generic
        } else {
            usize::from(
                segments
                    .first()
                    .is_some_and(|segment| !is_dynamic_segment(segment)),
            )
        }
    };
    let resource_length = segments[namespace_length..]
        .iter()
        .position(|segment| !is_dynamic_segment(segment) && !is_generic_segment(segment))
        .map_or(segments.len().max(namespace_length), |offset| {
            namespace_length + offset + 1
        });
    let prefix = |length: usize| {
        let normalized: Vec<&str> = segments[..length]
            .iter()
            .map(|segment| {
                if is_dynamic_segment(segment) {
                    "{}"
                } else {
                    segment
                }
            })
            .collect();
        format!("/{}", normalized.join("/"))
    };
    let generic = segments
        .iter()
        .take_while(|segment| is_generic_segment(segment))
        .count();
    Placement {
        namespace: prefix(namespace_length),
        resource: prefix(resource_length),
        class: MethodClass::of(&route.method),
        version: (generic > 0 && generic < segments.len()).then(|| prefix(generic)),
    }
}

/// A path without its leading `<unresolved:..>` mount segment, if any.
fn without_mount_prefix(path: &str) -> &str {
    match path.strip_prefix("/<unresolved:") {
        Some(rest) => rest.find('/').map_or("", |slash| &rest[slash..]),
        None => path,
    }
}

/// The resource prefix of a route; see `placement`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn peer_prefix(route: &Route) -> String {
    placement(route).resource
}

/// A parameter, or a part Archer could not resolve. A symbolic scope
/// (`<scope:cfg.prefix>`) is static: routes under the same expression
/// group together, and routes under another one stay apart.
pub(crate) fn is_dynamic_segment(segment: &str) -> bool {
    (segment.starts_with('{') && (segment.ends_with('}') || segment.ends_with("}*")))
        || (segment.starts_with('<') && segment.ends_with('>') && !segment.starts_with(super::routes::SYMBOLIC_SCOPE))
}

/// A path's segments, empty ones dropped (so `""`, `"/"` and a trailing
/// `/` agree), splitting only outside `{..}`: a parameter whose pattern
/// holds a slash (`{path:.*/raw}`) stays one dynamic segment.
pub(crate) fn path_segments(path: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (index, character) in path.char_indices() {
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            '/' if depth == 0 => {
                segments.push(&path[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    segments.push(&path[start..]);
    segments.retain(|segment| !segment.is_empty());
    segments
}

/// A tail parameter that matches the rest of the path (`{tail}*`,
/// `{rest:.*}`, `{path:.+}`): it names no record.
pub(crate) fn is_catch_all_segment(segment: &str) -> bool {
    segment.ends_with("}*")
        || (segment.starts_with('{')
            && segment
                .split_once(':')
                .is_some_and(|(_, pattern)| pattern.contains(".*") || pattern.contains(".+") || pattern.contains("/")))
}

/// Static segments of a path, in order.
fn static_segments(path: &str) -> Vec<String> {
    path_segments(path)
        .into_iter()
        .filter(|segment| !is_dynamic_segment(segment))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// An authentication endpoint such as `/auth/login`, `/api/token/{id}`, or
/// `/users/password/reset`: its last static segment names one, and the
/// segments before it are generic or about accounts. `/admin/settings/auth`
/// and `/admin/users/{id}/token` manage something and are analysed.
pub(crate) fn is_authentication_route(route: &Route) -> bool {
    const ENDPOINTS: [&str; 22] = [
        "device",
        "revoke",
        "certs",
        "jwks",
        "captcha",
        "auth",
        "login",
        "logout",
        "register",
        "signup",
        "signin",
        "signout",
        "token",
        "refresh",
        "callback",
        "authorize",
        "reset",
        "forgot",
        "verify",
        "verification",
        "confirm",
        "password",
    ];
    const ACCOUNT_CONTEXT: [&str; 17] = [
        "auth", "oauth", "oauth2", "session", "sessions", "account", "accounts", "user", "users",
        "identity", "sso", "saml", "oidc", "me", "password", "jwt", "token",
    ];
    let statics = static_segments(&route.path);
    let Some((last, before)) = statics.split_last() else {
        return false;
    };
    // `password_reset`, `request-reset`, `email_confirm`.
    let named = last.split(['_', '-'])
        .any(|word| ENDPOINTS.contains(&word))
        && before.iter().all(|segment| {
            is_generic_segment(segment) || ACCOUNT_CONTEXT.contains(&segment.as_str())
        });
    named && authenticates_structurally(route) && !kept_behind_exempt_list(route)
}

/// A route the app's own middleware checks while exempting other paths by
/// name (`IGNORE_ROUTES = ["/auth/login", "/auth/signup"]`): the app has
/// said which authentication endpoints are reached anonymously, and this
/// one (`/auth/logout`, `/auth/me`) is not among them, so it is compared
/// with its peers.
fn kept_behind_exempt_list(route: &Route) -> bool {
    route
        .authorization
        .iter()
        .any(|evidence| evidence.mechanism.contains(super::middleware::SKIP_RULE_MARK))
}

/// The structural half of an authentication endpoint: what its handler
/// does, beyond its path. It issues or clears a session or token, or takes
/// credentials, as its handler's name, the functions it calls, the models
/// it uses, or how it uses the caller say (`password_length_check`, `LoginResponse`,
/// `Identity::forget`, `read_auth_token`). A handler that checks a
/// privilege (`/auth/check_admin`, `validate_admin_session`) is not one:
/// logging in cannot require it. A handler Archer knows nothing about
/// keeps the name's verdict, so a login page is not compared with the
/// routes behind it.
fn authenticates_structurally(route: &Route) -> bool {
    const SIGNS: [&str; 30] = [
        "login", "logout", "signin", "signout", "signup", "register", "password", "credential",
        "token", "jwt", "session", "cookie", "forget", "remember", "oauth", "otp", "totp",
        "2fa", "captcha", "refresh", "verif", "reset", "confirm", "revoke", "cert", "jwks",
        "callback", "authorize", "forgot", "device",
    ];
    let behaviour: Vec<String> = route
        .resource_keys
        .iter()
        .chain(route.caller_use.iter().filter(|feature| {
            // Bookkeeping, not behaviour: where a check is made, and what
            // the request carries and the auth object is built with.
            !feature.starts_with("scheme:")
                && !feature.starts_with(super::caller_use::SITE)
                && !feature.starts_with(super::caller_use::BINDS)
                && !feature.starts_with(super::caller_use::MENTIONS)
                && !feature.starts_with(super::caller_use::GRANTS)
                && !feature.starts_with(super::caller_use::KEYED)
        }))
        .map(|text| text.to_ascii_lowercase())
        .collect();
    if behaviour.is_empty() || route.origin.takes_credentials {
        return true;
    }
    route.best_tier() < EvidenceTier::Privilege
        && behaviour
            .iter()
            .any(|text| SIGNS.iter().any(|sign| text.contains(sign)))
}

/// Health, readiness, version, metrics, and API-documentation endpoints at
/// the root or under a generic prefix (`/health`, `/api/v1/openapi.json`).
/// Under a namespace such as `/admin/metrics` they are analysed.
pub(crate) fn is_well_known_public_route(route: &Route) -> bool {
    const PUBLIC: [&str; 19] = [
        "health",
        "healthz",
        "healthcheck",
        "ready",
        "readyz",
        "readiness",
        "live",
        "livez",
        "liveness",
        "ping",
        "status",
        "version",
        "metrics",
        "docs",
        "swagger",
        "swagger-ui",
        "openapi",
        "openapi.json",
        "favicon.ico",
    ];
    // A leading runtime mount prefix (`/<unresolved:cfg.base_uri>/healthz`)
    // does not make the endpoint dynamic.
    let path = without_mount_prefix(&route.path);
    // A provider's webhook (`POST /api/stripe/webhook`) has no logged-in
    // caller; it authenticates the sender by a signature in the body.
    if route.method == "POST"
        && static_segments(path)
            .last()
            .is_some_and(|last| last == "webhook" || last == "webhooks")
    {
        return true;
    }
    if path_segments(path).into_iter().any(is_dynamic_segment) {
        return false;
    }
    let statics = static_segments(path);
    let Some((last, before)) = statics.split_last() else {
        return false;
    };
    // `health_check`, `health-check` and `healthcheck` are one name.
    let squash = |name: &str| name.replace(['_', '-'], "");
    // A liveness probe (`/api/v4/image/health`, `/storage/ping`) reports
    // whether a part of the app is up, whatever part it names, unless it
    // sits under an admin area; other names (`/users/status`) are public
    // only at the top.
    const PROBES: [&str; 11] = [
        "health", "healthz", "healthcheck", "ready", "readyz", "readiness", "live", "livez",
        "liveness", "ping", "alive",
    ];
    const PRIVILEGED: [&str; 6] = ["admin", "admins", "internal", "manage", "management", "ops"];
    if route.method == "GET"
        && PROBES.iter().any(|probe| squash(probe) == squash(last))
        && !before.iter().any(|segment| PRIVILEGED.contains(&segment.to_lowercase().as_str()))
    {
        return true;
    }
    PUBLIC.iter().any(|public| squash(public) == squash(last))
        && before.iter().all(|segment| is_generic_segment(segment))
}

pub(crate) fn unique_routes<'a, I>(routes: I) -> Vec<&'a Route>
where
    I: IntoIterator<Item = &'a Route>,
{
    let mut seen = HashSet::new();
    routes
        .into_iter()
        .filter(|route| seen.insert(route_identity(route)))
        .collect()
}

/// A route's method class, where a POST named as a read
/// (`POST /dataset/get_all_tags` handled by `get_all_tags`, `POST /search`)
/// is a read: APIs send a query body with POST, and such a route is
/// protected like the reads of its resource, not like its writes.
pub(crate) fn route_class(route: &Route) -> MethodClass {
    route_class_with_reason(route).0
}

/// The repository functions a route's handler calls, by name.
fn called_names(route: &Route) -> Vec<&str> {
    route.origin.called.iter().map(String::as_str).collect()
}

/// A route's method class with why, when it differs from its method's:
/// what the handler does wins over its name. A GET whose handler calls a
/// writing function (`delete_session`, `update_counter`) is a write; a
/// POST whose handler, unnamed by verb, calls only reading functions
/// (`search_points`, `get_stats`) is a read. Otherwise the handler's or
/// path's name decides, as below.
pub(crate) fn route_class_with_reason(route: &Route) -> (MethodClass, Option<String>) {
    let class = MethodClass::of(&route.method);
    let verbs = |name: &str| -> (bool, bool) {
        let words: Vec<String> = name
            .split(['_', '-'])
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        (
            words.iter().any(|word| CLASS_READ_WORDS.contains(&word.as_str())),
            words.iter().any(|word| CLASS_WRITE_WORDS.contains(&word.as_str())),
        )
    };
    let called = called_names(route);
    let handler = route.handler.as_deref().map(|handler| handler.rsplit("::").next().unwrap_or(handler));
    let (handler_reads, handler_writes) = handler.map_or((false, false), verbs);
    let writer = called.iter().copied().find(|name| {
        let (reads, writes) = verbs(name);
        writes && !reads
    });
    if class == MethodClass::Read {
        return match writer {
            Some(name) if !handler_reads && route.method == "GET" => (
                MethodClass::Write,
                Some(format!("a GET whose handler calls `{name}`, which writes")),
            ),
            _ => (class, None),
        };
    }
    if route.method != "POST" {
        return (class, None);
    }
    if !handler_reads && !handler_writes && writer.is_none() {
        let readers: Vec<&str> = called
            .iter()
            .copied()
            .filter(|name| verbs(name).0)
            .collect();
        if !readers.is_empty() && readers.len() == called.iter().filter(|name| verbs(name) != (false, false)).count() {
            return (
                MethodClass::Read,
                Some(format!("a POST whose handler only calls reading functions ({})", readers.join(", "))),
            );
        }
    }
    let class = route_class_by_name(route);
    let reason = (class == MethodClass::Read).then(|| "a POST named as a read".to_string());
    (class, reason)
}

const CLASS_READ_WORDS: [&str; 15] = [
    "get", "list", "search", "fetch", "count", "query", "find", "autocomplete", "suggest",
    "recommend", "retrieve", "lookup", "filter", "filters", "read",
];
const CLASS_WRITE_WORDS: [&str; 23] = [
    "create", "update", "delete", "remove", "add", "set", "put", "post", "upsert", "insert",
    "patch", "edit", "clear", "move", "upload", "send", "trigger", "cancel", "reset", "revoke",
    "invite", "import", "save",
];

fn route_class_by_name(route: &Route) -> MethodClass {
    let class = MethodClass::of(&route.method);
    if route.method != "POST" {
        return class;
    }
    // Read verbs; a name that also holds a write verb
    // (`delete_points_by_query`) stays a write.
    const READ_WORDS: [&str; 14] = [
        "get", "list", "search", "fetch", "count", "query", "find", "autocomplete", "suggest",
        "recommend", "retrieve", "lookup", "filter", "filters",
    ];
    const WRITE_WORDS: [&str; 22] = [
        "create", "update", "delete", "remove", "add", "set", "put", "post", "upsert", "insert",
        "patch", "edit", "clear", "move", "upload", "send", "trigger", "cancel", "reset", "revoke",
        "invite", "import",
    ];
    let words = |name: &str| -> Vec<String> {
        name.split(['_', '-'])
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    };
    let named_read = |name: &str| {
        let words = words(name);
        words.iter().any(|word| READ_WORDS.contains(&word.as_str()))
            && !words.iter().any(|word| WRITE_WORDS.contains(&word.as_str()))
    };
    let last_literal = route
        .path
        .split('/')
        .rfind(|segment| !segment.is_empty() && !is_dynamic_segment(segment));
    let read = match route.handler.as_deref() {
        // The handler's name is the better witness when it names a verb.
        Some(handler) if words(handler).iter().any(|word| {
            READ_WORDS.contains(&word.as_str()) || WRITE_WORDS.contains(&word.as_str())
        }) =>
        {
            named_read(handler)
        }
        _ => last_literal.is_some_and(named_read),
    };
    if read { MethodClass::Read } else { class }
}

pub(crate) fn route_identity(route: &Route) -> (&str, &str, &str, Option<&str>) {
    (
        &route.method,
        &route.path,
        &route.scope_prefix,
        route.handler.as_deref(),
    )
}

/// The last three components of a path, for evidence text.
fn short_file(path: &std::path::Path) -> String {
    let components: Vec<String> = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    components[components.len().saturating_sub(3)..].join("/")
}
