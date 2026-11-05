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
        {
            members.entry(key).or_default().push(index);
        }
    }
    let class_size = |key: &GroupKey| members.get(key).map_or(0, Vec::len);

    let mut stats: HashMap<GroupKey, GroupStats> = HashMap::new();
    let mut order: Vec<GroupKey> = Vec::new();
    let mut judged: Vec<(usize, GroupKey, Option<GroupKey>)> = Vec::new();
    let compute = |key: &GroupKey| {
        let indices: Vec<usize> = members.get(key).cloned().unwrap_or_default();
        let peers: Vec<&Route> = indices.iter().map(|&member| candidates[member]).collect();
        // Across a namespace, each resource counts once: a resource
        // with many routes must not outvote its single-route siblings.
        let weights: Vec<f64> = indices
            .iter()
            .map(|&member| match key.level {
                GroupLevel::Resource | GroupLevel::Handler | GroupLevel::Linked => 1.0,
                GroupLevel::Namespace | GroupLevel::Subtree => {
                    1.0 / class_size(&placed[member].key(GroupLevel::Resource)).max(1) as f64
                }
            })
            .collect();
        GroupStats::of(peers, weights, options)
    };
    for (index, place) in placed.iter().enumerate() {
        // A POST named as a read is held to the reads, when there are
        // reads to hold it to; it still counts among the writes as a peer,
        // which its method makes it.
        let as_read = Placement {
            class: MethodClass::Read,
            ..place.clone()
        };
        let place = if place.class == MethodClass::Write
            && route_class(candidates[index]) == MethodClass::Read
            && comparison_key(&as_read, &class_size).is_some_and(|key| class_size(&key) >= 2)
        {
            &as_read
        } else {
            place
        };
        let Some(mut own) = comparison_key(place, &class_size) else {
            pending.push((
                candidates[index],
                UnjudgedReason::NoPeers,
                format!(
                    "no other {} route shares its resource {} or a scope above it",
                    place.class, place.resource
                ),
            ));
            continue;
        };
        // A resource whose few routes disagree (one authenticated, one not)
        // cannot say what it expects. Its namespace can: hold the route to
        // the wider group instead. A resource whose routes all lack auth
        // agrees that it is public and keeps its own verdict.
        // The same holds above: a namespace whose routes disagree, below
        // the support threshold, defers to the enclosing scope tree, and so
        // on up to the outermost scope that is not only generic segments.
        loop {
            let undecided = {
                let group = stats.entry(own.clone()).or_insert_with(|| compute(&own));
                group.expected.is_none()
                    && group
                        .peers
                        .iter()
                        .any(|peer| peer.best_tier() > EvidenceTier::None)
            };
            if !undecided {
                break;
            }
            let next = match own.level {
                GroupLevel::Resource => wider_key(place, &class_size),
                GroupLevel::Namespace | GroupLevel::Subtree => {
                    parent_key(place, &own, &class_size)
                }
                GroupLevel::Handler | GroupLevel::Linked => None,
            };
            match next {
                Some(next) if next != own => own = next,
                _ => break,
            }
        }
        let reads = (place.class == MethodClass::Write).then(|| GroupKey {
            class: MethodClass::Read,
            ..own.clone()
        });
        for key in std::iter::once(&own).chain(reads.as_ref()) {
            let group = stats.entry(key.clone()).or_insert_with(|| compute(key));
            if !order.contains(key)
                && group.peers.len() >= 2
                && group
                    .peers
                    .iter()
                    .any(|peer| peer.best_tier() > EvidenceTier::None)
            {
                order.push(key.clone());
            }
        }
        judged.push((index, own, reads));
    }

    let mut peer_groups = Vec::new();
    let mut invariants = Vec::new();
    let mut ids: HashMap<&GroupKey, String> = HashMap::new();
    for (position, key) in order.iter().enumerate() {
        let id = format!("peer-group-{:03}", position + 1);
        let group = &stats[key];
        let description = format!(
            "{} routes of {} {}",
            key.class,
            match key.level {
                GroupLevel::Resource => "resource",
                GroupLevel::Namespace => "namespace",
                GroupLevel::Subtree => "scope tree",
                GroupLevel::Handler => "handler",
                GroupLevel::Linked => "linked routes",
            },
            key.prefix
        );
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
    for (index, own, reads) in judged {
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
                    format!("the only {} route under {}", own.class, own.prefix),
                )
            } else {
                (
                    UnjudgedReason::PeersUnprotected,
                    format!(
                        "none of its {} {} peers under {} carries protection; read as public by design",
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
            pending.push((
                route,
                UnjudgedReason::BelowSupport,
                format!(
                    "{protected} of {} {} routes under {} carry protection, below the {} routes and {:.0}% a pattern needs",
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
                peer.method == "POST" && peer.best_tier() >= EvidenceTier::Resource
            })
        {
            expected = EvidenceTier::Identity;
        }
        let tier = route.best_tier();
        let category = if tier < expected {
            if unverified_beyond_peers(route, basis, options) {
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
                let extra: Vec<String> = requirement
                    .roles
                    .iter()
                    .filter(|role| !group.dominant_roles.contains(role))
                    .map(|role| format!("`{role}`"))
                    .collect();
                reported.rationale = format!(
                    "Admits any of {} where its {} peers under {} admit only {}; it also lets in {}.",
                    requirement.roles.iter().map(|role| format!("`{role}`")).collect::<Vec<_>>().join(", "),
                    key.class,
                    key.prefix,
                    group.dominant_roles.iter().map(|role| format!("`{role}`")).collect::<Vec<_>>().join(", "),
                    extra.join(", "),
                );
            }
            finding_details.push(reported);
            continue;
        } else {
            continue;
        };
        finding_details.push(finding(
            route, category, expected, basis, basis_key, basis_id, options,
        ));
    }
    inconsistent_registrations(routes, &mut peer_groups, &mut invariants, &mut finding_details);
    writes_below_resource(&candidates, &mut peer_groups, &mut invariants, &mut finding_details);
    let linked = same_resource_weaker(routes, &mut peer_groups, &mut invariants, &mut finding_details, options);
    super::peer_checks::skipped_peer_checks(routes, &mut peer_groups, &mut invariants, &mut finding_details);
    per_route_permissions(routes, &mut finding_details);
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
    if stronger.ownership && !route.ownership && route.roles.is_empty() {
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
}

impl Placement {
    pub(crate) fn key(&self, level: GroupLevel) -> GroupKey {
        GroupKey {
            level,
            prefix: match level {
                GroupLevel::Resource => self.resource.clone(),
                GroupLevel::Namespace | GroupLevel::Subtree | GroupLevel::Handler | GroupLevel::Linked => {
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
    let depth = resource.split('/').filter(|segment| !segment.is_empty()).count();
    route
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .skip(depth)
        .all(is_dynamic_segment)
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
    if place.namespace == place.resource || place.namespace == "/" {
        return None;
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
fn unverified_beyond_peers(route: &Route, group: &GroupStats, _options: &AnalysisOptions) -> bool {
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
    let (severity, rationale) = match category {
        FindingCategory::MissingAuthentication => (
            Severity::High,
            format!(
                "No authentication or authorization evidence, while {compared} at least authenticate the caller."
            ),
        ),
        FindingCategory::MissingAuthorization => (
            if expected == EvidenceTier::Privilege {
                Severity::High
            } else {
                Severity::Medium
            },
            format!("Best evidence is {tier}, while {compared} reach {expected}."),
        ),
        FindingCategory::WeakerAuthorization => (
            Severity::Medium,
            format!("Best evidence is {tier}, while {compared} reach {expected}."),
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
    format!(
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
    )
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
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let scope_segments = scope_prefix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
        .min(segments.len());
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
    Placement {
        namespace: prefix(namespace_length),
        resource: prefix(resource_length),
        class: MethodClass::of(&route.method),
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

pub(crate) fn is_dynamic_segment(segment: &str) -> bool {
    (segment.starts_with('{') && segment.ends_with('}'))
        || (segment.starts_with('<') && segment.ends_with('>'))
}

/// Static segments of a path, in order.
fn static_segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|segment| !segment.is_empty() && !is_dynamic_segment(segment))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// An authentication endpoint such as `/auth/login`, `/api/token/{id}`, or
/// `/users/password/reset`: its last static segment names one, and the
/// segments before it are generic or about accounts. `/admin/settings/auth`
/// and `/admin/users/{id}/token` manage something and are analysed.
pub(crate) fn is_authentication_route(route: &Route) -> bool {
    const ENDPOINTS: [&str; 21] = [
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
    last.split(['_', '-'])
        .any(|word| ENDPOINTS.contains(&word))
        && before.iter().all(|segment| {
            is_generic_segment(segment) || ACCOUNT_CONTEXT.contains(&segment.as_str())
        })
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
    if path.split('/').any(is_dynamic_segment) {
        return false;
    }
    let statics = static_segments(path);
    let Some((last, before)) = statics.split_last() else {
        return false;
    };
    PUBLIC.contains(&last.as_str()) && before.iter().all(|segment| is_generic_segment(segment))
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
