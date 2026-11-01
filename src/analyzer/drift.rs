//! Peer grouping, invariant inference, and drift findings.

use std::collections::{HashMap, HashSet};

use super::{model::*, routes::has_unresolved_segment};

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

pub(crate) fn build_analysis_layers_with(
    routes: &[Route],
    options: &AnalysisOptions,
) -> (
    Vec<PeerGroup>,
    Vec<AuthorizationInvariant>,
    Vec<Finding>,
    Vec<String>,
) {
    // `same_peer_group` is an equivalence on routes that are neither
    // authentication endpoints nor unresolved, so peers are bucketed by its key
    // in one pass, in order of first appearance. Comparing every pair made
    // grouping cubic in the number of routes.
    let mut buckets: Vec<Vec<&Route>> = Vec::new();
    let mut bucket_of: HashMap<PeerKey, usize> = HashMap::new();
    for route in routes {
        if is_authentication_route(route) || has_unresolved_segment(&route.path) {
            continue;
        }
        let bucket = *bucket_of.entry(peer_key(route)).or_insert_with(|| {
            buckets.push(Vec::new());
            buckets.len() - 1
        });
        buckets[bucket].push(route);
    }
    let grouped_routes: Vec<Vec<&Route>> = buckets
        .into_iter()
        .map(unique_routes)
        .filter(|peers| peers.len() >= 2 && peers.iter().any(|peer| peer.is_authorized()))
        .collect();

    let mut peer_groups = Vec::new();
    let mut invariants = Vec::new();
    let mut finding_details = Vec::new();
    let mut findings = Vec::new();

    for (index, peers) in grouped_routes.iter().enumerate() {
        let id = format!("peer-group-{:03}", index + 1);
        let first = peers[0];
        let description = format!(
            "{} {} routes under {}",
            first.method,
            route_shape_description(first),
            if first.scope_prefix.is_empty() {
                "/"
            } else {
                &first.scope_prefix
            }
        );
        let references: Vec<RouteReference> = peers.iter().map(|route| (*route).into()).collect();
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: description.clone(),
            prefix: peer_prefix(first),
            routes: references.clone(),
        });

        let authorized = peers.iter().filter(|route| route.is_authorized()).count();
        let unauthorized = peers.len() - authorized;
        let mut evidence_patterns: Vec<String> = peers
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
        let strength = invariant_strength(authorized, peers.len(), options);
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "Peer routes under {} consistently contain authorization evidence.",
                if first.scope_prefix.is_empty() {
                    "/"
                } else {
                    &first.scope_prefix
                }
            ),
            total_routes: peers.len(),
            routes_with_authorization: authorized,
            routes_without_authorization: unauthorized,
            evidence_patterns,
            strength,
        };
        invariants.push(invariant.clone());

        if !is_dominant(authorized, peers.len(), options) {
            continue;
        }
        let expected_tier = dominant_tier(peers, options);
        for route in peers.iter().filter(|route| !route.is_authorized()) {
            let authorized_peer_routes: Vec<RouteReference> = peers
                .iter()
                .filter(|peer| peer.is_authorized())
                .map(|peer| (*peer).into())
                .collect();
            let finding = Finding {
                peer_group_id: id.clone(),
                category: FindingCategory::MissingAuthorization,
                invariant: invariant.clone(),
                suspicious_route: (*route).into(),
                suspicious_route_tier: route.best_tier(),
                expected_tier,
                suspicious_route_evidence: route.authorization.clone(),
                authorized_peer_routes,
            };
            findings.push(format_finding(&finding));
            finding_details.push(finding);
        }

        // Authorized routes whose best evidence is below the tier their peers
        // reach, such as an ownership check among role-checked peers.
        for route in peers
            .iter()
            .filter(|route| route.is_authorized() && route.best_tier() < expected_tier)
        {
            let finding = Finding {
                peer_group_id: id.clone(),
                category: FindingCategory::WeakerAuthorization,
                invariant: invariant.clone(),
                suspicious_route: (*route).into(),
                suspicious_route_tier: route.best_tier(),
                expected_tier,
                suspicious_route_evidence: route.authorization.clone(),
                authorized_peer_routes: peers
                    .iter()
                    .filter(|peer| peer.best_tier() >= expected_tier)
                    .map(|peer| (*peer).into())
                    .collect(),
            };
            findings.push(format_finding(&finding));
            finding_details.push(finding);
        }
    }

    (peer_groups, invariants, finding_details, findings)
}

#[cfg(test)]
pub(crate) fn infer_prototype_drift(routes: &[Route]) -> Vec<String> {
    build_analysis_layers(routes).3
}

/// The highest tier that a dominant share of the group reaches. Computed
/// only for groups whose authorized routes are dominant, so it is at least
/// the tier of the weakest authorization evidence.
pub(crate) fn dominant_tier(peers: &[&Route], options: &AnalysisOptions) -> EvidenceTier {
    [EvidenceTier::Privilege, EvidenceTier::Resource]
        .into_iter()
        .find(|tier| {
            let reaching = peers
                .iter()
                .filter(|peer| peer.best_tier() >= *tier)
                .count();
            is_dominant(reaching, peers.len(), options)
        })
        .unwrap_or(EvidenceTier::Resource)
}

/// Whether authorized routes are common enough in a group for its
/// unauthorized routes to be reported: at least `min_support` of them, making
/// up at least `dominance_threshold` of the group.
pub(crate) fn is_dominant(authorized: usize, total: usize, options: &AnalysisOptions) -> bool {
    total > 0
        && authorized >= options.min_support
        && authorized as f64 / total as f64 >= options.dominance_threshold
}

/// `Strong` for a unanimous group or a dominant one with three or more
/// authorized routes, `Medium` for any other dominant group, `Weak` for a
/// pattern too rare to report on.
pub(crate) fn invariant_strength(
    authorized: usize,
    total: usize,
    options: &AnalysisOptions,
) -> AuthStrength {
    if authorized == total || (authorized >= 3 && is_dominant(authorized, total, options)) {
        AuthStrength::Strong
    } else if is_dominant(authorized, total, options) {
        AuthStrength::Medium
    } else {
        AuthStrength::Weak
    }
}

pub(crate) fn route_shape_description(route: &Route) -> String {
    if dynamic_segment_shape(route).iter().any(|dynamic| *dynamic) {
        "parameterized".into()
    } else {
        "static".into()
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
    let category = match finding.category {
        FindingCategory::MissingAuthorization => String::new(),
        FindingCategory::WeakerAuthorization => format!(
            "  Category: weaker authorization (best evidence tier {}, peers reach {})\n",
            finding.suspicious_route_tier, finding.expected_tier
        ),
    };
    format!(
        "{}  Suspicious route: {} {} ({}:{})\n\
  Inferred invariant: {}\n\
  Authorized peer evidence ({} route(s)):\n{}\n\
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

/// What two routes must share to be peers: declared scope prefix, structural
/// prefix, method, and the static/dynamic shape of their path (which fixes
/// the segment count).
pub(crate) type PeerKey = (String, String, String, Vec<bool>);

pub(crate) fn peer_key(route: &Route) -> PeerKey {
    (
        route.scope_prefix.clone(),
        peer_prefix(route),
        route.method.clone(),
        dynamic_segment_shape(route),
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn same_peer_group(route: &Route, candidate: &Route) -> bool {
    if has_unresolved_segment(&route.path) || has_unresolved_segment(&candidate.path) {
        return false;
    }
    if peer_key(route) != peer_key(candidate) {
        return false;
    }

    if is_authentication_route(route) || is_authentication_route(candidate) {
        return route.path == candidate.path;
    }

    true
}

/// The segments of a route's full path before its last static segment:
/// `/admin` for `/admin/users` and `/admin/users/{id}`. Routes written with
/// full paths outside any scope (`/admin/users`, `/public/docs`) are only
/// peers when this prefix matches.
pub(crate) fn peer_prefix(route: &Route) -> String {
    let segments: Vec<&str> = route
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let end = segments
        .iter()
        .rposition(|segment| !is_dynamic_segment(segment))
        .unwrap_or(0);
    format!("/{}", segments[..end].join("/"))
}

pub(crate) fn dynamic_segment_shape(route: &Route) -> Vec<bool> {
    route
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(is_dynamic_segment)
        .collect()
}

pub(crate) fn is_dynamic_segment(segment: &str) -> bool {
    (segment.starts_with('{') && segment.ends_with('}'))
        || (segment.starts_with('<') && segment.ends_with('>'))
}

/// An authentication endpoint such as `/auth/login` or `/api/token/{id}`:
/// its last static segment names one. Other routes under an `/auth` or
/// `/token` prefix (`/auth/admin/purge`) are analysed like any route.
pub(crate) fn is_authentication_route(route: &Route) -> bool {
    let authentication_names = [
        "auth", "login", "logout", "register", "signup", "signin", "token", "refresh",
    ];
    route
        .path
        .split('/')
        .rfind(|segment| !segment.is_empty() && !is_dynamic_segment(segment))
        .is_some_and(|segment| {
            authentication_names.contains(&segment.to_ascii_lowercase().as_str())
        })
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

pub(crate) fn route_identity(route: &Route) -> (&str, &str, &str, Option<&str>) {
    (
        &route.method,
        &route.path,
        &route.scope_prefix,
        route.handler.as_deref(),
    )
}
