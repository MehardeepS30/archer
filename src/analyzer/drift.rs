//! Peer grouping, invariant inference, and drift findings.

use super::model::*;

pub(crate) fn build_analysis_layers(
    routes: &[Route],
) -> (
    Vec<PeerGroup>,
    Vec<AuthorizationInvariant>,
    Vec<Finding>,
    Vec<String>,
) {
    let mut grouped_routes: Vec<Vec<&Route>> = Vec::new();
    for route in routes {
        if is_authentication_route(route)
            || grouped_routes.iter().any(|group| {
                group
                    .iter()
                    .any(|candidate| route_identity(candidate) == route_identity(route))
            })
        {
            continue;
        }
        let peers = unique_routes(
            routes
                .iter()
                .filter(|candidate| same_peer_group(route, candidate)),
        );
        if peers.len() >= 2 && peers.iter().any(|peer| peer.is_authorized()) {
            grouped_routes.push(peers);
        }
    }

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
        let strength = invariant_strength(authorized, peers.len());
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

        if authorized < 2 || unauthorized == 0 {
            continue;
        }
        for route in peers.iter().filter(|route| !route.is_authorized()) {
            let authorized_peer_routes: Vec<RouteReference> = peers
                .iter()
                .filter(|peer| peer.is_authorized())
                .map(|peer| (*peer).into())
                .collect();
            finding_details.push(Finding {
                peer_group_id: id.clone(),
                invariant: invariant.clone(),
                suspicious_route: (*route).into(),
                suspicious_route_evidence: route.authorization.clone(),
                authorized_peer_routes,
            });
            let peer_lines = peers
                .iter()
                .filter(|peer| peer.is_authorized())
                .map(|peer| {
                    format!(
                        "    - {} {}\n      {}",
                        peer.method,
                        peer.path,
                        format_evidence(peer)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            findings.push(format!(
                "  Suspicious route: {} {} ({}:{})\n\
  Inferred invariant: {}\n\
  Authorized peer evidence ({} route(s)):\n{}\n\
  Suspicious route evidence: {}.",
                route.method,
                route.path,
                route.file.display(),
                route.line,
                invariant.description,
                authorized,
                peer_lines,
                format_evidence(route)
            ));
        }
    }

    (peer_groups, invariants, finding_details, findings)
}

#[cfg(test)]
pub(crate) fn infer_prototype_drift(routes: &[Route]) -> Vec<String> {
    build_analysis_layers(routes).3
}

pub(crate) fn invariant_strength(authorized: usize, total: usize) -> AuthStrength {
    if authorized == total || authorized >= 3 {
        AuthStrength::Strong
    } else if authorized >= 2 {
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

pub(crate) fn format_evidence(route: &Route) -> String {
    if route.authorization.is_empty() {
        return "No recognized authorization evidence".into();
    }
    route
        .authorization
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

pub(crate) fn same_peer_group(route: &Route, candidate: &Route) -> bool {
    if route.scope_prefix != candidate.scope_prefix
        || route.method != candidate.method
        || route_segment_count(route) != route_segment_count(candidate)
        || dynamic_segment_shape(route) != dynamic_segment_shape(candidate)
    {
        return false;
    }

    if is_authentication_route(route) || is_authentication_route(candidate) {
        return route.path == candidate.path;
    }

    true
}

pub(crate) fn route_segment_count(route: &Route) -> usize {
    route
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
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

pub(crate) fn is_authentication_route(route: &Route) -> bool {
    let authentication_names = [
        "auth", "login", "logout", "register", "signup", "signin", "token", "refresh",
    ];
    route
        .path
        .split('/')
        .chain(route.scope_prefix.split('/'))
        .filter(|segment| !segment.is_empty())
        .map(str::to_ascii_lowercase)
        .any(|segment| authentication_names.contains(&segment.as_str()))
}

pub(crate) fn unique_routes<'a, I>(routes: I) -> Vec<&'a Route>
where
    I: IntoIterator<Item = &'a Route>,
{
    let mut unique: Vec<&'a Route> = Vec::new();
    for route in routes {
        if !unique
            .iter()
            .any(|candidate| route_identity(candidate) == route_identity(route))
        {
            unique.push(route);
        }
    }
    unique
}

pub(crate) fn route_identity(route: &Route) -> (&str, &str, &str, Option<&str>) {
    (
        &route.method,
        &route.path,
        &route.scope_prefix,
        route.handler.as_deref(),
    )
}
