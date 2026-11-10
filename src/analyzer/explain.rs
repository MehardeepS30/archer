//! The case for each finding, stated so a reviewer can check it by hand.
//!
//! Every finding gets the check its peers make, up to five peers that make
//! it with file and line, what the route has instead, notes on protection
//! Archer cannot evaluate, and an `archer.toml` rule that dismisses it once
//! the difference is found intended. Checks that set these themselves
//! (the skipped-check comparison knows each peer's call site) keep them.

use std::collections::HashMap;

use super::model::*;

/// Support that holds even where the group is loose: at least this share
/// of the compared peers, and at least this many, make the check.
pub(crate) const STRONG_SHARE: f64 = 0.8;
pub(crate) const STRONG_COUNT: usize = 5;

pub(crate) fn strong_support(supporting: usize, compared: usize) -> bool {
    compared > 0 && supporting >= STRONG_COUNT && supporting as f64 >= STRONG_SHARE * compared as f64
}

/// Peers listed per finding.
pub(crate) const PEERS_SHOWN: usize = 5;

pub(crate) fn explain(findings: &mut [Finding]) {
    for finding in findings {
        let mut evidence = std::mem::take(&mut finding.evidence);
        if evidence.check.is_empty() {
            fill_from_peers(finding, &mut evidence);
        }
        if evidence.compared == 0 {
            evidence.compared = finding.invariant.total_routes.saturating_sub(1).max(evidence.supporting);
        }
        evidence.instead = instead(&finding.suspicious_route_evidence);
        if finding.category != FindingCategory::UnverifiedProtection {
            evidence.notes.extend(unevaluated(&finding.suspicious_route_evidence));
        }
        evidence.dismiss = dismiss_rule(finding);
        finding.evidence = evidence;
    }
}

/// The evidence a peer shows for the check: for a role or permission
/// difference, the evidence naming the peers' requirement; otherwise the
/// peer's strongest evaluated evidence.
fn peer_check<'a>(finding: &Finding, peer: &'a RouteReference) -> Option<&'a AuthEvidence> {
    let evaluated = || {
        peer.authorization
            .iter()
            .filter(|evidence| !matches!(evidence.kind, AuthEvidenceKind::Unknown | AuthEvidenceKind::Delegated))
    };
    if let Some(required) = finding.invariant.dominant_requirement.as_deref()
        && let Some(found) = evaluated().find(|evidence| evidence.requirements.iter().any(|named| named == required))
    {
        return Some(found);
    }
    evaluated()
        .filter(|evidence| EvidenceTier::of(&evidence.kind) <= finding.expected_tier.max(EvidenceTier::Identity))
        .max_by_key(|evidence| {
            (
                EvidenceTier::of(&evidence.kind),
                // An extractor that reads no credential (a pool, a metrics
                // handle) is not the check, whatever tier its body reads as.
                super::extractors::reads_credential(evidence),
                evidence.symbol.as_deref().map_or(0, |symbol| symbol.matches(" -> ").count()),
            )
        })
        .or_else(|| evaluated().max_by_key(|evidence| EvidenceTier::of(&evidence.kind)))
}

fn describe(evidence: &AuthEvidence) -> String {
    // A check made by an extractor the handler's own extractor runs: say
    // what it does, and how the handler reaches it.
    if evidence.mechanism.ends_with(super::extractors::CREDENTIAL_PATH_CHECK) {
        let mut text = format!("{}: {}", kind_label(&evidence.kind), evidence.mechanism);
        if let Some(chain) = evidence.symbol.as_deref().filter(|symbol| symbol.contains(" -> ")) {
            text.push_str(&format!(" (reached as `{chain}`)"));
        }
        return text;
    }
    let what = evidence.symbol.as_deref().unwrap_or(&evidence.mechanism);
    let mut text = format!("{}: `{what}`", kind_label(&evidence.kind));
    if !evidence.requirements.is_empty() && !what.contains(&evidence.requirements[0]) {
        text.push_str(&format!(" requiring {}", evidence.requirements.iter().map(|named| format!("`{named}`")).collect::<Vec<_>>().join(", ")));
    }
    text
}

fn kind_label(kind: &AuthEvidenceKind) -> &'static str {
    match kind {
        AuthEvidenceKind::RoleCheck => "role check",
        AuthEvidenceKind::PermissionCheck => "permission check",
        AuthEvidenceKind::AuthorizationGuard => "authorization guard",
        AuthEvidenceKind::AuthorizationMiddleware => "authorization middleware",
        AuthEvidenceKind::IdentityExtraction => "takes the caller",
        AuthEvidenceKind::OwnershipCheck => "ownership check",
        AuthEvidenceKind::SecretCheck => "secret check",
        AuthEvidenceKind::ManualAuthorizationCheck => "authorization check",
        AuthEvidenceKind::Unknown => "unrecognized component",
        AuthEvidenceKind::Delegated => "handed to unanalyzed code",
    }
}

fn fill_from_peers(finding: &Finding, evidence: &mut FindingEvidence) {
    let checks: Vec<(&RouteReference, &AuthEvidence)> = finding
        .authorized_peer_routes
        .iter()
        .filter_map(|peer| peer_check(finding, peer).map(|found| (peer, found)))
        .collect();
    // The check most of them make, by kind and mechanism.
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for (_, found) in &checks {
        *counts.entry((kind_label(&found.kind).to_string(), found.mechanism.clone())).or_default() += 1;
    }
    let leading = counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(key, _)| key.clone());
    let leading_first = |found: &AuthEvidence| {
        leading.as_ref().is_some_and(|(kind, mechanism)| kind_label(&found.kind) == kind && &found.mechanism == mechanism)
    };
    let mut ordered = checks.clone();
    ordered.sort_by_key(|(_, found)| !leading_first(found));
    evidence.check = ordered
        .first()
        .map(|(_, found)| describe(found))
        .unwrap_or_else(|| finding.invariant.description.clone());
    evidence.supporting = finding.authorized_peer_routes.len();
    evidence.peers = ordered
        .iter()
        .take(PEERS_SHOWN)
        .map(|(peer, found)| PeerCheck {
            method: peer.method.clone(),
            path: peer.path.clone(),
            check: describe(found),
            file: found.file.clone(),
            line: found.line,
        })
        .collect();
}

fn instead(own: &[AuthEvidence]) -> Vec<String> {
    let listed: Vec<String> = own
        .iter()
        .filter(|evidence| !matches!(evidence.kind, AuthEvidenceKind::Unknown | AuthEvidenceKind::Delegated))
        .map(|evidence| format!("{} ({}:{})", describe(evidence), evidence.file.display(), evidence.line))
        .collect();
    if listed.is_empty() {
        vec!["no authorization evidence Archer recognizes".into()]
    } else {
        listed
    }
}

fn unevaluated(own: &[AuthEvidence]) -> Vec<String> {
    own.iter()
        .filter(|evidence| matches!(evidence.kind, AuthEvidenceKind::Unknown | AuthEvidenceKind::Delegated))
        .map(|evidence| {
            format!(
                "{} ({}:{}) was not evaluated; check whether it makes the peers' check",
                describe(evidence),
                evidence.file.display(),
                evidence.line
            )
        })
        .collect()
}

fn dismiss_rule(finding: &Finding) -> String {
    format!(
        "[[dismiss]]\nmethod = \"{}\"\npath = \"{}\"\ncategory = \"{:?}\"\nreason = \"reviewed: <why the difference is intended>\"\n",
        finding.suspicious_route.method, finding.suspicious_route.path, finding.category
    )
}
