//! Routes that look public by design: findings on them are kept, at Low,
//! with the reason and an `archer.toml` rule that declares them public.
//!
//! A route looks public when all of these hold:
//! - it takes no caller and has no auth evidence of its own;
//! - it addresses no record by the path, loads no record with request data,
//!   and hands request data to no call that may fetch or store a record:
//!   every call given the request's values answers with a flag or a count
//!   (`handle_taken(&body.val) -> Result<bool>`), see `caller_use::KEYED`;
//! - it reads values from the body, query or form (an availability check, a
//!   statistic for given inputs), not nothing at all;
//! - it sits in the scope of a route that admits callers without one, such
//!   as sign-up or sign-in: the app's anonymous routes live beside it.

use super::caller_use::{BINDS, GUARDS, KEYED, LOADS, MENTIONS};
use super::drift::is_authentication_route;
use super::model::*;
use super::routes::has_unresolved_segment;

/// Whether a rule of the public-route round is on: `ARCHER_P6_<name>=0`
/// turns it off, for measuring what each one adds.
pub(crate) fn rule_on(name: &str) -> bool {
    std::env::var(format!("ARCHER_P6_{name}")).map_or(true, |value| value != "0")
}

/// Features that show a caller or a record: any one rules a route out.
fn shows_caller_or_record(feature: &str) -> bool {
    ["takes:", "auths:", "calls:", "requires:", "scheme:", "checks:", "compares:", "reads:", "acts:"]
        .iter()
        .any(|prefix| feature.starts_with(prefix))
        || [KEYED, LOADS, GUARDS, BINDS].iter().any(|prefix| feature.starts_with(prefix))
}

fn takes_no_caller(route: &Route) -> bool {
    route.best_tier() == EvidenceTier::None
        && !route.requirement.authenticated
        && !route.caller_use.iter().any(|feature| shows_caller_or_record(feature))
}

/// The scope of each route that admits callers without one, with the route:
/// the static path above it (`/api/v1` for `POST /api/v1/signup`).
fn anonymous_scopes(routes: &[Route]) -> Vec<(String, String)> {
    let mut scopes: Vec<(String, String)> = routes
        .iter()
        .filter(|route| {
            !has_unresolved_segment(&route.path)
                && is_authentication_route(route)
                && !route.caller_use.iter().any(|feature| {
                    feature.starts_with("takes:") || feature.starts_with("auths:") || feature.starts_with("calls:")
                })
        })
        .filter_map(|route| {
            let (scope, _) = route.path.trim_end_matches('/').rsplit_once('/')?;
            (!scope.is_empty()).then(|| (scope.to_string(), format!("{} {}", route.method, route.path)))
        })
        .collect();
    scopes.sort();
    scopes.dedup_by(|a, b| a.0 == b.0);
    scopes
}

/// Why a route looks public by design, if it does.
pub(crate) fn likely_public(route: &Route, scopes: &[(String, String)]) -> Option<String> {
    if has_unresolved_segment(&route.path) || !takes_no_caller(route) {
        return None;
    }
    if route.path.contains('{') {
        return None;
    }
    let body = format!("{MENTIONS}body:");
    let read: Vec<&str> = route
        .caller_use
        .iter()
        .filter_map(|feature| feature.strip_prefix(&body))
        .filter(|name| !name.is_empty())
        .collect();
    if read.is_empty() {
        return None;
    }
    let (scope, anonymous) = scopes
        .iter()
        .filter(|(scope, _)| route.path.starts_with(&format!("{scope}/")))
        .max_by_key(|(scope, _)| scope.len())?;
    Some(format!(
        "Likely public by design: it takes no caller, reads only `{}` from the request and answers with flags or counts, keyed by no record, and sits under {scope} beside {anonymous}, which admits callers without an account.",
        read.join("`, `")
    ))
}

/// Lowers findings on likely-public routes to Low, keeping them, with the
/// reason and a `[[public]]` rule to paste once reviewed.
pub(crate) fn demote_likely_public(routes: &[Route], findings: &mut [Finding]) {
    if !rule_on("S2") {
        return;
    }
    let scopes = anonymous_scopes(routes);
    for finding in findings {
        let reference = &finding.suspicious_route;
        let Some(route) = routes.iter().find(|route| {
            route.method == reference.method && route.path == reference.path && route.handler == reference.handler
        }) else {
            continue;
        };
        let Some(reason) = likely_public(route, &scopes) else {
            continue;
        };
        finding.severity = Severity::Low;
        finding.rationale.push(' ');
        finding.rationale.push_str(&reason);
        finding.evidence.notes.push(format!(
            "{reason} If so, declare it in archer.toml:\n[[public]]\nmethod = \"{}\"\npath = \"{}\"\nreason = \"reviewed: <why it is public>\"\n",
            route.method, route.path
        ));
    }
}
