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

/// A route whose handler is a function with no parameters and no auth
/// evidence, in an application whose handlers mostly take the request's
/// data or the application's state (not only the caller): it can
/// read nothing of the request, the application state or a database
/// handle, so every caller gets the same fixed answer (a status, the
/// build version, a "not found"). Where most handlers take nothing (a
/// sketch of an app), this says nothing about one of them.
fn fixed_answer(route: &Route, routes: &[Route]) -> Option<String> {
    if !super::rc::enabled("FIXED")
        || !route.origin.takes_nothing
        || route.best_tier() != EvidenceTier::None
        || route.requirement.authenticated
    {
        return None;
    }
    let resolved = routes.iter().filter(|other| other.origin.definition.is_some()).count();
    let taking = routes
        .iter()
        .filter(|other| other.origin.definition.is_some() && other.origin.takes_data)
        .count();
    (taking * 2 > resolved).then(|| {
        "Likely public by design: its handler takes no parameters, unlike most handlers here, so it reads neither the request nor the application's state and answers every caller alike.".to_string()
    })
}

/// A route that acts on the caller's own record (`GET /users/me` beside
/// `GET /users/{user_id}`): it authenticates, its path names no record
/// where a sibling takes one by id, and its handler works from a field
/// of the caller, loading nothing by an id the request chose. The caller
/// can reach only their own data, so the role the id-addressed siblings
/// require is not missing here.
fn own_record(route: &Route, finding: &Finding, routes: &[Route]) -> Option<String> {
    if !super::rc::enabled("SELF")
        || finding.suspicious_route_tier != EvidenceTier::Identity
        || finding.expected_tier <= EvidenceTier::Identity
        || has_unresolved_segment(&route.path)
    {
        return None;
    }
    let (parent, last) = route.path.rsplit_once('/')?;
    if last.is_empty() || last.contains('{') {
        return None;
    }
    let addressed = format!("{parent}/{{");
    let sibling = routes
        .iter()
        .find(|other| other.path.starts_with(&addressed) && other.path != route.path)?;
    let field = route
        .caller_use
        .iter()
        .find_map(|feature| feature.strip_prefix("reads:").and_then(|rest| rest.split_once(':')).map(|(_, field)| field))?;
    let unguarded = route.caller_use.iter().filter_map(|feature| feature.strip_prefix(LOADS)).any(|key| {
        let guard = format!("{GUARDS}{key}:");
        !route.caller_use.iter().any(|feature| feature.starts_with(&guard))
    });
    if unguarded {
        return None;
    }
    Some(format!(
        "Likely the caller's own record: the path names no record where {} {} takes one by id, and the handler works from the caller's own `{field}`, so it can reach only the caller's data. Dismiss if so.",
        sibling.method, sibling.path
    ))
}

/// The security requirement a handler's OpenAPI annotation declares:
/// `#[utoipa::path(.. security(("api_key" = ["admin"])))]` gives
/// `("api_key"=["admin"])`. An annotation without `security`, or one that
/// admits a request without any (`security(())`, `security((), (..))`),
/// gives the empty string; a handler without an annotation gives `None`.
/// The annotation is found inside `cfg_attr` too.
pub(crate) fn openapi_security(attributes: &[syn::Attribute]) -> Option<String> {
    use proc_macro2::{Delimiter, TokenStream, TokenTree};
    fn annotation(tokens: TokenStream) -> Option<TokenStream> {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (index, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Ident(ident) if ident == "path" => {
                    if let Some(TokenTree::Group(group)) = trees.get(index + 1)
                        && group.delimiter() == Delimiter::Parenthesis
                    {
                        return Some(group.stream());
                    }
                }
                TokenTree::Group(group) => {
                    if let Some(found) = annotation(group.stream()) {
                        return Some(found);
                    }
                }
                _ => {}
            }
        }
        None
    }
    let body = attributes
        .iter()
        .find_map(|attribute| annotation(quote::ToTokens::to_token_stream(&attribute.meta)))?;
    let trees: Vec<TokenTree> = body.into_iter().collect();
    let declared = trees.iter().enumerate().find_map(|(index, tree)| match tree {
        TokenTree::Ident(ident) if ident == "security" => match trees.get(index + 1) {
            Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis => Some(group.stream()),
            _ => None,
        },
        _ => None,
    });
    let Some(declared) = declared else {
        return Some(String::new());
    };
    let alternatives: Vec<TokenTree> = declared.clone().into_iter().collect();
    let admits_none = alternatives.is_empty()
        || alternatives.iter().any(|tree| match tree {
            TokenTree::Group(group) => group.stream().is_empty(),
            _ => false,
        });
    if admits_none {
        return Some(String::new());
    }
    Some(declared.to_string().split_whitespace().collect())
}

/// Whether the application documents security per route: most of its
/// annotated handlers declare a requirement, so one that declares none
/// says so on purpose. An app that declares it once for the whole
/// document annotates no handler with it, and this says nothing there.
fn documents_security(routes: &[Route]) -> Option<(usize, usize)> {
    let annotated = routes.iter().filter(|route| route.origin.openapi.is_some()).count();
    let declaring = routes
        .iter()
        .filter(|route| route.origin.openapi.as_deref().is_some_and(|security| !security.is_empty()))
        .count();
    (annotated >= 4 && declaring * 2 > annotated).then_some((declaring, annotated))
}

/// A route whose difference from its peers the application's own API
/// document states: its annotation declares no security requirement where
/// most annotated handlers declare one, or declares another requirement
/// than every annotated peer the finding cites. The difference is written
/// down twice, in the handler and in the document, so it is likely meant.
fn documented(route: &Route, finding: &Finding, routes: &[Route]) -> Option<String> {
    if !super::pu::enabled("OPENAPI") {
        return None;
    }
    let own = route.origin.openapi.as_deref()?;
    if own.is_empty() {
        if let Some((declaring, annotated)) = documents_security(routes) {
            return Some(format!(
                "Likely public by design: its OpenAPI annotation declares no security requirement, where {declaring} of {annotated} annotated handlers here declare one, so the API document states it as open."
            ));
        }
        // An application that documents security in one part only (an
        // older API version, one module): the peers compared say whether
        // the annotation means anything here.
        let annotated: Vec<&str> = finding
            .authorized_peer_routes
            .iter()
            .filter_map(|peer| {
                routes
                    .iter()
                    .find(|other| other.method == peer.method && other.path == peer.path && other.handler == peer.handler)
            })
            .filter_map(|peer| peer.origin.openapi.as_deref())
            .collect();
        let declaring = annotated.iter().filter(|security| !security.is_empty()).count();
        return (super::pu::enabled("PEERDOCS") && annotated.len() >= 3 && declaring * 2 > annotated.len()).then(|| {
            format!(
                "Likely public by design: its OpenAPI annotation declares no security requirement, where {declaring} of the {} annotated peers compared declare one, so the API document states it as open.",
                annotated.len()
            )
        });
    }
    documents_security(routes)?;
    if !matches!(
        finding.category,
        FindingCategory::MissingAuthorization | FindingCategory::WeakerAuthorization | FindingCategory::DifferentAuthorization
    ) {
        return None;
    }
    let peers: Vec<&str> = finding
        .authorized_peer_routes
        .iter()
        .filter_map(|peer| {
            routes
                .iter()
                .find(|other| other.method == peer.method && other.path == peer.path && other.handler == peer.handler)
        })
        .filter_map(|peer| peer.origin.openapi.as_deref())
        .filter(|security| !security.is_empty())
        .collect();
    let example = *peers.first()?;
    (peers.len() >= 2 && peers.iter().all(|security| *security != own)).then(|| {
        format!(
            "Likely intended: its OpenAPI annotation declares `security({own})` where the {} annotated peers compared declare another requirement (e.g. `security({example})`), so the API document states the difference.",
            peers.len()
        )
    })
}

/// The words of a route that name it: its path's static segments, its
/// handler's name and the modules the handler is defined in.
fn name_words(route: &Route) -> (Vec<String>, Vec<String>) {
    let split = |text: &str| -> Vec<String> {
        text.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    };
    let path: Vec<String> = route
        .path
        .split('/')
        .filter(|segment| !segment.contains('{') && !segment.contains('<'))
        .flat_map(split)
        .collect();
    let mut handler: Vec<String> = route.handler.as_deref().map(split).unwrap_or_default();
    for key in &route.resource_keys {
        if let Some(defined) = key.strip_prefix("handler ") {
            handler.extend(split(defined));
        }
    }
    (path, handler)
}

/// A route the application names as open to anyone: a word of its path,
/// of its handler or of the handler's module says that it serves the
/// public (`/published/{name}`, `mod public`), answers whether a name is
/// free before sign-up (`/username/exists`), serves what a page shows to a
/// visitor (`/logo`, `/favicon`, `/tos`, `/privacy`), or speaks a
/// server-to-server protocol whose callers have no account (`apub`,
/// `webfinger`, `nodeinfo`, `.well-known`). Only a route that takes no
/// caller at all is read this way, and only a read, except for the
/// sign-up form's availability checks and a static-file route that loads
/// no record.
fn named_public(route: &Route) -> Option<String> {
    const OPEN: [&str; 30] = [
        "public", "published", "publish", "unauthenticated", "unauth", "noauth", "anonymous", "anon",
        "guest", "shared", "share", "logo", "favicon", "icon", "avatar", "badge", "banner", "emoji",
        "tos", "terms", "privacy", "legal", "about", "faq", "robots", "sitemap", "rss", "atom",
        "oembed", "opengraph",
    ];
    const AVAILABILITY: [&str; 5] = ["exists", "exist", "available", "availability", "taken"];
    const STATIC: [&str; 3] = ["static", "assets", "asset"];
    const PROTOCOL: [&str; 6] = ["apub", "activitypub", "webfinger", "nodeinfo", "jwks", "wellknown"];
    const MACHINE: [&str; 3] = ["webhook", "webhooks", "ipn"];
    if !super::pu::enabled("NAMED") || route.best_tier() != EvidenceTier::None || route.requirement.authenticated {
        return None;
    }
    if route.caller_use.iter().any(|feature| {
        ["takes:", "auths:", "requires:", "checks:", "compares:"].iter().any(|prefix| feature.starts_with(prefix))
    }) {
        return None;
    }
    let (path, handler) = name_words(route);
    let read = matches!(route.method.as_str(), "GET" | "HEAD");
    let well_known = route.path.contains("/.well-known/");
    let found = |words: &[String], list: &[&str]| words.iter().find(|word| list.contains(&word.as_str())).cloned();
    let (word, what) = if let Some(word) = found(&path, &AVAILABILITY).or_else(|| found(&handler, &AVAILABILITY)) {
        (word, "answers whether a name or record exists, as a sign-up form asks before there is an account")
    } else if let Some(word) = found(&path, &STATIC).filter(|_| route.caller_use.iter().all(|feature| !feature.starts_with(LOADS))) {
        (word, "serves the files of the application's own pages")
    } else if let Some(word) = found(&handler, &MACHINE)
        .or_else(|| found(&path, &MACHINE))
        .filter(|_| super::pu::enabled("WEBHOOK") && !read)
    {
        (word, "is called by another service, which signs its request and has no account to log in with")
    } else if !read {
        return None;
    } else if well_known {
        (".well-known".to_string(), "is a discovery document other servers fetch without an account")
    } else if let Some(word) = found(&handler, &PROTOCOL).or_else(|| found(&path, &PROTOCOL)) {
        (word, "is an endpoint of a server-to-server protocol, whose callers are other servers without an account here")
    } else {
        let word = found(&path, &OPEN).or_else(|| found(&handler, &OPEN))?;
        (word, "is what the application shows to anyone")
    };
    Some(format!(
        "Likely public by design: it takes no caller and is named `{word}`, which {what}."
    ))
}

/// A route that calls the application's own guard for open access
/// (`protect_public_account_route` beside `protect_account_route`): the
/// handler picked the variant its author named public, optional or
/// anonymous, so the weaker check is a choice written in the code.
fn guarded_as_public(route: &Route) -> Option<String> {
    const OPEN: [&str; 5] = ["public", "optional", "anonymous", "unauthenticated", "maybe"];
    if !super::pu::enabled("GUARDNAME") {
        return None;
    }
    let guard = route.caller_use.iter().find_map(|feature| {
        let name = feature.strip_prefix("calls:").or_else(|| feature.strip_prefix("takes:"))?;
        let name = name.trim_end_matches("()");
        if name.contains('<') {
            return None;
        }
        name.split(|c: char| !c.is_ascii_alphanumeric())
            .flat_map(super::evidence::camel_case_words)
            .any(|word| OPEN.contains(&word.as_str()))
            .then(|| name.to_string())
    })?;
    Some(format!(
        "Likely intended: it goes through `{guard}`, the guard this application names for open access, where its peers call another."
    ))
}

/// A route whose handler reads the caller and goes on without one
/// (`current_user(&req).await.ok()`, an `Option<User>` handed on): the
/// code for the anonymous case is written out, so serving anonymous
/// callers is a decision, and the caller only adapts the answer.
fn optional_login(route: &Route, finding: &Finding) -> Option<String> {
    if !super::pu::enabled("OPTIONAL")
        || route.best_tier() != EvidenceTier::None
        || route.requirement.authenticated
        || !matches!(finding.category, FindingCategory::MissingAuthentication | FindingCategory::MissingAuthorization)
    {
        return None;
    }
    let source = route.caller_use.iter().find_map(|feature| {
        if let Some(label) = feature.strip_prefix(super::caller_use::OPTIONAL) {
            return Some(format!("{}.ok()", label.trim_end_matches("()")));
        }
        ["takes:", "acts:", "hands:", "compares:"]
            .iter()
            .find_map(|prefix| feature.strip_prefix(prefix))
            .filter(|label| label.starts_with("Option<"))
            .map(str::to_string)
    })?;
    // Taken and never looked at (`_user: Option<User>` on a write) is not
    // a decision about anonymous callers: the handler has to do something
    // with the caller it may have.
    let label = source.trim_end_matches(".ok()");
    let used = route.caller_use.iter().any(|feature| {
        ["hands:", "compares:", "reads:"]
            .iter()
            .find_map(|prefix| feature.strip_prefix(prefix))
            .is_some_and(|rest| rest.starts_with(label))
    });
    if !used {
        return None;
    }
    Some(format!(
        "Likely public by design: it reads the caller optionally (`{source}`) and goes on without one, so it serves anonymous callers on purpose and only adapts its answer to a signed-in one."
    ))
}

/// A route that authenticates its sender by a secret the request presents
/// (a webhook's shared secret, an agent's host key) while its peers
/// require a user's role: the sender is a machine with no account, so a
/// role cannot be asked of it. The two are different kinds of caller.
fn machine_caller(route: &Route, finding: &Finding) -> Option<String> {
    const SECRETS: [&str; 5] = ["secret", "signature", "hmac", "webhook", "psk"];
    if !super::pu::enabled("SECRET")
        || finding.expected_tier <= EvidenceTier::Identity
        || !matches!(finding.category, FindingCategory::WeakerAuthorization | FindingCategory::MissingAuthorization)
    {
        return None;
    }
    let names_secret = |evidence: &AuthEvidence| {
        evidence.symbol.as_deref().is_some_and(|symbol| {
            symbol
                .split(|c: char| !c.is_ascii_alphanumeric())
                .flat_map(super::evidence::camel_case_words)
                .any(|word| SECRETS.contains(&word.as_str()))
        })
    };
    let secret = route.authorization.iter().find(|evidence| {
        evidence.kind == AuthEvidenceKind::SecretCheck
            || (evidence.kind == AuthEvidenceKind::IdentityExtraction && names_secret(evidence))
    })?;
    let user = route.authorization.iter().any(|evidence| {
        matches!(
            evidence.kind,
            AuthEvidenceKind::OwnershipCheck | AuthEvidenceKind::RoleCheck | AuthEvidenceKind::PermissionCheck
        ) || (evidence.kind == AuthEvidenceKind::IdentityExtraction && !names_secret(evidence))
    }) || route.caller_use.iter().any(|feature| feature.starts_with("takes:"));
    (!user).then(|| {
        format!(
            "Likely another kind of caller: it takes no user and authenticates the sender by a secret the request presents (`{}`), as a webhook or an agent does, so what its peers require of users does not apply to it.",
            secret.symbol.as_deref().unwrap_or(&secret.mechanism)
        )
    })
}

/// A route that holds the record its path names to the caller (`POST
/// /users/{id}/self/..` comparing `{id}` with the session's user) beside
/// routes on the same records that require a role: the caller reaches
/// only their own record, which is what the role protects the others'
/// records from. Self-service beside administration is two designs, not
/// one check forgotten.
fn self_service(route: &Route, finding: &Finding) -> Option<String> {
    if !super::pu::enabled("SELFSERVICE")
        || finding.category != FindingCategory::WeakerAuthorization
        || finding.suspicious_route_tier != EvidenceTier::Resource
        || finding.expected_tier != EvidenceTier::Privilege
        || !route.requirement.ownership
    {
        return None;
    }
    let bound = route.caller_use.iter().any(|feature| feature.starts_with(&format!("{BINDS}path:")));
    let compares = route.caller_use.iter().any(|feature| feature.starts_with("compares:"));
    (bound && compares).then(|| {
        "Likely self-service: it holds the record its path names to the caller, so a caller reaches only their own record, where its peers require a role to reach anyone's.".to_string()
    })
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
        if let Some(reason) = own_record(route, finding, routes) {
            finding.severity = Severity::Low;
            finding.rationale.push(' ');
            finding.rationale.push_str(&reason);
            continue;
        }
        if let Some(reason) = guarded_as_public(route)
            .or_else(|| optional_login(route, finding))
            .or_else(|| machine_caller(route, finding))
            .or_else(|| self_service(route, finding))
        {
            if finding.severity != Severity::Low {
                finding.severity = Severity::Low;
                finding.rationale.push(' ');
                finding.rationale.push_str(&reason);
                finding.rationale.push_str(" Dismiss if so.");
            }
            continue;
        }
        if let Some(security) = route.origin.openapi.as_deref().filter(|security| !security.is_empty())
            && super::pu::enabled("OPENAPI")
            && documents_security(routes).is_some()
            && route.best_tier() == EvidenceTier::None
            && matches!(finding.category, FindingCategory::MissingAuthentication | FindingCategory::MissingAuthorization)
        {
            finding.evidence.notes.push(format!(
                "Its OpenAPI annotation declares `security({security})`, which nothing Archer reads in the handler enforces."
            ));
        }
        let Some(reason) = fixed_answer(route, routes)
            .or_else(|| likely_public(route, &scopes))
            .or_else(|| documented(route, finding, routes))
            .or_else(|| named_public(route))
        else {
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
