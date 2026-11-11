//! Report data model: routes, authorization evidence, peer groups, invariants, findings.

use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum AuthEvidenceKind {
    RoleCheck,
    PermissionCheck,
    AuthorizationGuard,
    AuthorizationMiddleware,
    IdentityExtraction,
    OwnershipCheck,
    /// The request presents a secret (a token, signature or password) that
    /// the code compares with a stored one: access to that object without
    /// an account.
    SecretCheck,
    ManualAuthorizationCheck,
    /// A guard or middleware that Archer cannot classify. It may protect the
    /// route, so a route carrying one is never reported as unprotected, only
    /// as unverified.
    Unknown,
    /// The caller's identity or an authentication object is handed to code
    /// Archer does not analyze: a method call such as `toc(&auth)` or
    /// `principal.validate_admin_session()`, or an `auth::ApiKeyAuth` passed
    /// to a request wrapper. Checks may happen there, so a route carrying
    /// this is reported only as unverified.
    Delegated,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum AuthStrength {
    Strong,
    Medium,
    Weak,
}

impl std::fmt::Display for AuthEvidenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RoleCheck => "role check",
            Self::PermissionCheck => "permission check",
            Self::AuthorizationGuard => "authorization guard",
            Self::AuthorizationMiddleware => "authorization middleware",
            Self::IdentityExtraction => "identity extraction (not authorization)",
            Self::OwnershipCheck => "ownership check",
            Self::SecretCheck => "secret check",
            Self::ManualAuthorizationCheck => "manual authorization check",
            Self::Unknown => "unrecognized guard or middleware",
            Self::Delegated => "identity passed to code Archer does not analyze",
        })
    }
}

impl std::fmt::Display for AuthStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Strong => "strong",
            Self::Medium => "medium",
            Self::Weak => "weak",
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthEvidence {
    pub kind: AuthEvidenceKind,
    pub mechanism: String,
    pub symbol: Option<String>,
    pub file: PathBuf,
    pub line: usize,
    pub handler: Option<String>,
    pub strength: AuthStrength,
    /// Normalized subjects the check requires, such as `admin` for
    /// `require_admin`, `AdminUser`, `#[has_roles("ADMIN")]`, or
    /// `user.role == Role::Admin`. Empty when no subject can be read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<String>,
    /// Recognized only by an identifier's name (a field called `owner_id`,
    /// a helper called `is_member`), not by what the code does with it.
    /// Shown so the user can weigh it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub name_based: bool,
}

impl AuthEvidence {
    pub fn is_authorization(&self) -> bool {
        matches!(
            self.kind,
            AuthEvidenceKind::RoleCheck
                | AuthEvidenceKind::PermissionCheck
                | AuthEvidenceKind::AuthorizationGuard
                | AuthEvidenceKind::AuthorizationMiddleware
                | AuthEvidenceKind::OwnershipCheck
                | AuthEvidenceKind::SecretCheck
                | AuthEvidenceKind::ManualAuthorizationCheck
        )
    }
}

/// How a route's handler expression was matched to a handler definition.
/// Only `Definition`, `Local`, `Imported`, `GlobImported`, `Qualified`, and
/// `UniqueName` attach the definition's evidence to the route.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum HandlerResolution {
    /// Attribute route: the annotated function is the handler.
    Definition,
    /// Defined in the module that registers the route.
    Local,
    /// Brought into scope by an explicit, possibly renamed, `use`.
    Imported,
    /// Brought into scope by exactly one matching glob `use`.
    GlobImported,
    /// Module-qualified path such as `handlers::payments`.
    Qualified,
    /// Path rules found nothing; the crate holds exactly one compatible definition.
    UniqueName,
    /// The handler is a closure written at the route; its own parameters and
    /// body are the evidence.
    Closure,
    /// Several definitions match; no evidence is attached.
    Ambiguous { candidates: Vec<String> },
    /// No definition could be identified; no evidence is attached.
    Unresolved,
}

#[derive(Debug, Clone, Serialize)]
pub struct Route {
    pub method: String,
    pub path: String,
    pub scope_prefix: String,
    pub handler: Option<String>,
    pub handler_path: Option<String>,
    pub handler_resolution: Option<HandlerResolution>,
    pub authorization: Vec<AuthEvidence>,
    pub line: usize,
    pub file: PathBuf,
    /// Why the route's protection cannot be fully judged statically, such as
    /// an unresolved handler. A route with reasons is never reported as
    /// missing authorization, only as unverified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unverified: Vec<String>,
    /// What the route's evidence requires of a caller, field by field.
    pub requirement: Requirement,
    /// What links the route to routes serving the same data: its handler
    /// definition, repository functions it calls, model types it names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_keys: Vec<String>,
    /// How the handler uses the caller's identity (`takes:T`, `reads:T:field`,
    /// `passes:T:callee`, `compares:T`), for comparison with peers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caller_use: Vec<String>,
    /// Extraction bookkeeping that is not part of the report.
    #[serde(skip)]
    pub(crate) origin: RouteOrigin,
}

/// What a route requires of its caller, read from its evidence. Peers are
/// compared on these fields; `EvidenceTier` is their summary for ranking.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Requirement {
    /// The caller must be identified.
    pub authenticated: bool,
    /// Roles or permissions a check names, sorted.
    pub roles: Vec<String>,
    /// The roles come from one allow-list (`allowed_roles([Admin, Editor])`):
    /// any one of them admits the caller.
    pub roles_any_of: bool,
    /// The handler compares a record's owner with the caller.
    pub ownership: bool,
    /// The handler checks the caller's relation to a record (member,
    /// moderator): an object-level role, not ownership.
    pub relation: bool,
    /// Some protection could not be evaluated. It never meets a peer's
    /// requirement; it only turns a shortfall into "review manually".
    pub unverified: bool,
}

/// Mechanism text of a check on the caller's relation to a record.
pub const RELATION_CHECK: &str = "the caller's relation to the data allows it";

impl Requirement {
    pub fn of(route: &Route) -> Self {
        let tier = route.best_tier();
        let roles: Vec<String> = route
            .privilege_requirements()
            .into_iter()
            .map(str::to_owned)
            .collect();
        // One check that admits several roles is an allow-list: a guard's
        // or middleware's role list, or a role check whose roles are the
        // arms it lets through, the variants it matches or the ones at or
        // above a rank. Several permissions in one check can be required
        // together, so only roles count.
        let roles_any_of = roles.len() > 1
            && route.authorization.iter().any(|evidence| {
                evidence.requirements.len() > 1
                    && (evidence.kind == AuthEvidenceKind::RoleCheck
                        || evidence
                            .symbol
                            .as_deref()
                            .is_some_and(|symbol| symbol.starts_with(".wrap") || symbol.starts_with(".guard")))
            });
        Self {
            authenticated: tier >= EvidenceTier::Identity,
            roles,
            roles_any_of,
            ownership: route.authorization.iter().any(|evidence| {
                evidence.kind == AuthEvidenceKind::OwnershipCheck
                    && !evidence.mechanism.contains(RELATION_CHECK)
            }),
            relation: route.authorization.iter().any(|evidence| {
                evidence.kind == AuthEvidenceKind::OwnershipCheck
                    && evidence.mechanism.contains(RELATION_CHECK)
            }),
            unverified: !route.unverified.is_empty()
                || route.authorization.iter().any(|evidence| {
                    matches!(evidence.kind, AuthEvidenceKind::Unknown | AuthEvidenceKind::Delegated)
                }),
        }
    }
}

/// Where a route was found, for ordering and for later extraction passes.
#[derive(Debug, Clone, Default)]
pub(crate) struct RouteOrigin {
    /// Line and column of the registering call or attribute, for source order.
    pub(crate) position: (usize, usize),
    /// For attribute routes: the handler definition and the attribute's own
    /// path, so the route can be re-rooted where `.service(handler)` registers it.
    pub(crate) attribute: Option<(usize, String)>,
    /// The module-level function whose own body (not a `.configure` expansion
    /// of it) produced the route.
    pub(crate) enclosing: Option<usize>,
    /// The handler definition the route resolved to, if any.
    pub(crate) definition: Option<usize>,
    /// Names of the repository functions its handler calls, other than
    /// checks and other handlers, for telling what the handler does.
    pub(crate) called: Vec<String>,
    /// Its handler takes a request body with a credential field.
    pub(crate) takes_credentials: bool,
    /// P13: its handler takes the raw request or a header, cookie or
    /// session extractor, so it can read a credential by itself.
    pub(crate) sees_request: bool,
    /// P13: registered on an `App` that is built but never served (one
    /// built only to produce the OpenAPI document).
    pub(crate) unserved: bool,
    /// P13: the `App::new()` the route was registered under, as
    /// `file:line:column`; `None` when no `App` constructor encloses it.
    pub(crate) app: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteReference {
    pub method: String,
    pub path: String,
    pub handler: Option<String>,
    pub file: PathBuf,
    pub line: usize,
    pub authorized: bool,
    pub tier: EvidenceTier,
    pub authorization: Vec<AuthEvidence>,
}

impl From<&Route> for RouteReference {
    fn from(route: &Route) -> Self {
        Self {
            method: route.method.clone(),
            path: route.path.clone(),
            handler: route.handler.clone(),
            file: route.file.clone(),
            line: route.line,
            authorized: route.is_authorized(),
            tier: route.best_tier(),
            authorization: route.authorization.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerGroup {
    pub id: String,
    pub description: String,
    /// The path prefix the group's routes share: a resource such as
    /// `/admin/users`, or a namespace such as `/admin`; see `GroupLevel`.
    pub prefix: String,
    pub level: GroupLevel,
    pub method_class: MethodClass,
    pub routes: Vec<RouteReference>,
}

/// How specific a peer group is. Routes are compared with the routes of
/// their own resource; a route whose resource has too few comparable routes
/// is compared with its whole namespace instead.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GroupLevel {
    /// One resource: `/admin/users`, `/admin/users/{id}`, `/admin/users/{id}/roles`.
    Resource,
    /// A declared scope, or for unscoped routes their leading segment(s).
    Namespace,
    /// A declared scope together with the scopes nested in it, used when a
    /// route's own scope holds no other route of its class: `/admin` for a
    /// lone read in `/admin/tagline`.
    Subtree,
    /// Registrations of one handler definition at several paths.
    Handler,
    /// Routes linked by the data they serve: a shared handler, repository
    /// function, or model type, whatever their paths.
    Linked,
    /// Every route under one API version root (`/api/v1`), used when no
    /// scope below it holds peers. Findings at this level are Low.
    Version,
    /// Every route of the application, the last fallback for a route with
    /// no peers anywhere narrower. Findings at this level are Low.
    App,
}

impl GroupLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Namespace => "namespace",
            Self::Subtree => "scope tree",
            Self::Handler => "handler",
            Self::Linked => "linked routes",
            Self::Version => "API version",
            Self::App => "whole app",
        }
    }

    /// A last-resort level, wider than any scope the route is in.
    pub fn is_fallback(self) -> bool {
        matches!(self, Self::Version | Self::App)
    }
}

/// Reads and writes of one resource are compared separately: reads are often
/// public where writes are not. Writes are additionally held to the tier
/// their resource's reads reach.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MethodClass {
    /// GET, HEAD, OPTIONS, TRACE.
    Read,
    /// POST, PUT, PATCH, DELETE, and routes answering any or an unknown method.
    Write,
}

impl std::fmt::Display for MethodClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
        })
    }
}

impl MethodClass {
    pub fn of(method: &str) -> Self {
        match method {
            "GET" | "HEAD" | "OPTIONS" | "TRACE" => Self::Read,
            _ => Self::Write,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationInvariant {
    pub peer_group_id: String,
    pub description: String,
    pub total_routes: usize,
    pub routes_with_authorization: usize,
    pub routes_without_authorization: usize,
    pub evidence_patterns: Vec<String>,
    pub strength: AuthStrength,
    /// The tier a dominant share of the group reaches, if any.
    pub expected_tier: Option<EvidenceTier>,
    /// A requirement (such as `admin`) that a dominant share of the group's
    /// privilege-tier routes carries.
    pub dominant_requirement: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub peer_group_id: String,
    pub category: FindingCategory,
    pub severity: Severity,
    /// One sentence on why the route was reported.
    pub rationale: String,
    pub invariant: AuthorizationInvariant,
    pub suspicious_route: RouteReference,
    /// The best tier of the suspicious route's own evidence.
    pub suspicious_route_tier: EvidenceTier,
    /// The tier a dominant share of the route's peers reaches.
    pub expected_tier: EvidenceTier,
    pub suspicious_route_evidence: Vec<AuthEvidence>,
    /// Peers that reach `expected_tier`, with their evidence.
    pub authorized_peer_routes: Vec<RouteReference>,
    /// What the finding rests on, for a reviewer to check: see
    /// [`FindingEvidence`].
    pub evidence: FindingEvidence,
}

/// The case for a finding, stated so it can be checked by hand: the check
/// the peers make, where some of them make it, what this route has
/// instead, and how to record the finding as reviewed.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct FindingEvidence {
    /// The check the peers make, as a call, comparison or component.
    pub check: String,
    /// How many of the compared peers make it, and how many were compared.
    pub supporting: usize,
    pub compared: usize,
    /// Up to five peers that make it, each with where.
    pub peers: Vec<PeerCheck>,
    /// The route's own evidence, or that it has none Archer recognizes.
    pub instead: Vec<String>,
    /// Protection on the route that Archer cannot evaluate and that did not
    /// lower the severity, because it cannot be the missing check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// A rule to paste into `archer.toml` once the difference is reviewed
    /// and found intended.
    pub dismiss: String,
}

/// One peer that makes the check, and where.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeerCheck {
    pub method: String,
    pub path: String,
    pub check: String,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum FindingCategory {
    /// The route has no evidence at all while its peers at least
    /// authenticate the caller.
    MissingAuthentication,
    /// The route has no authorization evidence while its peers do.
    MissingAuthorization,
    /// The route has authorization evidence, but of a lower tier than its
    /// peers', such as an ownership check where peers check a role.
    WeakerAuthorization,
    /// The route checks a privilege, but not the one its peers require, such
    /// as `viewer` where peers require `admin`.
    DifferentAuthorization,
    /// The route falls short of its peers, but carries a guard, middleware,
    /// or handler that Archer cannot analyze. Needs manual review.
    UnverifiedProtection,
    /// The same handler is registered at another path behind guards or
    /// middleware that this registration lacks.
    InconsistentRegistration,
    /// The route serves the same data as other routes (a shared handler,
    /// repository function, or model type) but requires less of the caller:
    /// no login, no role, or no ownership check where they have one.
    SameResourceWeakerProtection,
    /// Nearly all of the route's peers that take the same caller identity
    /// do something with it that this route does not: pass it to the same
    /// check (`check_private_instance`), compare it with a record, or take
    /// it at all.
    SkipsPeerCheck,
}

impl FindingCategory {
    pub const ALL: [Self; 8] = [
        Self::MissingAuthentication,
        Self::MissingAuthorization,
        Self::WeakerAuthorization,
        Self::DifferentAuthorization,
        Self::UnverifiedProtection,
        Self::InconsistentRegistration,
        Self::SameResourceWeakerProtection,
        Self::SkipsPeerCheck,
    ];

    /// The category the JSON report names `name`, ignoring case.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| format!("{category:?}").eq_ignore_ascii_case(name))
    }
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingAuthentication => "missing authentication",
            Self::MissingAuthorization => "missing authorization",
            Self::WeakerAuthorization => "weaker authorization",
            Self::DifferentAuthorization => "different authorization requirement",
            Self::UnverifiedProtection => "unverified protection",
            Self::InconsistentRegistration => "inconsistent registration of one handler",
            Self::SameResourceWeakerProtection => "same resource, weaker protection",
            Self::SkipsPeerCheck => "skips a check its peers make",
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        })
    }
}

/// How much a piece of evidence restricts access, ordered weakest first.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceTier {
    /// No recognized evidence.
    None,
    /// Establishes who the caller is, not what they may do.
    Identity,
    /// Restricts access to the caller's own resources (ownership checks).
    Resource,
    /// Restricts access by role, permission, or an authorization guard,
    /// middleware, or explicit authorize call.
    Privilege,
}

impl EvidenceTier {
    pub fn of(kind: &AuthEvidenceKind) -> Self {
        match kind {
            AuthEvidenceKind::RoleCheck
            | AuthEvidenceKind::PermissionCheck
            | AuthEvidenceKind::AuthorizationGuard
            | AuthEvidenceKind::AuthorizationMiddleware
            | AuthEvidenceKind::ManualAuthorizationCheck => Self::Privilege,
            AuthEvidenceKind::OwnershipCheck | AuthEvidenceKind::SecretCheck => Self::Resource,
            AuthEvidenceKind::IdentityExtraction => Self::Identity,
            AuthEvidenceKind::Unknown | AuthEvidenceKind::Delegated => Self::None,
        }
    }
}

impl std::fmt::Display for EvidenceTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Identity => "identity",
            Self::Resource => "resource",
            Self::Privilege => "privilege",
        })
    }
}

impl Route {
    pub fn is_authorized(&self) -> bool {
        self.authorization
            .iter()
            .any(AuthEvidence::is_authorization)
    }

    /// Requirement subjects of the route's privilege-tier evidence.
    pub fn privilege_requirements(&self) -> Vec<&str> {
        let mut requirements: Vec<&str> = self
            .authorization
            .iter()
            .filter(|evidence| EvidenceTier::of(&evidence.kind) == EvidenceTier::Privilege)
            .flat_map(|evidence| evidence.requirements.iter().map(String::as_str))
            .collect();
        requirements.sort_unstable();
        requirements.dedup();
        requirements
    }

    /// The highest tier among the route's evidence.
    pub fn best_tier(&self) -> EvidenceTier {
        self.authorization
            .iter()
            .map(|evidence| EvidenceTier::of(&evidence.kind))
            .max()
            .unwrap_or(EvidenceTier::None)
    }

    #[allow(dead_code)]
    pub fn evidence_summary(&self) -> String {
        if self.authorization.is_empty() {
            return "No recognized authorization evidence".into();
        }
        self.authorization
            .iter()
            .map(|evidence| format!("{:?}: {}", evidence.kind, evidence.mechanism))
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[allow(dead_code)]
    pub fn strongest_evidence(&self) -> Option<&AuthEvidence> {
        self.authorization
            .iter()
            .filter(|evidence| evidence.is_authorization())
            .min_by_key(|evidence| match evidence.strength {
                AuthStrength::Strong => 0,
                AuthStrength::Medium => 1,
                AuthStrength::Weak => 2,
            })
    }
}

/// Settings that change what is scanned and how drift is inferred.
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// Also scan `tests/`, `examples/`, and `benches/` directories.
    pub include_tests: bool,
    /// Minimum number of authorized peers before a group's pattern can
    /// produce findings.
    pub min_support: usize,
    /// Minimum share of a group's routes that must be authorized, in (0, 1],
    /// before its unauthorized routes are reported.
    pub dominance_threshold: f64,
    /// `archer.toml` to read instead of the one at the repository root.
    pub config_file: Option<std::path::PathBuf>,
}

impl AnalysisOptions {
    /// Two authorized peers, as before thresholds were configurable.
    pub const DEFAULT_MIN_SUPPORT: usize = 2;
    /// Keeps the earlier 2-of-3 groups reportable while rejecting minority
    /// patterns such as 2 of 7. A starting point for evaluation, not a
    /// validated value.
    pub const DEFAULT_DOMINANCE_THRESHOLD: f64 = 0.6;
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            include_tests: false,
            min_support: Self::DEFAULT_MIN_SUPPORT,
            dominance_threshold: Self::DEFAULT_DOMINANCE_THRESHOLD,
            config_file: None,
        }
    }
}

/// Why a route was not compared with any peers.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnjudgedReason {
    /// Login, registration, token, and similar endpoints: public by design.
    AuthenticationEndpoint,
    /// Health, metrics, documentation and similar endpoints at the root.
    WellKnownPublic,
    /// The path holds a part Archer cannot resolve, so its place is unknown.
    UnresolvedPath,
    /// No other route of its method class in its resource or any scope above.
    NoPeers,
    /// Its peers carry no protection at all.
    PeersUnprotected,
    /// Its peers disagree: no protection reaches the support threshold.
    BelowSupport,
    /// An `archer.toml` public rule declares it public by design.
    DeclaredPublic,
}

impl std::fmt::Display for UnjudgedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AuthenticationEndpoint => "authentication endpoint",
            Self::WellKnownPublic => "well-known public endpoint",
            Self::UnresolvedPath => "unresolved path",
            Self::NoPeers => "no peers",
            Self::PeersUnprotected => "peers carry no protection",
            Self::BelowSupport => "peers below the support threshold",
            Self::DeclaredPublic => "declared public in archer.toml",
        })
    }
}

/// A route that no peer group or resource link judged, and why.
#[derive(Debug, Clone, Serialize)]
pub struct UnjudgedRoute {
    pub method: String,
    pub path: String,
    pub handler: Option<String>,
    pub reason: UnjudgedReason,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

impl UnjudgedRoute {
    pub fn new(route: &Route, reason: UnjudgedReason, detail: String) -> Self {
        Self {
            method: route.method.clone(),
            path: route.path.clone(),
            handler: route.handler.clone(),
            reason,
            detail,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub files_scanned: usize,
    pub parse_errors: Vec<String>,
    /// Extraction problems that did not stop analysis, such as route paths
    /// that are neither string literals nor resolvable constants.
    pub warnings: Vec<String>,
    pub routes: Vec<Route>,
    pub peer_groups: Vec<PeerGroup>,
    pub invariants: Vec<AuthorizationInvariant>,
    /// How much of the repository's request handling the routes cover.
    pub coverage: Coverage,
    /// Text renderings of `finding_details`, for the CLI and tests; the JSON
    /// report carries only the structured findings.
    #[serde(skip)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub findings: Vec<String>,
    pub finding_details: Vec<Finding>,
    /// Routes no comparison judged, with the reason for each.
    pub unjudged: Vec<UnjudgedRoute>,
    /// The `archer.toml` applied, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<std::path::PathBuf>,
    /// Findings an `archer.toml` dismiss rule accepted, with its reason.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dismissed: Vec<super::config::DismissedFinding>,
}

/// How much of the repository's request handling Archer's routes cover. A
/// low share means routes are registered in a way Archer cannot read, such
/// as a custom routing macro, and that the findings speak for few handlers.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Coverage {
    /// Free functions that look like request handlers: async, taking an
    /// Actix extractor or returning a response.
    pub likely_handlers: usize,
    /// Of those, the ones some route names as its handler.
    pub routed_handlers: usize,
    /// A few of the unrouted ones, as `file:line name`.
    pub unrouted_examples: Vec<String>,
    /// Routes whose handler could not be resolved, or matched several.
    pub unresolved_handlers: usize,
    /// Routes whose path holds a part that is not a literal or a constant.
    pub unresolved_paths: usize,
    /// A few of those, as `file:line METHOD path`.
    pub unresolved_path_examples: Vec<String>,
    /// Attribute routes that nothing registers, left out of `routes`.
    pub unregistered_attribute_routes: usize,
    /// Route-like call sites seen (route constructors, resources, route
    /// attributes) and how many of them some route was read from.
    pub route_sites: usize,
    pub route_sites_read: usize,
    /// The unread ones, as `file:line `code``.
    pub unread_route_sites: Vec<String>,
    /// Distinct routes, and how many of them a peer group judged: they sit
    /// in a group and are not listed in `unjudged`.
    pub routes_total: usize,
    pub routes_compared: usize,
    pub peer_groups: usize,
    /// Macros that name unrouted handlers, with how many each names.
    pub macro_registrations: Vec<(String, usize)>,
    /// Names of the unrouted handler-like functions.
    #[serde(skip)]
    pub unrouted_names: std::collections::HashSet<String>,
}
