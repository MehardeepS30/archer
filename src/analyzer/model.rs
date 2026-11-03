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
    ManualAuthorizationCheck,
    /// A guard or middleware that Archer cannot classify. It may protect the
    /// route, so a route carrying one is never reported as unprotected, only
    /// as unverified.
    Unknown,
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
            Self::ManualAuthorizationCheck => "manual authorization check",
            Self::Unknown => "unrecognized guard or middleware",
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
    /// Extraction bookkeeping that is not part of the report.
    #[serde(skip)]
    pub(crate) origin: RouteOrigin,
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
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingAuthentication => "missing authentication",
            Self::MissingAuthorization => "missing authorization",
            Self::WeakerAuthorization => "weaker authorization",
            Self::DifferentAuthorization => "different authorization requirement",
            Self::UnverifiedProtection => "unverified protection",
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
            AuthEvidenceKind::OwnershipCheck => Self::Resource,
            AuthEvidenceKind::IdentityExtraction => Self::Identity,
            AuthEvidenceKind::Unknown => Self::None,
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
    /// Text renderings of `finding_details`, for the CLI and tests; the JSON
    /// report carries only the structured findings.
    #[serde(skip)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub findings: Vec<String>,
    pub finding_details: Vec<Finding>,
}
