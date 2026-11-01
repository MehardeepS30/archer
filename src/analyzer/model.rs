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
    #[allow(dead_code)]
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
            Self::Unknown => "unknown",
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
            authorization: route.authorization.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerGroup {
    pub id: String,
    pub description: String,
    /// The full-path prefix the group's routes share; see `peer_prefix`.
    pub prefix: String,
    pub routes: Vec<RouteReference>,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub peer_group_id: String,
    pub category: FindingCategory,
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
    /// The route has no authorization evidence while its peers do.
    MissingAuthorization,
    /// The route has authorization evidence, but of a lower tier than its
    /// peers', such as an ownership check where peers check a role.
    WeakerAuthorization,
}

/// How much a piece of evidence restricts access, ordered weakest first.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
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
