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
    pub invariant: AuthorizationInvariant,
    pub suspicious_route: RouteReference,
    pub suspicious_route_evidence: Vec<AuthEvidence>,
    pub authorized_peer_routes: Vec<RouteReference>,
}

impl Route {
    pub fn is_authorized(&self) -> bool {
        self.authorization
            .iter()
            .any(AuthEvidence::is_authorization)
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
#[derive(Debug, Clone, Default)]
pub struct AnalysisOptions {
    /// Also scan `tests/`, `examples/`, and `benches/` directories.
    pub include_tests: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub files_scanned: usize,
    pub parse_errors: Vec<String>,
    pub routes: Vec<Route>,
    pub peer_groups: Vec<PeerGroup>,
    pub invariants: Vec<AuthorizationInvariant>,
    pub findings: Vec<String>,
    pub finding_details: Vec<Finding>,
}
