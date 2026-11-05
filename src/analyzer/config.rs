//! `archer.toml`: the reviewer's decisions about routes and findings.
//!
//! ```toml
//! # Routes that are public by design. They are not judged, and they do not
//! # count as peers of other routes.
//! [[public]]
//! path = "/api/status/**"
//! reason = "status pages are public"
//!
//! # Findings reviewed and accepted. They move to `dismissed` in the report.
//! [[dismiss]]
//! method = "DELETE"
//! path = "/api/keys/{key}"
//! category = "MissingAuthorization"   # optional
//! reason = "checked inside delete_key by the key store"
//! ```
//!
//! Paths match segment by segment: `*` matches one segment, `**` any number
//! (only at the end), and a `{name}` segment matches any path parameter.
//! Methods and categories are optional and match case-insensitively.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::model::*;

/// The file read from the scanned repository's root when no other is given.
pub const CONFIG_FILE: &str = "archer.toml";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub public: Vec<RouteRule>,
    #[serde(default)]
    pub dismiss: Vec<DismissRule>,
    /// Where the configuration was read from, for the report.
    #[serde(skip)]
    pub source: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    pub path: String,
    #[serde(default)]
    pub method: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DismissRule {
    pub path: String,
    #[serde(default)]
    pub method: Option<String>,
    /// A finding category as the JSON report names it (`MissingAuthorization`).
    #[serde(default)]
    pub category: Option<String>,
    pub reason: String,
}

/// A finding the configuration dismissed, with the rule's reason.
#[derive(Debug, Clone, Serialize)]
pub struct DismissedFinding {
    pub reason: String,
    /// Index of the rule in `Config::dismiss`.
    #[serde(skip)]
    pub rule: usize,
    pub finding: Finding,
}

impl Config {
    /// `explicit` if given (it must exist), else `archer.toml` at `root` if
    /// present, else no rules.
    pub fn load(root: &Path, explicit: Option<&Path>) -> Result<Self> {
        let path = match explicit {
            Some(path) => path.to_path_buf(),
            None => {
                let default = if root.is_dir() {
                    root.join(CONFIG_FILE)
                } else {
                    root.with_file_name(CONFIG_FILE)
                };
                if !default.is_file() {
                    return Ok(Self::default());
                }
                default
            }
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut config: Self =
            toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))?;
        for rule in &config.dismiss {
            if let Some(category) = &rule.category
                && FindingCategory::from_name(category).is_none()
            {
                anyhow::bail!(
                    "{}: unknown finding category `{category}`; use one of {}",
                    path.display(),
                    FindingCategory::ALL
                        .iter()
                        .map(|category| format!("{category:?}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        config.source = Some(path);
        Ok(config)
    }

    /// The `[[public]]` rule a route matches, if any.
    pub fn public_rule(&self, route: &Route) -> Option<&RouteRule> {
        self.public
            .iter()
            .find(|rule| matches_route(&rule.path, rule.method.as_deref(), route))
    }

    /// The `[[dismiss]]` rule a finding matches, if any.
    pub fn dismiss_rule(&self, finding: &Finding) -> Option<(usize, &DismissRule)> {
        let route = &finding.suspicious_route;
        self.dismiss.iter().enumerate().find(|(_, rule)| {
            path_matches(&rule.path, &route.path)
                && method_matches(rule.method.as_deref(), &route.method)
                && rule.category.as_deref().is_none_or(|category| {
                    FindingCategory::from_name(category) == Some(finding.category)
                })
        })
    }

    /// Warnings for rules that matched nothing: a route was renamed or removed.
    pub fn unused_rules(&self, routes: &[Route], dismissed: &[DismissedFinding]) -> Vec<String> {
        let source = self
            .source
            .as_deref()
            .map_or_else(|| CONFIG_FILE.into(), |path| path.display().to_string());
        let mut warnings = Vec::new();
        for rule in &self.public {
            if !routes
                .iter()
                .any(|route| matches_route(&rule.path, rule.method.as_deref(), route))
            {
                warnings.push(format!(
                    "{source}: public rule `{}{}` matches no route",
                    rule.method.as_deref().map(|m| format!("{m} ")).unwrap_or_default(),
                    rule.path
                ));
            }
        }
        for (index, rule) in self.dismiss.iter().enumerate() {
            if !dismissed.iter().any(|dismissed| dismissed.rule == index) {
                warnings.push(format!(
                    "{source}: dismiss rule `{}{}` matches no finding; the finding may be fixed, or the route renamed",
                    rule.method.as_deref().map(|m| format!("{m} ")).unwrap_or_default(),
                    rule.path
                ));
            }
        }
        warnings
    }
}

fn matches_route(pattern: &str, method: Option<&str>, route: &Route) -> bool {
    path_matches(pattern, &route.path) && method_matches(method, &route.method)
}

fn method_matches(rule: Option<&str>, method: &str) -> bool {
    rule.is_none_or(|rule| rule == "*" || rule.eq_ignore_ascii_case(method))
}

fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|segment| !segment.is_empty()).collect()
}

fn is_parameter(segment: &str) -> bool {
    segment.starts_with('{') && segment.ends_with('}')
}

pub(crate) fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern = segments(pattern);
    let path = segments(path);
    let mut position = 0;
    for (index, expected) in pattern.iter().enumerate() {
        if *expected == "**" && index == pattern.len() - 1 {
            return true;
        }
        let Some(actual) = path.get(position) else {
            return false;
        };
        let matched = *expected == "*"
            || expected == actual
            || (is_parameter(expected) && is_parameter(actual));
        if !matched {
            return false;
        }
        position += 1;
    }
    position == path.len()
}

#[cfg(test)]
mod tests {
    use super::path_matches;

    #[test]
    fn paths_match_by_segment() {
        assert!(path_matches("/api/keys/{key}", "/api/keys/{uid}"));
        assert!(path_matches("/api/*/stats", "/api/indexes/stats"));
        assert!(path_matches("/api/**", "/api/a/b"));
        assert!(path_matches("/api/**", "/api"));
        assert!(path_matches("/", "/"));
        assert!(!path_matches("/api/keys", "/api/keys/{key}"));
        assert!(!path_matches("/api/keys/{key}", "/api/keys/all"));
        assert!(!path_matches("/api/*", "/api"));
    }
}
