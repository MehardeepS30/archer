//! Exit codes of the archer binary.

use std::process::Command;

fn archer(args: &[&str]) -> i32 {
    Command::new(env!("CARGO_BIN_EXE_archer"))
        .args(args)
        .output()
        .expect("archer runs")
        .status
        .code()
        .expect("archer exits normally")
}

const DRIFT: &str = "tests/fixtures/probes/a1_attribute_routes_in_scope.rs";
const NO_DRIFT: &str = "tests/fixtures/probes/a2_configure_in_scope.rs";

#[test]
fn findings_exit_zero_without_fail_on_findings() {
    assert_eq!(archer(&[DRIFT]), 0);
}

#[test]
fn fail_on_findings_exits_one_only_when_drift_is_found() {
    assert_eq!(archer(&["--fail-on-findings", DRIFT]), 1);
    assert_eq!(archer(&["--fail-on-findings", NO_DRIFT]), 0);
}

#[test]
fn runtime_errors_exit_two() {
    assert_eq!(archer(&["tests/fixtures/does-not-exist"]), 2);
}

#[test]
fn findings_carry_their_evidence_in_both_outputs() {
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_archer")).args(args).output().expect("archer runs");
        String::from_utf8(output.stdout).expect("utf-8 output")
    };
    let json = run(&["--json", DRIFT]);
    for field in ["\"evidence\"", "\"check\"", "\"peers\"", "\"instead\"", "\"dismiss\"", "[[dismiss]]"] {
        assert!(json.contains(field), "{field} missing from the JSON report");
    }
    let text = run(&[DRIFT]);
    assert!(text.contains("The check:"), "{text}");
    assert!(text.contains("If intended, add to archer.toml:"), "{text}");
}

/// Findings of a fixture, `severity method path`, with the given P10 rule
/// switches set.
fn findings_with(fixture: &str, switches: &[(&str, &str)]) -> Vec<String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_archer"));
    command.args(["--json", fixture]);
    for (name, value) in switches {
        command.env(name, value);
    }
    let output = command.output().expect("archer runs");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    report["finding_details"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| {
            format!(
                "{} {} {}",
                finding["severity"].as_str().unwrap_or_default(),
                finding["suspicious_route"]["method"].as_str().unwrap_or_default(),
                finding["suspicious_route"]["path"].as_str().unwrap_or_default()
            )
        })
        .collect()
}

#[test]
fn each_missed_drift_rule_has_a_switch() {
    let cases = [
        ("tests/fixtures/probes/drift/f57_wrapper_closures.rs", "ARCHER_P10_R1", "POST /boxes/stamp"),
        ("tests/fixtures/probes/drift/f58_path_bindings.rs", "ARCHER_P10_R2", "GET /people/{who}/notes"),
        ("tests/fixtures/probes/drift/f59_scheme_guards.rs", "ARCHER_P10_R3", "POST /coupons/{code}/apply"),
        ("tests/fixtures/probes/drift/f60_symbolic_scope.rs", "ARCHER_P10_R4", "/items/{id}/restock"),
        ("tests/fixtures/probes/drift/f61_grant_scopes.rs", "ARCHER_P10_R5", "GET /notes/all"),
    ];
    for (fixture, switch, route) in cases {
        let on = findings_with(fixture, &[]);
        let off = findings_with(fixture, &[(switch, "0")]);
        assert!(on.iter().any(|finding| finding.contains(route)), "{switch} on: {on:?}");
        assert!(!off.iter().any(|finding| finding.contains(route)), "{switch} off: {off:?}");
    }
}

#[test]
fn each_public_route_rule_has_a_switch() {
    let fixture = "tests/fixtures/probes/drift/f62_public_routes.rs";
    let on = findings_with(fixture, &[]);
    // With the rule on, the first line is there and the second is not;
    // with it off, the reverse. An empty line is not looked for.
    let cases = [
        // The secret lookup makes the pairing route authenticated, so the
        // writes under /api/v1 agree on a caller.
        ("ARCHER_P6_S1", "High POST /api/v1/account/close", ""),
        ("ARCHER_P6_S2", "Low POST /api/v1/account/handle/taken", "High POST /api/v1/account/handle/taken"),
        ("ARCHER_P6_S3", "", "Low POST /api/v1/boards"),
    ];
    for (switch, with, without) in cases {
        let off = findings_with(fixture, &[(switch, "0")]);
        for (present, absent, found) in [(with, without, &on), (without, with, &off)] {
            assert!(present.is_empty() || found.iter().any(|line| line == present), "{switch}: {found:?}");
            assert!(absent.is_empty() || !found.iter().any(|line| line == absent), "{switch}: {found:?}");
        }
    }
}

#[test]
fn the_nested_extractor_round_has_switches() {
    let fixture = "tests/fixtures/probes/drift/f63_nested_extractors.rs";
    let on = findings_with(fixture, &[]);
    let off = findings_with(fixture, &[("ARCHER_P11", "0")]);
    for route in ["Medium GET /shelves/{shelf}/summary", "Medium GET /shelves/{shelf}/preview"] {
        assert!(on.iter().any(|line| line == route), "on: {on:?}");
        assert!(!off.iter().any(|line| line == route), "off: {off:?}");
    }
    // The citation rule changes what a finding says, not which are made.
    let uncited = findings_with(fixture, &[("ARCHER_P12", "0")]);
    assert_eq!(on, uncited);
    let check = |switches: &[(&str, &str)]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_archer"));
        command.args(["--json", fixture]);
        for (name, value) in switches {
            command.env(name, value);
        }
        let output = command.output().expect("archer runs");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON report");
        report["finding_details"]
            .as_array()
            .expect("findings")
            .iter()
            .find(|finding| finding["suspicious_route"]["path"] == "/audit/raw")
            .map(|finding| finding["evidence"]["check"].as_str().unwrap_or_default().to_owned())
            .expect("the audit finding")
    };
    assert_eq!(check(&[]), "takes the caller: `Operator`");
    assert_eq!(check(&[("ARCHER_P12", "0")]), "takes the caller: `Stock`");
}

#[test]
fn the_built_paths_round_has_a_switch() {
    let fixture = "tests/fixtures/probes/drift/f64_built_paths.rs";
    let on = findings_with(fixture, &[]);
    let off = findings_with(fixture, &[("ARCHER_P7", "0")]);
    assert!(on.iter().any(|line| line == "High POST /v2/{book}/entries/{entry:[0-9]{1,8}}/merge"), "on: {on:?}");
    assert!(off.iter().all(|line| !line.contains("/v2/")), "off: {off:?}");
    let output = Command::new(env!("CARGO_BIN_EXE_archer"))
        .arg(fixture)
        .output()
        .expect("archer runs");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Paths: 11 of 15 routes have fully resolved paths"), "{text}");
    assert!(text.contains("  unresolved: "), "{text}");
}
