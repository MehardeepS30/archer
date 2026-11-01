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
const NO_DRIFT: &str = "tests/fixtures/probes/c3_weaker_evidence_kind.rs";

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
