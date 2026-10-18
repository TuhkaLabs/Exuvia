use assert_cmd::Command;
use predicates::prelude::*;

fn exuvia() -> Command {
    Command::cargo_bin("exuvia").expect("binary")
}

#[test]
fn prints_version() {
    exuvia()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("exuvia"));
}

#[test]
fn bundled_rules_validate() {
    let data = tempfile::tempdir().expect("temp dir");
    exuvia()
        .args([
            "rules",
            "validate",
            "--data-dir",
            data.path().to_str().expect("utf-8"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn history_is_empty_for_a_fresh_store() {
    let data = tempfile::tempdir().expect("temp dir");
    exuvia()
        .args([
            "history",
            "--data-dir",
            data.path().to_str().expect("utf-8"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No uninstall history yet"));
}

#[test]
fn list_json_has_a_stable_envelope() {
    let data = tempfile::tempdir().expect("temp dir");
    let output = exuvia()
        .args([
            "list",
            "--json",
            "--limit",
            "1",
            "--data-dir",
            data.path().to_str().expect("utf-8"),
        ])
        .output()
        .expect("run");

    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(value["schema_version"], 1);
    assert!(value["apps"].is_array());
}

#[test]
fn unknown_application_is_a_general_error() {
    let data = tempfile::tempdir().expect("temp dir");
    exuvia()
        .args([
            "scan",
            "ExuviaDefinitelyNotInstalledApplication",
            "--data-dir",
            data.path().to_str().expect("utf-8"),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no installed application matches"));
}

#[test]
fn invalid_manifest_id_is_a_usage_error() {
    let data = tempfile::tempdir().expect("temp dir");
    exuvia()
        .args([
            "restore",
            "../escape",
            "--data-dir",
            data.path().to_str().expect("utf-8"),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid manifest id"));
}
