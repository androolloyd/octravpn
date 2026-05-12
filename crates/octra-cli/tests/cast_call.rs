//! `cast call` + `cast tx` + `cast block` smoke against the in-process backend.

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

#[test]
fn cast_call_list_active_endpoints_inprocess() {
    cmd()
        .args([
            "cast",
            "call",
            "octPROG",
            "list_active_endpoints",
            "--rpc-url",
            "inprocess://octPROG",
        ])
        .assert()
        .success()
        .stdout(contains("[]"));
}

#[test]
fn cast_call_get_params_returns_param_object() {
    cmd()
        .args([
            "cast",
            "call",
            "octPROG",
            "get_params",
            "--rpc-url",
            "inprocess://octPROG",
        ])
        .assert()
        .success()
        .stdout(contains("min_session_deposit"));
}

#[test]
fn cast_block_fetches_epoch() {
    cmd()
        .args(["cast", "block", "1", "--rpc-url", "inprocess://octPROG"])
        .assert()
        .success()
        .stdout(contains("epoch_id"));
}

#[test]
fn cast_send_with_key_signs_and_submits() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("k.hex");
    fs::write(&key_path, "22".repeat(32)).unwrap();
    // retire_endpoint against a fresh mock — the caller is not a registered
    // endpoint, so the chain reverts with "not registered". The CLI should
    // still build/submit the tx and surface the chain's revert message.
    let out = cmd()
        .args([
            "cast",
            "send",
            "octPROG",
            "retire_endpoint",
            "--rpc-url",
            "inprocess://octPROG",
            "--key",
        ])
        .arg(&key_path)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not registered"), "stderr: {stderr}");
}
