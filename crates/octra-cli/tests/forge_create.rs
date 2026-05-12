//! `forge create` — compile + sign + deploy against in-process backend.

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

#[test]
fn create_in_process_returns_deploy_address() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("k.hex");
    fs::write(&key_path, "11".repeat(32)).unwrap();
    let src_path = dir.path().join("Demo.aml");
    fs::write(
        &src_path,
        "program Demo {\n  fn foo(x: int): bool { return true }\n}\n",
    )
    .unwrap();
    cmd()
        .args(["forge", "create"])
        .arg(&src_path)
        .arg("--key")
        .arg(&key_path)
        .arg("--rpc-url")
        .arg("inprocess://octPROG")
        .assert()
        .success()
        .stdout(contains("\"address\""))
        .stdout(contains("oct"));
}
