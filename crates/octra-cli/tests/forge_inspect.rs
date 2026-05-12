//! `forge inspect` — show ABI / bytecode / asm against an AML file.

use assert_cmd::Command;
use predicates::str::contains;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

#[test]
fn inspect_aml_file_dumps_abi() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = std::path::Path::new(&manifest)
        .ancestors()
        .nth(2)
        .unwrap();
    cmd()
        .args(["forge", "inspect"])
        .arg(workspace_root.join("program").join("main.aml"))
        .arg("--field")
        .arg("abi")
        .assert()
        .success()
        .stdout(contains("register_endpoint"));
}

#[test]
fn inspect_aml_file_dumps_bytecode() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = std::path::Path::new(&manifest)
        .ancestors()
        .nth(2)
        .unwrap();
    cmd()
        .args(["forge", "inspect"])
        .arg(workspace_root.join("program").join("main.aml"))
        .arg("--field")
        .arg("bytecode")
        .assert()
        .success()
        .stdout(contains("0x"));
}
