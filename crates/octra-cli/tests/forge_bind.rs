//! `forge bind` — ensure the generated Rust file compiles standalone.

use std::fs;
use std::process::Command as PCommand;

use assert_cmd::Command;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

#[test]
fn bind_generates_compileable_file() {
    let out_dir = tempdir().unwrap();
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = std::path::Path::new(&manifest)
        .ancestors()
        .nth(2)
        .unwrap();

    // 1. Build OctraVPN first to get the ABI.
    let build_out = tempdir().unwrap();
    cmd()
        .args(["forge", "build", "--offline", "--root"])
        .arg(workspace_root.join("program"))
        .arg("--out")
        .arg(build_out.path())
        .assert()
        .success();
    let abi_path = build_out.path().join("OctraVPN.abi");
    assert!(abi_path.exists());

    // 2. Bind.
    cmd()
        .args(["forge", "bind"])
        .arg(&abi_path)
        .arg("--out")
        .arg(out_dir.path())
        .arg("--module")
        .arg("octravpn")
        .assert()
        .success();
    let rs_path = out_dir.path().join("octravpn.rs");
    assert!(rs_path.exists());
    let body = fs::read_to_string(&rs_path).unwrap();
    // Spot-check: register_endpoint and a view method are wired up.
    assert!(body.contains("pub fn call_register_endpoint"), "got: {body}");
    assert!(body.contains("pub fn view_get_endpoint"), "got: {body}");

    // 3. Compile the generated file against a synthetic Cargo project
    //    to prove it parses + type-checks against `octravpn-core` and
    //    `serde_json` alone.
    let proj = tempdir().unwrap();
    fs::create_dir_all(proj.path().join("src")).unwrap();
    fs::write(
        proj.path().join("Cargo.toml"),
        r#"[package]
name = "bind_smoke"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
serde_json = "1"
octravpn-core = { path = "OCTRAVPN_CORE_PATH" }
"#
        .replace(
            "OCTRAVPN_CORE_PATH",
            workspace_root
                .join("crates")
                .join("octravpn-core")
                .to_str()
                .unwrap(),
        ),
    )
    .unwrap();
    let lib_rs = "pub mod gen;\n#[allow(unused_imports)]\nuse gen::Octravpn;\n";
    fs::write(proj.path().join("src").join("lib.rs"), lib_rs).unwrap();
    fs::copy(&rs_path, proj.path().join("src").join("gen.rs")).unwrap();
    let target_dir = tempdir().unwrap();
    let status = PCommand::new(option_env!("CARGO").unwrap_or("cargo"))
        .current_dir(proj.path())
        .arg("check")
        .arg("--target-dir")
        .arg(target_dir.path())
        .arg("--quiet")
        .status()
        .unwrap();
    assert!(status.success(), "generated binding failed to compile");
}
