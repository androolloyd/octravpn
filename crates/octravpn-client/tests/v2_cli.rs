//! Integration tests for the v2 (circle-native) client subcommands.
//!
//! The full v2 discovery / connect flow needs a live RPC and a deployed
//! v2 program — that's exercised by the docker-only e2e harness. Here
//! we cover the cheap surfaces:
//!
//! * `--help` for the new subcommands.
//! * Config gating: v1.1 configs must be rejected by `discover v2`
//!   and `connect-v2` with a clear error pointing at the config flag.
//! * bug-report redaction: when a config carries a sealed passphrase,
//!   the produced archive must NOT contain the passphrase contents.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use flate2::read::GzDecoder;
use tar::Archive;
use tempfile::TempDir;

const WALLET_SECRET: &str = "deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677";
const SEALED_PP: &str = "do-not-leak-this-passphrase";

fn octravpn_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_octravpn"))
}

fn write_v1_config(dir: &Path) -> PathBuf {
    let wallet = dir.join("wallet.hex");
    fs::write(&wallet, WALLET_SECRET).unwrap();
    let config = dir.join("client.toml");
    let body = format!(
        r#"
[chain]
rpc_url      = "http://127.0.0.1:1"
program_addr = "octPROG_TEST"

[wallet]
addr        = "octADDR_TEST"
secret_path = "{}"
"#,
        wallet.display()
    );
    fs::write(&config, body).unwrap();
    config
}

fn write_v2_config(dir: &Path) -> PathBuf {
    let wallet = dir.join("wallet.hex");
    fs::write(&wallet, WALLET_SECRET).unwrap();
    let config = dir.join("client.toml");
    let body = format!(
        r#"
[chain]
rpc_url          = "http://127.0.0.1:1"
program_addr     = "octPROG_TEST"
protocol_version = "v2"

[wallet]
addr        = "octADDR_TEST"
secret_path = "{}"

[v2]
sealed_passphrase = "{SEALED_PP}"
key_id            = "default"
"#,
        wallet.display()
    );
    fs::write(&config, body).unwrap();
    config
}

#[test]
fn discover_v2_help_renders() {
    let out = Command::new(octravpn_binary())
        .args(["discover", "v2", "--help"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("authorized circles"), "got: {stdout}");
    assert!(stdout.contains("--secret"), "got: {stdout}");
    assert!(stdout.contains("--refresh"), "got: {stdout}");
}

#[test]
fn connect_v2_help_renders() {
    let out = Command::new(octravpn_binary())
        .args(["connect-v2", "--help"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--tailnet-id"), "got: {stdout}");
    assert!(stdout.contains("--class"), "got: {stdout}");
    assert!(stdout.contains("--circle-id"), "got: {stdout}");
}

#[test]
fn discover_v2_rejects_v1_config() {
    let tmp = TempDir::new().unwrap();
    let cfg = write_v1_config(tmp.path());
    let out = Command::new(octravpn_binary())
        .arg("--config")
        .arg(&cfg)
        .args(["discover", "v2", "0"])
        .env("HOME", tmp.path())
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "v1.1 config should be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stderr}{stdout}");
    assert!(
        combined.contains("v2") && combined.contains("protocol_version"),
        "stderr/stdout should mention protocol_version + v2; got: {combined}",
    );
}

#[test]
fn connect_v2_rejects_v1_config() {
    let tmp = TempDir::new().unwrap();
    let cfg = write_v1_config(tmp.path());
    let out = Command::new(octravpn_binary())
        .arg("--config")
        .arg(&cfg)
        .args(["connect-v2", "--tailnet-id", "0", "--deposit", "100"])
        .env("HOME", tmp.path())
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "v1.1 config should be rejected by connect-v2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stderr}{stdout}");
    assert!(
        combined.contains("protocol_version"),
        "expected message to mention protocol_version; got: {combined}",
    );
}

#[test]
fn bug_report_redacts_sealed_passphrase() {
    let tmp = TempDir::new().unwrap();
    let cfg = write_v2_config(tmp.path());
    let out_path = tmp.path().join("bug.tar.gz");
    let status = Command::new(octravpn_binary())
        .arg("--config")
        .arg(&cfg)
        .args(["bug-report", "--out"])
        .arg(&out_path)
        .env("HOME", tmp.path())
        .status()
        .expect("spawn");
    assert!(status.success(), "bug-report exited {status:?}");

    let mut ar = Archive::new(GzDecoder::new(fs::File::open(&out_path).unwrap()));
    let mut leaked = false;
    for entry in ar.entries().unwrap() {
        let mut e = entry.unwrap();
        let mut bytes = Vec::new();
        e.read_to_end(&mut bytes).unwrap();
        if bytes
            .windows(SEALED_PP.len())
            .any(|w| w == SEALED_PP.as_bytes())
        {
            leaked = true;
            break;
        }
    }
    assert!(
        !leaked,
        "bug-report archive leaked the sealed passphrase ({SEALED_PP:?})"
    );

    // The redacted config should also mention the v2 block somehow so
    // recipients know v2 was active.
    let mut ar = Archive::new(GzDecoder::new(fs::File::open(&out_path).unwrap()));
    let mut saw_v2_block = false;
    for entry in ar.entries().unwrap() {
        let mut e = entry.unwrap();
        let path = e.path().unwrap().into_owned();
        if path == Path::new("config.toml") {
            let mut s = String::new();
            e.read_to_string(&mut s).unwrap();
            saw_v2_block = s.contains("[v2]") && s.contains("sealed_passphrase: <redacted>");
            break;
        }
    }
    assert!(
        saw_v2_block,
        "config.toml in bug-report should keep the [v2] block with the passphrase redacted",
    );
}
