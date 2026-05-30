// Skipped under cargo-tarpaulin: this subprocess-driven CLI test deadlocks
// tarpaulin's ptrace coverage engine (and adds no in-process coverage).
// Normal cargo test still runs it.
#![cfg(not(tarpaulin))]

//! Integration tests for `octravpn bugreport`.
//!
//! We exercise the subcommand by invoking the `octravpn` binary directly via
//! the binary path Cargo gives us at test time. The test fixture writes a
//! synthetic client config + wallet into a tempdir, runs the binary, then
//! cracks open the produced archive and asserts on its contents.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use flate2::read::GzDecoder;
use tar::Archive;
use tempfile::TempDir;

const SENSITIVE_SECRET: &str = "deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677";

fn octravpn_binary() -> PathBuf {
    // `CARGO_BIN_EXE_octravpn` is set by Cargo when running integration
    // tests for a crate that exposes a `[[bin]] name = "octravpn"`.
    PathBuf::from(env!("CARGO_BIN_EXE_octravpn"))
}

/// Write a minimal-but-valid client.toml + wallet.hex into `dir` and
/// return their paths.
fn write_fixture(dir: &Path) -> (PathBuf, PathBuf) {
    let wallet = dir.join("wallet.hex");
    fs::write(&wallet, SENSITIVE_SECRET).expect("write wallet");

    let config = dir.join("client.toml");
    let body = format!(
        r#"
[chain]
rpc_url      = "https://octra.network/rpc"
program_addr = "octPROG_TEST"

[wallet]
addr        = "octADDR_TEST"
secret_path = "{}"
"#,
        wallet.display()
    );
    fs::write(&config, body).expect("write config");
    (config, wallet)
}

/// Read every entry in a tar.gz into `(name, bytes)` pairs.
fn read_archive(path: &Path) -> Vec<(String, Vec<u8>)> {
    let f = fs::File::open(path).expect("open archive");
    let gz = GzDecoder::new(f);
    let mut ar = Archive::new(gz);
    let mut out = Vec::new();
    for entry in ar.entries().expect("entries") {
        let mut e = entry.expect("entry");
        let name = e.path().expect("entry path").to_string_lossy().into_owned();
        let mut buf = Vec::new();
        e.read_to_end(&mut buf).expect("read entry");
        out.push((name, buf));
    }
    out
}

#[test]
fn bugreport_creates_archive_with_expected_entries() {
    let tmp = TempDir::new().expect("tempdir");
    let (config, _wallet) = write_fixture(tmp.path());
    let out = tmp.path().join("bug.tar.gz");

    let status = Command::new(octravpn_binary())
        .arg("--config")
        .arg(&config)
        .arg("bug-report")
        .arg("--out")
        .arg(&out)
        // Don't accidentally pick up the tester's $HOME log dir.
        .env("HOME", tmp.path())
        .status()
        .expect("spawn octravpn");
    assert!(status.success(), "octravpn bug-report exited {status:?}");

    assert!(out.is_file(), "archive {} not produced", out.display());

    let entries = read_archive(&out);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();

    assert!(
        names.contains(&"config.toml"),
        "missing config.toml; got {names:?}"
    );
    assert!(
        names.contains(&"system.txt"),
        "missing system.txt; got {names:?}"
    );
    assert!(
        names.contains(&"state.json"),
        "missing state.json; got {names:?}"
    );

    // Entries must be in lexicographic order for snapshot stability.
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, names, "archive entries are not in sorted order");

    // state.json should parse as JSON and contain the timestamp + paths.
    let (_, state_bytes) = entries
        .iter()
        .find(|(n, _)| n == "state.json")
        .expect("state.json entry");
    let v: serde_json::Value = serde_json::from_slice(state_bytes).expect("parse state.json");
    assert!(v.get("timestamp").is_some(), "state.json missing timestamp");
    assert_eq!(
        v.get("config_path").and_then(|s| s.as_str()),
        Some(config.to_string_lossy().as_ref()),
        "state.json config_path mismatch"
    );
}

#[test]
fn bugreport_redacts_secret_contents() {
    let tmp = TempDir::new().expect("tempdir");
    let (config, wallet) = write_fixture(tmp.path());
    let out = tmp.path().join("bug.tar.gz");

    // Sanity: the secret really is on disk.
    assert_eq!(
        fs::read_to_string(&wallet).unwrap().trim(),
        SENSITIVE_SECRET
    );

    let status = Command::new(octravpn_binary())
        .arg("--config")
        .arg(&config)
        .arg("bug-report")
        .arg("--out")
        .arg(&out)
        .env("HOME", tmp.path())
        .status()
        .expect("spawn octravpn");
    assert!(status.success(), "octravpn bug-report exited {status:?}");

    let entries = read_archive(&out);

    // The wallet path string should appear *somewhere* in the bundle (so
    // the recipient knows where the wallet lives on the user's box).
    let wallet_path_str = wallet.to_string_lossy().into_owned();
    let mentions_path = entries.iter().any(|(_, bytes)| {
        std::str::from_utf8(bytes)
            .map(|s| s.contains(&wallet_path_str))
            .unwrap_or(false)
    });
    assert!(
        mentions_path,
        "no archive entry mentions the wallet path {wallet_path_str}"
    );

    // The sensitive secret bytes must NOT appear in any entry.
    for (name, bytes) in &entries {
        // Look for the secret as a substring of the raw bytes.
        let needle = SENSITIVE_SECRET.as_bytes();
        let leaked = bytes.windows(needle.len()).any(|w| w == needle);
        assert!(
            !leaked,
            "entry {name} leaked the wallet secret ({} bytes)",
            needle.len()
        );
    }
}
