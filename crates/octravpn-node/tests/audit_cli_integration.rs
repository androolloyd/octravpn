//! Integration tests for `octravpn-node audit replay` / `audit verify`.
//!
//! Drives the compiled `octravpn-node` binary against synthetic audit
//! and journal fixtures. Unlike the unit tests in `audit_cli::tests`
//! (which call the in-process module API), these spawn the real
//! binary as a subprocess so the clap surface, structured exit codes,
//! and on-disk fixture layout are exercised end-to-end. The audit log
//! is written via a tiny in-test helper that mirrors the daemon's
//! wire format (`{record_json, prev_mac, mac}` JSONL with an
//! HMAC-SHA256 chain — see `crates/octravpn-node/src/audit.rs`); the
//! journal is round-tripped via the public `ReceiptJournal::bump`
//! API.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use hmac::{Hmac, Mac};
use octravpn_core::{receipt_journal::ReceiptJournal, session::SessionId};
use serde_json::{json, Value};
use sha2::Sha256;
use tempfile::tempdir;

type HmacSha256 = Hmac<Sha256>;

/// Path to the built `octravpn-node` binary. `cargo test` sets
/// `CARGO_BIN_EXE_<name>` for every `[[bin]]` in the package.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_octravpn-node"))
}

/// Write a synthetic audit-log file at `<dir>/audit-1970-01-01.jsonl`
/// using `key` for the HMAC chain. The records are minimal — just a
/// timestamp + kind + session_id — but the wire format matches what
/// the daemon writes, so the binary's verify path will exercise the
/// same parser.
fn write_audit_fixture(
    dir: &Path,
    key: &[u8; 32],
    records: &[(u64, &str, Option<String>)],
) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    // The daemon names files by UTC day of the *first* record's
    // timestamp. With ts=0 we get audit-1970-01-01.jsonl, but for
    // realism we use a 2024 date.
    let path = dir.join("audit-2024-06-15.jsonl");
    let mut f = fs::File::create(&path).unwrap();
    let mut prev_mac = [0u8; 32];
    for (ts, kind, sid) in records {
        let rec = json!({
            "ts_unix": ts,
            "kind": kind,
            "source": Value::Null,
            "session_id": sid,
        });
        let canonical = serde_json::to_string(&rec).unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
        mac.update(&prev_mac);
        mac.update(canonical.as_bytes());
        let tag: [u8; 32] = mac.finalize().into_bytes().into();
        let chained = json!({
            "record_json": canonical,
            "prev_mac": hex::encode(prev_mac),
            "mac": hex::encode(tag),
        });
        writeln!(f, "{}", serde_json::to_string(&chained).unwrap()).unwrap();
        prev_mac = tag;
    }
    f.sync_all().unwrap();
    // Drop the HMAC key alongside the directory under the conventional
    // name the binary expects when --hmac-key is omitted.
    fs::write(dir.join(".audit.key"), key).unwrap();
    path
}

/// Build a small `(audit_dir, journal_path)` fixture pair simulating a
/// daemon that announced two sessions and signed receipts for both.
/// Returns the audit directory + journal path.
fn write_pair_fixture(root: &Path) -> (PathBuf, PathBuf) {
    let audit_dir = root.join("audit");
    let key = [0x42u8; 32];
    let sid_a = hex::encode([0xAA; 32]);
    let sid_b = hex::encode([0xBB; 32]);
    write_audit_fixture(
        &audit_dir,
        &key,
        &[
            (1_700_000_000, "announce", Some(sid_a.clone())),
            (1_700_000_001, "announce", Some(sid_b)),
            (1_700_000_002, "receipt_signed", Some(sid_a)),
        ],
    );
    let journal_path = root.join("receipts.bin");
    let j = ReceiptJournal::open(&journal_path).unwrap();
    j.bump(&SessionId::new([0xAA; 32]), 1).unwrap();
    j.bump(&SessionId::new([0xBB; 32]), 1).unwrap();
    drop(j);
    (audit_dir, journal_path)
}

#[test]
fn audit_replay_against_synthetic_fixture() {
    let dir = tempdir().unwrap();
    let (audit_dir, journal_path) = write_pair_fixture(dir.path());
    let out = Command::new(bin())
        .args(["audit", "replay", "--audit-path"])
        .arg(&audit_dir)
        .arg("--journal-path")
        .arg(&journal_path)
        .output()
        .expect("spawn octravpn-node");
    assert!(
        out.status.success(),
        "audit replay failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    // Both audit + journal events should appear.
    assert!(stdout.contains("announce"), "no announce in:\n{stdout}");
    assert!(
        stdout.contains("receipt_signed"),
        "no receipt_signed in:\n{stdout}"
    );
    assert!(
        stdout.contains("journal_floor"),
        "no journal_floor in:\n{stdout}"
    );
    // Short hex of 0xAA…
    assert!(stdout.contains("aaaaaa"), "missing session AA: {stdout}");
}

#[test]
fn audit_replay_filters_by_session_via_cli() {
    let dir = tempdir().unwrap();
    let (audit_dir, journal_path) = write_pair_fixture(dir.path());
    let want_sid = hex::encode([0xAA; 32]);
    let out = Command::new(bin())
        .args(["audit", "replay", "--audit-path"])
        .arg(&audit_dir)
        .arg("--journal-path")
        .arg(&journal_path)
        .arg("--session")
        .arg(&want_sid)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    // No 0xBB short-hex in output.
    assert!(!stdout.contains("bbbbbb"), "BB leaked: {stdout}");
    assert!(stdout.contains("aaaaaa"));
}

#[test]
fn audit_replay_jsonl_parses_per_line() {
    let dir = tempdir().unwrap();
    let (audit_dir, journal_path) = write_pair_fixture(dir.path());
    let out = Command::new(bin())
        .args(["audit", "replay", "--audit-path"])
        .arg(&audit_dir)
        .arg("--journal-path")
        .arg(&journal_path)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let mut lines = 0;
    for line in stdout.lines() {
        let v: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid jsonl line {line:?}: {e}"));
        assert!(v.get("ts_unix").is_some());
        lines += 1;
    }
    // 3 audit + 2 journal = 5 events.
    assert_eq!(lines, 5, "expected 5 events in:\n{stdout}");
}

#[test]
fn audit_verify_passes_on_valid_fixture() {
    let dir = tempdir().unwrap();
    let (audit_dir, journal_path) = write_pair_fixture(dir.path());
    let out = Command::new(bin())
        .args(["audit", "verify", "--audit-path"])
        .arg(&audit_dir)
        .arg("--journal-path")
        .arg(&journal_path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        out.status.success(),
        "expected success; stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("verification PASSED"),
        "missing PASSED in:\n{stdout}"
    );
}

#[test]
fn audit_verify_exit_code_1_on_broken_chain() {
    let dir = tempdir().unwrap();
    let (audit_dir, journal_path) = write_pair_fixture(dir.path());
    // Corrupt the second audit line by editing the inner record.
    let audit_file = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
        .unwrap()
        .path();
    let body = fs::read_to_string(&audit_file).unwrap();
    let mut lines: Vec<String> = body.lines().map(String::from).collect();
    // Mutate the kind of line 2.
    lines[1] = lines[1].replace("announce", "ANNOUNCE");
    fs::write(&audit_file, lines.join("\n") + "\n").unwrap();

    let out = Command::new(bin())
        .args(["audit", "verify", "--audit-path"])
        .arg(&audit_dir)
        .arg("--journal-path")
        .arg(&journal_path)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1; got {:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("FAIL"),
        "expected FAIL marker in:\n{stdout}"
    );
}

#[test]
fn audit_verify_exit_code_3_on_missing_audit() {
    let dir = tempdir().unwrap();
    let out = Command::new(bin())
        .args(["audit", "verify", "--audit-path"])
        .arg(dir.path().join("nowhere"))
        .arg("--journal-path")
        .arg(dir.path().join("none.bin"))
        .arg("--hmac-key")
        .arg(dir.path().join("none.key"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn deprecated_verify_audit_log_still_works() {
    // The pre-existing `verify-audit-log <path>` subcommand should
    // keep functioning after the `audit` parent landed — it's a
    // deprecated alias, not a removal.
    let dir = tempdir().unwrap();
    let (audit_dir, _) = write_pair_fixture(dir.path());
    let audit_file = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
        .unwrap()
        .path();
    // Even though `verify-audit-log` needs a Hub (it goes through the
    // legacy code path), it still exists on the clap surface; we
    // assert `--help` mentions it.
    let out = Command::new(bin()).arg("--help").output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("verify-audit-log") || stdout.contains("VerifyAuditLog"),
        "deprecated verify-audit-log subcommand missing from --help:\n{stdout}"
    );
    // Sanity: the new `audit` parent subcommand also shows up.
    assert!(stdout.contains("audit"), "missing audit parent:\n{stdout}");
    drop(audit_file);
}
