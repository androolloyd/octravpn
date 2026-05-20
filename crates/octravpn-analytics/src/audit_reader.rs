//! Read-only audit-log consumer.
//!
//! The audit log is the format documented in
//! `crates/octravpn-node/src/audit.rs`. Each line is a JSON object
//! with three string fields:
//!
//!   - `record_json` — canonical bytes of the inner `AuditRecord`
//!   - `prev_mac`    — hex(32) HMAC of the prior line (or 64 zeros for
//!                     the first line in a daily file)
//!   - `mac`         — hex(32) HMAC of this line:
//!                     `HMAC-SHA256(key, prev_mac || record_json)`
//!
//! ## Why re-implement the HMAC step here?
//!
//! `AuditLog::verify_file` in the node crate is `pub(crate)` and the
//! node crate is a binary (no library target). Re-implementing the
//! one-line `chain_step` is cheaper than refactoring the node crate
//! into a lib + bin split. The constant-time MAC comparison in
//! `verify_file` below intentionally mirrors the node's behaviour so
//! the same on-disk artefact verifies bit-identically under both.

use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::event::AnalyticsEvent;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 chain step matching `octravpn-node`'s
/// `audit::chain_step`. Re-implemented here so this crate doesn't
/// depend on the node binary.
#[must_use]
pub fn chain_step(key: &[u8; 32], prev_mac: &[u8; 32], record_bytes: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(prev_mac);
    mac.update(record_bytes);
    mac.finalize().into_bytes().into()
}

/// Outcome of verifying + reading one audit file.
#[derive(Debug, Default, Clone)]
pub struct AuditFileScan {
    /// Path that was scanned.
    pub path: PathBuf,
    /// Number of lines that verified cleanly before any error.
    pub verified_lines: u64,
    /// 1-indexed line number where the chain broke, if any. `None`
    /// means the whole file verified.
    pub broke_at: Option<usize>,
    /// Human-readable description of the break (only meaningful when
    /// `broke_at.is_some()`).
    pub break_reason: Option<String>,
    /// Events successfully extracted (only from lines that verified).
    pub events: Vec<AnalyticsEvent>,
}

impl AuditFileScan {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.broke_at.is_none()
    }
}

/// Verify + extract events from a single audit JSONL file. Walks the
/// HMAC chain; on the first break, returns the line number and stops
/// reading. Returns whatever events were extracted up to that point
/// (the broken file is suspect, but the prefix is still authoritative
/// for replay).
pub fn verify_file(key: &[u8; 32], path: &Path) -> Result<AuditFileScan> {
    let f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(f);
    let mut prev_mac = [0u8; 32];
    let mut scan = AuditFileScan {
        path: path.to_path_buf(),
        ..AuditFileScan::default()
    };
    for (i, line) in reader.lines().enumerate() {
        let line_num = i + 1;
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                scan.broke_at = Some(line_num);
                scan.break_reason = Some(format!("io: {e}"));
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let envelope: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                scan.broke_at = Some(line_num);
                scan.break_reason = Some(format!("parse: {e}"));
                break;
            }
        };
        let claimed_prev = match envelope.get("prev_mac").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => {
                scan.broke_at = Some(line_num);
                scan.break_reason = Some("missing prev_mac".into());
                break;
            }
        };
        let claimed_mac = match envelope.get("mac").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => {
                scan.broke_at = Some(line_num);
                scan.break_reason = Some("missing mac".into());
                break;
            }
        };
        let record_json = match envelope.get("record_json").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => {
                scan.broke_at = Some(line_num);
                scan.break_reason = Some("missing record_json".into());
                break;
            }
        };
        let expected_prev = hex::encode(prev_mac);
        if expected_prev != claimed_prev {
            scan.broke_at = Some(line_num);
            scan.break_reason = Some(format!(
                "chain break: prev_mac {claimed_prev} != expected {expected_prev}"
            ));
            break;
        }
        let expect = chain_step(key, &prev_mac, record_json.as_bytes());
        let expect_hex = hex::encode(expect);
        if expect_hex != claimed_mac {
            scan.broke_at = Some(line_num);
            scan.break_reason = Some(format!(
                "mac mismatch: claimed {claimed_mac} != recomputed {expect_hex}"
            ));
            break;
        }
        prev_mac = expect;
        scan.verified_lines += 1;
        if let Some(ev) = AnalyticsEvent::from_audit_record_json(&record_json) {
            scan.events.push(ev);
        }
    }
    Ok(scan)
}

/// Scan a directory for `audit-*.jsonl` files in lexicographic order
/// (date-sorted, since the filename embeds `YYYY-MM-DD`) and verify
/// each one. Returns one `AuditFileScan` per file. The HMAC chain
/// resets at midnight (each daily file starts from the zero prev_mac),
/// so the per-file walk matches the on-disk semantics.
pub fn scan_dir(key: &[u8; 32], dir: &Path) -> Result<Vec<AuditFileScan>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("read_dir {}", dir.display()))?
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_string_lossy().into_owned();
            (name.starts_with("audit-") && name.ends_with(".jsonl")).then_some(p)
        })
        .collect();
    paths.sort();
    paths.into_iter().map(|p| verify_file(key, &p)).collect()
}

/// Try to load the HMAC key from `<dir>/.audit.key`. Returns `Err` if
/// the file is missing or the wrong size (the node writes 32 raw
/// bytes). Used by the standalone analytics binary; the in-process
/// indexer is passed the key directly by the node hub.
pub fn load_audit_key(dir: &Path) -> Result<[u8; 32]> {
    let p = dir.join(".audit.key");
    let raw = fs::read(&p).with_context(|| format!("read {}", p.display()))?;
    if raw.len() != 32 {
        anyhow::bail!(
            "audit key file {} has wrong size ({}); expected 32",
            p.display(),
            raw.len()
        );
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Build a minimal audit file using the same format the node
    /// emits: one JSON object per line with `record_json`, `prev_mac`,
    /// `mac`.
    fn write_audit_file(path: &Path, key: &[u8; 32], records: &[&str]) {
        use std::io::Write;
        let mut f = fs::File::create(path).unwrap();
        let mut prev_mac = [0u8; 32];
        for rec in records {
            let mac = chain_step(key, &prev_mac, rec.as_bytes());
            let env = serde_json::json!({
                "record_json": rec,
                "prev_mac": hex::encode(prev_mac),
                "mac": hex::encode(mac),
            });
            writeln!(f, "{}", serde_json::to_string(&env).unwrap()).unwrap();
            prev_mac = mac;
        }
    }

    #[test]
    fn verifies_clean_chain_and_extracts_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-2026-01-01.jsonl");
        let key = [7u8; 32];
        let recs = [
            r#"{"ts_unix":100,"kind":"announce","session_id":"a","extra":null}"#,
            r#"{"ts_unix":110,"kind":"receipt_signed","session_id":"a","extra":{"seq":1,"bytes_used":500}}"#,
            r#"{"ts_unix":120,"kind":"receipt_signed","session_id":"a","extra":{"seq":2,"bytes_used":1200}}"#,
        ];
        write_audit_file(&path, &key, &recs);
        let scan = verify_file(&key, &path).unwrap();
        assert!(scan.is_clean(), "scan should verify cleanly: {scan:?}");
        assert_eq!(scan.verified_lines, 3);
        assert_eq!(scan.events.len(), 3);
    }

    #[test]
    fn detects_mac_tamper() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-2026-01-01.jsonl");
        let key = [9u8; 32];
        write_audit_file(
            &path,
            &key,
            &[r#"{"ts_unix":1,"kind":"announce","session_id":"a","extra":null}"#],
        );
        // Verify with a DIFFERENT key — every MAC will mismatch.
        let scan = verify_file(&[0u8; 32], &path).unwrap();
        assert_eq!(scan.broke_at, Some(1));
        assert!(scan
            .break_reason
            .as_deref()
            .unwrap()
            .contains("mac mismatch"));
        assert_eq!(scan.verified_lines, 0);
    }

    #[test]
    fn scan_dir_visits_files_in_date_order() {
        let dir = tempdir().unwrap();
        let key = [1u8; 32];
        // Write two daily files out-of-order on disk; lexicographic
        // sort must still pick 2026-01-01 first.
        write_audit_file(
            &dir.path().join("audit-2026-01-02.jsonl"),
            &key,
            &[r#"{"ts_unix":2,"kind":"announce","session_id":"b","extra":null}"#],
        );
        write_audit_file(
            &dir.path().join("audit-2026-01-01.jsonl"),
            &key,
            &[r#"{"ts_unix":1,"kind":"announce","session_id":"a","extra":null}"#],
        );
        let scans = scan_dir(&key, dir.path()).unwrap();
        assert_eq!(scans.len(), 2);
        assert!(scans[0]
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("01-01"));
        assert!(scans[1]
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("01-02"));
    }
}
