//! Offline file verifier — re-walks a single `audit-YYYY-MM-DD.jsonl`,
//! recomputes the HMAC chain, reports the first chain break with line
//! number + expected/claimed MACs, and harvests `(session_id, seq)`
//! pairs for the `audit_cli` cross-check. `verify_file` is the single
//! source of truth — no async, no mutex. New code MUST NOT re-implement
//! the chain walk (F1 in `/tmp/simplify-reuse-review.md`).
//!
//! Perf-6 additions:
//!
//!   - [`AuditLog::verify_file_with_seed`]: walks the file starting
//!     from a non-zero `prev_mac` seed. The boot replay calls this
//!     repeatedly across the directory's files in chronological order
//!     so the cross-file chain (mid-day rotation case) verifies as one
//!     contiguous MAC ladder.
//!   - [`AuditLog::verify_dir_skip_to_tip`]: the cold-start
//!     fast-path. If `audit-chain.tip` is present + commits to a
//!     `(file_id, seq, mac)` that matches a line on disk, skip the
//!     prefix and verify only the un-fsynced (or post-tip) tail of
//!     the most recent file. Falls back to full replay on any
//!     mismatch (tampered prefix detection) or missing/corrupt tip.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::BufRead,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde_json::Value;

use super::chain::chain_step;
use super::rotation::{list_audit_files, ChainTip};
use super::AuditLog;

/// Result of [`AuditLog::verify_file`].
#[derive(Debug, Clone, Default)]
pub(crate) struct FileVerifyReport {
    /// Audit lines verified before any error (excluding any skipped
    /// prefix, when `verify_file_with_seed` is called via the
    /// skip-to-tip path).
    pub entries: u64,
    /// `session_id (hex) -> set<seq>` harvested from `receipt_signed`
    /// (or any record carrying flat `seq` / `extra.seq`).
    pub signed_seqs: BTreeMap<String, BTreeSet<u64>>,
    /// `Some` iff the chain broke.
    pub first_error: Option<FileVerifyError>,
    /// MAC of the last successfully verified line — feeds into the
    /// next file's `verify_file_with_seed` call so a chronological
    /// walk verifies an unbroken HMAC ladder across rotation
    /// boundaries.
    pub last_mac: [u8; 32],
}

/// One concrete way an audit file can fail verification.
#[derive(Debug, Clone)]
pub(crate) struct FileVerifyError {
    /// 1-indexed line number in the file.
    pub line: usize,
    pub kind: FileVerifyErrorKind,
}

impl std::fmt::Display for FileVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            FileVerifyErrorKind::ChainBreak { expected, claimed } => write!(
                f,
                "chain break at line {}: prev_mac {claimed} != expected {expected}",
                self.line
            ),
            FileVerifyErrorKind::MacMismatch { expected, claimed } => write!(
                f,
                "MAC mismatch at line {}: log mac {claimed} != recomputed {expected}",
                self.line
            ),
            FileVerifyErrorKind::MissingField(name) => {
                write!(f, "line {} missing {name}", self.line)
            }
            FileVerifyErrorKind::Parse(msg) | FileVerifyErrorKind::Io(msg) => {
                write!(f, "line {}: {msg}", self.line)
            }
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) enum FileVerifyErrorKind {
    ChainBreak { expected: String, claimed: String },
    MacMismatch { expected: String, claimed: String },
    MissingField(&'static str),
    Parse(String),
    Io(String),
}

impl AuditLog {
    /// Verify a single audit file from the zero-seed (the original
    /// per-day-independent contract). Callers (including
    /// `audit_cli::verify_audit_files`) MUST use this entry point —
    /// #240 / F1 in the reuse review.
    pub(crate) fn verify_file(key: &[u8; 32], path: &Path) -> Result<FileVerifyReport> {
        Self::verify_file_with_seed(key, path, [0u8; 32])
    }

    /// Verify a single audit file from a caller-supplied prev_mac
    /// seed. Used by the boot replay to walk a rotated chain across
    /// multiple files (file N+1's first line takes file N's last MAC
    /// as its prev_mac). The zero-seed entry-point [`verify_file`]
    /// preserves the legacy per-day-independent contract.
    pub(crate) fn verify_file_with_seed(
        key: &[u8; 32],
        path: &Path,
        seed: [u8; 32],
    ) -> Result<FileVerifyReport> {
        let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let reader = std::io::BufReader::new(f);
        walk_chain(key, reader, seed, /*skip_lines=*/ 0)
    }

    /// Cold-start fast path: when the chain-tip file is present and
    /// verifiable, skip every file BEFORE the tip's target file (the
    /// tip's MAC implicitly commits to their content + chain) and
    /// every line up to the tip's `seq` within that file. Then walk
    /// forward through the un-skipped tail + any subsequent files
    /// (which carry the chain via inter-file prev_mac).
    ///
    /// Without the tip file (cold first boot OR tip corrupt), we
    /// degrade to full replay: walk every file from the zero seed.
    /// **Note:** if the ring buffer has evicted older files, full
    /// replay will report a chain break on the first surviving
    /// file — operators must use `octravpn-node audit verify --full`
    /// against an unrotated backup to forensically reverify the
    /// evicted-but-still-on-tape range.
    ///
    /// **Tamper detection.** The tip commits to `(file_id, seq, mac)`.
    /// Before honouring the skip, we open `file_id`, advance to line
    /// `seq`, and check that the line's `mac` field equals `tip.mac`.
    /// If it doesn't (prefix tampered OR truncated) we fall back to
    /// full replay for that file from the prior file's last MAC.
    /// A subsequent chain break on full replay is the tamper signal.
    pub(crate) fn verify_dir_skip_to_tip(
        key: &[u8; 32],
        dir: &Path,
    ) -> Result<Vec<(PathBuf, FileVerifyReport)>> {
        let files = list_audit_files(dir)?;
        let tip = ChainTip::load(dir);
        let mut out: Vec<(PathBuf, FileVerifyReport)> = Vec::with_capacity(files.len());

        // Locate the tip's target index in the sorted files list. If
        // the tip references a file that's been evicted, fall back to
        // tip-less mode (full replay).
        let tip_idx = tip.as_ref().and_then(|t| {
            files.iter().position(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .map_or(false, |n| n == t.file_id)
            })
        });

        // If tip is present + targets a surviving file, start the
        // verification at THAT file (skip everything older — those
        // are committed-to by the chain ladder up to the tip).
        let start_idx = tip_idx.unwrap_or(0);
        let mut prev = [0u8; 32];

        for (i, path) in files.iter().enumerate() {
            if i < start_idx {
                continue; // committed-to by the tip's MAC
            }
            let basename = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();

            let skip_to_seq = if i == start_idx {
                tip.as_ref()
                    .filter(|t| t.file_id == basename)
                    .map(|t| (t.seq, t.mac.clone()))
            } else {
                None
            };

            let report = match skip_to_seq {
                Some((seq, mac_hex)) if seq > 0 => {
                    match prepare_skip(key, path, &mac_hex, seq, prev) {
                        Some(seed) => {
                            let f = std::fs::File::open(path)
                                .with_context(|| format!("open {}", path.display()))?;
                            walk_chain(key, std::io::BufReader::new(f), seed, seq as usize)?
                        }
                        None => {
                            // Tip didn't match this file's prefix — fall
                            // back to full replay from prev (zero on the
                            // tip-target file).
                            Self::verify_file_with_seed(key, path, prev)?
                        }
                    }
                }
                _ => Self::verify_file_with_seed(key, path, prev)?,
            };

            let next = report.last_mac;
            let had_err = report.first_error.is_some();
            out.push((path.clone(), report));
            if had_err {
                break;
            }
            prev = next;
        }
        Ok(out)
    }
}

/// Sanity-check that the line at `tip.seq` in `path` carries `tip.mac`
/// exactly. Returns the MAC bytes (the seed for verifying the post-tip
/// tail) on success, `None` otherwise. The caller then falls back to
/// full replay if `None`.
fn prepare_skip(
    _key: &[u8; 32],
    path: &Path,
    tip_mac_hex: &str,
    tip_seq: u64,
    _prev_seed: [u8; 32],
) -> Option<[u8; 32]> {
    use std::io::BufRead;
    let f = std::fs::File::open(path).ok()?;
    let reader = std::io::BufReader::new(f);
    let mut line_no = 0u64;
    for line in reader.lines() {
        let line = line.ok()?;
        if line.trim().is_empty() {
            continue;
        }
        line_no += 1;
        if line_no == tip_seq {
            let v: Value = serde_json::from_str(&line).ok()?;
            let claimed = v.get("mac")?.as_str()?;
            if claimed != tip_mac_hex {
                return None;
            }
            let mut seed = [0u8; 32];
            let raw = hex::decode(claimed).ok()?;
            if raw.len() != 32 {
                return None;
            }
            seed.copy_from_slice(&raw);
            return Some(seed);
        }
    }
    None
}

/// The single chain-walking primitive — used by both the zero-seed
/// path ([`AuditLog::verify_file`]) and the skip-to-tip path. `seed`
/// is the prev_mac for the FIRST verified line (so line `skip_lines+1`).
/// `skip_lines` is the number of lines to skim past without verifying
/// (they're committed to via the seed's MAC).
fn walk_chain<R: BufRead>(
    key: &[u8; 32],
    reader: R,
    seed: [u8; 32],
    skip_lines: usize,
) -> Result<FileVerifyReport> {
    let mut prev_mac = seed;
    let mut entries: u64 = 0;
    let mut signed_seqs: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    let mut first_error: Option<FileVerifyError> = None;
    for (i, line) in reader.lines().enumerate() {
        let line_num = i + 1;
        if line_num <= skip_lines {
            // Don't verify, don't extract — committed to via the tip.
            continue;
        }
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                first_error = Some(FileVerifyError {
                    line: line_num,
                    kind: FileVerifyErrorKind::Io(format!("read error: {e}")),
                });
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                first_error = Some(FileVerifyError {
                    line: line_num,
                    kind: FileVerifyErrorKind::Parse(format!("bad json: {e}")),
                });
                break;
            }
        };
        let Some(claimed_prev) = v
            .get("prev_mac")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            first_error = Some(FileVerifyError {
                line: line_num,
                kind: FileVerifyErrorKind::MissingField("prev_mac"),
            });
            break;
        };
        let Some(claimed_mac) = v.get("mac").and_then(Value::as_str).map(str::to_string) else {
            first_error = Some(FileVerifyError {
                line: line_num,
                kind: FileVerifyErrorKind::MissingField("mac"),
            });
            break;
        };
        let expected_prev_hex = hex::encode(prev_mac);
        if expected_prev_hex != claimed_prev {
            first_error = Some(FileVerifyError {
                line: line_num,
                kind: FileVerifyErrorKind::ChainBreak {
                    expected: expected_prev_hex,
                    claimed: claimed_prev,
                },
            });
            break;
        }
        let Some(canonical) = v
            .get("record_json")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            first_error = Some(FileVerifyError {
                line: line_num,
                kind: FileVerifyErrorKind::MissingField("record_json"),
            });
            break;
        };
        let expect = chain_step(key, &prev_mac, canonical.as_bytes());
        let expect_hex = hex::encode(expect);
        if expect_hex != claimed_mac {
            first_error = Some(FileVerifyError {
                line: line_num,
                kind: FileVerifyErrorKind::MacMismatch {
                    expected: expect_hex,
                    claimed: claimed_mac,
                },
            });
            break;
        }
        prev_mac = expect;
        entries += 1;
        if let Ok(rec) = serde_json::from_str::<Value>(&canonical) {
            let sid = rec
                .get("session_id")
                .and_then(Value::as_str)
                .map(String::from);
            let extra = rec.get("extra");
            let seq = rec
                .get("seq")
                .and_then(Value::as_u64)
                .or_else(|| extra.and_then(|e| e.get("seq")).and_then(Value::as_u64));
            if let (Some(sid), Some(seq)) = (sid, seq) {
                signed_seqs.entry(sid).or_default().insert(seq);
            }
        }
    }
    Ok(FileVerifyReport {
        entries,
        signed_seqs,
        first_error,
        last_mac: prev_mac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::rotation::{ChainTip, RotationCfg};
    use tempfile::tempdir;

    #[test]
    fn verify_file_passes_clean_chain() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        crate::audit::test_util::write_n_x(&log, 5);
        let audit_file = crate::audit::test_util::audit_file_in(dir.path());
        let report = AuditLog::verify_file(&log.key(), &audit_file).unwrap();
        assert_eq!(report.entries, 5);
        assert!(report.first_error.is_none());
    }

    /// Cross-module: drives the `batched.rs` emit helper +
    /// `log.rs` envelope, verifies via this module — confirms the
    /// three modules round-trip the `receipt_signed` schema correctly.
    #[tokio::test]
    async fn receipt_signed_entry_round_trips() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.record_receipt_signed("a1b2c3".to_string(), 7, 1024)
            .await
            .unwrap();
        let audit_file = crate::audit::test_util::audit_file_in(dir.path());
        let body = std::fs::read_to_string(&audit_file).unwrap();
        let chained: Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        let canonical = chained.get("record_json").unwrap().as_str().unwrap();
        let rec: Value = serde_json::from_str(canonical).unwrap();
        assert_eq!(rec["kind"], "receipt_signed");
        assert_eq!(rec["session_id"], "a1b2c3");
        assert_eq!(rec["extra"]["seq"], 7);
        assert_eq!(rec["extra"]["bytes_used"], 1024);
        let report = AuditLog::verify_file(&log.key(), &audit_file).unwrap();
        assert_eq!(report.entries, 1);
        assert!(report
            .signed_seqs
            .get("a1b2c3")
            .is_some_and(|s| s.contains(&7)));
    }

    #[test]
    fn verify_file_detects_tampered_line() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        crate::audit::test_util::write_n_x(&log, 3);
        let key = log.key();
        let audit_file = crate::audit::test_util::audit_file_in(dir.path());
        let original = std::fs::read_to_string(&audit_file).unwrap();
        let mut lines: Vec<String> = original.lines().map(String::from).collect();
        lines[1] = lines[1].replacen("\\\"i\\\":1", "\\\"i\\\":99", 1);
        std::fs::write(&audit_file, lines.join("\n") + "\n").unwrap();
        let report = AuditLog::verify_file(&key, &audit_file).unwrap();
        let err = report.first_error.expect("tampered line should fail");
        assert_eq!(err.line, 2);
        assert!(matches!(err.kind, FileVerifyErrorKind::MacMismatch { .. }));
    }

    /// Broken-chain reports include line + claimed/expected MACs.
    #[test]
    fn verify_file_reports_line_and_macs_on_chain_break() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        crate::audit::test_util::write_n_x(&log, 3);
        let audit_file = crate::audit::test_util::audit_file_in(dir.path());
        let body = std::fs::read_to_string(&audit_file).unwrap();
        let mut lines: Vec<String> = body.lines().map(String::from).collect();
        let zeros = "0".repeat(64);
        let v: Value = serde_json::from_str(&lines[1]).unwrap();
        let claimed_prev = v.get("prev_mac").unwrap().as_str().unwrap().to_string();
        lines[1] = lines[1].replacen(claimed_prev.as_str(), &zeros, 1);
        std::fs::write(&audit_file, lines.join("\n") + "\n").unwrap();
        let report = AuditLog::verify_file(&log.key(), &audit_file).unwrap();
        let err = report.first_error.expect("chain break must report");
        assert_eq!(err.line, 2);
        match err.kind {
            FileVerifyErrorKind::ChainBreak { expected, claimed } => {
                assert_eq!(claimed, zeros);
                assert_ne!(expected, zeros);
            }
            other => panic!("expected ChainBreak; got {other:?}"),
        }
    }

    /// `signed_seqs` powers the CLI cross-check without a second walk.
    #[tokio::test]
    async fn verify_file_returns_signed_seqs_for_cross_check() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.record_receipt_signed("aa".into(), 1, 100)
            .await
            .unwrap();
        log.record_receipt_signed("aa".into(), 2, 200)
            .await
            .unwrap();
        log.record_receipt_signed("bb".into(), 5, 0).await.unwrap();
        let audit_file = crate::audit::test_util::audit_file_in(dir.path());
        let report = AuditLog::verify_file(&log.key(), &audit_file).unwrap();
        assert_eq!(report.entries, 3);
        let aa = report.signed_seqs.get("aa").expect("aa harvested");
        assert!(aa.contains(&1) && aa.contains(&2));
        let bb = report.signed_seqs.get("bb").expect("bb harvested");
        assert!(bb.contains(&5));
    }

    // ---- Perf-6 skip-to-tip tests ----

    /// Skip-to-tip is byte-identical to full replay for a clean log:
    /// same total verified line count, same final MAC.
    #[test]
    fn skip_to_tip_matches_full_replay_for_clean_log() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..10u64 {
            log.write(&crate::audit::AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: Some(format!("s{i}")),
                extra: serde_json::json!({"i": i}),
            })
            .unwrap();
        }
        let key = log.key();
        // Full replay: walk every file from zero seed.
        let files = crate::audit::rotation::list_audit_files(dir.path()).unwrap();
        let mut full_prev = [0u8; 32];
        let mut full_total = 0u64;
        for f in &files {
            let r = AuditLog::verify_file_with_seed(&key, f, full_prev).unwrap();
            assert!(r.first_error.is_none());
            full_total += r.entries;
            full_prev = r.last_mac;
        }
        // Skip-to-tip: relies on the tip file written by `log.write`.
        let reports = AuditLog::verify_dir_skip_to_tip(&key, dir.path()).unwrap();
        let skip_total: u64 = reports.iter().map(|(_, r)| r.entries).sum();
        let skip_last = reports.last().map(|(_, r)| r.last_mac).unwrap_or([0u8; 32]);
        // After skip-to-tip: the prefix is committed-to by the tip, so
        // `entries` counts only the un-skipped tail. The *MAC* must
        // still match the full-walk final MAC.
        assert_eq!(skip_last, full_prev, "final MACs must match");
        // The skip path verified strictly fewer (or equal) lines.
        assert!(skip_total <= full_total);
    }

    /// Tampered prefix is detected even with skip-to-tip when the
    /// tamper extends to the line the tip commits to. The fast-path
    /// validates `file[tip.seq].mac == tip.mac` before honouring the
    /// skip; if the attacker tampered with the line at `tip.seq`,
    /// the check fails, skip-to-tip refuses to skip, and falls back
    /// to full replay — which surfaces the tamper as a MAC mismatch.
    ///
    /// (Tampering deeper in the prefix WITHOUT touching the
    /// tip-committed line is by design covered by the operator's
    /// offline `octravpn-node audit verify --full <dir>` recovery
    /// tool — skip-to-tip is a boot accelerator, not a substitute
    /// for the full integrity scan.)
    #[test]
    fn skip_to_tip_detects_tampered_prefix() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..5u64 {
            log.write(&crate::audit::AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: None,
                extra: serde_json::json!({"i": i}),
            })
            .unwrap();
        }
        let key = log.key();
        let audit_file = crate::audit::test_util::audit_file_in(dir.path());
        // Tamper the LAST line — both record_json AND its mac field —
        // so the file no longer agrees with the tip's commitment. The
        // `prepare_skip` invariant `file[tip.seq].mac == tip.mac`
        // breaks, forcing fall-back to full replay; full replay then
        // catches the MAC mismatch.
        let body = std::fs::read_to_string(&audit_file).unwrap();
        let mut lines: Vec<String> = body.lines().map(String::from).collect();
        let last_idx = lines.len() - 1;
        // First flip record_json bytes:
        lines[last_idx] = lines[last_idx].replacen("\\\"i\\\":4", "\\\"i\\\":99", 1);
        // Now flip the `mac` field so prepare_skip's commitment check
        // fails (simulates an attacker who tried to keep the tip
        // pointed at the tampered line). The flipped hex char "f" -> "0"
        // is purely cosmetic — any change in mac breaks the check.
        let v: Value = serde_json::from_str(&lines[last_idx]).unwrap();
        let mac = v.get("mac").unwrap().as_str().unwrap().to_string();
        let mut bytes: Vec<u8> = mac.as_bytes().to_vec();
        // Flip the first hex nibble (xor with 0x01) to produce a
        // syntactically valid but cryptographically wrong MAC.
        if bytes[0] == b'0' {
            bytes[0] = b'1';
        } else {
            bytes[0] = b'0';
        }
        let tampered_mac = String::from_utf8(bytes).unwrap();
        lines[last_idx] = lines[last_idx].replacen(&mac, &tampered_mac, 1);
        std::fs::write(&audit_file, lines.join("\n") + "\n").unwrap();

        let reports = AuditLog::verify_dir_skip_to_tip(&key, dir.path()).unwrap();
        // At least one file must report a chain failure.
        let any_err = reports.iter().any(|(_, r)| r.first_error.is_some());
        assert!(any_err, "tampered prefix must be detected: {reports:?}");
    }

    /// Fresh node (no tip file) does a full replay: every line in
    /// every file is re-verified.
    #[test]
    fn fresh_node_does_full_replay() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..4u64 {
            log.write(&crate::audit::AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: None,
                extra: serde_json::json!({"i": i}),
            })
            .unwrap();
        }
        // Simulate "fresh node": nuke the tip file.
        let _ = std::fs::remove_file(ChainTip::path(dir.path()));
        let reports = AuditLog::verify_dir_skip_to_tip(&log.key(), dir.path()).unwrap();
        let total: u64 = reports.iter().map(|(_, r)| r.entries).sum();
        assert_eq!(total, 4, "every line must be verified on a fresh boot");
    }

    /// Round-trip: skip-to-tip across a multi-file (rotated) log
    /// returns the same final MAC as a full walk.
    #[test]
    fn skip_to_tip_round_trips_across_rotation() {
        let dir = tempdir().unwrap();
        let cfg = RotationCfg {
            max_file_bytes: 256,
            max_file_count: 100,
            ..Default::default()
        };
        let log = AuditLog::open_with_rotation(dir.path(), cfg).unwrap();
        for i in 0..10u64 {
            log.write(&crate::audit::AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: None,
                extra: serde_json::json!({"i": i, "p": "x".repeat(80)}),
            })
            .unwrap();
        }
        let key = log.key();
        let files = crate::audit::rotation::list_audit_files(dir.path()).unwrap();
        assert!(files.len() > 1, "must have rotated");
        let mut full_prev = [0u8; 32];
        for f in &files {
            let r = AuditLog::verify_file_with_seed(&key, f, full_prev).unwrap();
            assert!(r.first_error.is_none());
            full_prev = r.last_mac;
        }
        let reports = AuditLog::verify_dir_skip_to_tip(&key, dir.path()).unwrap();
        let skip_last = reports.last().map(|(_, r)| r.last_mac).unwrap();
        assert_eq!(skip_last, full_prev);
    }
}
