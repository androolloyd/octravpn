//! Offline file verifier — re-walks a single `audit-YYYY-MM-DD.jsonl`,
//! recomputes the HMAC chain, reports the first chain break with line
//! number + expected/claimed MACs, and harvests `(session_id, seq)`
//! pairs for the `audit_cli` cross-check. `verify_file` is the single
//! source of truth — no async, no mutex. New code MUST NOT re-implement
//! the chain walk (F1 in `/tmp/simplify-reuse-review.md`).

use std::{
    collections::{BTreeMap, BTreeSet},
    io::BufRead,
    path::Path,
};

use anyhow::{Context, Result};
use serde_json::Value;

use super::chain::chain_step;
use super::AuditLog;

/// Result of [`AuditLog::verify_file`].
#[derive(Debug, Clone, Default)]
pub(crate) struct FileVerifyReport {
    /// Audit lines verified before any error.
    pub entries: u64,
    /// `session_id (hex) -> set<seq>` harvested from `receipt_signed`
    /// (or any record carrying flat `seq` / `extra.seq`).
    pub signed_seqs: BTreeMap<String, BTreeSet<u64>>,
    /// `Some` iff the chain broke.
    pub first_error: Option<FileVerifyError>,
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
    /// Verify a single audit file. Callers (including
    /// `audit_cli::verify_audit_files`) MUST use this entry point —
    /// #240 / F1 in the reuse review.
    pub(crate) fn verify_file(key: &[u8; 32], path: &Path) -> Result<FileVerifyReport> {
        let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let reader = std::io::BufReader::new(f);
        let mut prev_mac = [0u8; 32];
        let mut entries: u64 = 0;
        let mut signed_seqs: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        let mut first_error: Option<FileVerifyError> = None;
        for (i, line) in reader.lines().enumerate() {
            let line_num = i + 1;
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
