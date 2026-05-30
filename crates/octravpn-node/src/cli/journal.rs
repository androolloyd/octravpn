//! `octravpn-node journal rebuild` — disaster-recovery CLI that
//! reconstructs a v1 receipt journal from the operator's HMAC-chained
//! audit log.
//!
//! ## Problem (audit-9 H-RTO)
//!
//! When the receipt journal file is corrupted (bit-flip in a v1 record,
//! CRC mismatch, partial write that didn't end on a record boundary
//! beyond the silent torn-tail tolerance), the daemon refuses to start
//! with `JournalError::ChecksumMismatch`. The only recovery option pre-
//! this CLI was to hand-rebuild the 44-byte v1 records from the audit
//! log — operators reported ≥30 minutes RTO per the DR-drill audit.
//!
//! ## Solution
//!
//! The audit log already carries every `(session_id, seq)` pair that
//! the journal could possibly hold: every `receipt_signed` row records
//! the seq the daemon committed before signing. [`AuditLog::verify_file`]
//! returns these as `signed_seqs: BTreeMap<session_hex, BTreeSet<seq>>`
//! after walking and HMAC-verifying every line. From that map the floor
//! per session is just `max(seqs)`.
//!
//! `journal rebuild --from-audit <dir> --output <path>` walks every
//! `audit-YYYY-MM-DD.jsonl` file, harvests the signed_seqs, computes
//! the per-session floor, and writes a fresh v1 journal via
//! `ReceiptJournal::bump`. The result is byte-different from a
//! compacted live journal in record order, but the *floor map* —
//! which is what the daemon consults — is identical.
//!
//! ## Safety
//!
//! A tampered audit log will not pass `verify_file`'s HMAC chain check;
//! the CLI surfaces this as a hard failure (exit 1) and refuses to
//! emit a journal. An attacker who can rewrite the audit log cannot
//! influence the rebuilt floor map.
//!
//! ## Validation
//!
//! After writing, the rebuild reopens the journal with
//! `ReceiptJournal::open` and compares the floor map to the
//! audit-derived set. Any divergence (which would indicate a codec bug
//! or a partial write that survived fsync somehow) surfaces as exit
//! code 4 with the per-session diff.
//!
//! ## Performance
//!
//! On a ~10k-entry audit log the rebuild walks the file in O(n),
//! computes one BTreeMap pass to fold by session, and emits one
//! `bump()` per live session (typically ≪ 10k since the same session
//! signs many times). The whole pipeline runs in well under 2 minutes
//! at typical sizes (audit-9 H-RTO target).

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::{Args, Subcommand as ClapSubcommand};
use serde::Serialize;
use tracing::info;

use octravpn_core::{receipt_journal::ReceiptJournal, session::SessionId};

use crate::audit::{resolve_hmac_key, AuditLog, HmacKeyError};

use super::{CliContext, Subcommand};

/// `octravpn-node journal …` top-level args.
#[derive(Args, Debug)]
pub(crate) struct JournalArgs {
    #[command(subcommand)]
    pub(crate) cmd: JournalCmd,
}

/// `journal` subcommand variants.
#[derive(ClapSubcommand, Debug)]
pub(crate) enum JournalCmd {
    /// Reconstruct a v1 receipt journal from an HMAC-verified audit log
    /// directory. Closes the audit-9 H-RTO recovery gap: when the live
    /// journal file is corrupted (CRC mismatch on a v1 record), an
    /// operator can synthesize the floor map from the audit log without
    /// touching individual 44-byte records by hand.
    Rebuild(RebuildArgs),
}

#[derive(Args, Debug)]
pub(crate) struct RebuildArgs {
    /// Audit log directory (the path that contains
    /// `audit-YYYY-MM-DD.jsonl` files + `.audit.key`).
    #[arg(long)]
    pub(crate) from_audit: PathBuf,
    /// Output path for the reconstructed journal. Refuses to overwrite
    /// an existing file unless `--force` is set.
    #[arg(long)]
    pub(crate) output: PathBuf,
    /// Path to the HMAC key file. Defaults to `<from-audit>/.audit.key`,
    /// matching what the running daemon writes.
    #[arg(long)]
    pub(crate) hmac_key: Option<PathBuf>,
    /// Print the rebuild plan (sessions + their derived floor) without
    /// writing the output journal. Useful for a "what would change"
    /// preview before touching disk.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Overwrite `--output` if it already exists. Default refuses, to
    /// avoid stomping a partially-recovered journal.
    #[arg(long)]
    pub(crate) force: bool,
}

#[async_trait]
impl Subcommand for JournalArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, _ctx: CliContext<'_>) -> Result<i32> {
        match self.cmd {
            JournalCmd::Rebuild(args) => {
                let mut stdout = std::io::stdout();
                let code = run_rebuild(&args, &mut stdout)?;
                Ok(code)
            }
        }
    }
}

/// Result of a successful rebuild (or a dry-run preview). Serializable
/// so a future `--format json` flag can stream this verbatim.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RebuildReport {
    /// Total number of `(session_id, seq)` pairs harvested from the
    /// audit log.
    pub harvested_pairs: u64,
    /// Number of distinct sessions in the rebuild plan (== number of
    /// records the rebuilt journal will hold).
    pub sessions: usize,
    /// Per-session floor (max seq per session). Sorted by session id.
    pub plan: Vec<(String, u64)>,
    /// Wall-clock seconds spent walking the audit log + verifying the
    /// rebuilt journal. Reported so operators can compare against the
    /// audit-9 H-RTO 2-minute target.
    pub elapsed_secs: f64,
    /// True if `--dry-run` was passed; the output file was NOT written.
    pub dry_run: bool,
}

/// Pure helper: walk the audit directory, HMAC-verify every file,
/// fold the `signed_seqs` map into a per-session floor, and return the
/// plan. Does NOT touch the output path. Pulled out of [`run_rebuild`]
/// so unit tests can exercise it without an output file.
pub(crate) fn build_plan(
    audit_dir: &Path,
    explicit_key: Option<&Path>,
) -> Result<(BTreeMap<String, u64>, u64)> {
    let key = load_hmac_key(audit_dir, explicit_key)?;
    let files = discover_audit_files(audit_dir)?;
    if files.is_empty() {
        anyhow::bail!("no audit-*.jsonl files found under {}", audit_dir.display());
    }
    let mut signed: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    let mut total_pairs: u64 = 0;
    for file in &files {
        let report = AuditLog::verify_file(&key, file)
            .with_context(|| format!("verify {}", file.display()))?;
        if let Some(err) = report.first_error {
            anyhow::bail!(
                "audit log {} failed HMAC verification at {err}; \
                 refusing to rebuild journal from a tampered source",
                file.display()
            );
        }
        for (sid, seqs) in report.signed_seqs {
            total_pairs += seqs.len() as u64;
            signed.entry(sid).or_default().extend(seqs);
        }
    }
    let floors: BTreeMap<String, u64> = signed
        .into_iter()
        .filter_map(|(sid, seqs)| seqs.iter().copied().max().map(|m| (sid, m)))
        .collect();
    Ok((floors, total_pairs))
}

/// Top-level CLI body. Exit codes:
///   0 — success (rebuild written + verified, or dry-run plan printed)
///   1 — audit log invalid (HMAC chain broken)
///   2 — IO failure
///   3 — refusing to overwrite an existing output without `--force`
///   4 — post-write verification mismatch
pub(crate) fn run_rebuild(args: &RebuildArgs, out: &mut dyn std::io::Write) -> Result<i32> {
    let t0 = Instant::now();
    let (plan, total_pairs) = match build_plan(&args.from_audit, args.hmac_key.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            writeln!(out, "rebuild plan failed: {e:#}")?;
            // HMAC chain breakage is the load-bearing case we want to
            // surface as exit 1; lower-level IO errors collapse into
            // anyhow::Error which we report as 2 below.
            let msg = format!("{e:#}");
            if msg.contains("HMAC verification") || msg.contains("tampered") {
                return Ok(1);
            }
            return Ok(2);
        }
    };
    let sessions = plan.len();
    let plan_vec: Vec<(String, u64)> = plan.iter().map(|(k, v)| (k.clone(), *v)).collect();

    writeln!(out, "rebuild plan:")?;
    writeln!(out, "  audit_dir       = {}", args.from_audit.display())?;
    writeln!(out, "  output          = {}", args.output.display())?;
    writeln!(out, "  harvested pairs = {total_pairs}")?;
    writeln!(out, "  live sessions   = {sessions}")?;
    for (sid, floor) in &plan_vec {
        writeln!(out, "    {} -> seq={floor}", short_hex(sid))?;
    }

    if args.dry_run {
        let elapsed = t0.elapsed().as_secs_f64();
        writeln!(out)?;
        writeln!(out, "dry-run: no journal written (elapsed {elapsed:.3}s)")?;
        emit_report_footer(
            out,
            &RebuildReport {
                harvested_pairs: total_pairs,
                sessions,
                plan: plan_vec,
                elapsed_secs: elapsed,
                dry_run: true,
            },
        )?;
        return Ok(0);
    }

    if args.output.exists() && !args.force {
        writeln!(
            out,
            "refusing to overwrite {} (pass --force to replace)",
            args.output.display()
        )?;
        return Ok(3);
    }
    if args.output.exists() && args.force {
        fs::remove_file(&args.output)
            .with_context(|| format!("remove existing {}", args.output.display()))?;
    }

    // Write the journal. We use the public `ReceiptJournal::open` +
    // `bump` API so the on-disk format is whatever the codec emits
    // today — a future v2 codec change requires zero changes here.
    let journal = ReceiptJournal::open(&args.output)
        .with_context(|| format!("open output journal {}", args.output.display()))?;
    for (sid_hex, floor) in &plan_vec {
        let sid =
            SessionId::from_hex(sid_hex).with_context(|| format!("decode session id {sid_hex}"))?;
        journal
            .bump(&sid, *floor)
            .with_context(|| format!("bump session {sid_hex} to seq {floor}"))?;
    }
    drop(journal);

    // Re-open and confirm the floor map matches the plan.
    let verify = ReceiptJournal::open(&args.output)
        .with_context(|| format!("re-open for verify {}", args.output.display()))?;
    let live_floors: BTreeMap<String, u64> = verify
        .entries()
        .into_iter()
        .map(|(s, seq)| (s.to_hex(), seq))
        .collect();
    drop(verify);

    if live_floors != plan {
        writeln!(
            out,
            "VERIFY FAILED — rebuilt journal floor map does not match plan"
        )?;
        // Diff helper: report sessions whose floor differs (or is missing).
        let plan_keys: BTreeSet<&String> = plan.keys().collect();
        let live_keys: BTreeSet<&String> = live_floors.keys().collect();
        for missing in plan_keys.difference(&live_keys) {
            writeln!(
                out,
                "  missing in journal: {} (plan seq={})",
                short_hex(missing),
                plan.get(*missing).copied().unwrap_or_default()
            )?;
        }
        for extra in live_keys.difference(&plan_keys) {
            writeln!(out, "  extra in journal: {}", short_hex(extra))?;
        }
        for (sid, plan_seq) in &plan {
            if let Some(live_seq) = live_floors.get(sid) {
                if live_seq != plan_seq {
                    writeln!(
                        out,
                        "  drift {}: plan seq={plan_seq} live seq={live_seq}",
                        short_hex(sid)
                    )?;
                }
            }
        }
        return Ok(4);
    }

    let elapsed = t0.elapsed().as_secs_f64();
    writeln!(out)?;
    writeln!(
        out,
        "rebuild complete: {sessions} sessions written + verified \
         (elapsed {elapsed:.3}s)"
    )?;
    info!(sessions, elapsed, "journal rebuild ok");
    emit_report_footer(
        out,
        &RebuildReport {
            harvested_pairs: total_pairs,
            sessions,
            plan: plan_vec,
            elapsed_secs: elapsed,
            dry_run: false,
        },
    )?;
    Ok(0)
}

fn emit_report_footer(out: &mut dyn std::io::Write, r: &RebuildReport) -> std::io::Result<()> {
    // audit-13: textual `[ ok ]` prefix so color-blind operators or
    // screen readers get the status independently of any future
    // colourization.
    let prefix = if r.dry_run { "[plan]" } else { "[ ok ]" };
    writeln!(
        out,
        "{prefix} rebuild: harvested={} sessions={} elapsed={:.3}s",
        r.harvested_pairs, r.sessions, r.elapsed_secs
    )
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

/// Resolve the HMAC key file. Shares the discovery + validation rule
/// with the `audit`/`receipt` CLI surfaces via [`resolve_hmac_key`].
fn load_hmac_key(audit_dir: &Path, explicit: Option<&Path>) -> Result<[u8; 32]> {
    resolve_hmac_key(audit_dir, explicit).map_err(|e| match e {
        HmacKeyError::NotFound(p) => anyhow::anyhow!(
            "HMAC key not found at {} (pass --hmac-key explicitly)",
            p.display()
        ),
        HmacKeyError::Invalid(e) => e,
    })
}

fn discover_audit_files(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    if path.is_dir() {
        let mut out = Vec::new();
        for entry in fs::read_dir(path).with_context(|| format!("readdir {}", path.display()))? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("audit-") && name_str.ends_with(".jsonl") {
                out.push(entry.path());
            }
        }
        out.sort();
        Ok(out)
    } else {
        // Single-file path — accept it (matches `audit_cli`).
        Ok(vec![path.to_path_buf()])
    }
}

fn short_hex(s: &str) -> String {
    if s.len() <= 12 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..6], &s[s.len() - 4..])
    }
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditRecord;
    use serde_json::{json, Value};
    use tempfile::tempdir;

    fn write_signed_seq(log: &AuditLog, sid_hex: &str, seq: u64, ts: u64) {
        log.write(&AuditRecord {
            ts_unix: ts,
            kind: "receipt_signed",
            source: None,
            session_id: Some(sid_hex.to_string()),
            extra: json!({ "seq": seq, "bytes_used": 0 }),
        })
        .unwrap();
    }

    fn sid_hex(b: u8) -> String {
        hex::encode([b; 32])
    }

    /// End-to-end: build an audit log with several sessions, walk it
    /// via the public CLI body, and confirm the rebuilt journal's floor
    /// map matches the per-session max.
    #[tokio::test]
    async fn rebuild_writes_journal_matching_audit_floors() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let log = AuditLog::open(&audit_dir).unwrap();
        let a = sid_hex(0xAA);
        let b = sid_hex(0xBB);
        // Session A signed seqs 1, 5, 9 (floor = 9).
        write_signed_seq(&log, &a, 1, 100);
        write_signed_seq(&log, &a, 5, 101);
        write_signed_seq(&log, &a, 9, 102);
        // Session B signed seqs 3, 4 (floor = 4).
        write_signed_seq(&log, &b, 3, 103);
        write_signed_seq(&log, &b, 4, 104);
        drop(log);

        let output = dir.path().join("rebuilt.bin");
        let args = RebuildArgs {
            from_audit: audit_dir,
            output: output.clone(),
            hmac_key: None,
            dry_run: false,
            force: false,
        };
        let mut buf = Vec::new();
        let code = run_rebuild(&args, &mut buf).unwrap();
        let txt = String::from_utf8(buf).unwrap();
        assert_eq!(code, 0, "expected success; output:\n{txt}");
        assert!(txt.contains("[ ok ]"), "expected colorblind prefix: {txt}");

        // Verify by re-opening the journal directly.
        let j = ReceiptJournal::open(&output).unwrap();
        let mut got: Vec<(String, u64)> = j
            .entries()
            .into_iter()
            .map(|(s, seq)| (s.to_hex(), seq))
            .collect();
        got.sort();
        assert_eq!(got, vec![(a, 9u64), (b, 4u64)]);
    }

    /// `--dry-run` prints the plan but writes nothing.
    #[tokio::test]
    async fn rebuild_dry_run_does_not_create_output() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let log = AuditLog::open(&audit_dir).unwrap();
        write_signed_seq(&log, &sid_hex(0xCC), 7, 100);
        drop(log);

        let output = dir.path().join("never-written.bin");
        let args = RebuildArgs {
            from_audit: audit_dir,
            output: output.clone(),
            hmac_key: None,
            dry_run: true,
            force: false,
        };
        let mut buf = Vec::new();
        let code = run_rebuild(&args, &mut buf).unwrap();
        assert_eq!(code, 0);
        let txt = String::from_utf8(buf).unwrap();
        assert!(txt.contains("dry-run"), "expected dry-run marker: {txt}");
        assert!(txt.contains("[plan]"), "expected [plan] prefix: {txt}");
        assert!(!output.exists(), "dry-run must not create output");
    }

    /// A tampered audit log produces exit code 1 — the rebuild refuses
    /// to use it as a source. This is the load-bearing sanity check
    /// from the spec: a CRC-corrupted journal must NEVER be replaced
    /// with one derived from a forged audit log.
    #[tokio::test]
    async fn rebuild_refuses_tampered_audit_log() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let log = AuditLog::open(&audit_dir).unwrap();
        for i in 1..=5u64 {
            write_signed_seq(&log, &sid_hex(0xDD), i, 1_700_000_000 + i);
        }
        drop(log);

        // Flip a byte inside one of the audit lines' record_json so the
        // MAC no longer covers the content.
        let audit_file = fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let body = fs::read_to_string(&audit_file).unwrap();
        let mut lines: Vec<String> = body.lines().map(String::from).collect();
        // Mutate the 3rd line's record (escaped `\"seq\":3` -> `\"seq\":33`).
        lines[2] = lines[2].replacen("\\\"seq\\\":3", "\\\"seq\\\":33", 1);
        fs::write(&audit_file, lines.join("\n") + "\n").unwrap();

        let output = dir.path().join("must-not-write.bin");
        let args = RebuildArgs {
            from_audit: audit_dir,
            output: output.clone(),
            hmac_key: None,
            dry_run: false,
            force: false,
        };
        let mut buf = Vec::new();
        let code = run_rebuild(&args, &mut buf).unwrap();
        assert_eq!(code, 1, "expected exit 1 for tampered log");
        let txt = String::from_utf8(buf).unwrap();
        assert!(
            txt.contains("HMAC") || txt.contains("tampered"),
            "expected HMAC/tampered diagnostic: {txt}"
        );
        assert!(
            !output.exists(),
            "must not create output on tampered source"
        );
    }

    /// Existing output without `--force` returns exit 3.
    #[tokio::test]
    async fn rebuild_refuses_to_overwrite_without_force() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let log = AuditLog::open(&audit_dir).unwrap();
        write_signed_seq(&log, &sid_hex(0xEE), 1, 100);
        drop(log);

        let output = dir.path().join("preexisting.bin");
        fs::write(&output, b"do-not-stomp").unwrap();
        let args = RebuildArgs {
            from_audit: audit_dir,
            output: output.clone(),
            hmac_key: None,
            dry_run: false,
            force: false,
        };
        let mut buf = Vec::new();
        let code = run_rebuild(&args, &mut buf).unwrap();
        assert_eq!(code, 3);
        // Output untouched.
        assert_eq!(fs::read(&output).unwrap(), b"do-not-stomp");
    }

    /// Sanity check: an audit log containing only non-`receipt_signed`
    /// kinds (announce / get_state etc) yields an empty plan, NOT a
    /// failure. Rebuilding a journal for a node that never signed a
    /// receipt is legitimate.
    #[tokio::test]
    async fn rebuild_empty_plan_for_announce_only_log() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let log = AuditLog::open(&audit_dir).unwrap();
        // Write an `announce` row (no seq field).
        log.write(&AuditRecord {
            ts_unix: 100,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(0xFF)),
            extra: Value::Null,
        })
        .unwrap();
        drop(log);

        let output = dir.path().join("empty.bin");
        let args = RebuildArgs {
            from_audit: audit_dir,
            output: output.clone(),
            hmac_key: None,
            dry_run: false,
            force: false,
        };
        let mut buf = Vec::new();
        let code = run_rebuild(&args, &mut buf).unwrap();
        assert_eq!(code, 0);
        let j = ReceiptJournal::open(&output).unwrap();
        assert!(j.entries().is_empty());
    }

    /// 10k-entry stress: the rebuild walks a sizable log + emits a
    /// fresh journal in well under the audit-9 H-RTO 2-minute target.
    /// Doubles as the bench fixture: the wall-clock is part of the
    /// final report.
    #[tokio::test]
    async fn rebuild_10k_entries_under_two_minutes() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let log = AuditLog::open(&audit_dir).unwrap();
        // 100 sessions × 100 signings each = 10 000 receipt_signed rows.
        let n_sessions = 100u8;
        let signings = 100u64;
        for s in 0..n_sessions {
            let sid = sid_hex(s.wrapping_add(1));
            for seq in 1..=signings {
                log.write(&AuditRecord {
                    ts_unix: 1_700_000_000 + u64::from(s) * 1000 + seq,
                    kind: "receipt_signed",
                    source: None,
                    session_id: Some(sid.clone()),
                    extra: json!({ "seq": seq }),
                })
                .unwrap();
            }
        }
        drop(log);

        let output = dir.path().join("big.bin");
        let args = RebuildArgs {
            from_audit: audit_dir,
            output: output.clone(),
            hmac_key: None,
            dry_run: false,
            force: false,
        };
        let mut buf = Vec::new();
        let t0 = Instant::now();
        let code = run_rebuild(&args, &mut buf).unwrap();
        let elapsed = t0.elapsed();
        eprintln!(
            "[bench] 10k-entry rebuild wall-clock: {:.3}s",
            elapsed.as_secs_f64()
        );
        assert_eq!(
            code,
            0,
            "expected ok; output:\n{}",
            String::from_utf8_lossy(&buf)
        );
        assert!(
            elapsed.as_secs() < 120,
            "rebuild must beat 2 min target; got {elapsed:?}"
        );
        let j = ReceiptJournal::open(&output).unwrap();
        assert_eq!(j.entries().len() as u8, n_sessions);
        for (sid, seq) in j.entries() {
            assert_eq!(seq, signings, "floor mismatch on {}", sid.to_hex());
        }
    }

    /// `build_plan` is the pure layer: same input must produce the same
    /// plan twice. Pins determinism — the floor is `max(seqs)` which is
    /// order-independent, but a future "merge by timestamp" regression
    /// would break this property.
    #[tokio::test]
    async fn build_plan_is_deterministic() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let log = AuditLog::open(&audit_dir).unwrap();
        let s = sid_hex(0x42);
        // Out-of-order seqs.
        write_signed_seq(&log, &s, 5, 100);
        write_signed_seq(&log, &s, 1, 101);
        write_signed_seq(&log, &s, 3, 102);
        drop(log);

        let (p1, n1) = build_plan(&audit_dir, None).unwrap();
        let (p2, n2) = build_plan(&audit_dir, None).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(n1, n2);
        assert_eq!(p1.get(&s).copied(), Some(5));
        assert_eq!(n1, 3);
    }

    /// Missing audit directory surfaces as an actionable error.
    #[tokio::test]
    async fn rebuild_missing_audit_dir_is_io_error() {
        let dir = tempdir().unwrap();
        let args = RebuildArgs {
            from_audit: dir.path().join("does-not-exist"),
            output: dir.path().join("never.bin"),
            hmac_key: None,
            dry_run: true,
            force: false,
        };
        let mut buf = Vec::new();
        let code = run_rebuild(&args, &mut buf).unwrap();
        // Missing audit dir → key-not-found OR no-files; both surface
        // as non-zero with a diagnostic. Both are IO-class so they
        // collapse to exit 2.
        assert_ne!(code, 0);
        assert!(code == 1 || code == 2);
    }
}
