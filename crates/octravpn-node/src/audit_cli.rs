//! Operator-facing audit tooling — `octravpn-node audit replay` and
//! `octravpn-node audit verify`.
//!
//! The node already writes two persistent artifacts:
//!
//!   * **Audit log** (`crate::audit::AuditLog`) — JSONL, one file per
//!     UTC day in `<audit_dir>/audit-YYYY-MM-DD.jsonl`, with an
//!     HMAC-SHA256 chain across every line.
//!   * **Receipt journal** (`octravpn_core::receipt_journal`) — a
//!     binary file containing one `(session_id, last_signed_seq)`
//!     entry per session. Used as the floor that prevents
//!     forced-restart double-signing (P1-8/9).
//!
//! Until now the only operator surface for these was `verify-audit-log
//! <path>` — a yes/no integrity check on a single file. This module
//! adds two richer views:
//!
//!   * `audit replay <path>` — walk both artifacts, merge by timestamp,
//!     emit a structured timeline (human-readable or JSONL).
//!   * `audit verify <path>` — full cryptographic verification of the
//!     audit log + the journal's per-session monotonicity + a
//!     warning-only cross-check that every journal record has a
//!     matching audit entry.
//!
//! Exit codes (verify):
//!   * 0 — all checks passed
//!   * 1 — verification failure (one of the strict checks broke)
//!   * 2 — IO or parse error
//!   * 3 — missing files
//!
//! The CLI is intentionally additive. The existing `Cmd::VerifyAuditLog`
//! is wired here as a deprecated alias for `audit verify` so existing
//! operator runbooks keep working until a follow-up removes it.

use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::Value;

use octravpn_core::session::SessionId;

use crate::audit::{days_to_ymd, resolve_hmac_key, AuditLog, FileVerifyReport, HmacKeyError};
use crate::cli_report::Check;

/// `octravpn-node audit …` top-level subcommand.
#[derive(Subcommand, Debug)]
pub(crate) enum AuditCmd {
    /// Pretty-print every entry in the audit log + receipt journal as
    /// a structured timeline. Useful for debugging "what did this node
    /// do between 12:00 and 12:30 yesterday."
    Replay(ReplayArgs),

    /// Cryptographically verify the HMAC chain of an audit log AND
    /// the receipt-seq monotonicity of a journal. Exits 0 on full
    /// verification; non-zero with the specific check that failed.
    Verify(VerifyArgs),
}

#[derive(Args, Debug)]
pub(crate) struct ReplayArgs {
    /// Path to the audit log file OR the audit directory containing
    /// `audit-YYYY-MM-DD.jsonl` files. Defaults to `./state/audit.log`
    /// for compatibility with operators who pipe the daemon's audit
    /// directory through a single file; the directory form (one file
    /// per UTC day) is auto-detected.
    #[arg(long, default_value = "./state/audit.log")]
    audit_path: PathBuf,

    /// Path to the receipt journal file. Defaults to
    /// `./state/receipts.bin`.
    #[arg(long, default_value = "./state/receipts.bin")]
    journal_path: PathBuf,

    /// Filter by session id. Accepts either the 64-char hex form or
    /// the legacy v1 u64 decimal form (which is zero-padded to 32
    /// bytes internally).
    #[arg(long)]
    session: Option<String>,

    /// Lower bound on the timestamp range (Unix seconds, inclusive).
    #[arg(long)]
    since: Option<u64>,

    /// Upper bound on the timestamp range (Unix seconds, inclusive).
    #[arg(long)]
    until: Option<u64>,

    /// Output format: `human` (default, one line per event) or
    /// `json` / `jsonl` (newline-delimited JSON for downstream tooling).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

/// `audit replay --format` choices. Was a free `String` matched with a
/// silent `_ => human` fallthrough, which swallowed typos (`--format xml`
/// → human); a `ValueEnum` makes clap reject unknown values up front and
/// the dispatch exhaustive.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub(crate) enum OutputFormat {
    /// One human-readable line per event.
    Human,
    /// Newline-delimited JSON (alias of `jsonl`).
    Json,
    /// Newline-delimited JSON.
    Jsonl,
}

#[derive(Args, Debug)]
pub(crate) struct VerifyArgs {
    /// Path to the audit log file or directory. Same semantics as
    /// `replay --audit-path`.
    #[arg(long, default_value = "./state/audit.log")]
    audit_path: PathBuf,

    /// Path to the receipt journal file.
    #[arg(long, default_value = "./state/receipts.bin")]
    journal_path: PathBuf,

    /// HMAC key file. Must be exactly 32 bytes. If omitted, the tool
    /// tries `<audit_path>.key` (file case) or `<audit_path>/.audit.key`
    /// (directory case) — the conventional locations the running
    /// daemon writes the key to.
    #[arg(long)]
    hmac_key: Option<PathBuf>,
}

/// Top-level dispatcher. Returns a numeric exit code so the binary can
/// surface the structured verify exit codes (1/2/3) cleanly.
pub(crate) fn dispatch(cmd: AuditCmd) -> i32 {
    match cmd {
        AuditCmd::Replay(args) => match run_replay(&args, &mut std::io::stdout()) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("audit replay: {e:#}");
                2
            }
        },
        AuditCmd::Verify(args) => run_verify_cli(&args),
    }
}

// ============================================================================
// Event model
// ============================================================================

/// One row in the merged timeline. Audit-log entries and receipt-journal
/// records both reduce to this — the renderer can stay format-agnostic.
#[derive(Debug, Clone, Serialize)]
struct TimelineEvent {
    /// Unix seconds. For journal entries this is unknown (the journal
    /// stores no timestamp), so we sentinel-value to 0 and render as
    /// `<no-ts>` in the human format. JSONL preserves the zero so
    /// downstream tooling can detect the "synthetic" origin.
    ts_unix: u64,
    /// Short verb describing the event. Mirrors `AuditRecord::kind`
    /// for log-derived events; for journal-derived events the kind is
    /// `journal_floor`.
    kind: String,
    /// Session id in hex (if applicable).
    session_id: Option<String>,
    /// Sequence number (audit log entries that carry one, journal
    /// floor records).
    seq: Option<u64>,
    /// Bytes-used if the event carries it.
    bytes_used: Option<u64>,
    /// Free-form extra fields preserved from the source record.
    #[serde(skip_serializing_if = "Value::is_null")]
    extra: Value,
    /// Source artifact — `audit` or `journal`. Helps the operator
    /// follow up.
    source: &'static str,
}

// ============================================================================
// Replay
// ============================================================================

fn run_replay(args: &ReplayArgs, out: &mut dyn Write) -> Result<()> {
    let want_session = parse_session_filter(args.session.as_deref())?;
    let audit_events = load_audit_events(&args.audit_path).unwrap_or_default();
    let journal_events = load_journal_events(&args.journal_path).unwrap_or_default();

    let mut all: Vec<TimelineEvent> = audit_events.into_iter().chain(journal_events).collect();

    // Filter by session id.
    if let Some(want) = want_session.as_ref() {
        all.retain(|e| e.session_id.as_deref() == Some(want.as_str()));
    }
    // Filter by time range. Journal entries have ts_unix=0, which the
    // operator can include by leaving --since unset (the default 0 lower
    // bound) or by explicitly passing 0.
    if let Some(s) = args.since {
        all.retain(|e| e.ts_unix >= s);
    }
    if let Some(u) = args.until {
        all.retain(|e| e.ts_unix <= u);
    }

    // Stable sort by (ts, source, kind) so two events at the same
    // second print in a deterministic order — important for tests and
    // for diff-able operator output across runs.
    all.sort_by(|a, b| {
        a.ts_unix
            .cmp(&b.ts_unix)
            .then(a.source.cmp(b.source))
            .then(a.kind.cmp(&b.kind))
            .then(a.seq.cmp(&b.seq))
    });

    match args.format {
        OutputFormat::Json | OutputFormat::Jsonl => render_jsonl(&all, out)?,
        OutputFormat::Human => render_human(&all, out)?,
    }
    Ok(())
}

fn render_human(events: &[TimelineEvent], out: &mut dyn Write) -> Result<()> {
    for e in events {
        let ts = if e.ts_unix == 0 {
            "<no-ts>             ".to_string()
        } else {
            format_ts_utc(e.ts_unix)
        };
        let sid = e
            .session_id
            .as_deref()
            .map_or_else(|| "-".to_string(), short_hex);
        use std::fmt::Write as _;
        let mut line = format!("[{ts}]  session {sid}  {}", e.kind);
        if let Some(seq) = e.seq {
            let _ = write!(line, " seq={seq}");
        }
        if let Some(b) = e.bytes_used {
            let _ = write!(line, " bytes={b}");
        }
        if !e.extra.is_null() {
            // Compact JSON of the extra blob keeps the line greppable.
            let extra =
                serde_json::to_string(&e.extra).unwrap_or_else(|_| "<unprintable>".to_string());
            let _ = write!(line, " extra={extra}");
        }
        let _ = write!(line, "  ({})", e.source);
        writeln!(out, "{line}").context("write replay line")?;
    }
    Ok(())
}

fn render_jsonl(events: &[TimelineEvent], out: &mut dyn Write) -> Result<()> {
    for e in events {
        let s = serde_json::to_string(e).context("serialize event")?;
        writeln!(out, "{s}").context("write replay jsonl")?;
    }
    Ok(())
}

// ============================================================================
// Audit log loading
// ============================================================================

/// Find every audit log file at `path`. Supports two layouts:
///   * `path` is a file — return [path].
///   * `path` is a directory — return every `audit-*.jsonl` file
///     inside, sorted by name (which is also chronological order).
fn discover_audit_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_dir() {
        let mut out = Vec::new();
        for entry in fs::read_dir(path).with_context(|| format!("readdir {}", path.display()))? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("audit-") && name.ends_with(".jsonl") {
                out.push(entry.path());
            }
        }
        out.sort();
        Ok(out)
    } else if path.exists() {
        Ok(vec![path.to_path_buf()])
    } else {
        Ok(Vec::new())
    }
}

/// Load every parseable JSONL line from every audit file under `path`
/// and convert into `TimelineEvent`s. Lines that fail to parse are
/// skipped with a stderr warning — operator-facing tooling shouldn't
/// abort on a single corrupt line.
fn load_audit_events(path: &Path) -> Result<Vec<TimelineEvent>> {
    let files = discover_audit_files(path)?;
    let mut out = Vec::new();
    for file in files {
        let f = fs::File::open(&file).with_context(|| format!("open {}", file.display()))?;
        let reader = BufReader::new(f);
        for (i, line) in reader.lines().enumerate() {
            let line = match line {
                Ok(s) if s.trim().is_empty() => continue,
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "audit replay: skip {}:{}: read error {e}",
                        file.display(),
                        i + 1
                    );
                    continue;
                }
            };
            // The wire format is `ChainedLine { record_json, prev_mac,
            // mac }` — the canonical record is escaped inside
            // `record_json`. Parse twice.
            let chained: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "audit replay: skip {}:{}: bad json ({e})",
                        file.display(),
                        i + 1
                    );
                    continue;
                }
            };
            let Some(record_json) = chained.get("record_json").and_then(|v| v.as_str()) else {
                continue;
            };
            let rec: Value = match serde_json::from_str(record_json) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "audit replay: skip {}:{}: bad inner record ({e})",
                        file.display(),
                        i + 1
                    );
                    continue;
                }
            };
            out.push(audit_record_to_event(&rec));
        }
    }
    Ok(out)
}

fn audit_record_to_event(rec: &Value) -> TimelineEvent {
    let ts_unix = rec.get("ts_unix").and_then(Value::as_u64).unwrap_or(0);
    let kind = rec
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let session_id = rec
        .get("session_id")
        .and_then(Value::as_str)
        .map(String::from);
    let extra = rec.get("extra").cloned().unwrap_or(Value::Null);
    // Some kinds we know carry these in `extra` — pull them up for
    // friendlier rendering. We accept either flat-on-record or
    // nested-in-extra to stay forward-compat with future emit sites.
    let seq = rec
        .get("seq")
        .and_then(Value::as_u64)
        .or_else(|| extra.get("seq").and_then(Value::as_u64));
    let bytes_used = rec
        .get("bytes_used")
        .and_then(Value::as_u64)
        .or_else(|| extra.get("bytes_used").and_then(Value::as_u64));
    TimelineEvent {
        ts_unix,
        kind,
        session_id,
        seq,
        bytes_used,
        extra,
        source: "audit",
    }
}

// ============================================================================
// Journal loading
// ============================================================================

fn load_journal_events(path: &Path) -> Result<Vec<TimelineEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    // Use the public `ReceiptJournal::entries()` accessor so we never
    // duplicate the on-disk codec.
    let j = octravpn_core::receipt_journal::ReceiptJournal::open(path)
        .with_context(|| format!("open journal {}", path.display()))?;
    let mut out = Vec::new();
    for (sid, seq) in j.entries() {
        out.push(TimelineEvent {
            ts_unix: 0,
            kind: "journal_floor".to_string(),
            session_id: Some(sid.to_hex()),
            seq: Some(seq),
            bytes_used: None,
            extra: Value::Null,
            source: "journal",
        });
    }
    Ok(out)
}

// ============================================================================
// Verify
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VerifyReport {
    pub audit_log: Check,
    pub receipt_journal: Check,
    pub cross_check: Check,
    pub overall_pass: bool,
}

fn run_verify_cli(args: &VerifyArgs) -> i32 {
    let mut stdout = std::io::stdout();
    match run_verify(args, &mut stdout) {
        Ok(report) => i32::from(!report.overall_pass),
        Err(VerifyError::Missing(msg)) => {
            eprintln!("audit verify: {msg}");
            3
        }
        Err(VerifyError::Io(e)) => {
            eprintln!("audit verify: {e:#}");
            2
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum VerifyError {
    Missing(String),
    Io(anyhow::Error),
}

impl From<anyhow::Error> for VerifyError {
    fn from(e: anyhow::Error) -> Self {
        Self::Io(e)
    }
}

pub(crate) fn run_verify(
    args: &VerifyArgs,
    out: &mut dyn Write,
) -> Result<VerifyReport, VerifyError> {
    // Locate the HMAC key.
    let key = load_hmac_key(&args.audit_path, args.hmac_key.as_deref())?;

    // ---- Audit log chain ----
    let files = discover_audit_files(&args.audit_path).map_err(VerifyError::Io)?;
    if files.is_empty() {
        return Err(VerifyError::Missing(format!(
            "no audit log found at {}",
            args.audit_path.display()
        )));
    }
    let (audit_log_result, audit_signed_seqs) = verify_audit_files(&key, &files);
    let audit_log_ok = matches!(audit_log_result, Check::Ok { .. });

    // ---- Journal monotonicity ----
    let journal_result = if args.journal_path.exists() {
        verify_journal(&args.journal_path).map_err(VerifyError::Io)?
    } else {
        // The journal is optional — an operator who never signed a
        // receipt has no journal. Treat absence as OK with detail.
        Check::Ok {
            detail: format!("no journal at {}", args.journal_path.display()),
        }
    };
    let journal_ok = matches!(journal_result, Check::Ok { .. });

    // ---- Cross-check ----
    let cross_check = if !audit_log_ok {
        Check::Skipped {
            detail: "audit log invalid".into(),
        }
    } else if !args.journal_path.exists() {
        Check::Skipped {
            detail: "no journal".into(),
        }
    } else {
        cross_check_journal(&args.journal_path, &audit_signed_seqs).map_err(VerifyError::Io)?
    };

    let overall_pass = audit_log_ok
        && journal_ok
        // Warn / Ok pass; Fail / Skipped fail.
        && !matches!(cross_check, Check::Fail { .. });

    let report = VerifyReport {
        audit_log: audit_log_result,
        receipt_journal: journal_result,
        cross_check,
        overall_pass,
    };
    render_verify_report(&report, out).map_err(VerifyError::Io)?;
    Ok(report)
}

fn render_verify_report(r: &VerifyReport, out: &mut dyn Write) -> Result<()> {
    writeln!(
        out,
        "audit log:        {:<8} {}",
        r.audit_log.label(),
        r.audit_log.detail()
    )?;
    writeln!(
        out,
        "receipt journal:  {:<8} {}",
        r.receipt_journal.label(),
        r.receipt_journal.detail()
    )?;
    writeln!(
        out,
        "cross-check:      {:<8} {}",
        r.cross_check.label(),
        r.cross_check.detail()
    )?;
    writeln!(out)?;
    if r.overall_pass {
        writeln!(out, "verification PASSED")?;
    } else {
        writeln!(out, "verification FAILED")?;
    }
    Ok(())
}

/// Verify every audit file in `files` as a contiguous HMAC chain
/// (each file resets the chain, matching the writer's behaviour at
/// midnight rotation). Returns the aggregated check result plus a map
/// of `session_id -> set<seq>` derived from `receipt_signed` audit
/// entries — used by the cross-check.
///
/// #240 / F1: this used to be a hand-rolled walker shadowing
/// `AuditLog::verify_file`. The reuse review at
/// `/tmp/simplify-reuse-review.md` flagged the duplication; now this
/// function is a thin aggregator over per-file `verify_file` calls.
/// All HMAC math + `(session_id, seq)` harvesting lives in `audit.rs`.
fn verify_audit_files(
    key: &[u8; 32],
    files: &[PathBuf],
) -> (Check, BTreeMap<String, std::collections::BTreeSet<u64>>) {
    let mut total: u64 = 0;
    let mut signed_seqs: BTreeMap<String, std::collections::BTreeSet<u64>> = BTreeMap::new();
    for file in files {
        let report: FileVerifyReport = match AuditLog::verify_file(key, file) {
            Ok(r) => r,
            Err(e) => {
                return (
                    Check::Fail {
                        detail: format!("{}: {e:#}", file.display()),
                    },
                    signed_seqs,
                );
            }
        };
        total += report.entries;
        // Merge per-file harvested seqs into the aggregate map.
        for (sid, seqs) in report.signed_seqs {
            signed_seqs.entry(sid).or_default().extend(seqs);
        }
        if let Some(err) = report.first_error {
            return (
                Check::Fail {
                    detail: format!("{}: {err}", file.display()),
                },
                signed_seqs,
            );
        }
    }
    (
        Check::Ok {
            detail: format!("{total} entries, HMAC chain valid"),
        },
        signed_seqs,
    )
}

fn verify_journal(path: &Path) -> Result<Check> {
    // The journal's on-disk format is now append-only with per-record
    // checksums (see `octravpn_core::receipt_journal` module doc). We
    // delegate to the public API rather than re-parsing the bytes here
    // — `ReceiptJournal::open` runs the full replay (magic check,
    // per-record CRC32, v0 migration) and surfaces every failure mode
    // we used to hand-roll. The in-memory `entries()` then gives us
    // the live per-session floor; the codec guarantees one entry per
    // session.
    if !path.exists() {
        return Ok(Check::Ok {
            detail: "0 records (empty journal)".into(),
        });
    }
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if metadata.len() == 0 {
        return Ok(Check::Ok {
            detail: "0 records (empty journal)".into(),
        });
    }
    let journal = match octravpn_core::receipt_journal::ReceiptJournal::open(path) {
        Ok(j) => j,
        Err(e) => {
            return Ok(Check::Fail {
                detail: format!("{e}"),
            });
        }
    };
    let entries = journal.entries();
    // Floor=0 is the "never seen" sentinel; the writer enforces seq>=1
    // on every successful `bump`, so seeing 0 on disk indicates a
    // hand-edited file or a format bug.
    if let Some((sid, _)) = entries.iter().find(|(_, seq)| *seq == 0) {
        return Ok(Check::Fail {
            detail: format!(
                "session {} has floor=0 (sentinel; should never be written)",
                sid.to_hex()
            ),
        });
    }
    let sessions = entries.len();
    Ok(Check::Ok {
        detail: format!(
            "{sessions} records, monotonic seq for {sessions} session{}",
            if sessions == 1 { "" } else { "s" }
        ),
    })
}

/// Soft cross-check: every journal record SHOULD have at least one
/// audit-log entry for its session_id. Audit-log entries for sessions
/// not in the journal are also reported but as informational warnings.
/// Both directions emit `Warn`, never `Fail` — the audit log can carry
/// non-receipt entries (announce, lag, etc.) and the journal is the
/// floor not a record-per-receipt, so symmetry is not required.
fn cross_check_journal(
    journal_path: &Path,
    audit_seqs: &BTreeMap<String, std::collections::BTreeSet<u64>>,
) -> Result<Check> {
    let j = octravpn_core::receipt_journal::ReceiptJournal::open(journal_path)?;
    let entries = j.entries();
    let total = entries.len();
    let mut matched = 0usize;
    let mut orphan_journal = Vec::new();
    for (sid, _) in &entries {
        let hex = sid.to_hex();
        if audit_seqs.contains_key(&hex) {
            matched += 1;
        } else {
            orphan_journal.push(hex);
        }
    }
    let orphan_audit: Vec<&String> = audit_seqs
        .keys()
        .filter(|k| !entries.iter().any(|(s, _)| &s.to_hex() == *k))
        .collect();

    if orphan_journal.is_empty() && orphan_audit.is_empty() {
        Ok(Check::Ok {
            detail: format!("{matched}/{total} journal records have audit entries"),
        })
    } else {
        use std::fmt::Write as _;
        let mut detail = format!("{matched}/{total} journal records have audit entries");
        if !orphan_journal.is_empty() {
            let list = orphan_journal
                .iter()
                .map(|s| short_hex(s))
                .collect::<Vec<_>>()
                .join(",");
            let _ = write!(detail, " — journal-only sessions: {list}");
        }
        if !orphan_audit.is_empty() {
            let list = orphan_audit
                .iter()
                .map(|s| short_hex(s))
                .collect::<Vec<_>>()
                .join(",");
            let _ = write!(detail, " — audit-only sessions: {list}");
        }
        Ok(Check::Warn { detail })
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn load_hmac_key(audit_path: &Path, explicit: Option<&Path>) -> Result<[u8; 32], VerifyError> {
    resolve_hmac_key(audit_path, explicit).map_err(|e| match e {
        HmacKeyError::NotFound(p) => VerifyError::Missing(format!(
            "HMAC key not found at {} (pass --hmac-key explicitly)",
            p.display()
        )),
        HmacKeyError::Invalid(e) => VerifyError::Io(e),
    })
}

fn parse_session_filter(s: Option<&str>) -> Result<Option<String>> {
    match s {
        None => Ok(None),
        Some(raw) => {
            if let Some(sid) = SessionId::from_hex(raw) {
                Ok(Some(sid.to_hex()))
            } else if let Ok(n) = raw.parse::<u64>() {
                Ok(Some(SessionId::from_u64(n).to_hex()))
            } else {
                anyhow::bail!(
                    "--session {raw}: must be 64-char hex or a u64 (legacy v1 session id)"
                )
            }
        }
    }
}

fn short_hex(s: &str) -> String {
    if s.len() <= 8 {
        s.to_string()
    } else {
        format!("{}…", &s[..6])
    }
}

/// Format a unix timestamp as `YYYY-MM-DDTHH:MM:SSZ`. Reuses the same
/// "no chrono" arithmetic ([`days_to_ymd`]) the audit log uses for
/// rotation; keeping the formatter local means we don't drag in a new
/// dep just for replay output.
#[allow(clippy::many_single_char_names)]
fn format_ts_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let (y, m, d) = days_to_ymd(days);
    let secs_of_day = ts % 86_400;
    let h = secs_of_day / 3_600;
    let min = (secs_of_day % 3_600) / 60;
    let s = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditLog, AuditRecord};
    use serde_json::json;
    use tempfile::tempdir;

    fn write_synthetic_audit_log(dir: &Path, ts_pairs: &[(u64, &str, Option<&str>)]) -> AuditLog {
        let log = AuditLog::open(dir).unwrap();
        for (ts, kind, sid) in ts_pairs {
            // The AuditRecord kind is `&'static str`; map at the call
            // site below.
            let kind_static: &'static str = match *kind {
                "announce" => "announce",
                "receipt_signed" => "receipt_signed",
                "x" => "x",
                "y" => "y",
                "other" => "other",
                _ => "unknown",
            };
            log.write(&AuditRecord {
                ts_unix: *ts,
                kind: kind_static,
                source: None,
                session_id: sid.map(std::string::ToString::to_string),
                extra: Value::Null,
            })
            .unwrap();
        }
        log
    }

    fn sid_hex(b: u8) -> String {
        hex::encode([b; 32])
    }

    /// replay sorts events by ts even when they arrived out of order.
    #[test]
    fn replay_emits_chronological_order() {
        let dir = tempdir().unwrap();
        write_synthetic_audit_log(
            dir.path(),
            &[
                (200, "announce", Some(&sid_hex(1))),
                (100, "announce", Some(&sid_hex(2))),
                (150, "announce", Some(&sid_hex(3))),
            ],
        );
        let args = ReplayArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("does-not-exist.bin"),
            session: None,
            since: None,
            until: None,
            format: OutputFormat::Human,
        };
        let mut buf = Vec::new();
        run_replay(&args, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        // Lines must be in ascending ts order.
        assert!(lines[0].contains("1970-01-01T00:01:40Z"));
        assert!(lines[1].contains("1970-01-01T00:02:30Z"));
        assert!(lines[2].contains("1970-01-01T00:03:20Z"));
    }

    #[test]
    fn replay_filters_by_session() {
        let dir = tempdir().unwrap();
        write_synthetic_audit_log(
            dir.path(),
            &[
                (100, "announce", Some(&sid_hex(0xAA))),
                (101, "announce", Some(&sid_hex(0xBB))),
                (102, "announce", Some(&sid_hex(0xAA))),
            ],
        );
        let args = ReplayArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("none.bin"),
            session: Some(sid_hex(0xAA)),
            since: None,
            until: None,
            format: OutputFormat::Human,
        };
        let mut buf = Vec::new();
        run_replay(&args, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let n = out.lines().count();
        assert_eq!(n, 2, "expected only the two 0xAA entries; got:\n{out}");
        assert!(!out.contains(&sid_hex(0xBB)[..6]));
    }

    #[test]
    fn replay_filters_by_time_range() {
        let dir = tempdir().unwrap();
        write_synthetic_audit_log(
            dir.path(),
            &[
                (50, "announce", Some(&sid_hex(1))),
                (150, "announce", Some(&sid_hex(2))),
                (250, "announce", Some(&sid_hex(3))),
            ],
        );
        let args = ReplayArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("none.bin"),
            session: None,
            since: Some(100),
            until: Some(200),
            format: OutputFormat::Human,
        };
        let mut buf = Vec::new();
        run_replay(&args, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("1970-01-01T00:02:30Z"));
    }

    #[test]
    fn replay_json_emits_jsonl() {
        let dir = tempdir().unwrap();
        write_synthetic_audit_log(
            dir.path(),
            &[
                (100, "announce", Some(&sid_hex(1))),
                (101, "receipt_signed", Some(&sid_hex(1))),
            ],
        );
        let args = ReplayArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("none.bin"),
            session: None,
            since: None,
            until: None,
            format: OutputFormat::Json,
        };
        let mut buf = Vec::new();
        run_replay(&args, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        for line in out.lines() {
            let v: Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("not valid jsonl: {e} ({line})"));
            assert!(v.get("ts_unix").is_some());
            assert!(v.get("kind").is_some());
        }
    }

    /// Journal entries appear in the replay too, even though they have
    /// no timestamp. They sort to the start (ts=0) of the timeline.
    #[test]
    fn replay_includes_journal_entries() {
        let dir = tempdir().unwrap();
        write_synthetic_audit_log(dir.path(), &[(100, "announce", Some(&sid_hex(1)))]);
        let journal_path = dir.path().join("receipts.bin");
        let j = octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&SessionId::new([1u8; 32]), 7).unwrap();
        let args = ReplayArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path,
            session: None,
            since: None,
            until: None,
            format: OutputFormat::Human,
        };
        let mut buf = Vec::new();
        run_replay(&args, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("journal_floor"), "missing journal line: {out}");
        assert!(out.contains("seq=7"));
    }

    #[test]
    fn verify_passes_on_valid_log() {
        let dir = tempdir().unwrap();
        for i in 0..100 {
            write_synthetic_audit_log(
                dir.path(),
                &[((1_700_000_000 + i) as u64, "x", Some(&sid_hex(1)))],
            );
            // Open-and-write per iter to exercise the same single
            // AuditLog handle's chain. Reusing the handle keeps the
            // chain coherent.
        }
        // Re-emit on a single handle so the chain is one continuous
        // run (the helper opens-and-drops each time, which would reset
        // prev_mac per call). Build the 100-entry file inline.
        let dir2 = tempdir().unwrap();
        let log = AuditLog::open(dir2.path()).unwrap();
        for i in 0..100u64 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "announce",
                source: None,
                session_id: Some(sid_hex(1)),
                extra: json!({"i": i}),
            })
            .unwrap();
        }
        let args = VerifyArgs {
            audit_path: dir2.path().to_path_buf(),
            journal_path: dir2.path().join("no-journal.bin"),
            hmac_key: None,
        };
        let mut buf = Vec::new();
        let report = run_verify(&args, &mut buf).unwrap();
        assert!(report.overall_pass, "expected pass; got: {report:#?}");
        assert!(matches!(report.audit_log, Check::Ok { .. }));
    }

    #[test]
    fn verify_fails_on_broken_chain() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..5u64 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "announce",
                source: None,
                session_id: Some(sid_hex(1)),
                extra: json!({"i": i}),
            })
            .unwrap();
        }
        // Find the file and flip a byte inside its embedded
        // record_json so the MAC no longer covers the content.
        let audit_file = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let body = fs::read_to_string(&audit_file).unwrap();
        let mut lines: Vec<String> = body.lines().map(String::from).collect();
        lines[2] = lines[2].replacen("\\\"i\\\":2", "\\\"i\\\":99", 1);
        fs::write(&audit_file, lines.join("\n") + "\n").unwrap();

        let args = VerifyArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("no-journal.bin"),
            hmac_key: None,
        };
        let mut buf = Vec::new();
        let report = run_verify(&args, &mut buf).unwrap();
        assert!(!report.overall_pass);
        let detail = match &report.audit_log {
            Check::Fail { detail } => detail.clone(),
            other => panic!("expected fail; got {other:?}"),
        };
        assert!(
            detail.contains("line 3"),
            "expected line 3 in detail: {detail}"
        );
    }

    #[test]
    fn verify_collapses_duplicate_ids_to_one_entry() {
        // Since #235 the journal is append-only and replay takes the
        // max seq per session_id, so a "duplicate id" on disk is a
        // legitimate shape (a long-running session with many bumps).
        // Verify reports one entry per live session, not an error.
        //
        // We craft a v0 fixture with two same-id entries (which the
        // old format technically could encode if hand-edited) and
        // confirm migration + verify treats the file as one session.
        let dir = tempdir().unwrap();
        let path = dir.path().join("rj.bin");
        let mut buf = Vec::new();
        buf.extend_from_slice(b"OCRJ1\0\0\0");
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 32]);
        buf.extend_from_slice(&5u64.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 32]);
        buf.extend_from_slice(&7u64.to_be_bytes());
        fs::write(&path, &buf).unwrap();
        let r = verify_journal(&path).unwrap();
        match r {
            Check::Ok { detail } => {
                assert!(
                    detail.contains("1 records"),
                    "expected one collapsed record; got: {detail}"
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    /// With both an audit-log `receipt_signed` row and a journal
    /// entry for the SAME session, the cross-check returns `Ok`
    /// (not `Warn`). This is the path the new `get_state` audit
    /// emission unlocks: every floor in the journal now has at
    /// least one matching audit row.
    #[test]
    fn verify_cross_check_passes_when_receipt_signed_entries_match() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        let sid = sid_hex(0xAA);
        // Audit row carrying a real seq, mirroring what
        // `control.rs::get_state` now writes.
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "receipt_signed",
            source: None,
            session_id: Some(sid),
            extra: json!({ "seq": 1, "bytes_used": 0 }),
        })
        .unwrap();
        // Journal floor for the same session.
        let journal_path = dir.path().join("receipts.bin");
        let j = octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&SessionId::new([0xAA; 32]), 1).unwrap();

        let args = VerifyArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path,
            hmac_key: None,
        };
        let mut buf = Vec::new();
        let report = run_verify(&args, &mut buf).unwrap();
        assert!(
            matches!(report.cross_check, Check::Ok { .. }),
            "expected Ok cross-check; got {:?}",
            report.cross_check
        );
        assert!(report.overall_pass);
    }

    #[test]
    fn verify_cross_check_warns_on_orphan() {
        // Audit log says session 0xAA exists; journal has session 0xBB.
        // Both checks pass; cross-check warns about the asymmetry but
        // does NOT fail overall (audit logs legitimately carry entries
        // for sessions that never reached the journal — e.g. announce
        // with no subsequent receipt sign).
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(0xAA)),
            extra: Value::Null,
        })
        .unwrap();
        // Journal has a different session id, with a non-zero seq so
        // we don't trip the floor=0 check.
        let journal_path = dir.path().join("receipts.bin");
        let j = octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&SessionId::new([0xBB; 32]), 4).unwrap();
        // Also write an announce for 0xAA into the audit log; the
        // cross-check uses (session_id, seq) pairs, and only the seq
        // path is meaningful — we use the matched-set logic by
        // session_id alone for orphan reporting.
        let args = VerifyArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path,
            hmac_key: None,
        };
        let mut buf = Vec::new();
        let report = run_verify(&args, &mut buf).unwrap();
        // audit_log + journal pass; cross-check is a Warn (not Fail).
        assert!(matches!(report.audit_log, Check::Ok { .. }));
        assert!(matches!(report.receipt_journal, Check::Ok { .. }));
        assert!(
            matches!(report.cross_check, Check::Warn { .. }),
            "expected Warn; got {:?}",
            report.cross_check
        );
        assert!(report.overall_pass, "warn does not flip overall_pass");
    }

    #[test]
    fn verify_missing_audit_log_returns_exit_3() {
        let dir = tempdir().unwrap();
        let args = VerifyArgs {
            audit_path: dir.path().join("nowhere"),
            journal_path: dir.path().join("nope.bin"),
            hmac_key: None,
        };
        let mut buf = Vec::new();
        let err = run_verify(&args, &mut buf).unwrap_err();
        match err {
            VerifyError::Missing(_) => {}
            VerifyError::Io(e) => panic!("expected Missing; got io: {e:#}"),
        }
    }

    #[test]
    fn replay_session_filter_accepts_decimal_u64() {
        let dir = tempdir().unwrap();
        let hex_zero_padded = octravpn_core::session::SessionId::from_u64(42).to_hex();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: None,
            session_id: Some(hex_zero_padded.clone()),
            extra: Value::Null,
        })
        .unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_001,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(0xCC)),
            extra: Value::Null,
        })
        .unwrap();
        let args = ReplayArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("none.bin"),
            session: Some("42".into()),
            since: None,
            until: None,
            format: OutputFormat::Human,
        };
        let mut buf = Vec::new();
        run_replay(&args, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out.lines().count(), 1, "decimal filter must match u64 form");
        assert!(out.contains(&hex_zero_padded[..6]));
    }

    #[test]
    fn verify_journal_rejects_zero_floor() {
        // A hand-constructed journal whose only record has seq=0
        // (the "never seen" sentinel) must FAIL.
        let dir = tempdir().unwrap();
        let path = dir.path().join("rj.bin");
        let mut buf = Vec::new();
        buf.extend_from_slice(b"OCRJ1\0\0\0");
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 32]);
        buf.extend_from_slice(&0u64.to_be_bytes());
        fs::write(&path, &buf).unwrap();
        let r = verify_journal(&path).unwrap();
        assert!(matches!(r, Check::Fail { .. }));
    }

    #[test]
    fn verify_journal_rejects_bad_magic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rj.bin");
        fs::write(&path, b"NOTAMAGIC\0\0\0\0\0\0\0").unwrap();
        let r = verify_journal(&path).unwrap();
        match r {
            Check::Fail { detail } => assert!(detail.contains("magic"), "got: {detail}"),
            other => panic!("expected Fail; got {other:?}"),
        }
    }

    /// Format conversion matches the audit module's ymd helper at the
    /// well-known epoch boundaries — sanity check that our locally
    /// copied algorithm hasn't drifted.
    #[test]
    fn ts_formatting_known_dates() {
        assert_eq!(format_ts_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_ts_utc(946_684_800), "2000-01-01T00:00:00Z");
        assert_eq!(format_ts_utc(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    // ----------------------------------------------------------------
    // Additional coverage — verify edge cases + signed_seqs cross-check
    // ----------------------------------------------------------------

    #[test]
    fn verify_signed_seqs_populated_from_receipt_signed_entries() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        let sid_a = sid_hex(0xAA);
        let sid_b = sid_hex(0xBB);
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "receipt_signed",
            source: None,
            session_id: Some(sid_a.clone()),
            extra: json!({"seq": 1}),
        })
        .unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_001,
            kind: "receipt_signed",
            source: None,
            session_id: Some(sid_a.clone()),
            extra: json!({"seq": 2}),
        })
        .unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_002,
            kind: "receipt_signed",
            source: None,
            session_id: Some(sid_b.clone()),
            extra: json!({"seq": 9}),
        })
        .unwrap();
        let key = log.key();
        // Discover the file under dir.
        let files = discover_audit_files(dir.path()).unwrap();
        let (_, signed_seqs) = verify_audit_files(&key, &files);
        let seqs_a = signed_seqs.get(&sid_a).expect("sid_a present");
        assert!(seqs_a.contains(&1));
        assert!(seqs_a.contains(&2));
        let seqs_b = signed_seqs.get(&sid_b).expect("sid_b present");
        assert!(seqs_b.contains(&9));
    }

    #[test]
    fn verify_empty_log_file_passes_with_zero_entries() {
        // Zero-length file is OK — no records to verify.
        let dir = tempdir().unwrap();
        let log_file = dir.path().join("audit-2024-01-01.jsonl");
        std::fs::write(&log_file, b"").unwrap();
        // Need an HMAC key alongside.
        std::fs::write(log_file.with_extension("jsonl.key"), [0u8; 32]).unwrap();
        let args = VerifyArgs {
            audit_path: log_file,
            journal_path: dir.path().join("no-journal.bin"),
            hmac_key: None,
        };
        let mut buf = Vec::new();
        let report = run_verify(&args, &mut buf).unwrap();
        assert!(report.overall_pass);
        let detail = match &report.audit_log {
            Check::Ok { detail } => detail,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert!(detail.contains("0 entries"));
    }

    #[test]
    fn verify_single_line_passes() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(1)),
            extra: Value::Null,
        })
        .unwrap();
        let args = VerifyArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("missing.bin"),
            hmac_key: None,
        };
        let mut buf = Vec::new();
        let report = run_verify(&args, &mut buf).unwrap();
        assert!(report.overall_pass);
    }

    #[test]
    fn verify_handles_file_without_trailing_newline() {
        // Build a real chained line, write WITHOUT trailing newline.
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(1)),
            extra: Value::Null,
        })
        .unwrap();
        // The audit log API writes a trailing newline; rebuild a copy
        // without the trailer.
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let body = std::fs::read_to_string(&audit_file).unwrap();
        let trimmed = body.trim_end_matches('\n');
        std::fs::write(&audit_file, trimmed.as_bytes()).unwrap();
        let args = VerifyArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("missing.bin"),
            hmac_key: None,
        };
        let mut buf = Vec::new();
        let report = run_verify(&args, &mut buf).unwrap();
        assert!(report.overall_pass);
    }

    #[test]
    fn verify_explicit_hmac_key_wrong_size_io_error() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(1)),
            extra: Value::Null,
        })
        .unwrap();
        let bad = dir.path().join("bad.key");
        std::fs::write(&bad, b"shortkey").unwrap();
        let args = VerifyArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("missing.bin"),
            hmac_key: Some(bad),
        };
        let mut buf = Vec::new();
        let err = run_verify(&args, &mut buf).unwrap_err();
        match err {
            VerifyError::Io(e) => assert!(format!("{e:#}").contains("wrong size")),
            VerifyError::Missing(m) => panic!("expected Io; got Missing: {m}"),
        }
    }

    #[test]
    fn replay_jsonl_emits_one_per_line() {
        let dir = tempdir().unwrap();
        write_synthetic_audit_log(
            dir.path(),
            &[
                (10, "x", Some(&sid_hex(1))),
                (20, "y", Some(&sid_hex(1))),
                (30, "x", Some(&sid_hex(2))),
            ],
        );
        let args = ReplayArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("none.bin"),
            session: None,
            since: None,
            until: None,
            format: OutputFormat::Jsonl,
        };
        let mut buf = Vec::new();
        run_replay(&args, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn replay_human_format_renders_no_ts_for_journal_only() {
        let dir = tempdir().unwrap();
        let journal_path = dir.path().join("receipts.bin");
        let j = octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&SessionId::new([1u8; 32]), 4).unwrap();
        let args = ReplayArgs {
            audit_path: dir.path().join("no-audit-dir"),
            journal_path,
            session: None,
            since: None,
            until: None,
            format: OutputFormat::Human,
        };
        let mut buf = Vec::new();
        run_replay(&args, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("<no-ts>"));
        assert!(out.contains("journal_floor"));
    }

    #[test]
    fn parse_session_filter_rejects_garbage() {
        let r = parse_session_filter(Some("not-valid"));
        assert!(r.is_err());
    }

    #[test]
    fn parse_session_filter_handles_none() {
        let r = parse_session_filter(None).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn discover_audit_files_returns_sorted_files() {
        let dir = tempdir().unwrap();
        // Write three files out of order to ensure sort is enforced.
        for name in [
            "audit-2024-03-15.jsonl",
            "audit-2024-01-01.jsonl",
            "audit-2024-02-15.jsonl",
        ] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        // Add an unrelated file that must be skipped.
        std::fs::write(dir.path().join("other.txt"), b"").unwrap();
        let files = discover_audit_files(dir.path()).unwrap();
        assert_eq!(files.len(), 3);
        // Lexicographically sorted = chronologically sorted (YYYY-MM-DD).
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names[0], "audit-2024-01-01.jsonl");
        assert_eq!(names[2], "audit-2024-03-15.jsonl");
    }

    #[test]
    fn discover_audit_files_returns_empty_for_missing_path() {
        let dir = tempdir().unwrap();
        let files = discover_audit_files(&dir.path().join("nowhere")).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn audit_record_to_event_extracts_seq_and_bytes_from_extra() {
        let rec = json!({
            "ts_unix": 1_234_567_890u64,
            "kind": "receipt_signed",
            "session_id": sid_hex(0xAA),
            "extra": { "seq": 5, "bytes_used": 999 }
        });
        let ev = audit_record_to_event(&rec);
        assert_eq!(ev.kind, "receipt_signed");
        assert_eq!(ev.seq, Some(5));
        assert_eq!(ev.bytes_used, Some(999));
        assert_eq!(ev.source, "audit");
    }

    #[test]
    fn check_result_label_and_detail_helpers() {
        let ok = Check::Ok { detail: "x".into() };
        let f = Check::Fail { detail: "y".into() };
        let s = Check::Skipped { detail: "z".into() };
        let w = Check::Warn { detail: "q".into() };
        assert_eq!(ok.label(), "OK");
        assert_eq!(f.label(), "FAIL");
        assert_eq!(s.label(), "SKIP");
        assert_eq!(w.label(), "WARN");
        assert_eq!(ok.detail(), "x");
        assert_eq!(f.detail(), "y");
        assert_eq!(s.detail(), "z");
        assert_eq!(w.detail(), "q");
    }

    #[test]
    fn short_hex_truncates_long_strings() {
        let h = "a".repeat(20);
        let out = short_hex(&h);
        assert!(out.ends_with('…'));
        assert!(out.starts_with(&"a".repeat(6)));
    }

    #[test]
    fn short_hex_passes_through_short_strings() {
        assert_eq!(short_hex("abcd"), "abcd");
    }

    #[test]
    fn dispatch_replay_returns_zero_on_success() {
        let dir = tempdir().unwrap();
        write_synthetic_audit_log(dir.path(), &[(100, "announce", Some(&sid_hex(1)))]);
        let cmd = AuditCmd::Replay(ReplayArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("missing.bin"),
            session: None,
            since: None,
            until: None,
            format: OutputFormat::Human,
        });
        let code = dispatch(cmd);
        assert_eq!(code, 0);
    }

    #[test]
    fn verify_journal_only_no_audit_dir_returns_skipped_cross_check() {
        // Verify against a single-file path where the audit log exists
        // standalone (not in a dir) and the journal is present.
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(1)),
            extra: Value::Null,
        })
        .unwrap();
        let args = VerifyArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path: dir.path().join("missing.bin"),
            hmac_key: None,
        };
        let mut buf = Vec::new();
        let report = run_verify(&args, &mut buf).unwrap();
        // Journal missing → cross-check is skipped (not Fail).
        assert!(matches!(report.cross_check, Check::Skipped { .. }));
    }
}
