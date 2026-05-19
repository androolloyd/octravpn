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
use clap::{Args, Subcommand};
use hmac::Mac;
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;

use octravpn_core::session::SessionId;

type HmacSha256 = hmac::Hmac<Sha256>;

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
    /// `json` (newline-delimited JSON for downstream tooling).
    #[arg(long, default_value = "human")]
    format: String,
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

    let mut all: Vec<TimelineEvent> = audit_events
        .into_iter()
        .chain(journal_events)
        .collect();

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

    match args.format.as_str() {
        "json" | "jsonl" => render_jsonl(&all, out)?,
        _ => render_human(&all, out)?,
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
            let extra = serde_json::to_string(&e.extra)
                .unwrap_or_else(|_| "<unprintable>".to_string());
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
                    eprintln!("audit replay: skip {}:{}: read error {e}", file.display(), i + 1);
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
    pub audit_log: CheckResult,
    pub receipt_journal: CheckResult,
    pub cross_check: CheckResult,
    pub overall_pass: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum CheckResult {
    Ok {
        detail: String,
    },
    Fail {
        detail: String,
    },
    /// Used when an earlier check made this one un-runnable (e.g. the
    /// audit log was invalid, so cross-check is meaningless).
    Skipped {
        detail: String,
    },
    /// Soft warning — orphaned entries are reported here but do NOT
    /// flip overall_pass.
    Warn {
        detail: String,
    },
}

impl CheckResult {
    fn label(&self) -> &'static str {
        match self {
            Self::Ok { .. } => "OK",
            Self::Fail { .. } => "FAIL",
            Self::Skipped { .. } => "SKIPPED",
            Self::Warn { .. } => "WARN",
        }
    }
    fn detail(&self) -> &str {
        match self {
            Self::Ok { detail }
            | Self::Fail { detail }
            | Self::Skipped { detail }
            | Self::Warn { detail } => detail,
        }
    }
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
pub(crate) enum VerifyError {
    Missing(String),
    Io(anyhow::Error),
}

impl From<anyhow::Error> for VerifyError {
    fn from(e: anyhow::Error) -> Self {
        Self::Io(e)
    }
}

pub(crate) fn run_verify(args: &VerifyArgs, out: &mut dyn Write) -> Result<VerifyReport, VerifyError> {
    // Locate the HMAC key.
    let key = load_hmac_key(&args.audit_path, args.hmac_key.as_deref())?;

    // ---- Audit log chain ----
    let files = discover_audit_files(&args.audit_path)
        .map_err(VerifyError::Io)?;
    if files.is_empty() {
        return Err(VerifyError::Missing(format!(
            "no audit log found at {}",
            args.audit_path.display()
        )));
    }
    let (audit_log_result, audit_signed_seqs) = verify_audit_files(&key, &files);
    let audit_log_ok = matches!(audit_log_result, CheckResult::Ok { .. });

    // ---- Journal monotonicity ----
    let journal_result = if args.journal_path.exists() {
        verify_journal(&args.journal_path).map_err(VerifyError::Io)?
    } else {
        // The journal is optional — an operator who never signed a
        // receipt has no journal. Treat absence as OK with detail.
        CheckResult::Ok {
            detail: format!("no journal at {}", args.journal_path.display()),
        }
    };
    let journal_ok = matches!(journal_result, CheckResult::Ok { .. });

    // ---- Cross-check ----
    let cross_check = if !audit_log_ok {
        CheckResult::Skipped {
            detail: "audit log invalid".into(),
        }
    } else if !args.journal_path.exists() {
        CheckResult::Skipped {
            detail: "no journal".into(),
        }
    } else {
        cross_check_journal(&args.journal_path, &audit_signed_seqs).map_err(VerifyError::Io)?
    };

    let overall_pass = audit_log_ok
        && journal_ok
        // Warn / Ok pass; Fail / Skipped fail.
        && !matches!(cross_check, CheckResult::Fail { .. });

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
fn verify_audit_files(
    key: &[u8; 32],
    files: &[PathBuf],
) -> (CheckResult, BTreeMap<String, std::collections::BTreeSet<u64>>) {
    let mut total = 0usize;
    let mut signed_seqs: BTreeMap<String, std::collections::BTreeSet<u64>> = BTreeMap::new();
    for file in files {
        match verify_audit_file_collect(key, file, &mut signed_seqs) {
            Ok(n) => total += n,
            Err(e) => {
                return (
                    CheckResult::Fail {
                        detail: format!("{}: {e}", file.display()),
                    },
                    signed_seqs,
                );
            }
        }
    }
    (
        CheckResult::Ok {
            detail: format!("{total} entries, HMAC chain valid"),
        },
        signed_seqs,
    )
}

fn verify_audit_file_collect(
    key: &[u8; 32],
    path: &Path,
    signed_seqs: &mut BTreeMap<String, std::collections::BTreeSet<u64>>,
) -> Result<usize> {
    let f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(f);
    let mut prev_mac = [0u8; 32];
    let mut count = 0usize;
    for (i, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read line {}", i + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line)
            .with_context(|| format!("parse line {}", i + 1))?;
        let claimed_prev = v
            .get("prev_mac")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("line {} missing prev_mac", i + 1))?;
        let claimed_mac = v
            .get("mac")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("line {} missing mac", i + 1))?;
        if hex::encode(prev_mac) != claimed_prev {
            anyhow::bail!(
                "chain break at line {}: prev_mac {} != expected {}",
                i + 1,
                claimed_prev,
                hex::encode(prev_mac)
            );
        }
        let canonical = v
            .get("record_json")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("line {} missing record_json", i + 1))?
            .to_string();
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key");
        mac.update(&prev_mac);
        mac.update(canonical.as_bytes());
        let expect: [u8; 32] = mac.finalize().into_bytes().into();
        if hex::encode(expect) != claimed_mac {
            anyhow::bail!(
                "MAC mismatch at line {}: log mac {} != recomputed {}",
                i + 1,
                claimed_mac,
                hex::encode(expect)
            );
        }
        prev_mac = expect;
        count += 1;
        // Harvest any `(session_id, seq)` pair embedded in the line —
        // used for the cross-check. The record JSON is canonical; we
        // re-parse to read it.
        if let Ok(rec) = serde_json::from_str::<Value>(&canonical) {
            let ev = audit_record_to_event(&rec);
            // We only feed the cross-check from entries that look
            // receipt-related. The current writer emits `kind="announce"`
            // (no seq) and downstream tooling may emit `receipt_signed`
            // with a seq — both are accepted here; non-seq entries
            // contribute the session_id but no seq.
            if let (Some(sid), Some(seq)) = (ev.session_id, ev.seq) {
                signed_seqs.entry(sid).or_default().insert(seq);
            }
        }
    }
    Ok(count)
}

fn verify_journal(path: &Path) -> Result<CheckResult> {
    // The on-disk format stores at most one (session_id, last_seq) per
    // session — i.e. monotonicity within a session is structurally
    // enforced by the codec (you cannot encode two entries for the
    // same session_id; the writer keys the map by session_id). So the
    // monotonicity check is largely a parse-shaped no-op, but we DO
    // verify:
    //   * the file decodes cleanly (catches corruption);
    //   * no session_id appears twice in the on-disk stream (would
    //     indicate a hand-edited file or a format bug);
    //   * every recorded floor is > 0 (a floor of 0 is the "never
    //     seen" sentinel and should never be written).
    let raw = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if raw.is_empty() {
        return Ok(CheckResult::Ok {
            detail: "0 records (empty journal)".into(),
        });
    }
    // Raw codec check — we know the format from the journal module's
    // doc comment: 8B magic + u32 BE count + N × (32B id + u64 BE seq).
    const MAGIC: &[u8; 8] = b"OCRJ1\0\0\0";
    if raw.len() < MAGIC.len() + 4 {
        return Ok(CheckResult::Fail {
            detail: format!("truncated journal ({} bytes)", raw.len()),
        });
    }
    if &raw[..MAGIC.len()] != MAGIC {
        return Ok(CheckResult::Fail {
            detail: "bad journal magic".into(),
        });
    }
    let mut n_arr = [0u8; 4];
    n_arr.copy_from_slice(&raw[MAGIC.len()..MAGIC.len() + 4]);
    let n = u32::from_be_bytes(n_arr) as usize;
    let entry_size = 32 + 8;
    let expected = MAGIC.len() + 4 + n * entry_size;
    if raw.len() != expected {
        return Ok(CheckResult::Fail {
            detail: format!(
                "size mismatch: expected {expected} bytes for {n} entries; got {} bytes",
                raw.len()
            ),
        });
    }
    let mut cursor = MAGIC.len() + 4;
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::default();
    let mut sessions = 0usize;
    for i in 0..n {
        let mut id = [0u8; 32];
        id.copy_from_slice(&raw[cursor..cursor + 32]);
        cursor += 32;
        let mut seq_arr = [0u8; 8];
        seq_arr.copy_from_slice(&raw[cursor..cursor + 8]);
        cursor += 8;
        let seq = u64::from_be_bytes(seq_arr);
        if !seen.insert(id) {
            return Ok(CheckResult::Fail {
                detail: format!(
                    "duplicate session_id at record {} ({})",
                    i + 1,
                    hex::encode(id)
                ),
            });
        }
        if seq == 0 {
            return Ok(CheckResult::Fail {
                detail: format!(
                    "record {} has floor=0 (sentinel; should never be written)",
                    i + 1
                ),
            });
        }
        sessions += 1;
    }
    Ok(CheckResult::Ok {
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
) -> Result<CheckResult> {
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
        Ok(CheckResult::Ok {
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
        Ok(CheckResult::Warn { detail })
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn load_hmac_key(audit_path: &Path, explicit: Option<&Path>) -> Result<[u8; 32], VerifyError> {
    let candidate: PathBuf = match explicit {
        Some(p) => p.to_path_buf(),
        None => {
            if audit_path.is_dir() {
                audit_path.join(".audit.key")
            } else {
                let mut p = audit_path.as_os_str().to_os_string();
                p.push(".key");
                PathBuf::from(p)
            }
        }
    };
    if !candidate.exists() {
        return Err(VerifyError::Missing(format!(
            "HMAC key not found at {} (pass --hmac-key explicitly)",
            candidate.display()
        )));
    }
    let raw = fs::read(&candidate)
        .with_context(|| format!("read hmac key {}", candidate.display()))
        .map_err(VerifyError::Io)?;
    if raw.len() != 32 {
        return Err(VerifyError::Io(anyhow::anyhow!(
            "hmac key file {} has wrong size ({}); expected 32",
            candidate.display(),
            raw.len()
        )));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    Ok(k)
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
/// "no chrono" arithmetic the audit log uses for rotation; keeping the
/// formatter local means we don't drag in a new dep just for replay
/// output.
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

/// Howard Hinnant days-since-1970 → (year, month, day). Copy of the
/// same algorithm in `audit.rs`; the function is private over there.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
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
            format: "human".into(),
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
            format: "human".into(),
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
            format: "human".into(),
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
            format: "json".into(),
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
        write_synthetic_audit_log(
            dir.path(),
            &[(100, "announce", Some(&sid_hex(1)))],
        );
        let journal_path = dir.path().join("receipts.bin");
        let j = octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&SessionId::new([1u8; 32]), 7).unwrap();
        let args = ReplayArgs {
            audit_path: dir.path().to_path_buf(),
            journal_path,
            session: None,
            since: None,
            until: None,
            format: "human".into(),
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
        assert!(matches!(report.audit_log, CheckResult::Ok { .. }));
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
            CheckResult::Fail { detail } => detail.clone(),
            other => panic!("expected fail; got {other:?}"),
        };
        assert!(detail.contains("line 3"), "expected line 3 in detail: {detail}");
    }

    #[test]
    fn verify_fails_on_seq_collision() {
        // The codec rejects duplicates on encode, so we craft a raw
        // file with two records sharing the same session_id and
        // assert verify_journal catches the on-disk shape.
        let dir = tempdir().unwrap();
        let path = dir.path().join("rj.bin");
        let mut buf = Vec::new();
        buf.extend_from_slice(b"OCRJ1\0\0\0");
        buf.extend_from_slice(&2u32.to_be_bytes());
        // Two records with the same id.
        buf.extend_from_slice(&[0xAA; 32]);
        buf.extend_from_slice(&5u64.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 32]);
        buf.extend_from_slice(&7u64.to_be_bytes());
        fs::write(&path, &buf).unwrap();
        let r = verify_journal(&path).unwrap();
        match r {
            CheckResult::Fail { detail } => {
                assert!(
                    detail.contains("duplicate session_id"),
                    "got: {detail}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
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
            matches!(report.cross_check, CheckResult::Ok { .. }),
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
        assert!(matches!(report.audit_log, CheckResult::Ok { .. }));
        assert!(matches!(report.receipt_journal, CheckResult::Ok { .. }));
        assert!(
            matches!(report.cross_check, CheckResult::Warn { .. }),
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
            format: "human".into(),
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
        assert!(matches!(r, CheckResult::Fail { .. }));
    }

    #[test]
    fn verify_journal_rejects_bad_magic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rj.bin");
        fs::write(&path, b"NOTAMAGIC\0\0\0\0\0\0\0").unwrap();
        let r = verify_journal(&path).unwrap();
        match r {
            CheckResult::Fail { detail } => assert!(detail.contains("magic"), "got: {detail}"),
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
}
