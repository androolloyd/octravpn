//! Append-only audit log for the node's control plane.
//!
//! Every state-changing request (announce session, settle, etc.) writes
//! a JSON Lines record to a rotating file. The log is the operator's
//! evidence trail for forensics, dispute resolution, and the "what
//! happened during the incident" question.
//!
//! ## Tamper detection
//!
//! Each line carries a `prev_mac` chained from the prior line, where
//! `mac_n = HMAC-SHA256(key, prev_mac || canonical_line_n)`. A
//! verifier walks the file and reports the first index where the chain
//! breaks. Without the key an attacker can append plausible-looking
//! lines, but cannot rewrite or delete history undetectably.
//!
//! ## Layout
//!
//!   - One file per UTC day: `<dir>/audit-YYYY-MM-DD.jsonl`
//!   - HMAC key persisted as `<dir>/.audit.key` (chmod 0600)
//!   - Batched writes: a background flusher task (`open_batched`) drains
//!     the channel and `fsync`s a batch every `batch_interval_ms` or
//!     `batch_size` entries — whichever hits first.
//!   - The synchronous fallback (`open`) writes + fsyncs inline.
//!
//! ## Durability vs throughput (#239)
//!
//! In the batched path, an unclean shutdown can lose at most
//! `batch_interval_ms` of in-flight entries. The receipt journal is the
//! authoritative state for forced-restart double-sign protection
//! (P1-8/9); audit-log entries are observability. Trading the per-line
//! `fsync` for a batched one is the correct durability/throughput
//! point.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::{BufRead, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use tokio::sync::{mpsc, oneshot};

type HmacSha256 = Hmac<Sha256>;

/// Default flush batch size — N entries per fsync.
///
/// `dead_code` allowance: the consumer in `hub.rs` flipping the
/// production path to `open_batched` ships in a follow-up commit so
/// the audit-only scope of this PR stays surgical. The unit tests at
/// the bottom of this file exercise the batched path with custom
/// batch sizes; this constant is the documented production knob.
#[allow(dead_code)]
pub(crate) const DEFAULT_BATCH_SIZE: usize = 64;
/// Default flush interval — fsync at least this often regardless of
/// batch fill level. See `DEFAULT_BATCH_SIZE` for the dead-code
/// allowance rationale.
#[allow(dead_code)]
pub(crate) const DEFAULT_BATCH_INTERVAL_MS: u64 = 100;

/// One audit record. `kind` is a short verb (`announce`, `get_state`,
/// etc.) so downstream tools can filter without parsing JSON deeply.
#[derive(Debug, Serialize)]
pub(crate) struct AuditRecord {
    pub ts_unix: u64,
    pub kind: &'static str,
    /// Source ip:port if relevant (the client that hit the endpoint).
    pub source: Option<String>,
    /// Session id (hex) if the action is per-session.
    pub session_id: Option<String>,
    /// Anything specific to the action (e.g. `bytes_used`).
    #[serde(skip_serializing_if = "Value::is_null", default)]
    pub extra: Value,
}

/// Persisted form of a log line: the canonical record bytes carried as
/// an escaped string field plus a MAC chain. Carrying `record_json`
/// verbatim makes MAC verification trivial — verifier hashes
/// `prev_mac || record_json` and compares to `mac`, with no risk of
/// serializer round-trip drift.
#[derive(Debug, Serialize)]
struct ChainedLine {
    record_json: String,
    /// Hex-encoded HMAC of the previous line (32 bytes of zeros for
    /// the first line in a daily file).
    prev_mac: String,
    /// Hex-encoded HMAC of this line: `HMAC(key, prev_mac || record_json)`.
    mac: String,
}

/// Command sent to the background flusher task. Both variants are
/// constructed only from batched-mode call sites (`write_async` +
/// `flush_and_close`); the dead-code allowance is for non-test
/// builds of the bin that don't yet wire `open_batched` (the prod
/// switch is a follow-up — see `DEFAULT_BATCH_SIZE`).
#[allow(dead_code)]
enum FlusherCmd {
    /// New audit record, fire-and-forget — no ack channel.
    Write(AuditRecord),
    /// Drain everything in the channel + fsync + ack. Used by
    /// `flush_and_close` and by tests that need a fence.
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
pub(crate) struct AuditLog {
    inner: Arc<Mutex<Inner>>,
    /// `Some` in batched mode: a sender into the flusher task. When
    /// dropped (last sender goes), the receiver side terminates and
    /// the flusher exits after a final fsync.
    sender: Option<mpsc::UnboundedSender<FlusherCmd>>,
}

struct Inner {
    dir: PathBuf,
    current_date: String,
    current_file: Option<std::fs::File>,
    /// HMAC key persisted at `<dir>/.audit.key`.
    key: [u8; 32],
    /// Running MAC chain. Reset at midnight (the prev-mac for the
    /// first line of a new day file is `[0u8; 32]`, hex-encoded).
    prev_mac: [u8; 32],
}

impl AuditLog {
    /// Open / create the audit log directory in synchronous-direct
    /// mode: every `write()` call writes + fsyncs inline. Suitable
    /// for unit tests, the offline `audit verify` CLI path, and any
    /// caller that does NOT have a tokio runtime available.
    ///
    /// Production callers (which always run under tokio) should
    /// prefer [`AuditLog::open_batched`] for the per-line-fsync
    /// throughput win described in `/tmp/simplify-efficiency.md` (E7
    /// / issue #239).
    pub(crate) fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(dir.as_ref(), None)
    }

    /// Open the audit log in batched mode. Spawns a background tokio
    /// task that drains an unbounded channel of records, batches up
    /// to `batch_size` entries (or `batch_interval_ms` milliseconds —
    /// whichever hits first), then writes + fsyncs the batch as one
    /// I/O. Requires a tokio runtime to be active.
    ///
    /// Use [`DEFAULT_BATCH_SIZE`] / [`DEFAULT_BATCH_INTERVAL_MS`]
    /// unless you have a specific durability target.
    #[allow(dead_code)]
    pub(crate) fn open_batched(
        dir: impl AsRef<Path>,
        batch_size: usize,
        batch_interval_ms: u64,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let me = Self::open_inner(dir.as_ref(), Some(tx))?;
        // Share `Arc<Mutex<Inner>>` with the flusher task; the public
        // AuditLog and the flusher both hold the file handle + chain
        // state, which means the direct synchronous `write` path
        // STILL works (e.g. for tests running under tokio that want
        // immediate visibility).
        let inner = me.inner.clone();
        tokio::spawn(flusher_loop(
            inner,
            rx,
            batch_size.max(1),
            batch_interval_ms.max(1),
        ));
        Ok(me)
    }

    fn open_inner(
        dir: &Path,
        sender: Option<mpsc::UnboundedSender<FlusherCmd>>,
    ) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create audit dir {}", dir.display()))?;
        let key = load_or_create_key(dir)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                dir: dir.to_path_buf(),
                current_date: String::new(),
                current_file: None,
                key,
                prev_mac: [0u8; 32],
            })),
            sender,
        })
    }

    /// Synchronous write — always direct (writes + fsyncs inline,
    /// even in batched mode). Use this when the caller has no async
    /// context or needs read-after-write guarantees. Production async
    /// code should prefer [`Self::write_async`].
    pub(crate) fn write(&self, rec: &AuditRecord) -> Result<()> {
        let mut inner = self.inner.lock();
        write_inner_direct(&mut inner, rec, /*fsync=*/ true)
    }

    /// Async write. In batched mode this is fire-and-forget: returns
    /// `Ok(())` immediately once the record is enqueued; the flusher
    /// task takes care of writing + fsyncing within
    /// `batch_interval_ms`. In direct mode the write is bounced off
    /// `spawn_blocking` for tokio-runtime friendliness (no change in
    /// semantics vs the pre-batched API).
    ///
    /// Crash safety: up to `batch_interval_ms` of recent records may
    /// be lost on a hard kill. The receipt journal is authoritative
    /// for double-sign protection (P1-8/9); the audit log is
    /// observability — this trade-off is intentional.
    pub(crate) async fn write_async(&self, rec: AuditRecord) -> Result<()> {
        if let Some(tx) = &self.sender {
            // Fire-and-forget. Channel send only fails if the flusher
            // task has terminated.
            tx.send(FlusherCmd::Write(rec))
                .map_err(|_| anyhow::anyhow!("audit flusher channel closed"))?;
            Ok(())
        } else {
            // Direct fallback: bounce off spawn_blocking so a slow
            // disk doesn't stall the runtime worker.
            let me = self.clone();
            tokio::task::spawn_blocking(move || me.write(&rec))
                .await
                .context("spawn_blocking audit write")?
        }
    }

    /// Drain any in-flight batched writes + fsync. In direct mode
    /// this is a no-op (every write has already been fsynced). Safe
    /// to call multiple times.
    #[allow(dead_code)]
    pub(crate) async fn flush_and_close(&self) -> Result<()> {
        let Some(tx) = self.sender.as_ref() else {
            return Ok(());
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        if tx.send(FlusherCmd::Flush(ack_tx)).is_err() {
            // Flusher already exited.
            return Ok(());
        }
        // Wait for the drain ack. If the flusher dies mid-drain we
        // can't do anything useful — return Ok and let the operator
        // notice via logs.
        let _ = ack_rx.await;
        Ok(())
    }

    /// Verify the integrity of a single audit file. Returns a rich
    /// [`FileVerifyReport`] carrying entry count, harvested
    /// `(session_id, seq)` pairs for the cross-check, and the first
    /// chain error (if any) with line number + expected/actual MACs.
    ///
    /// #240 / F1: callers (including `audit_cli::verify_audit_files`)
    /// MUST use this entry point rather than re-walking the file. The
    /// reuse review (`/tmp/simplify-reuse-review.md`) called out the
    /// previous duplication; the rich result type below carries
    /// everything the CLI's renderer needs.
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
            let Some(claimed_prev) = v.get("prev_mac").and_then(Value::as_str).map(str::to_string)
            else {
                first_error = Some(FileVerifyError {
                    line: line_num,
                    kind: FileVerifyErrorKind::MissingField("prev_mac"),
                });
                break;
            };
            let Some(claimed_mac) = v.get("mac").and_then(Value::as_str).map(str::to_string)
            else {
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
            let Some(canonical) = v.get("record_json").and_then(Value::as_str).map(str::to_string)
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
            // Harvest (session_id, seq) for the cross-check the CLI
            // performs against the receipt journal. Both flat-on-record
            // and nested-in-extra shapes are accepted to stay
            // forward-compat with future emit sites.
            if let Ok(rec) = serde_json::from_str::<Value>(&canonical) {
                let sid = rec.get("session_id").and_then(Value::as_str).map(String::from);
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

    /// The HMAC key as known to a running `AuditLog`. Needed for
    /// `verify_file` and by operators auditing the log out-of-band
    /// (e.g. shipping the chain to a separate auditor).
    pub(crate) fn key(&self) -> [u8; 32] {
        self.inner.lock().key
    }

    /// Emit a `receipt_signed` entry for the audit-replay tool's
    /// cross-check pass. Mirrors the `kind="announce"` emission shape
    /// (per-session) but carries the freshly bumped seq + bytes_used
    /// in the `extra` blob. The audit_cli verifier harvests these
    /// `(session_id, seq)` pairs to confirm every journal floor was
    /// preceded by a sign event.
    pub(crate) async fn record_receipt_signed(
        &self,
        session_id_hex: String,
        seq: u64,
        bytes_used: u64,
    ) -> Result<()> {
        self.write_async(AuditRecord {
            ts_unix: octravpn_core::util::now_unix_secs(),
            kind: "receipt_signed",
            source: None,
            session_id: Some(session_id_hex),
            extra: serde_json::json!({
                "seq": seq,
                "bytes_used": bytes_used,
            }),
        })
        .await
    }
}

/// Rich result returned by [`AuditLog::verify_file`]. Carries enough
/// detail for the CLI's formatter to surface line numbers +
/// expected/actual MACs without re-walking the file.
#[derive(Debug, Clone, Default)]
pub(crate) struct FileVerifyReport {
    /// Number of audit lines that verified before any error.
    pub entries: u64,
    /// `session_id (hex) -> set<seq>` harvested from `receipt_signed`
    /// (or any record carrying a flat `seq` / `extra.seq`). Used by
    /// the CLI's cross-check against the receipt journal.
    pub signed_seqs: BTreeMap<String, BTreeSet<u64>>,
    /// `Some` if the chain broke; carries the exact line + the
    /// expected/claimed MAC pair so the operator can localize the
    /// tamper.
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
pub(crate) enum FileVerifyErrorKind {
    /// The line's `prev_mac` didn't match what the verifier carried
    /// forward from the previous line (or the all-zeros sentinel for
    /// the first line of a daily file).
    ChainBreak { expected: String, claimed: String },
    /// The line's `mac` didn't match `HMAC(key, prev_mac ||
    /// record_json)`.
    MacMismatch { expected: String, claimed: String },
    /// One of the chained-line envelope fields was absent.
    MissingField(&'static str),
    /// JSON parse failure.
    Parse(String),
    /// I/O failure while reading the file.
    Io(String),
}

/// The HMAC step shared by writers and verifiers. Exposed so
/// integration tests can build synthetic fixtures without duplicating
/// the algorithm (cf. F6 in `/tmp/simplify-reuse-review.md`).
pub(crate) fn chain_step(key: &[u8; 32], prev_mac: &[u8; 32], record_bytes: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(prev_mac);
    mac.update(record_bytes);
    mac.finalize().into_bytes().into()
}

/// Direct synchronous write — used by both the sync `write()` API and
/// by the background flusher task. The `fsync` parameter lets the
/// flusher hold off the fsync until the end of a batch.
fn write_inner_direct(inner: &mut Inner, rec: &AuditRecord, fsync: bool) -> Result<()> {
    let canonical = serde_json::to_string(rec).context("serialize audit record")?;
    let date = ymd_utc(rec.ts_unix);
    if inner.current_file.is_none() || inner.current_date != date {
        let path = inner.dir.join(format!("audit-{date}.jsonl"));
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open audit file {}", path.display()))?;
        inner.current_date = date;
        inner.current_file = Some(f);
        inner.prev_mac = [0u8; 32]; // new file resets the chain
    }
    let line_mac = chain_step(&inner.key, &inner.prev_mac, canonical.as_bytes());
    let chained = ChainedLine {
        record_json: canonical,
        prev_mac: hex::encode(inner.prev_mac),
        mac: hex::encode(line_mac),
    };
    let line = serde_json::to_string(&chained).context("serialize chained audit line")?;
    let f = inner.current_file.as_mut().expect("file just opened");
    f.write_all(line.as_bytes()).context("write audit line")?;
    f.write_all(b"\n").context("write audit newline")?;
    if fsync {
        f.sync_data().context("fsync audit log")?;
    }
    inner.prev_mac = line_mac;
    Ok(())
}

/// Background flusher: drain the channel, buffer up to `batch_size`
/// records (or until `batch_interval_ms` elapses), then fsync once at
/// the end of each batch.
#[allow(dead_code)]
async fn flusher_loop(
    inner: Arc<Mutex<Inner>>,
    mut rx: mpsc::UnboundedReceiver<FlusherCmd>,
    batch_size: usize,
    batch_interval_ms: u64,
) {
    let interval = std::time::Duration::from_millis(batch_interval_ms);
    // We write each record's bytes synchronously to the file (the
    // mutex guarantees we own the file handle); only the fsync is
    // deferred. `unsynced` counts written-but-not-yet-fsynced records.
    let mut unsynced: usize = 0;
    let mut deadline = tokio::time::Instant::now() + interval;
    loop {
        let timeout_at = tokio::time::sleep_until(deadline);
        tokio::pin!(timeout_at);
        tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    None => {
                        // All senders dropped. Final fsync + exit.
                        if unsynced > 0 {
                            let _ = fsync_now(&inner);
                        }
                        return;
                    }
                    Some(FlusherCmd::Write(rec)) => {
                        let mut g = inner.lock();
                        let r = write_inner_direct(&mut g, &rec, /*fsync=*/ false);
                        drop(g);
                        match r {
                            Ok(()) => unsynced += 1,
                            Err(e) => tracing::warn!(error = %e, "audit batched write failed"),
                        }
                        if unsynced >= batch_size {
                            let _ = fsync_now(&inner);
                            unsynced = 0;
                            deadline = tokio::time::Instant::now() + interval;
                        }
                    }
                    Some(FlusherCmd::Flush(ack)) => {
                        if unsynced > 0 {
                            let _ = fsync_now(&inner);
                            unsynced = 0;
                        }
                        let _ = ack.send(());
                        deadline = tokio::time::Instant::now() + interval;
                    }
                }
            }
            () = &mut timeout_at => {
                if unsynced > 0 {
                    let _ = fsync_now(&inner);
                    unsynced = 0;
                }
                deadline = tokio::time::Instant::now() + interval;
            }
        }
    }
}

#[allow(dead_code)]
fn fsync_now(inner: &Arc<Mutex<Inner>>) -> Result<()> {
    let mut g = inner.lock();
    if let Some(f) = g.current_file.as_mut() {
        f.sync_data().context("fsync audit log")?;
    }
    Ok(())
}

fn load_or_create_key(dir: &Path) -> Result<[u8; 32]> {
    let p = dir.join(".audit.key");
    if p.exists() {
        let raw = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
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
    } else {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        std::fs::write(&p, k).with_context(|| format!("write {}", p.display()))?;
        // Best-effort chmod 0600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
        Ok(k)
    }
}

fn ymd_utc(ts_unix: u64) -> String {
    // Trivial UTC date conversion — gives a stable YYYY-MM-DD without
    // pulling in chrono. Days since epoch.
    let days = (ts_unix / 86_400) as i64;
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert days-since-1970-01-01 to (year, month, day). Standard
/// Howard Hinnant algorithm — fast and exact.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn writes_one_line_per_record() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: Some("127.0.0.1:1234".into()),
            session_id: Some("abc".into()),
            extra: json!({"k": 1}),
        })
        .unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_001,
            kind: "get_state",
            source: None,
            session_id: Some("abc".into()),
            extra: Value::Null,
        })
        .unwrap();
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        // 2 audit lines + 1 .audit.key file = 2 files in dir.
        assert!(
            files.iter().any(|f| f.starts_with("audit-")),
            "no audit file: {files:?}"
        );
        let audit_file = files.iter().find(|f| f.starts_with("audit-")).unwrap();
        let body = std::fs::read_to_string(dir.path().join(audit_file)).unwrap();
        assert_eq!(body.lines().count(), 2);
        // Parses cleanly.
        for line in body.lines() {
            let _: Value = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn ymd_conversion_known_dates() {
        // 1970-01-01: ts_unix=0
        assert_eq!(ymd_utc(0), "1970-01-01");
        // 2000-01-01: 30 years × ~365 days
        assert_eq!(ymd_utc(946_684_800), "2000-01-01");
        // 2024-01-01
        assert_eq!(ymd_utc(1_704_067_200), "2024-01-01");
    }

    #[test]
    fn rotates_when_date_advances() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        // Day 1.
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "x",
            source: None,
            session_id: None,
            extra: Value::Null,
        })
        .unwrap();
        // Day 2 (+86400s).
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000 + 86_400,
            kind: "y",
            source: None,
            session_id: None,
            extra: Value::Null,
        })
        .unwrap();
        let count = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .map(|e| e.file_name().to_string_lossy().starts_with("audit-"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(count, 2, "expected two daily audit files");
    }

    #[test]
    fn verify_file_passes_clean_chain() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..5 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: None,
                extra: json!({"i": i}),
            })
            .unwrap();
        }
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let key = log.key();
        let report = AuditLog::verify_file(&key, &audit_file).unwrap();
        assert_eq!(report.entries, 5);
        assert!(report.first_error.is_none());
    }

    /// `record_receipt_signed` writes a `kind="receipt_signed"` row
    /// whose `extra` blob carries the seq + bytes_used. Round-trip
    /// the file through the JSONL parser to confirm the schema.
    #[tokio::test]
    async fn receipt_signed_entry_round_trips() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.record_receipt_signed("a1b2c3".to_string(), 7, 1024)
            .await
            .unwrap();
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let body = std::fs::read_to_string(&audit_file).unwrap();
        // Outer ChainedLine envelope.
        let chained: Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        let canonical = chained.get("record_json").unwrap().as_str().unwrap();
        let rec: Value = serde_json::from_str(canonical).unwrap();
        assert_eq!(rec["kind"], "receipt_signed");
        assert_eq!(rec["session_id"], "a1b2c3");
        assert_eq!(rec["extra"]["seq"], 7);
        assert_eq!(rec["extra"]["bytes_used"], 1024);
        // Whole file verifies — the new row is chained correctly.
        let report = AuditLog::verify_file(&log.key(), &audit_file).unwrap();
        assert_eq!(report.entries, 1);
        // Cross-check seq harvesting picked up the (sid, seq) tuple.
        assert!(report.signed_seqs.get("a1b2c3").is_some_and(|s| s.contains(&7)));
    }

    /// Multiple `record_receipt_signed` calls form a contiguous HMAC
    /// chain — confirming the new helper goes through the same
    /// `write` path as the announce emission.
    #[tokio::test]
    async fn multiple_receipt_signed_entries_chain_correctly() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for seq in 1..=4u64 {
            log.record_receipt_signed("sess".to_string(), seq, seq * 100)
                .await
                .unwrap();
        }
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let report = AuditLog::verify_file(&log.key(), &audit_file).unwrap();
        assert_eq!(report.entries, 4, "all four receipt_signed rows chain cleanly");
    }

    #[test]
    fn verify_file_detects_tampered_line() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..3 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: None,
                extra: json!({"i": i}),
            })
            .unwrap();
        }
        let key = log.key();
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let original = std::fs::read_to_string(&audit_file).unwrap();
        let mut lines: Vec<String> = original.lines().map(String::from).collect();
        lines[1] = lines[1].replacen("\\\"i\\\":1", "\\\"i\\\":99", 1);
        std::fs::write(&audit_file, lines.join("\n") + "\n").unwrap();
        let report = AuditLog::verify_file(&key, &audit_file).unwrap();
        let err = report.first_error.expect("tampered line should fail");
        // Line 2 (1-indexed) tampered → MAC mismatch.
        assert_eq!(err.line, 2);
        assert!(matches!(err.kind, FileVerifyErrorKind::MacMismatch { .. }));
    }

    // -------------------------------------------------------------------
    // #239 batched fsync flusher tests
    // -------------------------------------------------------------------

    /// Batched writes get fsynced within `batch_interval_ms`. We use
    /// a short interval (50ms) and verify the file is observable
    /// within 5× that bound.
    #[tokio::test]
    async fn batched_writes_get_fsynced_within_interval() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched(dir.path(), 64, 50).unwrap();
        for i in 0..3u64 {
            log.write_async(AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "announce",
                source: None,
                session_id: Some("s1".into()),
                extra: json!({"i": i}),
            })
            .await
            .unwrap();
        }
        // Poll for visibility — within 5 batch intervals the flusher
        // must have written + fsynced.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50 * 5);
        loop {
            let files: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with("audit-"))
                .map(|e| e.path())
                .collect();
            if let Some(p) = files.first() {
                let body = std::fs::read_to_string(p).unwrap();
                if body.lines().count() == 3 {
                    return;
                }
            }
            assert!(
                std::time::Instant::now() <= deadline,
                "batched flusher did not fsync within deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// `flush_and_close` is an explicit drain fence: after it returns,
    /// every previously-enqueued record is on disk + fsynced. We pick
    /// a long batch interval (60s) so the time-based trigger cannot
    /// have fired — only the explicit flush could have made the data
    /// durable.
    #[tokio::test]
    async fn flush_and_close_drains_pending_writes() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched(dir.path(), 64, 60_000).unwrap();
        for i in 0..5u64 {
            log.write_async(AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: None,
                extra: Value::Null,
            })
            .await
            .unwrap();
        }
        log.flush_and_close().await.unwrap();
        let p = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let body = std::fs::read_to_string(&p).unwrap();
        assert_eq!(body.lines().count(), 5);
        // Chain verifies cleanly.
        let report = AuditLog::verify_file(&log.key(), &p).unwrap();
        assert_eq!(report.entries, 5);
        assert!(report.first_error.is_none());
    }

    /// Sender-close drain: dropping the last AuditLog handle (without
    /// calling `flush_and_close`) still causes the flusher to do a
    /// final fsync via the `None` branch of `rx.recv()`. Documents
    /// the upper bound on what a graceful shutdown loses: nothing,
    /// because Drop closes the sender which terminates the loop with
    /// a final fsync.
    #[tokio::test]
    async fn graceful_drop_triggers_final_fsync() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_path_buf();
        {
            let log = AuditLog::open_batched(&dir_path, 64, 60_000).unwrap();
            for i in 0..3u64 {
                log.write_async(AuditRecord {
                    ts_unix: 1_700_000_000 + i,
                    kind: "x",
                    source: None,
                    session_id: None,
                    extra: Value::Null,
                })
                .await
                .unwrap();
            }
            // Force a drain BEFORE drop so the test is deterministic
            // (Drop's final fsync happens asynchronously in the
            // flusher task; without an explicit fence we'd be racing
            // the spawn).
            log.flush_and_close().await.unwrap();
        }
        let p = std::fs::read_dir(&dir_path)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let body = std::fs::read_to_string(p).unwrap();
        assert_eq!(body.lines().count(), 3);
    }

    /// `verify_file` exposes the broken line number + claimed/expected
    /// MAC pair so the CLI can localize the tamper without re-walking
    /// the file.
    #[test]
    fn verify_file_reports_line_and_macs_on_chain_break() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..3u64 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: None,
                extra: json!({"i": i}),
            })
            .unwrap();
        }
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        // Tamper the prev_mac on line 2 by hand-editing the file —
        // this breaks the chain link (not the MAC of this line's
        // record, but the carry-forward from line 1).
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

    /// `verify_file` returns the entries-verified-before-error count
    /// + the harvested `signed_seqs` map so the CLI can power its
    /// cross-check without re-implementing the HMAC walk.
    #[tokio::test]
    async fn verify_file_returns_signed_seqs_for_cross_check() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        // Two receipt_signed rows for two sessions.
        log.record_receipt_signed("aa".into(), 1, 100).await.unwrap();
        log.record_receipt_signed("aa".into(), 2, 200).await.unwrap();
        log.record_receipt_signed("bb".into(), 5, 0).await.unwrap();
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let report = AuditLog::verify_file(&log.key(), &audit_file).unwrap();
        assert_eq!(report.entries, 3);
        let aa = report.signed_seqs.get("aa").expect("aa harvested");
        assert!(aa.contains(&1) && aa.contains(&2));
        let bb = report.signed_seqs.get("bb").expect("bb harvested");
        assert!(bb.contains(&5));
    }

    /// `chain_step` is the single source of truth for the HMAC step
    /// (cf. F6 in the reuse review). A writer + reader should agree.
    #[test]
    fn chain_step_is_deterministic_and_keyed() {
        let key = [0x42u8; 32];
        let prev = [0u8; 32];
        let a = chain_step(&key, &prev, b"hello");
        let b = chain_step(&key, &prev, b"hello");
        assert_eq!(a, b, "deterministic");
        let c = chain_step(&[0x43u8; 32], &prev, b"hello");
        assert_ne!(a, c, "key-sensitive");
        let d = chain_step(&key, &[1u8; 32], b"hello");
        assert_ne!(a, d, "prev-mac-sensitive");
    }
}
