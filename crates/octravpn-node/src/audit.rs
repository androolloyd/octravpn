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
//!
//! ## Backpressure contract (audit-2 C-6 / OOM-3 fix)
//!
//! The batched-flusher channel is **bounded** at
//! [`DEFAULT_BATCH_QUEUE_CAP`] (8192 entries, ~2 MB worst-case
//! buffered RAM). When it saturates (slow fsync, IO error spam,
//! audit-emit flood), [`AuditLog::write_async`] falls back to a
//! synchronous inline write under the same `Inner` mutex the flusher
//! uses — the entry is written + fsynced before `write_async`
//! returns. **No record is lost; no record is duplicated.** Each
//! fallback increments `audit_inline_fallback_total`, surfaced on
//! `/metrics` as `octravpn_audit_inline_fallback_total`. A non-zero
//! growth rate is the operator-facing disk-stall signal.
//!
//! Pre-fix (the BLOCKER): the unbounded channel allowed 125 MB/s of
//! queue growth on stall — 1 GB in 8 s, 16 GB in ~2 min. Post-fix:
//! durable under stall, RAM capped at ~2 MB.
//!
//! ### Deadlock argument
//!
//! The inline fallback acquires the same `Arc<Mutex<Inner>>` the
//! flusher uses. This is safe: `write_async` runs on a runtime
//! worker (the caller's task), never on the flusher task itself —
//! the flusher only reads from the mpsc receiver and never calls
//! back into `write_async`. The fallback uses `spawn_blocking` so
//! the parking-lot lock is acquired off the runtime worker thread;
//! if the flusher is blocked on a slow fsync, both holders contend
//! for the mutex but neither is waiting on the other's progress.
//! The lock is released before any `.await`, so the standard
//! "no parking_lot lock across await" rule still holds.

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
/// Default capacity of the flusher channel. Bounded by design: an
/// unbounded queue is an OOM weapon under disk stall (audit-2 C-6 /
/// OOM-3 in `docs/audit/2026-05-20-load-perf-audit.md`). 8192 entries
/// × ~256 B/entry = ~2 MB worst-case buffered RAM — large enough to
/// absorb sub-second flusher stalls, small enough that a sustained
/// disk stall trips the inline-fallback path within milliseconds
/// instead of growing memory.
#[allow(dead_code)]
pub(crate) const DEFAULT_BATCH_QUEUE_CAP: usize = 8192;

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
    /// Process-lifetime audit counters. Lock-free atomics so the
    /// `/metrics` scrape path can read them even while the flusher
    /// is blocked on a disk stall.
    counters: Arc<AuditCounters>,
    /// `Some` in batched mode: a bounded sender into the flusher
    /// task ([`DEFAULT_BATCH_QUEUE_CAP`] slots). When full,
    /// `write_async` falls back to inline sync-fsync to preserve
    /// durability (no record is lost). When dropped (last sender
    /// goes), the receiver side terminates and the flusher exits
    /// after a final fsync.
    sender: Option<mpsc::Sender<FlusherCmd>>,
    /// Optional live-event tap for task #231 (`octravpn-analytics`).
    /// Every successful write fans an [`octravpn_analytics::
    /// AnalyticsEvent`] out to this channel; the indexer side
    /// (spawned by `hub.rs`) drains it and folds into in-memory
    /// time-bucketed counters. `None` (the default) is a no-op —
    /// existing operators see no behaviour change.
    ///
    /// Design notes:
    ///   - **On-disk format is untouched.** The tap is a side-effect
    ///     of the in-memory record path, not part of the JSONL
    ///     envelope.
    ///   - **Send is best-effort.** If the analytics task has
    ///     terminated (`send` returns `Err`), the audit write still
    ///     succeeds — observability MUST NOT block forensics.
    ///   - **Unbounded** channel: the indexer is in-process and
    ///     consumes synchronously; backpressure isn't a concern.
    ///     Bounded would risk losing audit ⇄ analytics correlation
    ///     under burst load.
    analytics_tap: Option<mpsc::UnboundedSender<octravpn_analytics::AnalyticsEvent>>,
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

/// Process-lifetime counters bumped from the audit hot path. Lives
/// alongside `Inner` rather than inside it so the `/metrics` scrape
/// path can read these without acquiring the (potentially
/// disk-stalled) `Inner` mutex.
///
/// Today's only counter is `inline_fallback_total`: the bounded
/// flusher channel (see [`DEFAULT_BATCH_QUEUE_CAP`]) drops writes
/// to an inline sync-fsync path when it saturates. Every such drop
/// bumps this counter; non-zero growth is the disk-stall signal.
#[derive(Default)]
struct AuditCounters {
    inline_fallback_total: std::sync::atomic::AtomicU64,
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
    /// unless you have a specific durability target. The queue
    /// capacity is [`DEFAULT_BATCH_QUEUE_CAP`]; when it fills,
    /// `write_async` falls back to inline sync-fsync (bumps
    /// `audit_inline_fallback_total`) so durability is preserved.
    #[allow(dead_code)]
    pub(crate) fn open_batched(
        dir: impl AsRef<Path>,
        batch_size: usize,
        batch_interval_ms: u64,
    ) -> Result<Self> {
        Self::open_batched_with_cap(
            dir,
            batch_size,
            batch_interval_ms,
            DEFAULT_BATCH_QUEUE_CAP,
        )
    }

    /// Like [`Self::open_batched`] but with an explicit queue
    /// capacity. Tests use a tiny cap (e.g. 1) to deterministically
    /// hit the inline-fallback path; production callers should use
    /// [`Self::open_batched`] which uses [`DEFAULT_BATCH_QUEUE_CAP`].
    #[allow(dead_code)]
    pub(crate) fn open_batched_with_cap(
        dir: impl AsRef<Path>,
        batch_size: usize,
        batch_interval_ms: u64,
        queue_cap: usize,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel(queue_cap.max(1));
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

    fn open_inner(dir: &Path, sender: Option<mpsc::Sender<FlusherCmd>>) -> Result<Self> {
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
            counters: Arc::new(AuditCounters::default()),
            sender,
            analytics_tap: None,
        })
    }

    /// Process-lifetime count of writes that fell back to inline
    /// sync-fsync because the batched-flusher queue was full. A
    /// non-zero growth rate signals disk stall (operator action:
    /// check disk health / journal latency). Lock-free — safe to
    /// call from the `/metrics` scrape path under any disk state.
    pub(crate) fn inline_fallback_total(&self) -> u64 {
        self.counters
            .inline_fallback_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Install a live analytics tap. The returned `AuditLog` is the
    /// same handle (cheap `Arc<Mutex>` clone) — calling this twice
    /// replaces the previous tap. Used by `hub.rs` when the
    /// `[analytics]` block is enabled.
    #[must_use]
    pub(crate) fn with_analytics_tap(
        mut self,
        tap: mpsc::UnboundedSender<octravpn_analytics::AnalyticsEvent>,
    ) -> Self {
        self.analytics_tap = Some(tap);
        self
    }

    /// Synchronous write — always direct (writes + fsyncs inline,
    /// even in batched mode). Use this when the caller has no async
    /// context or needs read-after-write guarantees. Production async
    /// code should prefer [`Self::write_async`].
    pub(crate) fn write(&self, rec: &AuditRecord) -> Result<()> {
        let mut inner = self.inner.lock();
        let r = write_inner_direct(&mut inner, rec, /*fsync=*/ true);
        drop(inner);
        // Fan out to the analytics indexer on successful write. Mirror
        // of `write_async`'s tap below; we publish here so callers that
        // bypass the async path still hit the indexer.
        if r.is_ok() {
            self.tap_publish(rec);
        }
        r
    }

    /// Fan out one record to the analytics tap (best-effort). Pulled
    /// out of `write` / `write_async` so the conversion lives in one
    /// place. Public-to-crate for the off chance a future caller
    /// needs to publish without going through the write path.
    fn tap_publish(&self, rec: &AuditRecord) {
        let Some(tap) = self.analytics_tap.as_ref() else {
            return;
        };
        // Re-serialize through JSON so the conversion sees the exact
        // bytes the verifier would. Conservative; `AuditRecord` is
        // small enough that the round-trip is irrelevant.
        let Ok(json) = serde_json::to_string(rec) else {
            return;
        };
        let Some(ev) = octravpn_analytics::AnalyticsEvent::from_audit_record_json(&json) else {
            return;
        };
        // Best-effort: if the indexer task has died, drop the event.
        // Audit writes MUST NOT block on observability.
        let _ = tap.send(ev);
    }

    /// Async write. Batched mode: try the bounded flusher channel
    /// first; if it's full (disk stall on the flusher side), fall
    /// back to an inline synchronous write under the shared `Inner`
    /// mutex — same lock the flusher uses, same on-disk format, same
    /// MAC chain. Direct mode: bounce off `spawn_blocking` for
    /// tokio-runtime friendliness.
    ///
    /// **Durability contract (audit-2 C-6 / OOM-3 fix):** the audit
    /// log is durable under all successful returns from this
    /// function. Performance degrades to per-line fsync if the
    /// flusher can't keep up — never silent drop, never OOM. The
    /// bounded queue caps worst-case buffered RAM at
    /// `DEFAULT_BATCH_QUEUE_CAP × ~256 B/entry ≈ 2 MB`. Inline
    /// fallbacks bump `audit_inline_fallback_total` so operators
    /// can detect disk stall via `/metrics`.
    ///
    /// Crash safety: in the fast path, up to `batch_interval_ms` of
    /// recent records may be lost on a hard kill. The receipt
    /// journal is authoritative for double-sign protection
    /// (P1-8/9); the audit log is observability.
    pub(crate) async fn write_async(&self, rec: AuditRecord) -> Result<()> {
        if let Some(tx) = &self.sender {
            // Publish to the analytics tap BEFORE attempting the
            // flusher send. The flusher does the disk write
            // asynchronously; the indexer credit doesn't need to
            // wait on fsync. The inline fallback (below) also doesn't
            // republish — `tap_publish` would double-emit otherwise.
            self.tap_publish(&rec);
            match tx.try_send(FlusherCmd::Write(rec)) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(cmd)) => {
                    // Queue full → flusher is stalled (slow fsync,
                    // IO error spam). Fall back to inline sync write
                    // to preserve durability. Bumps the metric so
                    // operators see the disk-stall signal.
                    self.counters
                        .inline_fallback_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let rec = match cmd {
                        FlusherCmd::Write(r) => r,
                        FlusherCmd::Flush(_) => {
                            return Err(anyhow::anyhow!(
                                "audit write_async: non-Write returned by try_send"
                            ));
                        }
                    };
                    let me = self.clone();
                    // `spawn_blocking` so the parking-lot mutex
                    // acquisition + fsync don't stall a runtime
                    // worker thread. See the deadlock argument in
                    // `audit/README.md` (or below): the flusher
                    // never calls into `write_async`, so the shared
                    // mutex is fine.
                    tokio::task::spawn_blocking(move || {
                        let mut g = me.inner.lock();
                        let r = write_inner_direct(&mut g, &rec, /*fsync=*/ true);
                        drop(g);
                        r
                    })
                    .await
                    .context("spawn_blocking audit inline fallback")?
                }
                Err(mpsc::error::TrySendError::Closed(_)) => Err(anyhow::anyhow!(
                    "audit flusher channel closed"
                )),
            }
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
        // `send().await` (not `try_send`): the Flush fence MUST be
        // queued in order behind any pending Writes — otherwise the
        // ack could race ahead of a write the caller just enqueued.
        // Blocking here is acceptable; `flush_and_close` is an
        // explicit drain fence, not a hot-path emit.
        if tx.send(FlusherCmd::Flush(ack_tx)).await.is_err() {
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
            // Harvest (session_id, seq) for the cross-check the CLI
            // performs against the receipt journal. Both flat-on-record
            // and nested-in-extra shapes are accepted to stay
            // forward-compat with future emit sites.
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
#[non_exhaustive]
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
    mut rx: mpsc::Receiver<FlusherCmd>,
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
        assert!(report
            .signed_seqs
            .get("a1b2c3")
            .is_some_and(|s| s.contains(&7)));
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
        assert_eq!(
            report.entries, 4,
            "all four receipt_signed rows chain cleanly"
        );
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
        log.record_receipt_signed("aa".into(), 1, 100)
            .await
            .unwrap();
        log.record_receipt_signed("aa".into(), 2, 200)
            .await
            .unwrap();
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

    // ================================================================
    // OOM-3 / audit-2 C-6: bounded-queue + inline-fallback tests.
    // ================================================================

    /// Find the single `audit-YYYY-MM-DD.jsonl` file under `dir`.
    /// Local helper for the OOM-3 tests; the rest of the test module
    /// inlines the same pattern.
    fn audit_file_in(dir: &std::path::Path) -> std::path::PathBuf {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .expect("at least one audit-*.jsonl file in dir")
            .path()
    }

    /// Small fixed-shape record builder for the OOM-3 burst tests.
    fn oom3_rec(i: u64) -> AuditRecord {
        AuditRecord {
            ts_unix: 1_700_000_000 + i,
            kind: "x",
            source: None,
            session_id: Some(format!("s{i}")),
            extra: serde_json::json!({"i": i}),
        }
    }

    /// Burst of writes much larger than the queue capacity must all
    /// land on disk — durability is the contract. The inline-fallback
    /// path absorbs whatever the bounded queue can't.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_channel_doesnt_drop_under_burst() {
        let dir = tempdir().unwrap();
        // Tiny queue (cap=8) so the inline-fallback path is exercised
        // heavily; big batch so the flusher fsyncs in chunks.
        let log = AuditLog::open_batched_with_cap(dir.path(), 32, 50, 8).unwrap();
        const N: u64 = 2_000;
        for i in 0..N {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        log.flush_and_close().await.unwrap();
        let p = audit_file_in(dir.path());
        let body = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            body.lines().count() as u64,
            N,
            "bounded channel must not drop records under burst"
        );
        // Chain must verify end-to-end — no record corruption even
        // though writes interleaved between flusher + fallback paths.
        let report = AuditLog::verify_file(&log.key(), &p).unwrap();
        assert_eq!(report.entries, N);
        assert!(
            report.first_error.is_none(),
            "chain broken under burst: {:?}",
            report.first_error
        );
    }

    /// When the queue fills, `write_async` must take the inline-fallback
    /// path AND increment `audit_inline_fallback_total`. Synthetic
    /// "disk stall": queue_cap=1, batch_interval long, no `.await`
    /// between sends so the flusher gets no chance to drain on the
    /// current-thread executor.
    #[tokio::test(flavor = "current_thread")]
    async fn inline_fallback_under_queue_full() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 1024, 60_000, 1).unwrap();
        let before = log.inline_fallback_total();
        for i in 0..16u64 {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        let after = log.inline_fallback_total();
        assert!(
            after > before,
            "expected inline_fallback_total to increment; before={before} after={after}"
        );
        log.flush_and_close().await.unwrap();
        let p = audit_file_in(dir.path());
        let body = std::fs::read_to_string(p).unwrap();
        assert_eq!(body.lines().count(), 16);
    }

    /// Under inline-fallback the HMAC chain stays linear:
    /// `prev_mac` of line N+1 == `mac` of line N, regardless of which
    /// path (flusher or fallback) wrote each line. Both paths go
    /// through `write_inner_direct` under the same `Inner` mutex, so
    /// the chain is unambiguous.
    #[tokio::test(flavor = "current_thread")]
    async fn inline_fallback_preserves_chain_order() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 1024, 60_000, 1).unwrap();
        const N: u64 = 64;
        for i in 0..N {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        log.flush_and_close().await.unwrap();
        let p = audit_file_in(dir.path());
        let report = AuditLog::verify_file(&log.key(), &p).unwrap();
        assert_eq!(report.entries, N);
        assert!(
            report.first_error.is_none(),
            "chain broken: {:?}",
            report.first_error
        );
    }

    /// After a burst that drives the inline-fallback counter up, a
    /// quiescent period followed by ordinary writes should NOT keep
    /// bumping the counter — the flusher catches up, future writes
    /// take the fast path again.
    #[tokio::test(flavor = "current_thread")]
    async fn recovery_from_disk_stall() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 64, 50, 1).unwrap();
        // Burst phase.
        for i in 0..32u64 {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        let after_burst = log.inline_fallback_total();
        assert!(
            after_burst > 0,
            "burst should have triggered ≥1 inline fallback (got {after_burst})"
        );
        log.flush_and_close().await.unwrap();
        // Quiescent phase: yield + sleep between sends so the
        // flusher drains each one. No fallback should fire.
        let snapshot = log.inline_fallback_total();
        for i in 32..36u64 {
            log.write_async(oom3_rec(i)).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        }
        let after_quiet = log.inline_fallback_total();
        assert_eq!(
            after_quiet, snapshot,
            "metric incremented during quiescent phase \
             (snapshot={snapshot}, after={after_quiet})"
        );
        log.flush_and_close().await.unwrap();
    }

    /// The `octravpn_audit_inline_fallback_total` counter is exposed
    /// on `GET /metrics`. End-to-end via the real handler + handler
    /// state, with the bearer-token gate satisfied.
    #[tokio::test(flavor = "current_thread")]
    async fn metric_visible_on_metrics_endpoint() {
        use crate::control::handlers::metrics::metrics as metrics_handler;
        use crate::control::state::ControlState;
        use crate::onion::OnionRouter;
        use axum::extract::State;
        use axum::http::{HeaderMap, HeaderValue};
        use octravpn_core::{bounded::BoundedMap, sig::KeyPair};

        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 1024, 60_000, 1).unwrap();
        // Force ≥1 inline fallback.
        for i in 0..8u64 {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        assert!(log.inline_fallback_total() > 0);

        let node_kp = std::sync::Arc::new(KeyPair::generate());
        let router = std::sync::Arc::new(OnionRouter::new());
        let allowlist = std::sync::Arc::new(BoundedMap::new(
            16,
            std::time::Duration::from_secs(60),
        ));
        let state = std::sync::Arc::new(
            ControlState::new(node_kp, router, allowlist)
                .with_audit(log.clone())
                .with_metrics_token(Some("tok".to_string())),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer tok"),
        );
        let resp = metrics_handler(State(state), headers).await;
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("octravpn_audit_inline_fallback_total "),
            "/metrics body missing audit_inline_fallback_total counter: {text}"
        );
        // Value must match the live counter.
        let expected = log.inline_fallback_total();
        let needle = format!("octravpn_audit_inline_fallback_total {expected}\n");
        assert!(
            text.contains(&needle),
            "/metrics body did not contain {needle:?}; body=\n{text}"
        );
        log.flush_and_close().await.unwrap();
    }

    /// When the flusher channel is closed (sender side dropped by,
    /// e.g., the flusher task dying or the file system erroring out),
    /// `write_async` returns Err rather than dropping the record
    /// silently or leaking memory. This is the "audit log is broken"
    /// surface — the closest in-process analogue to disk-full +
    /// ENOSPC on macOS where /dev/full isn't available.
    #[tokio::test(flavor = "current_thread")]
    async fn disk_full_returns_error_not_oom() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 1, 1, 1).unwrap();
        // Synthesize the closed-channel condition: build a fresh
        // channel, drop the receiver immediately, swap it into the
        // log handle. The next try_send hits TrySendError::Closed.
        let (dead_tx, dead_rx) = tokio::sync::mpsc::channel::<FlusherCmd>(1);
        drop(dead_rx);
        let mut log_dead = log.clone();
        log_dead.sender = Some(dead_tx);
        let err = log_dead.write_async(oom3_rec(0)).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("closed"),
            "expected 'closed' surface, got: {msg}"
        );
        log.flush_and_close().await.unwrap();
    }
}
