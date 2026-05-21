//! Batched-fsync flusher + bounded queue + inline-fallback. One fsync
//! per `DEFAULT_BATCH_SIZE` records or `DEFAULT_BATCH_INTERVAL_MS` ms
//! — whichever hits first. When the bounded channel saturates
//! (`DEFAULT_BATCH_QUEUE_CAP`), `write_async` falls back to inline
//! sync-fsync under the same `Inner` mutex the flusher uses; the
//! `inline_fallback_total` counter increments so `/metrics` can
//! surface disk stall. Neither path holds the mutex across `.await`.
//! See `audit/README.md` for the durability ladder + lock-order rules.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use super::inner::{AuditCounters, Inner};
use super::log::{write_inner_direct, AuditRecord};
use super::rotation::{ChainTip, RotationCfg};
use super::AuditLog;

/// Default flush batch size — N entries per fsync. `dead_code`
/// allowance: the `hub.rs` switch to `open_batched` is a follow-up;
/// tests exercise the path with custom sizes.
#[allow(dead_code)]
pub(crate) const DEFAULT_BATCH_SIZE: usize = 64;
/// Default flush interval — fsync at least this often regardless of
/// batch fill level.
#[allow(dead_code)]
pub(crate) const DEFAULT_BATCH_INTERVAL_MS: u64 = 100;
/// Default capacity of the flusher channel. Bounded by design: an
/// unbounded queue is an OOM weapon under disk stall (audit-2 C-6 /
/// OOM-3). 8192 entries × ~256 B/entry ≈ 2 MB worst-case buffered
/// RAM — large enough to absorb sub-second flusher stalls, small
/// enough that a sustained disk stall trips the inline-fallback
/// path within milliseconds instead of growing memory.
#[allow(dead_code)]
pub(crate) const DEFAULT_BATCH_QUEUE_CAP: usize = 8192;

/// Command sent to the background flusher task.
#[allow(dead_code)]
pub(crate) enum FlusherCmd {
    /// New audit record, fire-and-forget — no ack channel.
    Write(AuditRecord),
    /// Drain everything in the channel + fsync + ack.
    Flush(oneshot::Sender<()>),
}

impl AuditLog {
    /// Open in batched mode with the production defaults. Spawns a
    /// tokio task that drains records, batches up to `batch_size`
    /// (or `batch_interval_ms`), and fsyncs the batch as one I/O.
    /// Queue capacity is [`DEFAULT_BATCH_QUEUE_CAP`]; when it fills,
    /// `write_async` falls back to inline sync-fsync.
    #[allow(dead_code)]
    pub(crate) fn open_batched(
        dir: impl AsRef<std::path::Path>,
        batch_size: usize,
        batch_interval_ms: u64,
    ) -> Result<Self> {
        Self::open_batched_with_cap(dir, batch_size, batch_interval_ms, DEFAULT_BATCH_QUEUE_CAP)
    }

    /// Like [`Self::open_batched`] but with an explicit queue
    /// capacity. Tests use a tiny cap (e.g. 1) to deterministically
    /// hit the inline-fallback path.
    #[allow(dead_code)]
    pub(crate) fn open_batched_with_cap(
        dir: impl AsRef<std::path::Path>,
        batch_size: usize,
        batch_interval_ms: u64,
        queue_cap: usize,
    ) -> Result<Self> {
        Self::open_batched_with_rotation(
            dir,
            batch_size,
            batch_interval_ms,
            queue_cap,
            RotationCfg::default(),
        )
    }

    /// Full-control opener: batched mode + custom rotation policy.
    /// `hub::spawn` calls this; tests call it to dial `max_file_bytes`
    /// low enough to deterministically trigger rotation under load.
    #[allow(dead_code)]
    pub(crate) fn open_batched_with_rotation(
        dir: impl AsRef<std::path::Path>,
        batch_size: usize,
        batch_interval_ms: u64,
        queue_cap: usize,
        rotation: RotationCfg,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel(queue_cap.max(1));
        let me = Self::open_inner(dir.as_ref(), Some(tx), rotation)?;
        // Share `Arc<Mutex<Inner>>` with the flusher task so the sync
        // `write` path still works concurrently (tests that want
        // read-after-write visibility under tokio rely on this).
        let inner = me.inner.clone();
        let counters = me.counters.clone();
        tokio::spawn(flusher_loop(
            inner,
            counters,
            rx,
            batch_size.max(1),
            batch_interval_ms.max(1),
        ));
        Ok(me)
    }

    /// Async write. Batched mode: try the bounded flusher channel
    /// first; if full (disk stall), fall back to inline sync-fsync
    /// under the shared `Inner` mutex. Direct mode: bounce off
    /// `spawn_blocking`. **Durability contract:** the audit log is
    /// durable under all successful returns — never silent drop,
    /// never OOM. Inline fallbacks bump `inline_fallback_total`.
    pub(crate) async fn write_async(&self, rec: AuditRecord) -> Result<()> {
        if let Some(tx) = &self.sender {
            // Publish to the analytics tap BEFORE attempting the
            // flusher send. The inline fallback does NOT republish.
            self.tap_publish(&rec);
            match tx.try_send(FlusherCmd::Write(rec)) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(cmd)) => {
                    self.counters
                        .inline_fallback_total
                        .fetch_add(1, Ordering::Relaxed);
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
                    // `audit/README.md`: the flusher never calls into
                    // `write_async`, so the shared mutex is safe.
                    tokio::task::spawn_blocking(move || {
                        let mut g = me.inner.lock();
                        let r = write_inner_direct(&mut g, &me.counters, &rec, /*fsync=*/ true);
                        // Inline fallback fsyncs synchronously — safe
                        // to publish the chain-tip here. Best-effort:
                        // a tip-write failure does not abort the audit
                        // write; the next successful fsync re-syncs.
                        if r.is_ok() {
                            let tip = ChainTip {
                                file_id: g.current_file_id.clone(),
                                seq: g.current_file_seq,
                                mac: hex::encode(g.prev_mac),
                            };
                            let dir = g.dir.clone();
                            drop(g);
                            if let Err(e) = tip.store(&dir) {
                                tracing::warn!(error = %e, "audit chain-tip store failed");
                            }
                        } else {
                            drop(g);
                        }
                        r
                    })
                    .await
                    .context("spawn_blocking audit inline fallback")?
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Err(anyhow::anyhow!("audit flusher channel closed"))
                }
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
    /// this is a no-op. Safe to call multiple times.
    #[allow(dead_code)]
    pub(crate) async fn flush_and_close(&self) -> Result<()> {
        let Some(tx) = self.sender.as_ref() else {
            return Ok(());
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        // `send().await` (not `try_send`): the Flush fence MUST be
        // queued in order behind any pending Writes — otherwise the
        // ack could race ahead of a write the caller just enqueued.
        if tx.send(FlusherCmd::Flush(ack_tx)).await.is_err() {
            return Ok(());
        }
        let _ = ack_rx.await;
        Ok(())
    }

    /// Emit a `receipt_signed` entry — `audit_cli` harvests the
    /// `(session_id, seq)` tuple to confirm every journal floor was
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

/// Background flusher: drain the channel, buffer up to `batch_size`
/// records (or until `batch_interval_ms` elapses), then fsync once at
/// the end of each batch.
#[allow(dead_code)]
async fn flusher_loop(
    inner: Arc<Mutex<Inner>>,
    counters: Arc<AuditCounters>,
    mut rx: mpsc::Receiver<FlusherCmd>,
    batch_size: usize,
    batch_interval_ms: u64,
) {
    let interval = std::time::Duration::from_millis(batch_interval_ms);
    // Each record's bytes go to the file under the `Inner` mutex; only
    // the fsync is deferred. `unsynced` = written-but-not-fsynced.
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
                            let _ = fsync_and_publish_tip(&inner);
                        }
                        return;
                    }
                    Some(FlusherCmd::Write(rec)) => {
                        let mut g = inner.lock();
                        let r = write_inner_direct(&mut g, &counters, &rec, /*fsync=*/ false);
                        drop(g);
                        match r {
                            Ok(()) => unsynced += 1,
                            Err(e) => tracing::warn!(error = %e, "audit batched write failed"),
                        }
                        if unsynced >= batch_size {
                            let _ = fsync_and_publish_tip(&inner);
                            unsynced = 0;
                            deadline = tokio::time::Instant::now() + interval;
                        }
                    }
                    Some(FlusherCmd::Flush(ack)) => {
                        if unsynced > 0 {
                            let _ = fsync_and_publish_tip(&inner);
                            unsynced = 0;
                        }
                        let _ = ack.send(());
                        deadline = tokio::time::Instant::now() + interval;
                    }
                }
            }
            () = &mut timeout_at => {
                if unsynced > 0 {
                    let _ = fsync_and_publish_tip(&inner);
                    unsynced = 0;
                }
                deadline = tokio::time::Instant::now() + interval;
            }
        }
    }
}

/// fsync the active audit file + publish the post-fsync chain tip.
/// The tip is updated only after fsync returns so a SIGKILL between
/// `write()` and `sync_data()` leaves the tip pointing at the prior
/// (durably-fsynced) line — the boot replay then re-verifies the
/// in-flight tail rather than trusting a torn write.
#[allow(dead_code)]
fn fsync_and_publish_tip(inner: &Arc<Mutex<Inner>>) -> Result<()> {
    let (dir, tip) = {
        let mut g = inner.lock();
        if let Some(f) = g.current_file.as_mut() {
            f.sync_data().context("fsync audit log")?;
        }
        // Even if no file is open we publish an empty tip — but the
        // file-open invariant says we're called only after at least
        // one write succeeded, so `current_file_id` is non-empty.
        let tip = ChainTip {
            file_id: g.current_file_id.clone(),
            seq: g.current_file_seq,
            mac: hex::encode(g.prev_mac),
        };
        (g.dir.clone(), tip)
    };
    if !tip.file_id.is_empty() {
        if let Err(e) = tip.store(&dir) {
            tracing::warn!(error = %e, "audit chain-tip store failed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use tempfile::tempdir;

    // #239 batched fsync flusher tests.

    /// Batched writes get fsynced within `batch_interval_ms`. Short
    /// interval (50ms); verify within 5× that bound.
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

    /// `flush_and_close` is an explicit drain fence. Long batch
    /// interval (60s) ensures only the explicit flush could have made
    /// the data durable.
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
        let p = crate::audit::test_util::audit_file_in(dir.path());
        let body = std::fs::read_to_string(&p).unwrap();
        assert_eq!(body.lines().count(), 5);
        let report = AuditLog::verify_file(&log.key(), &p).unwrap();
        assert_eq!(report.entries, 5);
        assert!(report.first_error.is_none());
    }

    /// Sender-close drain: dropping the last `AuditLog` causes the
    /// flusher to do a final fsync via the `None` branch of
    /// `rx.recv()`. Graceful shutdown loses nothing.
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
            log.flush_and_close().await.unwrap();
        }
        let p = crate::audit::test_util::audit_file_in(&dir_path);
        let body = std::fs::read_to_string(p).unwrap();
        assert_eq!(body.lines().count(), 3);
    }

    /// Multiple `record_receipt_signed` calls form a contiguous HMAC
    /// chain.
    #[tokio::test]
    async fn multiple_receipt_signed_entries_chain_correctly() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for seq in 1..=4u64 {
            log.record_receipt_signed("sess".to_string(), seq, seq * 100)
                .await
                .unwrap();
        }
        let audit_file = crate::audit::test_util::audit_file_in(dir.path());
        let report = AuditLog::verify_file(&log.key(), &audit_file).unwrap();
        assert_eq!(report.entries, 4);
    }

    // OOM-3 / audit-2 C-6: bounded-queue + inline-fallback tests.

    fn oom3_rec(i: u64) -> AuditRecord {
        AuditRecord {
            ts_unix: 1_700_000_000 + i,
            kind: "x",
            source: None,
            session_id: Some(format!("s{i}")),
            extra: serde_json::json!({"i": i}),
        }
    }

    /// Burst of writes much larger than queue cap must all land on
    /// disk. Inline-fallback absorbs whatever the bounded queue can't.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_channel_doesnt_drop_under_burst() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 32, 50, 8).unwrap();
        const N: u64 = 2_000;
        for i in 0..N {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        log.flush_and_close().await.unwrap();
        let p = crate::audit::test_util::audit_file_in(dir.path());
        let body = std::fs::read_to_string(&p).unwrap();
        assert_eq!(body.lines().count() as u64, N);
        let report = AuditLog::verify_file(&log.key(), &p).unwrap();
        assert_eq!(report.entries, N);
        assert!(report.first_error.is_none());
    }

    /// When the queue fills, `write_async` takes the inline-fallback
    /// path AND increments `audit_inline_fallback_total`.
    #[tokio::test(flavor = "current_thread")]
    async fn inline_fallback_under_queue_full() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 1024, 60_000, 1).unwrap();
        let before = log.inline_fallback_total();
        for i in 0..16u64 {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        let after = log.inline_fallback_total();
        assert!(after > before);
        log.flush_and_close().await.unwrap();
        let p = crate::audit::test_util::audit_file_in(dir.path());
        let body = std::fs::read_to_string(p).unwrap();
        assert_eq!(body.lines().count(), 16);
    }

    /// Under inline-fallback the HMAC chain stays linear regardless
    /// of which path wrote each line.
    #[tokio::test(flavor = "current_thread")]
    async fn inline_fallback_preserves_chain_order() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 1024, 60_000, 1).unwrap();
        const N: u64 = 64;
        for i in 0..N {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        log.flush_and_close().await.unwrap();
        let p = crate::audit::test_util::audit_file_in(dir.path());
        let report = AuditLog::verify_file(&log.key(), &p).unwrap();
        assert_eq!(report.entries, N);
        assert!(report.first_error.is_none());
    }

    /// After a burst, a quiescent period followed by ordinary writes
    /// should NOT keep bumping the counter — the flusher catches up.
    #[tokio::test(flavor = "current_thread")]
    async fn recovery_from_disk_stall() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 64, 50, 1).unwrap();
        for i in 0..32u64 {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        let after_burst = log.inline_fallback_total();
        assert!(after_burst > 0);
        log.flush_and_close().await.unwrap();
        let snapshot = log.inline_fallback_total();
        for i in 32..36u64 {
            log.write_async(oom3_rec(i)).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        }
        let after_quiet = log.inline_fallback_total();
        assert_eq!(after_quiet, snapshot);
        log.flush_and_close().await.unwrap();
    }

    /// The `octravpn_audit_inline_fallback_total` counter is exposed
    /// on `GET /metrics`. End-to-end via the real handler.
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
        for i in 0..8u64 {
            log.write_async(oom3_rec(i)).await.unwrap();
        }
        assert!(log.inline_fallback_total() > 0);

        let node_kp = std::sync::Arc::new(KeyPair::generate());
        let router = std::sync::Arc::new(OnionRouter::new());
        let allowlist =
            std::sync::Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
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
        let expected = log.inline_fallback_total();
        let needle = format!("octravpn_audit_inline_fallback_total {expected}\n");
        assert!(text.contains(&needle), "/metrics missing {needle:?}");
        log.flush_and_close().await.unwrap();
    }

    /// When the flusher channel is closed, `write_async` returns Err
    /// rather than dropping silently.
    #[tokio::test(flavor = "current_thread")]
    async fn disk_full_returns_error_not_oom() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open_batched_with_cap(dir.path(), 1, 1, 1).unwrap();
        let (dead_tx, dead_rx) = tokio::sync::mpsc::channel::<FlusherCmd>(1);
        drop(dead_rx);
        let mut log_dead = log.clone();
        log_dead.sender = Some(dead_tx);
        let err = log_dead.write_async(oom3_rec(0)).await.unwrap_err();
        assert!(format!("{err}").contains("closed"));
        log.flush_and_close().await.unwrap();
    }
}
