//! In-memory analytics indexer.
//!
//! Owns one [`BucketSeries`] per `(metric, width)` pair. Every event
//! the indexer ingests is fanned out to every retained width (1m, 5m,
//! 1h, 1d), so a single query against any width returns the same
//! sub-window sum the operator would compute by hand.
//!
//! ## Bytes-settled de-duplication
//!
//! `receipt_signed.bytes_used` is a session-scoped high-watermark, so
//! summing every receipt double-counts. The indexer tracks
//! `last_bytes_used[session_id]` and only credits the *delta* into
//! `bytes_settled`. Out-of-order receipts (a lower `bytes_used` after
//! a higher one) credit 0 — never a negative number.

use std::{
    collections::HashMap,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::Result;
use parking_lot::RwLock;

use crate::{
    audit_reader::{self, AuditFileScan},
    bucket::{BucketSeries, BucketWidth},
    event::AnalyticsEvent,
};

/// Canonical metric names. Stable strings — they appear in the
/// Prometheus exposition format and in the JSON `?metric=` query
/// parameter, so changing one is a breaking API change.
pub mod metric {
    pub const SESSIONS_OPENED: &str = "sessions_opened";
    pub const SESSIONS_CLOSED: &str = "sessions_closed";
    pub const SETTLE_CLAIMS: &str = "settle_claims";
    pub const RECEIPTS_SIGNED: &str = "receipts_signed";
    pub const PREAUTH_MINTED: &str = "preauth_minted";
    pub const PREAUTH_REDEEMED: &str = "preauth_redeemed";
    pub const SLASH_DOUBLE_SIGN: &str = "slash_double_sign";
    pub const VALIDATOR_HEALTH_PINGS: &str = "validator_health_pings";
    pub const BYTES_SETTLED: &str = "bytes_settled";
    pub const EVENTS_OTHER: &str = "events_other";

    /// All metrics in stable order — used by the Prometheus exposition
    /// to ensure the output is deterministic across scrapes.
    pub const ALL: &[&str] = &[
        SESSIONS_OPENED,
        SESSIONS_CLOSED,
        SETTLE_CLAIMS,
        RECEIPTS_SIGNED,
        PREAUTH_MINTED,
        PREAUTH_REDEEMED,
        SLASH_DOUBLE_SIGN,
        VALIDATOR_HEALTH_PINGS,
        BYTES_SETTLED,
        EVENTS_OTHER,
    ];
}

/// One file's chain-verify summary, kept on the indexer for the
/// `/analytics/health` endpoint.
#[derive(Debug, Clone, Default)]
pub struct ChainVerifyStatus {
    /// Total audit files scanned in the most recent ingest call.
    pub files: u64,
    /// Total lines that verified across all files.
    pub verified_lines: u64,
    /// First file that failed verification, if any (filename + reason).
    pub first_break: Option<(String, String)>,
}

/// In-memory state. Cheap to clone (it's `Arc<RwLock>` internally).
#[derive(Default)]
pub struct IndexerState {
    /// `metric_name -> width -> BucketSeries`.
    series: RwLock<HashMap<&'static str, HashMap<BucketWidth, BucketSeries>>>,
    /// Per-session last-credited `bytes_used`, for delta-only
    /// `bytes_settled` accounting.
    last_bytes: RwLock<HashMap<String, u64>>,
    /// Total events ingested since process start.
    total_events: AtomicU64,
    /// `ts_unix` of the most-recently ingested event. 0 = none yet.
    last_event_ts: AtomicU64,
    /// Wall-clock unix when the most-recent ingest landed. Used by
    /// `/analytics/health` to detect "indexer is stuck".
    last_ingest_wall_unix: AtomicU64,
    /// Result of the most-recent chain-verify pass.
    chain_status: RwLock<ChainVerifyStatus>,
}

impl IndexerState {
    /// Bump a counter by `delta` at the given event timestamp.
    fn bump(&self, metric: &'static str, ts_unix: u64, delta: u64) {
        if delta == 0 {
            return;
        }
        let mut guard = self.series.write();
        let per_width = guard.entry(metric).or_default();
        for w in BucketWidth::all() {
            per_width.entry(w).or_default().add(w, ts_unix, delta);
        }
    }

    /// Fold one event into the counters. Public so tests + the
    /// streaming task can drive it; the file-replay path is
    /// [`Indexer::ingest_audit_log`].
    pub fn ingest(&self, ev: &AnalyticsEvent) {
        self.total_events.fetch_add(1, Ordering::Relaxed);
        // Monotonic-only update for `last_event_ts`: late-arriving
        // events MUST NOT roll the timestamp backwards. The health
        // endpoint reads this as "freshness", so going backwards
        // would mask a stuck pipeline.
        let ts = ev.ts_unix();
        self.last_event_ts.fetch_max(ts, Ordering::Relaxed);
        self.last_ingest_wall_unix
            .store(now_unix_secs(), Ordering::Relaxed);
        match ev {
            AnalyticsEvent::SessionOpen { .. } => {
                self.bump(metric::SESSIONS_OPENED, ts, 1);
            }
            AnalyticsEvent::SessionClose { .. } => {
                self.bump(metric::SESSIONS_CLOSED, ts, 1);
            }
            AnalyticsEvent::SettleClaim { bytes_used, .. } => {
                self.bump(metric::SETTLE_CLAIMS, ts, 1);
                // `settle_claim` carries the authoritative final
                // bytes; credit it directly (no de-dup needed because
                // settles happen once per session id).
                self.bump(metric::BYTES_SETTLED, ts, *bytes_used);
            }
            AnalyticsEvent::ReceiptSigned {
                session_id,
                bytes_used,
                ..
            } => {
                self.bump(metric::RECEIPTS_SIGNED, ts, 1);
                // De-dup bytes via delta-from-last accounting.
                let mut last = self.last_bytes.write();
                let prev = last.get(session_id).copied().unwrap_or(0);
                if *bytes_used > prev {
                    self.bump(metric::BYTES_SETTLED, ts, *bytes_used - prev);
                    last.insert(session_id.clone(), *bytes_used);
                }
            }
            AnalyticsEvent::PreauthMinted { .. } => {
                self.bump(metric::PREAUTH_MINTED, ts, 1);
            }
            AnalyticsEvent::PreauthRedeemed { .. } => {
                self.bump(metric::PREAUTH_REDEEMED, ts, 1);
            }
            AnalyticsEvent::SlashDoubleSign { .. } => {
                self.bump(metric::SLASH_DOUBLE_SIGN, ts, 1);
            }
            AnalyticsEvent::ValidatorHealthPing { .. } => {
                self.bump(metric::VALIDATOR_HEALTH_PINGS, ts, 1);
            }
            AnalyticsEvent::Other { .. } => {
                self.bump(metric::EVENTS_OTHER, ts, 1);
            }
        }
    }

    /// Series for a given `(metric, width)`. Returns an empty vector
    /// when the metric was never seen.
    #[must_use]
    pub fn series(&self, metric: &str, width: BucketWidth) -> Vec<(u64, u64)> {
        self.series
            .read()
            .get(metric)
            .and_then(|m| m.get(&width))
            .map(BucketSeries::series)
            .unwrap_or_default()
    }

    /// Range-filtered series (half-open `[from, to)`).
    #[must_use]
    pub fn series_in(
        &self,
        metric: &str,
        width: BucketWidth,
        from: u64,
        to: u64,
    ) -> Vec<(u64, u64)> {
        self.series
            .read()
            .get(metric)
            .and_then(|m| m.get(&width))
            .map(|s| s.series_in(from, to))
            .unwrap_or_default()
    }

    /// Total count summed across the retention window.
    #[must_use]
    pub fn total(&self, metric: &str, width: BucketWidth) -> u64 {
        self.series
            .read()
            .get(metric)
            .and_then(|m| m.get(&width))
            .map_or(0, BucketSeries::total)
    }

    /// Number of events ingested since process start.
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }

    /// `ts_unix` of the most-recently ingested event (0 = none).
    #[must_use]
    pub fn last_event_ts(&self) -> u64 {
        self.last_event_ts.load(Ordering::Relaxed)
    }

    /// Wall-clock unix of the most-recent ingest call (0 = none).
    #[must_use]
    pub fn last_ingest_wall_unix(&self) -> u64 {
        self.last_ingest_wall_unix.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn chain_status(&self) -> ChainVerifyStatus {
        self.chain_status.read().clone()
    }
}

/// High-level orchestrator: holds an `Arc<IndexerState>` plus knows
/// how to feed it from audit files / live streams.
#[derive(Clone, Default)]
pub struct Indexer {
    pub state: std::sync::Arc<IndexerState>,
}

impl Indexer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replay a single audit file into the indexer. The chain is
    /// verified up front via [`audit_reader::verify_file`]; events
    /// extracted from verified lines are ingested. If the chain
    /// breaks mid-file, the prefix is still ingested (it's
    /// authoritative — the break is downstream of those lines) and
    /// the break is recorded in `chain_status`.
    pub fn ingest_audit_log(&self, key: &[u8; 32], path: &Path) -> Result<AuditFileScan> {
        let scan = audit_reader::verify_file(key, path)?;
        for ev in &scan.events {
            self.state.ingest(ev);
        }
        let mut cs = self.state.chain_status.write();
        cs.files += 1;
        cs.verified_lines += scan.verified_lines;
        if cs.first_break.is_none() {
            if let (Some(_l), Some(reason)) = (scan.broke_at, scan.break_reason.as_ref()) {
                cs.first_break = Some((
                    scan.path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    reason.clone(),
                ));
            }
        }
        Ok(scan)
    }

    /// Replay every `audit-YYYY-MM-DD.jsonl` in `dir` (date order).
    /// Convenience wrapper around `audit_reader::scan_dir` + per-file
    /// ingest. Suitable for boot-time backfill.
    pub fn ingest_audit_dir(&self, key: &[u8; 32], dir: &Path) -> Result<Vec<AuditFileScan>> {
        let scans = audit_reader::scan_dir(key, dir)?;
        // Re-walk through the public single-file path so the
        // chain_status bookkeeping is identical to the per-file API.
        let mut out = Vec::with_capacity(scans.len());
        for scan in &scans {
            for ev in &scan.events {
                self.state.ingest(ev);
            }
            let mut cs = self.state.chain_status.write();
            cs.files += 1;
            cs.verified_lines += scan.verified_lines;
            if cs.first_break.is_none() {
                if let (Some(_l), Some(reason)) = (scan.broke_at, scan.break_reason.as_ref()) {
                    cs.first_break = Some((
                        scan.path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        reason.clone(),
                    ));
                }
            }
            out.push(scan.clone());
        }
        Ok(out)
    }

    /// Spawn a tokio task that ingests live events from a tokio mpsc
    /// channel until all senders are dropped. Returns the handle so
    /// the caller (the node hub) can shut it down cleanly on Drop.
    pub fn spawn_streaming(
        &self,
        mut rx: tokio::sync::mpsc::Receiver<AnalyticsEvent>,
    ) -> tokio::task::JoinHandle<()> {
        let state = self.state.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                state.ingest(&ev);
            }
        })
    }

    /// Ingest a batch of events synchronously. Used by unit tests +
    /// the e2e fixture test in `tests/`.
    pub fn ingest_batch(&self, evs: impl IntoIterator<Item = AnalyticsEvent>) {
        for ev in evs {
            self.state.ingest(&ev);
        }
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_session_open_bumps_counter_at_every_width() {
        let idx = Indexer::new();
        idx.state.ingest(&AnalyticsEvent::SessionOpen {
            ts_unix: 100,
            session_id: "a".into(),
        });
        for w in BucketWidth::all() {
            assert_eq!(idx.state.total(metric::SESSIONS_OPENED, w), 1);
        }
        assert_eq!(idx.state.total_events(), 1);
        assert_eq!(idx.state.last_event_ts(), 100);
    }

    #[test]
    fn bytes_settled_credits_only_the_delta() {
        let idx = Indexer::new();
        idx.state.ingest(&AnalyticsEvent::ReceiptSigned {
            ts_unix: 100,
            session_id: "s".into(),
            seq: 1,
            bytes_used: 500,
        });
        idx.state.ingest(&AnalyticsEvent::ReceiptSigned {
            ts_unix: 110,
            session_id: "s".into(),
            seq: 2,
            bytes_used: 1500,
        });
        // First receipt credits 500; second credits 1000 (1500 - 500).
        assert_eq!(
            idx.state
                .total(metric::BYTES_SETTLED, BucketWidth::OneMinute),
            1500
        );
        assert_eq!(
            idx.state
                .total(metric::RECEIPTS_SIGNED, BucketWidth::OneMinute),
            2
        );
    }

    #[test]
    fn bytes_settled_ignores_out_of_order_receipt() {
        let idx = Indexer::new();
        idx.state.ingest(&AnalyticsEvent::ReceiptSigned {
            ts_unix: 100,
            session_id: "s".into(),
            seq: 2,
            bytes_used: 2000,
        });
        // Earlier receipt arrives later with a lower watermark.
        idx.state.ingest(&AnalyticsEvent::ReceiptSigned {
            ts_unix: 110,
            session_id: "s".into(),
            seq: 1,
            bytes_used: 500,
        });
        assert_eq!(
            idx.state
                .total(metric::BYTES_SETTLED, BucketWidth::OneMinute),
            2000
        );
    }

    #[test]
    fn late_arriving_event_lands_in_correct_bucket() {
        let idx = Indexer::new();
        idx.state.ingest(&AnalyticsEvent::SessionOpen {
            ts_unix: 600,
            session_id: "a".into(),
        });
        idx.state.ingest(&AnalyticsEvent::SessionOpen {
            ts_unix: 700,
            session_id: "b".into(),
        });
        // Late event ts=30 falls in the [0, 60) 1m bucket.
        idx.state.ingest(&AnalyticsEvent::SessionOpen {
            ts_unix: 30,
            session_id: "c".into(),
        });
        let s = idx
            .state
            .series(metric::SESSIONS_OPENED, BucketWidth::OneMinute);
        // Three buckets: (0, 1), (600, 1), (660, 1).
        assert_eq!(s.len(), 3);
        assert_eq!(s[0], (0, 1));
        // last_event_ts must NOT roll backwards.
        assert_eq!(idx.state.last_event_ts(), 700);
    }

    #[test]
    fn other_kind_lands_in_events_other_bucket() {
        let idx = Indexer::new();
        idx.state.ingest(&AnalyticsEvent::Other {
            ts_unix: 1,
            kind: "future_event".into(),
        });
        assert_eq!(
            idx.state.total(metric::EVENTS_OTHER, BucketWidth::OneDay),
            1
        );
    }
}
