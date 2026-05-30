//! Append-only audit log — tamper-evident JSONL, one file per UTC
//! day, HMAC-SHA256-chained line by line. Submodules: `inner` (owned
//! state + counters), `log` (sync write + `AuditRecord` + envelope),
//! `batched` (async flusher + bounded queue + inline fallback),
//! `chain` (pure HMAC + key + date math), `rotation` (Perf-6 size
//! rotation + chain-tip persistence + ring-buffer eviction),
//! `verify` (offline file verifier — full + skip-to-tip modes),
//! `tap` (analytics side-channel). See `audit/README.md` for the
//! threading model, durability ladder, and the on-disk format
//! contract.

use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;

mod batched;
mod chain;
mod inner;
mod log;
mod rotation;
mod tap;
mod verify;

#[cfg(test)]
mod test_util;

pub(crate) use batched::{DEFAULT_BATCH_INTERVAL_MS, DEFAULT_BATCH_QUEUE_CAP, DEFAULT_BATCH_SIZE};
pub(crate) use chain::{chain_step, days_to_ymd, resolve_hmac_key, HmacKeyError};
pub(crate) use log::AuditRecord;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use rotation::ChainTip;
pub(crate) use rotation::{
    BootReplayMode, RotationCfg, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_FILE_COUNT,
};
pub(crate) use verify::FileVerifyReport;

use batched::FlusherCmd;
use inner::{AuditCounters, Inner};

/// Cloneable handle. Every clone shares the same file handle + MAC
/// chain state; concurrent `write()` calls serialise under the mutex.
#[derive(Clone)]
pub(crate) struct AuditLog {
    inner: Arc<Mutex<Inner>>,
    /// Process-lifetime counters (lock-free atomics). Readable from
    /// `/metrics` even while the flusher is blocked on a disk stall.
    counters: Arc<AuditCounters>,
    /// `Some` in batched mode: a bounded sender into the flusher task
    /// ([`DEFAULT_BATCH_QUEUE_CAP`] slots). When full, `write_async`
    /// falls back to inline sync-fsync. When the last sender drops,
    /// the flusher exits after a final fsync.
    sender: Option<mpsc::Sender<FlusherCmd>>,
    /// Optional analytics-indexer tap (task #231). See `tap.rs`.
    analytics_tap: Option<mpsc::UnboundedSender<octravpn_analytics::AnalyticsEvent>>,
}

impl AuditLog {
    /// Process-lifetime count of writes that fell back to inline
    /// sync-fsync because the batched-flusher queue was full. A
    /// non-zero growth rate signals disk stall. Lock-free.
    pub(crate) fn inline_fallback_total(&self) -> u64 {
        self.counters
            .inline_fallback_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Process-lifetime count of size-triggered audit-log rotations
    /// (Perf-6). Excludes date roll-overs at UTC midnight (those are
    /// time-driven, not load-driven). Lock-free.
    #[allow(dead_code)]
    pub(crate) fn rotations_total(&self) -> u64 {
        self.counters
            .rotations_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
