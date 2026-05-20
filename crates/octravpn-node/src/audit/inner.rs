//! Owned mutable state shared between the sync-write path and the
//! batched-fsync flusher task via `Arc<parking_lot::Mutex<Inner>>`.
//! Neither path holds the lock across `.await`. The `AuditCounters`
//! sit outside the mutex so the `/metrics` scrape path can read them
//! lock-free even while the flusher is blocked on a disk stall. See
//! `audit/README.md` for the threading model + lock-order rules.

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;

/// All mutable state owned by the audit log: directory layout, today's
/// open file handle, the HMAC chain key, and the running MAC.
///
/// Reset semantics: when `current_date` advances, the file is reopened
/// and `prev_mac` resets to `[0u8; 32]` so each daily file is its own
/// independent chain (verifiable in isolation by the CLI).
pub(crate) struct Inner {
    pub(crate) dir: PathBuf,
    pub(crate) current_date: String,
    pub(crate) current_file: Option<std::fs::File>,
    /// HMAC key persisted at `<dir>/.audit.key`.
    pub(crate) key: [u8; 32],
    /// Running MAC chain. Reset at midnight (the prev-mac for the
    /// first line of a new day file is `[0u8; 32]`, hex-encoded).
    pub(crate) prev_mac: [u8; 32],
}

/// Process-lifetime counters bumped from the audit hot path. Sits
/// outside `Inner` rather than inside it so the `/metrics` scrape
/// path can read these without acquiring the (potentially
/// disk-stalled) `Inner` mutex — atomics are lock-free by design.
///
/// Today: `inline_fallback_total`. The bounded flusher channel
/// (see `batched::DEFAULT_BATCH_QUEUE_CAP`) drops `try_send`s to the
/// inline sync-fsync path when full. Every such fallback bumps this
/// counter — non-zero growth rate is the disk-stall signal.
#[derive(Default)]
pub(crate) struct AuditCounters {
    pub(crate) inline_fallback_total: AtomicU64,
}
