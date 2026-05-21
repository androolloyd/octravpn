//! Owned mutable state shared between the sync-write path and the
//! batched-fsync flusher task via `Arc<parking_lot::Mutex<Inner>>`.
//! Neither path holds the lock across `.await`. The `AuditCounters`
//! sit outside the mutex so the `/metrics` scrape path can read them
//! lock-free even while the flusher is blocked on a disk stall. See
//! `audit/README.md` for the threading model + lock-order rules.

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;

use super::rotation::RotationCfg;

/// All mutable state owned by the audit log: directory layout, today's
/// open file handle, the HMAC chain key, and the running MAC.
///
/// Reset semantics: when `current_date` advances, the file is reopened
/// and `prev_mac` resets to `[0u8; 32]` so each daily file is its own
/// independent chain (verifiable in isolation by the CLI).
///
/// Size-based rotation (Perf-6) is **mid-day**: when the active file
/// would exceed `rotation.max_file_bytes` the writer closes it and
/// opens a sequenced sibling (`audit-YYYY-MM-DD-001.jsonl`). Unlike
/// the date roll-over, mid-day rotation carries the running `prev_mac`
/// across files so the chain stays linear within a day.
pub(crate) struct Inner {
    pub(crate) dir: PathBuf,
    pub(crate) current_date: String,
    pub(crate) current_file: Option<std::fs::File>,
    /// Basename of the currently-open file (e.g.
    /// `audit-2026-05-21-003.jsonl`). `String::new()` while no file
    /// is open.
    pub(crate) current_file_id: String,
    /// Bytes already on disk in `current_file` (after the most recent
    /// successful write). Used to decide when to rotate without
    /// hitting `metadata()` on the hot path.
    pub(crate) current_file_size: u64,
    /// 1-indexed count of lines written into `current_file`. Combined
    /// with `current_file_id` + the running `prev_mac` it forms the
    /// chain-tip the boot replay uses to skip the verified prefix.
    pub(crate) current_file_seq: u64,
    /// HMAC key persisted at `<dir>/.audit.key`.
    pub(crate) key: [u8; 32],
    /// Running MAC chain. Reset to zeros at midnight (the prev-mac for
    /// the first line of a new day file is `[0u8; 32]`, hex-encoded).
    /// On mid-day rotation it is carried forward unchanged so file
    /// N+1 chains off file N's last MAC.
    pub(crate) prev_mac: [u8; 32],
    /// Rotation + boot-replay config. Read on every write to decide
    /// whether to roll over.
    pub(crate) rotation: RotationCfg,
}

/// Process-lifetime counters bumped from the audit hot path. Sits
/// outside `Inner` rather than inside it so the `/metrics` scrape
/// path can read these without acquiring the (potentially
/// disk-stalled) `Inner` mutex — atomics are lock-free by design.
///
/// Today: `inline_fallback_total` + `rotations_total`. The bounded
/// flusher channel (see `batched::DEFAULT_BATCH_QUEUE_CAP`) drops
/// `try_send`s to the inline sync-fsync path when full. Every such
/// fallback bumps the fallback counter — non-zero growth rate is the
/// disk-stall signal. `rotations_total` bumps once per size-triggered
/// roll-over (NOT once per date roll-over — that's day-driven, not
/// load-driven).
#[derive(Default)]
pub(crate) struct AuditCounters {
    pub(crate) inline_fallback_total: AtomicU64,
    pub(crate) rotations_total: AtomicU64,
}
