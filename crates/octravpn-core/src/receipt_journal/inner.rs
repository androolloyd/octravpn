//! `Inner` — the mutex-guarded core state of [`ReceiptJournal`]. Lives
//! behind an `Arc<Mutex<Inner>>` so the spawn-blocking compaction task
//! can share ownership across threads. `by_session` is always
//! authoritative: `bump` appends and then updates the map under the
//! same lock.

use std::{
    collections::BTreeMap,
    fs::File,
    path::PathBuf,
    time::Instant,
};

use crate::session::SessionId;

use super::fsync_policy::FsyncPolicy;

/// Mutex-guarded core state for [`ReceiptJournal`](super::ReceiptJournal).
#[derive(Debug)]
pub(crate) struct Inner {
    /// In-memory snapshot. Always reflects the on-disk state because
    /// the only mutator (`bump`) appends before releasing the lock.
    pub(crate) by_session: BTreeMap<SessionId, u64>,
    /// Persistent path. `None` ⇒ in-memory-only mode (test fixtures).
    pub(crate) path: Option<PathBuf>,
    /// Open append handle. `None` for in-memory mode or when the path
    /// is set but the handle has been deliberately dropped (compaction
    /// re-opens it).
    pub(crate) handle: Option<File>,
    /// Current on-disk file size in bytes (header + records). Tracked
    /// so we can decide when to auto-compact without a `metadata()`
    /// syscall per call.
    pub(crate) file_size: u64,
    /// Live durability policy.
    pub(crate) fsync_policy: FsyncPolicy,
    /// Last `sync_data` instant — only consulted under
    /// `FsyncPolicy::Periodic`.
    pub(crate) last_fsync: Instant,
    /// Auto-compaction threshold in bytes. Bumps that cross this
    /// watermark spawn an async compaction (via `compact_async`) so the
    /// hot path stays O(1). The watermark is conservative enough that
    /// compaction remains rare; an operator running near it can call
    /// `compact()` explicitly during a maintenance window.
    pub(crate) compaction_watermark: u64,
    /// `true` while a `compact_async` task is between phase 1
    /// (snapshot under lock) and phase 3 (swap under lock). Re-entrant
    /// `compact_async` calls return early when set — the in-flight
    /// compaction already covers the current state. Cleared by the
    /// swap phase (whether successful or not).
    pub(crate) compaction_inflight: bool,
}
