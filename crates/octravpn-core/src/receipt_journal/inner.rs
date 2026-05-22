//! `Inner` — the mutex-guarded core state of [`ReceiptJournal`]. Lives
//! behind an `Arc<Mutex<Inner>>` so the spawn-blocking compaction task
//! can share ownership across threads.
//!
//! Perf-8 (audit-8 OOM-1): `by_session` is no longer an unbounded
//! cumulative mirror — it is a **cache** of the durable on-disk floor
//! capped at [`max_in_mem_sessions`](Self::max_in_mem_sessions) entries
//! and evicted after
//! [`session_in_mem_ttl`](Self::session_in_mem_ttl) of idleness. The
//! on-disk journal is the source of truth for the seq-monotonic
//! invariant; any `bump` that hits an evicted entry resurrects the
//! floor from disk before checking monotonicity (see
//! `super::bump_with_eviction`).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fs::File,
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc},
    time::{Duration, Instant},
};

use crate::session::SessionId;

use super::fsync_policy::{
    FsyncPolicy, DEFAULT_MAX_IN_MEM_SESSIONS, DEFAULT_RECENTLY_EVICTED_CAP,
    DEFAULT_SESSION_IN_MEM_TTL,
};

/// Hot-path counters surfaced via `/metrics` (Perf-8). Shared between
/// [`Inner`] and the Prometheus handler via an `Arc`; the gauge/counter
/// types are `AtomicU64` so the scrape never blocks on the journal
/// lock.
#[derive(Debug, Default)]
pub(crate) struct JournalMetrics {
    /// Gauge: current number of entries cached in the in-mem mirror.
    /// Updated under the journal lock on every bump/eviction/sweep.
    /// Exposed as `octravpn_receipt_journal_in_mem_sessions`.
    pub(crate) in_mem_sessions: AtomicU64,
    /// Counter: total entries evicted from the in-mem mirror over the
    /// process lifetime (cap-overflow + TTL sweeps combined). Exposed as
    /// `octravpn_receipt_journal_evictions_total`.
    pub(crate) evictions_total: AtomicU64,
    /// Counter: bumps whose session-id was not in the in-mem mirror
    /// and therefore forced a disk read to recover the floor. A steady
    /// non-zero rate means the working set exceeds
    /// `max_in_mem_sessions` — operator should raise the cap. Exposed
    /// as `octravpn_receipt_journal_disk_resurrect_total`.
    pub(crate) disk_resurrect_total: AtomicU64,
}

/// Mutex-guarded core state for [`ReceiptJournal`](super::ReceiptJournal).
#[derive(Debug)]
pub(crate) struct Inner {
    /// In-memory cache of `(session_id → last_signed_seq)`. Bounded by
    /// `max_in_mem_sessions`; entries idle for `session_in_mem_ttl` are
    /// evicted by the periodic sweeper. The on-disk journal is the
    /// authoritative source — a miss here triggers a disk-resurrect
    /// (see `super::bump_with_eviction`).
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

    // ----------------------------------------------------------------
    // Perf-8: in-mem mirror eviction state.
    // ----------------------------------------------------------------
    /// Hard cap on `by_session` size. Cap overflow evicts the LRU
    /// entry on the hot bump path. Default
    /// [`DEFAULT_MAX_IN_MEM_SESSIONS`].
    pub(crate) max_in_mem_sessions: usize,
    /// TTL after which an idle entry is evicted by the periodic
    /// sweeper. Default [`DEFAULT_SESSION_IN_MEM_TTL`].
    pub(crate) session_in_mem_ttl: Duration,
    /// Per-entry `Instant` of the most recent bump (or
    /// resurrect-from-disk). Used by both the LRU eviction path
    /// (cap overflow) and the TTL sweep. Kept in lock-step with
    /// `by_session`: every insert into `by_session` also inserts here,
    /// every eviction removes from both.
    pub(crate) last_seen: HashMap<SessionId, Instant>,
    /// Auxiliary recency index: `(last_seen, session_id) → ()` ordered
    /// by time, so the LRU pop is `O(log n)` (`pop_first`). The
    /// session_id tiebreak keeps the entries unique even when two
    /// bumps land on the same `Instant`. This costs an extra
    /// `BTreeSet` insert + remove per bump (~50 ns on warm caches),
    /// which is dominated by the journal fsync on the hot path. See
    /// the README's "Perf-8 LRU bookkeeping" note.
    pub(crate) lru_index: BTreeSet<(Instant, SessionId)>,
    /// "Recently evicted" LRU: session_ids that have been evicted from
    /// `by_session` since the last bump landed for them. The hot path
    /// consults this to skip the redundant disk-resurrect when the
    /// same session was bumped, evicted, and bumped again within a
    /// short window (flapping). Bounded at
    /// [`DEFAULT_RECENTLY_EVICTED_CAP`] entries (~64 KB) so the LRU
    /// can never itself become an OOM vector. Stored as a deque so
    /// FIFO insertion-order eviction is O(1).
    pub(crate) recently_evicted: VecDeque<SessionId>,
    /// O(1) membership probe paired with `recently_evicted`.
    pub(crate) recently_evicted_set: std::collections::HashSet<SessionId>,
    /// Perf-8: tracks whether any eviction has happened since the
    /// last compaction. Phase 3a of the async compaction worker
    /// reads it: when `false`, the existing in-mem delta computation
    /// is sufficient (no session was evicted during phase 2, so all
    /// post-snapshot bumps are visible in `by_session`); when `true`,
    /// phase 3a must re-read the live journal under the lock to
    /// capture deltas for evicted sessions. Reset by the compaction
    /// swap phase. Bumped by `record_eviction`.
    pub(crate) evictions_since_compaction: bool,
    /// Hot-path counter surface (Perf-8). Wrapped in an `Arc` so the
    /// `/metrics` handler can read it without taking the journal
    /// lock — it's all `AtomicU64`.
    pub(crate) metrics: Arc<JournalMetrics>,
}

/// Eviction state tuple for a newly-opened journal: (last-seen map,
/// LRU index, recently-evicted FIFO, recently-evicted membership set).
/// Aliased so the constructor signature isn't itself a clippy lint.
pub(crate) type FreshEvictionState = (
    HashMap<SessionId, Instant>,
    BTreeSet<(Instant, SessionId)>,
    VecDeque<SessionId>,
    std::collections::HashSet<SessionId>,
);

impl Inner {
    /// Default eviction state for a newly-opened journal. Centralised
    /// so `ReceiptJournal::open` and `ReceiptJournal::in_memory` build
    /// identical inner state — Perf-8 must not introduce in-memory vs
    /// persistent skew.
    pub(crate) fn fresh_eviction_state() -> FreshEvictionState {
        (
            HashMap::new(),
            BTreeSet::new(),
            VecDeque::with_capacity(DEFAULT_RECENTLY_EVICTED_CAP),
            std::collections::HashSet::with_capacity(DEFAULT_RECENTLY_EVICTED_CAP),
        )
    }

    /// Default `max_in_mem_sessions` for a newly-opened journal.
    pub(crate) const fn default_max_in_mem_sessions() -> usize {
        DEFAULT_MAX_IN_MEM_SESSIONS
    }

    /// Default `session_in_mem_ttl` for a newly-opened journal.
    pub(crate) const fn default_session_in_mem_ttl() -> Duration {
        DEFAULT_SESSION_IN_MEM_TTL
    }

    /// Touch a session's recency: bring it to the head of the LRU and
    /// reset its TTL clock. The caller holds the lock and is
    /// responsible for ensuring `by_session` contains `session_id` —
    /// this only updates the auxiliary indices. Returns `true` if the
    /// recency was updated (a stale entry existed) and `false` for the
    /// first-touch path (no prior entry).
    pub(crate) fn touch_recency(&mut self, session_id: &SessionId, now: Instant) -> bool {
        // Pull any existing recency entry so the LRU index never holds
        // a stale `(Instant, SessionId)` tuple after a re-bump.
        let prev = self.last_seen.insert(session_id.clone(), now);
        if let Some(p) = prev {
            self.lru_index.remove(&(p, session_id.clone()));
        }
        self.lru_index.insert((now, session_id.clone()));
        // Bumping a session clears it from the "recently evicted" LRU
        // — it's back in memory, no need to keep the dampener entry
        // around.
        if self.recently_evicted_set.remove(session_id) {
            // O(n) lookup in the deque is fine here: the deque is
            // bounded at DEFAULT_RECENTLY_EVICTED_CAP = 1024 and the
            // common case (no flapping) hits the early-out above.
            if let Some(pos) = self.recently_evicted.iter().position(|s| s == session_id) {
                self.recently_evicted.remove(pos);
            }
        }
        prev.is_some()
    }

    /// Record an eviction in the auxiliary structures. Caller is
    /// responsible for removing the entry from `by_session`. Updates
    /// the metrics gauge + counter atomically.
    pub(crate) fn record_eviction(&mut self, session_id: &SessionId) {
        use std::sync::atomic::Ordering;
        if let Some(seen) = self.last_seen.remove(session_id) {
            self.lru_index.remove(&(seen, session_id.clone()));
        }
        // FIFO ring: push to back, pop oldest from the front when at
        // capacity. The set mirrors the deque exactly.
        if self.recently_evicted_set.insert(session_id.clone()) {
            self.recently_evicted.push_back(session_id.clone());
            while self.recently_evicted.len() > DEFAULT_RECENTLY_EVICTED_CAP {
                if let Some(old) = self.recently_evicted.pop_front() {
                    self.recently_evicted_set.remove(&old);
                }
            }
        }
        self.metrics.evictions_total.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .in_mem_sessions
            .store(self.by_session.len() as u64, Ordering::Relaxed);
        // Mark for the next compaction so phase 3a knows to
        // disk-merge.
        self.evictions_since_compaction = true;
    }

    /// Update the in-mem-sessions gauge to match `by_session.len()`.
    /// Called after every mutation that the eviction-record path
    /// didn't already update.
    pub(crate) fn update_gauge(&self) {
        use std::sync::atomic::Ordering;
        self.metrics
            .in_mem_sessions
            .store(self.by_session.len() as u64, Ordering::Relaxed);
    }
}
