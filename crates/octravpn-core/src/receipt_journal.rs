//! Persistent per-session receipt-sequence floor.
//!
//! Fixes threat model items P1-8 and P1-9 (`docs/v2-threat-model.md`).
//!
//! ## Problem
//!
//! `ControlSession.last_seq` lives in a `BoundedMap` whose state is
//! lost on daemon restart. An attacker (or an OOM-killer, or a transient
//! segfault) that forces the node to restart mid-session would then
//! see the node sign a *fresh* `seq=K' < K_previously_signed` receipt
//! at a different `bytes_used`. Two distinct receipts for the same
//! `(session_id, seq)` under the operator's receipt-signing pubkey are
//! exactly what `slash_double_sign` (program/main-v2.aml:382-418) needs
//! to burn the operator's bond — i.e. an honest operator loses money
//! from a forced restart.
//!
//! ## Fix
//!
//! Every receipt-signing decision is gated on a persistent floor
//! `journal[session_id]`. The flow is:
//!
//! 1. Acquire the journal mutex.
//! 2. Load `prev = journal.get(session_id).unwrap_or(0)`.
//! 3. Compute the seq we want to sign at; the caller computes
//!    `next = max(in_mem_last_seq, prev) + 1`.
//! 4. Bump `journal[session_id] = next`.
//! 5. Append the new record + (per policy) fsync.
//! 6. Release the mutex.
//! 7. Sign the receipt.
//!
//! Step 5 is what makes the fix work: after `sync_data` returns, the
//! on-disk journal records the highest seq we have ever committed to
//! signing for this session. A crash *before* step 5 means we never
//! signed anything; a crash *after* means the operator might have
//! signed but not transmitted — fine, because the floor is still
//! recorded and the next call will skip past it.
//!
//! ## File format (v1 — append-only)
//!
//! The original v0 format (`OCRJ1\0\0\0` magic, `BTreeMap` snapshot)
//! rewrote the entire file on every bump — O(N) bytes per write,
//! synchronous fsync, single mutex serialising every receipt. At 10k
//! sessions that's ~400 KB written and fsync'd per receipt. The new
//! v1 format is append-only:
//!
//! ```text
//!   "OCRJ2\0\0\0"        (8 bytes — magic + version)
//!   record × N
//! ```
//!
//! Each record:
//!
//! ```text
//!   [session_id: 32B][seq: u64 BE][checksum: u32 BE]
//! ```
//!
//! `checksum = crc32_ieee(session_id || seq_be)`. A truncated tail (the
//! last partial record after a crash mid-write) is detected and ignored
//! on replay — the floor advances only for fully-written records. The
//! in-memory `BTreeMap<SessionId, u64>` mirrors the on-disk authoritative
//! state and is rebuilt by replaying the file on open.
//!
//! Compaction: the journal supports manual `compact()` (synchronous —
//! used by tests and explicit maintenance windows) and `compact_async()`
//! (the production hot-path: rewrites the snapshot off-thread, then
//! atomically swaps the file in place while holding the journal lock for
//! only the brief rename + delta-replay step). Compaction rewrites a
//! snapshot of the live map atomically (tempfile + rename + fsync) and
//! replaces the journal file in place. The append-only invariant is
//! preserved across compactions (the rewritten file is itself a sequence
//! of records, just one per live entry).
//!
//! ### Async compaction snapshot/swap protocol
//!
//! At mainnet receipt rates a 10 MB synchronous compaction blocks every
//! `bump()` for hundreds of ms — unacceptable. `compact_async()` splits
//! the work into three phases:
//!
//! 1. **Snapshot under lock** (cheap, O(N) memory clone): clone the
//!    in-memory `by_session` map, mark `compaction_inflight = true`.
//!    Drop the lock.
//! 2. **Off-lock write** (the slow part, runs on a `spawn_blocking`
//!    tokio task): write the snapshot to a sibling tempfile
//!    `<journal>.compacting` in v1 format, `sync_all` it. No journal
//!    lock is held — `bump()` continues to append to the live file.
//! 3. **Atomic swap under lock** (cheap, bounded by the number of bumps
//!    that landed during phase 2): re-acquire the journal lock, drop
//!    the live append handle, `rename(tempfile, journal_path)` (atomic
//!    on Unix; replaces the destination inode), reopen the append
//!    handle on the new file, then write the **delta** — every entry
//!    `(id, seq)` in the current in-memory map whose `seq` is strictly
//!    greater than the snapshot's value for that `id`, plus any
//!    sessions that didn't exist in the snapshot. fsync. Clear the
//!    `compaction_inflight` flag.
//!
//! **Atomicity proof.** The in-memory `by_session` map is always
//! authoritative — `bump()` updates it under the lock after the append,
//! so it always reflects the set of `(id, seq)` pairs the operator has
//! committed to signing. The swap step preserves the invariant
//! "file == in-mem map" by replacing the file inode with the snapshot
//! and appending the delta = (current in-mem) − (snapshot) under the
//! same lock that any concurrent `bump` would need to acquire. After
//! step 3 the on-disk file is exactly the v1 encoding of the live
//! in-mem map at swap time. `rename(2)` is atomic on Unix (and the
//! tempfile lives in the same directory as the journal so it's the
//! same filesystem — POSIX guarantees atomicity); any open file
//! descriptor on the old inode is invalidated for our purposes by us
//! having dropped the handle before the rename.
//!
//! **Compaction-during-compaction.** If `compact_async()` is called
//! while one is already in flight, the second call returns immediately
//! with a no-op JoinHandle. This is intentional: the in-flight
//! compaction is already writing a strictly-recent snapshot, and the
//! swap-phase delta-replay will pick up any further bumps that landed
//! before the swap completes. Stacking a second compaction would only
//! add I/O for no invariant gain.
//!
//! **Crash-during-compaction.** The tempfile is written with a
//! deterministic suffix (`<journal>.compacting`). If the process
//! crashes between phase 2 and phase 3, the tempfile is left on disk
//! but the journal_path still contains the pre-compaction file, which
//! is consistent. `open()` detects the orphan and deletes it before
//! opening the journal — the live journal is authoritative and the
//! tempfile contents are a strict subset of it (the snapshot).
//!
//! ## Fsync policy
//!
//! `FsyncPolicy::EveryWrite` (default) calls `sync_data` after every
//! append — durable at the cost of one fsync round-trip per receipt.
//! `FsyncPolicy::Periodic(Duration)` defers `sync_data` to the
//! configured interval; the OS write buffer still receives every append
//! immediately. Throughput-mode for environments where the operator
//! accepts a bounded loss window across a crash.
//!
//! ## Backward compatibility
//!
//! On `open`, the file magic is inspected. A v0 (`OCRJ1`) file is read
//! once, every entry replayed into the new in-memory map, then a fresh
//! v1 journal is written atomically over the same path. The v0 → v1
//! migration is a one-shot cost paid on the first boot after this
//! change.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use tokio::task::JoinHandle;

use crate::session::SessionId;

/// Suffix used for the in-progress async compaction tempfile. We use a
/// deterministic name so a crash mid-compaction leaves a single,
/// recognisable orphan that `open()` can scrub before re-opening the
/// authoritative journal file.
const COMPACTING_SUFFIX: &str = ".compacting";

/// Append-only v1 journal magic.
const MAGIC_V1: &[u8; 8] = b"OCRJ2\0\0\0";
/// Legacy v0 (snapshot) journal magic — read for migration only.
const MAGIC_V0: &[u8; 8] = b"OCRJ1\0\0\0";
const RECORD_SIZE: usize = 32 + 8 + 4;
const V0_ENTRY_SIZE: usize = 32 + 8;
/// Compaction watermark: rewrite the journal once it grows past this
/// many bytes. 10 MB ≈ 240k records at v1 (44 B/record), well above any
/// realistic tailnet's live session count.
pub const DEFAULT_COMPACTION_WATERMARK: u64 = 10 * 1024 * 1024;

/// Durability policy for `bump`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FsyncPolicy {
    /// `sync_data` after every append. Durable; slow.
    #[default]
    EveryWrite,
    /// `sync_data` only when the configured interval has elapsed since
    /// the last fsync. Bounded loss window across crash = `Duration`.
    /// The OS write buffer still receives every append immediately
    /// (an `append`-mode `File::write_all` doesn't buffer in user
    /// space), so a process crash without an OS crash still preserves
    /// every record.
    Periodic(Duration),
}

/// Persistent floor for `(session_id → last_signed_seq)`.
///
/// The state lives behind an `Arc<Mutex<Inner>>` so async compaction
/// tasks can share ownership across threads. `ReceiptJournal` is not
/// itself `Clone` (the daemon owns one), but the inner is shared with
/// the spawned-blocking compaction worker.
#[derive(Debug)]
pub struct ReceiptJournal {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    /// In-memory snapshot. Always reflects the on-disk state because
    /// the only mutator (`bump`) appends before releasing the lock.
    by_session: BTreeMap<SessionId, u64>,
    /// Persistent path. `None` ⇒ in-memory-only mode (test fixtures).
    path: Option<PathBuf>,
    /// Open append handle. `None` for in-memory mode or when the path
    /// is set but the handle has been deliberately dropped (compaction
    /// re-opens it).
    handle: Option<File>,
    /// Current on-disk file size in bytes (header + records). Tracked
    /// so we can decide when to auto-compact without a `metadata()`
    /// syscall per call.
    file_size: u64,
    /// Live durability policy.
    fsync_policy: FsyncPolicy,
    /// Last `sync_data` instant — only consulted under
    /// `FsyncPolicy::Periodic`.
    last_fsync: Instant,
    /// Auto-compaction threshold in bytes. Bumps that cross this
    /// watermark spawn an async compaction (via `compact_async`) so the
    /// hot path stays O(1). The watermark is conservative enough that
    /// compaction remains rare; an operator running near it can call
    /// `compact()` explicitly during a maintenance window.
    compaction_watermark: u64,
    /// `true` while a `compact_async` task is between phase 1
    /// (snapshot under lock) and phase 3 (swap under lock). Re-entrant
    /// `compact_async` calls return early when set — the in-flight
    /// compaction already covers the current state. Cleared by the
    /// swap phase (whether successful or not).
    compaction_inflight: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad journal magic at {path} — refusing to clobber an unrelated file")]
    BadMagic { path: String },
    #[error("truncated journal at {path}: {detail}")]
    Truncated { path: String, detail: String },
    #[error("checksum mismatch in journal at {path} at offset {offset}")]
    ChecksumMismatch { path: String, offset: u64 },
    /// The caller's proposed `seq` does not exceed the on-disk floor.
    /// The threat model wants the daemon to surface this as a hard
    /// refusal — the alternative is silent double-signing.
    #[error("seq {proposed} <= journal floor {floor} for session {session}")]
    SeqNotMonotonic {
        session: String,
        floor: u64,
        proposed: u64,
    },
}

pub type JournalResult<T> = std::result::Result<T, JournalError>;

impl ReceiptJournal {
    /// Open or initialise a journal at `path`. If the file does not
    /// exist, an empty journal is returned (the file is created on
    /// the first `bump`). Caller must hold the journal for the life of
    /// the daemon — there's no concurrency-safe way to share a single
    /// path between multiple processes (file locks would be brittle).
    ///
    /// If `path` already exists and starts with the v0 (`OCRJ1`) magic,
    /// the file is migrated in place: every v0 entry is read, the new
    /// v1 journal is written atomically over the same path, then the
    /// fresh v1 file is opened in append mode.
    pub fn open(path: impl Into<PathBuf>) -> JournalResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let (by_session, needs_migration) = if path.exists() {
            let raw = fs::read(&path)?;
            replay_any(&raw, &path)?
        } else {
            (BTreeMap::new(), false)
        };

        if needs_migration {
            // One-shot v0 → v1 rewrite. After this returns the path
            // holds a fresh v1 file containing one record per live
            // entry; auditors can replay it without ever seeing v0
            // again.
            write_v1_snapshot(&path, &by_session)?;
        }

        // Scrub any orphan async-compaction tempfile left behind by a
        // crash between snapshot-write and atomic-swap. The live
        // journal file is the authoritative state — the tempfile is by
        // construction a strict subset (the snapshot), so removing it
        // is invariant-preserving. We tolerate failure here (best
        // effort): if the unlink fails, the next `compact_async` will
        // overwrite it.
        let compacting_path = compacting_tempfile_path(&path);
        if compacting_path.exists() {
            let _ = fs::remove_file(&compacting_path);
        }

        // Ensure the file exists with the v1 header so the append
        // handle below sees a well-formed file. `replay_any` has
        // already validated any pre-existing content.
        ensure_v1_header(&path)?;
        let handle = OpenOptions::new().append(true).read(true).open(&path)?;
        let file_size = handle.metadata()?.len();

        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                by_session,
                path: Some(path),
                handle: Some(handle),
                file_size,
                fsync_policy: FsyncPolicy::default(),
                last_fsync: Instant::now(),
                compaction_watermark: DEFAULT_COMPACTION_WATERMARK,
                compaction_inflight: false,
            })),
        })
    }

    /// In-memory journal — for tests / control-plane unit harness.
    /// Equivalent to `open()` on a path that's never written.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                by_session: BTreeMap::new(),
                path: None,
                handle: None,
                file_size: 0,
                fsync_policy: FsyncPolicy::default(),
                last_fsync: Instant::now(),
                compaction_watermark: DEFAULT_COMPACTION_WATERMARK,
                compaction_inflight: false,
            })),
        }
    }

    /// Swap the durability policy. `EveryWrite` is the default and
    /// matches the original v0 behaviour; `Periodic` defers fsyncs to
    /// the configured interval. Throughput-mode for operators who
    /// accept a bounded loss window.
    pub fn set_fsync_policy(&self, policy: FsyncPolicy) {
        self.inner.lock().fsync_policy = policy;
    }

    /// Configure the auto-compaction watermark. Mainly useful in tests
    /// (so they don't have to write 10 MB to trigger compaction); in
    /// production the default is the right call.
    pub fn set_compaction_watermark(&self, bytes: u64) {
        self.inner.lock().compaction_watermark = bytes;
    }

    /// Return the persistent floor for `session_id`. Used by the
    /// control plane to compute `next_seq = max(in_mem, journal_floor)
    /// + 1`. Returns 0 if the session has never been seen.
    pub fn floor(&self, session_id: &SessionId) -> u64 {
        let g = self.inner.lock();
        g.by_session.get(session_id).copied().unwrap_or(0)
    }

    /// Alias for `floor`. Matches the naming used in the v2 threat
    /// model doc (where the per-session floor is referred to as the
    /// "read floor" of the receipt sequence).
    pub fn read_floor(&self, session_id: &SessionId) -> u64 {
        self.floor(session_id)
    }

    /// Snapshot of every `(session_id, last_signed_seq)` pair in the
    /// journal. Used by the operator-facing `audit replay` / `audit
    /// verify` tooling — the journal is a per-session floor, so each
    /// session appears at most once.
    ///
    /// The lock is held only long enough to clone the in-memory map.
    pub fn entries(&self) -> Vec<(SessionId, u64)> {
        let g = self.inner.lock();
        g.by_session
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Commit `new_seq` as the new floor for `session_id`. The write
    /// is durable (append + fsync per policy) and atomic per record
    /// (the on-disk format is a sequence of fixed-width self-checksumed
    /// records; a torn tail is rejected on replay). Fails with
    /// `SeqNotMonotonic` if `new_seq <= journal[session_id]` — callers
    /// MUST handle this as a refusal-to-sign event, never as "try a
    /// different seq".
    ///
    /// Hold the lock across the append so a concurrent `floor` call
    /// can't observe a half-written state.
    pub fn bump(&self, session_id: &SessionId, new_seq: u64) -> JournalResult<()> {
        let mut g = self.inner.lock();
        let prev = g.by_session.get(session_id).copied().unwrap_or(0);
        if new_seq <= prev {
            return Err(JournalError::SeqNotMonotonic {
                session: session_id.to_hex(),
                floor: prev,
                proposed: new_seq,
            });
        }
        // Persist first, then update in-memory state — that way a
        // failing write doesn't leave us with an in-memory floor higher
        // than what's on disk.
        if g.path.is_some() {
            let record = encode_record(session_id, new_seq);
            {
                let handle = g
                    .handle
                    .as_mut()
                    .expect("path is Some so handle must be Some");
                handle.write_all(&record)?;
            }
            // Durability decision.
            let do_fsync = match g.fsync_policy {
                FsyncPolicy::EveryWrite => true,
                FsyncPolicy::Periodic(dt) => g.last_fsync.elapsed() >= dt,
            };
            if do_fsync {
                if let Some(h) = g.handle.as_ref() {
                    h.sync_data()?;
                }
                g.last_fsync = Instant::now();
            }
            g.file_size += record.len() as u64;
        }
        g.by_session.insert(session_id.clone(), new_seq);
        // Auto-compact off-thread if the journal has grown beyond the
        // watermark and no compaction is already in flight. Doing this
        // *after* the in-mem update means the snapshot the async
        // worker takes already includes this bump. The async path
        // keeps the bump hot-path O(1) — only the brief snapshot
        // clone (step 1) and the bounded swap (step 3) ever touch the
        // journal lock.
        let needs_compaction = g.path.is_some()
            && !g.compaction_inflight
            && g.file_size > g.compaction_watermark;
        if needs_compaction {
            // Inside-lock: take the snapshot + mark inflight. The
            // tokio task that actually writes the snapshot is spawned
            // after we release the lock at function return.
            let snapshot = g.by_session.clone();
            let path = g.path.clone().expect("path checked above");
            g.compaction_inflight = true;
            drop(g);
            // Best-effort: try to spawn onto the current tokio runtime.
            // If we're not in a tokio context (e.g. a sync caller from
            // a non-async harness), fall back to a synchronous in-line
            // compaction so the invariant ("file size stays near the
            // watermark") still holds. This keeps `bump` callable from
            // both async and sync contexts.
            let inner = self.inner.clone();
            match tokio::runtime::Handle::try_current() {
                Ok(_) => {
                    // Fire-and-forget: the JoinHandle is dropped, but
                    // the spawned task runs to completion. The
                    // `compaction_inflight` flag is cleared by the
                    // task's swap-phase regardless of outcome.
                    let handle: JoinHandle<()> =
                        tokio::task::spawn_blocking(move || {
                            let _ = compact_async_worker(&inner, &snapshot, &path);
                        });
                    drop(handle);
                }
                Err(_) => {
                    // No tokio context — degrade to a synchronous
                    // compaction. This is a maintenance/testing path;
                    // production callers (control plane, hub) always
                    // hold a tokio runtime.
                    let _ = compact_async_worker(&inner, &snapshot, &path);
                }
            }
        }
        Ok(())
    }

    /// Manually trigger a **synchronous** compaction pass. Rewrites the
    /// journal as a minimal sequence of records (one per live session),
    /// atomically replacing the previous file. The in-memory state is
    /// unchanged.
    ///
    /// Holds the journal lock for the duration of the rewrite — at
    /// mainnet receipt rates the 10 MB write can block bumps for
    /// hundreds of ms, so production callers should prefer
    /// [`compact_async`](Self::compact_async). This sync path remains
    /// for tests, maintenance windows, and sync (non-tokio) callers.
    pub fn compact(&self) -> JournalResult<()> {
        let mut g = self.inner.lock();
        if g.path.is_none() {
            return Ok(());
        }
        compact_locked(&mut g)
    }

    /// Trigger an **asynchronous** compaction pass. Returns a
    /// [`JoinHandle`] that resolves to the compaction result once the
    /// off-thread snapshot write + atomic swap have completed. See the
    /// module-level docs ("Async compaction snapshot/swap protocol")
    /// for the full atomicity argument.
    ///
    /// - The journal lock is held only briefly (phase 1: snapshot
    ///   clone; phase 3: rename + delta-replay). The slow tempfile
    ///   write + fsync (phase 2) runs on a `spawn_blocking` task with
    ///   no lock held.
    /// - Re-entrant calls while a compaction is already in flight
    ///   return a no-op handle that resolves immediately to `Ok(())`.
    ///   The in-flight worker already covers any state that the second
    ///   call would have snapshotted.
    /// - **Must** be called from within a tokio runtime — uses
    ///   `tokio::task::spawn_blocking`. Sync callers should use
    ///   [`compact`](Self::compact) instead.
    pub fn compact_async(&self) -> JoinHandle<JournalResult<()>> {
        let (snapshot, path) = {
            let mut g = self.inner.lock();
            if g.path.is_none() {
                // In-memory journal — nothing to write. Return a
                // resolved handle.
                return tokio::task::spawn(async { Ok(()) });
            }
            if g.compaction_inflight {
                // Another worker is already writing a strictly-recent
                // snapshot; don't stack.
                return tokio::task::spawn(async { Ok(()) });
            }
            g.compaction_inflight = true;
            (g.by_session.clone(), g.path.clone().expect("checked above"))
        };
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || compact_async_worker(&inner, &snapshot, &path))
    }

    /// Current on-disk file size in bytes. Test/inspection helper.
    pub fn file_size(&self) -> u64 {
        self.inner.lock().file_size
    }

    /// Reopen the journal from disk. Used by tests to simulate a
    /// restart: drop the live journal, then `ReceiptJournal::open` the
    /// same path. Production code never calls this — restart is by
    /// process restart.
    #[cfg(test)]
    fn reload(&self) -> JournalResult<()> {
        let mut g = self.inner.lock();
        let path = g
            .path
            .clone()
            .expect("reload only valid on a persistent journal");
        // Drop the handle so the read below sees the post-rename file.
        g.handle = None;
        let raw = fs::read(&path)?;
        let (map, _migrate) = replay_any(&raw, &path)?;
        g.by_session = map;
        let h = OpenOptions::new().append(true).read(true).open(&path)?;
        g.file_size = h.metadata()?.len();
        g.handle = Some(h);
        Ok(())
    }
}

/// Compaction routine. The lock is held by the caller; this rewrites
/// the journal in place via tempfile + rename and re-opens the append
/// handle.
fn compact_locked(g: &mut Inner) -> JournalResult<()> {
    let path = g.path.clone().expect("compact_locked requires a path");
    // Close the current handle before atomic rename (Windows would
    // refuse the rename otherwise; on Unix it's tidier).
    g.handle = None;
    write_v1_snapshot(&path, &g.by_session)?;
    let h = OpenOptions::new().append(true).read(true).open(&path)?;
    g.file_size = h.metadata()?.len();
    g.handle = Some(h);
    g.last_fsync = Instant::now();
    Ok(())
}

/// The async compaction worker. Runs *off* the journal lock for the
/// slow phase (writing + fsyncing the snapshot tempfile), then acquires
/// the lock only briefly to perform the atomic swap and replay the
/// delta of bumps that landed during phase 2. See the module-level
/// docs for the invariants.
///
/// On any error, clears the `compaction_inflight` flag so future
/// compactions can retry. The journal file is left untouched on phase-2
/// failure (no rename has happened) and is left in a consistent state
/// on phase-3 failure (the rename either happened or didn't; the
/// in-mem map is the source of truth and the delta-replay would have
/// brought it back to consistency on the next compaction).
fn compact_async_worker(
    inner: &Arc<Mutex<Inner>>,
    snapshot: &BTreeMap<SessionId, u64>,
    path: &Path,
) -> JournalResult<()> {
    // Phase 2: write the snapshot tempfile with no lock held. This is
    // the slow part — for a 10 MB journal it's ~100 ms of write + a
    // full fsync round-trip. Concurrent `bump()` calls keep appending
    // to the live (pre-compaction) journal file.
    let tmp_path = compacting_tempfile_path(path);
    let result = (|| -> JournalResult<()> {
        write_v1_snapshot_at(&tmp_path, snapshot)?;

        // Phase 3: atomic swap under the lock. This is bounded by the
        // number of bumps that landed during phase 2 (one extra
        // record per such bump in the delta-replay), so it remains
        // O(bumps_during_compaction) and not O(N).
        let mut g = inner.lock();
        let path = g.path.clone().expect("worker only runs with a path");
        // Drop the live append handle before the rename so we don't
        // hold an open fd into the soon-to-be-replaced inode. On Unix
        // this isn't strictly required (rename works fine over an
        // open fd) but it's tidier and matches the sync path.
        g.handle = None;
        // Atomic rename: replaces the journal inode with our snapshot
        // tempfile. POSIX guarantees this is observable as a single
        // step to concurrent observers; the tempfile is in the same
        // directory as the journal, so it's the same filesystem and
        // the rename is genuinely atomic.
        fs::rename(&tmp_path, &path)?;
        // fsync the parent directory so the rename itself is durable
        // (otherwise a crash could leave the directory entry stale).
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        // Reopen the append handle on the freshly-swapped file.
        let mut handle = OpenOptions::new().append(true).read(true).open(&path)?;
        let mut size = handle.metadata()?.len();
        // Delta-replay: any entry where the current in-mem seq has
        // advanced past the snapshot's value, or didn't exist in the
        // snapshot at all, gets one fresh record appended. This is
        // bounded by the number of bumps that landed during phase 2,
        // which is small at any realistic compaction frequency.
        for (id, &cur_seq) in &g.by_session {
            let snap_seq = snapshot.get(id).copied().unwrap_or(0);
            if cur_seq > snap_seq {
                let record = encode_record(id, cur_seq);
                handle.write_all(&record)?;
                size += record.len() as u64;
            }
        }
        // Durability: a single fsync covers every delta record we
        // just wrote (plus the rename, via the dir fsync above).
        handle.sync_data()?;
        g.handle = Some(handle);
        g.file_size = size;
        g.last_fsync = Instant::now();
        Ok(())
    })();
    // Always clear the inflight flag, even on failure — otherwise a
    // transient I/O hiccup would wedge the journal at "no future
    // compactions allowed".
    {
        let mut g = inner.lock();
        g.compaction_inflight = false;
    }
    if result.is_err() {
        // Clean up the orphan tempfile so the next compaction starts
        // from a clean state. Best-effort.
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// Compute the deterministic tempfile path used by `compact_async`.
/// Lives in the same directory as the journal so the rename is
/// guaranteed to be on the same filesystem (POSIX atomicity).
fn compacting_tempfile_path(journal_path: &Path) -> PathBuf {
    let mut name = journal_path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(COMPACTING_SUFFIX);
    match journal_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

/// Write a v1 snapshot to an explicit path (no temp-file dance, no
/// rename — the caller does that). Used by the async compaction
/// worker, which needs to write to a deterministic sibling path so
/// `open()` can detect orphans after a crash.
fn write_v1_snapshot_at(
    dest: &Path,
    by_session: &BTreeMap<SessionId, u64>,
) -> std::io::Result<()> {
    // Create / truncate, then write the snapshot.
    let mut handle = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dest)?;
    handle.write_all(MAGIC_V1)?;
    for (id, seq) in by_session {
        let rec = encode_record(id, *seq);
        handle.write_all(&rec)?;
    }
    handle.sync_all()?;
    Ok(())
}

/// Encode a single v1 record: `[id:32][seq:u64 BE][crc:u32 BE]`.
fn encode_record(session_id: &SessionId, seq: u64) -> [u8; RECORD_SIZE] {
    let mut out = [0u8; RECORD_SIZE];
    out[..32].copy_from_slice(session_id.as_bytes());
    out[32..40].copy_from_slice(&seq.to_be_bytes());
    let crc = crc32_ieee(&out[..40]);
    out[40..44].copy_from_slice(&crc.to_be_bytes());
    out
}

/// Replay either a v0 or v1 file. Returns `(map, needs_migration)`.
fn replay_any(raw: &[u8], path: &Path) -> JournalResult<(BTreeMap<SessionId, u64>, bool)> {
    if raw.is_empty() {
        return Ok((BTreeMap::new(), false));
    }
    if raw.len() < MAGIC_V1.len() {
        return Err(JournalError::Truncated {
            path: path.display().to_string(),
            detail: format!("file too short ({} bytes)", raw.len()),
        });
    }
    let magic = &raw[..MAGIC_V1.len()];
    if magic == MAGIC_V1 {
        Ok((replay_v1(raw, path)?, false))
    } else if magic == MAGIC_V0 {
        Ok((decode_v0(raw, path)?, true))
    } else {
        Err(JournalError::BadMagic {
            path: path.display().to_string(),
        })
    }
}

/// Replay a v1 append-only file. A truncated tail (the file ended
/// mid-record because of a crash during append) is **dropped silently**:
/// any record that didn't get fully written can never have been signed
/// because the caller fsyncs before signing, so dropping it is the
/// invariant-preserving choice. A *checksum-failed* record, by
/// contrast, is a real corruption signal and bubbles up as an error.
fn replay_v1(raw: &[u8], path: &Path) -> JournalResult<BTreeMap<SessionId, u64>> {
    debug_assert!(raw.starts_with(MAGIC_V1));
    let body = &raw[MAGIC_V1.len()..];
    let mut out: BTreeMap<SessionId, u64> = BTreeMap::new();
    let mut cursor = 0usize;
    while cursor + RECORD_SIZE <= body.len() {
        let record = &body[cursor..cursor + RECORD_SIZE];
        let expected_crc = crc32_ieee(&record[..40]);
        let mut crc_arr = [0u8; 4];
        crc_arr.copy_from_slice(&record[40..44]);
        let got_crc = u32::from_be_bytes(crc_arr);
        if expected_crc != got_crc {
            return Err(JournalError::ChecksumMismatch {
                path: path.display().to_string(),
                offset: (MAGIC_V1.len() + cursor) as u64,
            });
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&record[..32]);
        let mut seq_arr = [0u8; 8];
        seq_arr.copy_from_slice(&record[32..40]);
        let seq = u64::from_be_bytes(seq_arr);
        // Take the max — the journal is monotonic per session; later
        // records always supersede earlier ones for the same id.
        out.entry(SessionId::new(id))
            .and_modify(|cur| {
                if seq > *cur {
                    *cur = seq;
                }
            })
            .or_insert(seq);
        cursor += RECORD_SIZE;
    }
    // Trailing partial record (cursor < body.len()): silently dropped.
    // See the function doc above.
    Ok(out)
}

/// Decode a legacy v0 snapshot file. Used only by the migration path.
fn decode_v0(raw: &[u8], path: &Path) -> JournalResult<BTreeMap<SessionId, u64>> {
    debug_assert!(raw.starts_with(MAGIC_V0));
    if raw.len() < MAGIC_V0.len() + 4 {
        return Err(JournalError::Truncated {
            path: path.display().to_string(),
            detail: format!("v0 file too short ({} bytes)", raw.len()),
        });
    }
    let mut cursor = MAGIC_V0.len();
    let mut n_arr = [0u8; 4];
    n_arr.copy_from_slice(&raw[cursor..cursor + 4]);
    let n = u32::from_be_bytes(n_arr) as usize;
    cursor += 4;
    let expected = MAGIC_V0.len() + 4 + n * V0_ENTRY_SIZE;
    if raw.len() != expected {
        return Err(JournalError::Truncated {
            path: path.display().to_string(),
            detail: format!(
                "expected {expected} bytes for {n} v0 entries; got {} bytes",
                raw.len()
            ),
        });
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        let mut id = [0u8; 32];
        id.copy_from_slice(&raw[cursor..cursor + 32]);
        cursor += 32;
        let mut seq_arr = [0u8; 8];
        seq_arr.copy_from_slice(&raw[cursor..cursor + 8]);
        cursor += 8;
        out.insert(SessionId::new(id), u64::from_be_bytes(seq_arr));
    }
    Ok(out)
}

/// Atomically write a v1 journal snapshot at `dest`. One record per
/// live entry, in `BTreeMap` iteration order (lexicographic by
/// session id). The temp file is fsync'd before rename and the parent
/// directory is fsync'd after.
fn write_v1_snapshot(dest: &Path, by_session: &BTreeMap<SessionId, u64>) -> std::io::Result<()> {
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let dir_for_tmp = parent.unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(dir_for_tmp)?;
    {
        let mut handle = tmp.as_file();
        handle.write_all(MAGIC_V1)?;
        for (id, seq) in by_session {
            let rec = encode_record(id, *seq);
            handle.write_all(&rec)?;
        }
        handle.sync_all()?;
    }
    tmp.persist(dest)
        .map_err(|e| std::io::Error::other(format!("persist tempfile to {}: {e}", dest.display())))?;
    if let Some(parent) = parent {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Ensure `path` exists and starts with v1 magic. Called from `open`
/// after `replay_any` has already validated any pre-existing content:
/// here we only handle the "absent" and "exists-but-empty" cases by
/// writing a magic-only header. A non-empty file is left as-is — by
/// construction it either starts with `MAGIC_V1` (we just wrote it via
/// `write_v1_snapshot` during v0 migration, or this is a normal reopen
/// of an existing journal) or `replay_any` would already have returned
/// an error.
fn ensure_v1_header(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        let len = fs::metadata(path)?.len();
        if len > 0 {
            return Ok(());
        }
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir_for_tmp = parent.unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(dir_for_tmp)?;
    {
        let mut handle = tmp.as_file();
        handle.write_all(MAGIC_V1)?;
        handle.sync_all()?;
    }
    tmp.persist(path)
        .map_err(|e| std::io::Error::other(format!("persist v1 header to {}: {e}", path.display())))?;
    if let Some(parent) = parent {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// CRC-32 IEEE (the Ethernet / PNG / zip polynomial). Pulled inline so
/// we don't take a new dep for ~30 lines of code; the table is built
/// once on first call.
fn crc32_ieee(bytes: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = table[idx] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> SessionId {
        SessionId::new([b; 32])
    }

    /// P1-8/9: fresh session_id starts at floor 0.
    #[test]
    fn fresh_session_floor_is_zero() {
        let j = ReceiptJournal::in_memory();
        assert_eq!(j.floor(&id(0xAA)), 0);
        assert_eq!(j.floor(&id(0xBB)), 0);
        // `read_floor` is the named alias.
        assert_eq!(j.read_floor(&id(0xAA)), 0);
    }

    /// P1-8/9: bump increases the floor. Subsequent floor() reads see
    /// the new value.
    #[test]
    fn bump_records_floor() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(0xAA), 1).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 1);
        j.bump(&id(0xAA), 5).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 5);
    }

    /// P1-8/9 core: bumping with `seq <= prev` fails. This is the
    /// invariant that protects against forced-restart double-signing.
    #[test]
    fn bump_rejects_non_monotonic() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(0xAA), 7).unwrap();
        let err = j.bump(&id(0xAA), 7).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
        let err = j.bump(&id(0xAA), 3).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
    }

    /// P1-8/9 restart-replay rejection test. Sign N, drop the journal,
    /// reopen the same path, attempt to bump back to <=N. Must fail
    /// even though the in-memory state was lost.
    #[test]
    fn restart_replay_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipts.bin");
        let sess = id(0xCC);

        // Boot 1: sign up to seq=10.
        let j1 = ReceiptJournal::open(&path).unwrap();
        j1.bump(&sess, 1).unwrap();
        j1.bump(&sess, 7).unwrap();
        j1.bump(&sess, 10).unwrap();
        drop(j1);

        // Boot 2: fresh process, same disk.
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&sess), 10, "journal must persist across restart");
        // Attacker (or in-mem reset bug) tries to sign seq=1 again.
        let err = j2.bump(&sess, 1).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
        // Or seq=10 (replay of the last legitimate one).
        let err = j2.bump(&sess, 10).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
        // Floor must NOT have moved.
        assert_eq!(j2.floor(&sess), 10);
        // Legitimate next seq is OK.
        j2.bump(&sess, 11).unwrap();
        assert_eq!(j2.floor(&sess), 11);
    }

    /// P1-8/9: each session_id has an independent floor. Bumping one
    /// must not affect the floor of another.
    #[test]
    fn per_session_isolation() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(0xAA), 5).unwrap();
        j.bump(&id(0xBB), 3).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 5);
        assert_eq!(j.floor(&id(0xBB)), 3);
        // A previously-unseen session is still at zero.
        assert_eq!(j.floor(&id(0xCC)), 0);
        // Bumping BB must not move AA.
        j.bump(&id(0xBB), 9).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 5);
        assert_eq!(j.floor(&id(0xBB)), 9);
    }

    /// The reload helper exercises the codec by writing through it
    /// once, dropping, and reading back. This is the "the file is
    /// actually durable" check.
    #[test]
    fn reload_reads_durable_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(1), 42).unwrap();
        j.bump(&id(2), 1000).unwrap();
        j.reload().unwrap();
        assert_eq!(j.floor(&id(1)), 42);
        assert_eq!(j.floor(&id(2)), 1000);
    }

    /// Bad magic on disk MUST error out rather than silently treat the
    /// file as empty. Protects against pointing the journal at the
    /// wrong file (e.g. swapping wg.key with receipts.bin in a config
    /// typo).
    #[test]
    fn bad_magic_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-journal.bin");
        // 16 bytes of "definitely-not-the-magic".
        fs::write(&path, b"NOTAJOURNAL\0\0\0\0\0\0").unwrap();
        let err = ReceiptJournal::open(&path).unwrap_err();
        assert!(matches!(err, JournalError::BadMagic { .. }));
    }

    /// Truncated v0 file is rejected (migration path). Catches crashes
    /// during the v0 era — not a current bug, but we'd rather reject
    /// than partial-decode.
    #[test]
    fn truncated_v0_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trunc.bin");
        // v0 magic + a count of 3 — but only one entry's worth of bytes.
        let mut buf = MAGIC_V0.to_vec();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; V0_ENTRY_SIZE]); // one entry
        fs::write(&path, &buf).unwrap();
        let err = ReceiptJournal::open(&path).unwrap_err();
        assert!(matches!(err, JournalError::Truncated { .. }));
    }

    /// P1-8/9: end-to-end durability — after `bump` returns, an
    /// independent reader sees the new floor.
    #[test]
    fn bump_durable_for_independent_reader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dur.bin");
        let writer = ReceiptJournal::open(&path).unwrap();
        writer.bump(&id(0xEE), 99).unwrap();
        // Parallel reader, separate in-memory state.
        let reader = ReceiptJournal::open(&path).unwrap();
        assert_eq!(reader.floor(&id(0xEE)), 99);
    }

    /// Empty file (e.g. created by `touch`) opens as an empty journal.
    /// After open, the file holds at minimum the v1 header.
    #[test]
    fn empty_file_decodes_to_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        fs::write(&path, b"").unwrap();
        let j = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j.floor(&id(0)), 0);
        let raw = fs::read(&path).unwrap();
        assert_eq!(&raw, MAGIC_V1);
    }

    /// v1 append-only round trip: bump several times for the same
    /// session, reload, and confirm the highest seq is the floor.
    #[test]
    fn v1_append_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rt.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(0xAA), 1).unwrap();
        j.bump(&id(0xAA), 2).unwrap();
        j.bump(&id(0xAA), 99).unwrap();
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 99);
        // 3 records of size 44, plus the 8-byte v1 header.
        assert_eq!(j2.file_size(), 8 + 3 * RECORD_SIZE as u64);
    }

    /// Verify v0 → v1 migration: write a hand-crafted v0 file, open
    /// through `ReceiptJournal::open`, confirm the entries replay, then
    /// confirm the on-disk file is now v1 magic-prefixed.
    #[test]
    fn migrates_v0_to_v1_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.bin");

        // Hand-roll a v0 fixture: magic + count + 2 entries.
        let mut buf = MAGIC_V0.to_vec();
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(id(0xAA).as_bytes());
        buf.extend_from_slice(&42u64.to_be_bytes());
        buf.extend_from_slice(id(0xBB).as_bytes());
        buf.extend_from_slice(&1000u64.to_be_bytes());
        fs::write(&path, &buf).unwrap();

        // Open through the public API — migration runs in `open`.
        let j = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 42);
        assert_eq!(j.floor(&id(0xBB)), 1000);

        // On-disk file is now v1.
        let raw = fs::read(&path).unwrap();
        assert!(raw.starts_with(MAGIC_V1));

        // And it round-trips: a second open sees the same entries.
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 42);
        assert_eq!(j2.floor(&id(0xBB)), 1000);
    }

    /// Checksum-mismatch detection: flip a bit in a v1 record and
    /// confirm `open` surfaces a `ChecksumMismatch` error rather than
    /// silently accepting the tampered seq.
    #[test]
    fn checksum_mismatch_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(0xAA), 5).unwrap();
        drop(j);

        // Open the raw file and flip a bit inside the seq field of the
        // single record. The record starts immediately after the
        // 8-byte v1 magic.
        let mut raw = fs::read(&path).unwrap();
        let seq_off = MAGIC_V1.len() + 32; // skip magic + id
        raw[seq_off] ^= 0x01;
        fs::write(&path, &raw).unwrap();

        let err = ReceiptJournal::open(&path).unwrap_err();
        assert!(matches!(err, JournalError::ChecksumMismatch { .. }));
    }

    /// Torn-tail tolerance: a record that didn't fully write (e.g. the
    /// process crashed mid-append) appears as a short trailing tail in
    /// the file. Replay must drop it silently — the operator never
    /// signed at that seq, so dropping the bogus tail is safe.
    #[test]
    fn torn_tail_dropped_silently() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torn.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(0xAA), 5).unwrap();
        drop(j);

        // Append a half-written record (35 bytes, less than the 44-byte
        // record size).
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0xFF; 35]).unwrap();
        drop(f);

        let j2 = ReceiptJournal::open(&path).unwrap();
        // Only the original record survives.
        assert_eq!(j2.floor(&id(0xAA)), 5);
    }

    /// Compaction preserves all entries and shrinks the file to the
    /// minimum size (one record per live session + header).
    #[test]
    fn compaction_preserves_entries_and_shrinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compact.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        // Hammer one session with many bumps so the file grows.
        for s in 1..=50u64 {
            j.bump(&id(0xAA), s).unwrap();
        }
        // And add a few independent sessions.
        j.bump(&id(0xBB), 7).unwrap();
        j.bump(&id(0xCC), 100).unwrap();
        let pre_size = j.file_size();
        assert!(pre_size >= 8 + 52 * RECORD_SIZE as u64);

        j.compact().unwrap();

        // After compaction, file size should be 3 records + header.
        let post_size = j.file_size();
        assert_eq!(post_size, 8 + 3 * RECORD_SIZE as u64);
        assert!(post_size < pre_size);

        // Floors preserved.
        assert_eq!(j.floor(&id(0xAA)), 50);
        assert_eq!(j.floor(&id(0xBB)), 7);
        assert_eq!(j.floor(&id(0xCC)), 100);

        // And after a real reopen.
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 50);
        assert_eq!(j2.floor(&id(0xBB)), 7);
        assert_eq!(j2.floor(&id(0xCC)), 100);
    }

    /// Auto-compaction kicks in when the file crosses the watermark.
    /// Use a tiny watermark so the test runs fast.
    #[test]
    fn auto_compaction_at_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auto.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        // Set the watermark to ~10 records' worth so the auto-compact
        // path triggers quickly.
        j.set_compaction_watermark(8 + 10 * RECORD_SIZE as u64);
        for s in 1..=100u64 {
            j.bump(&id(0xAA), s).unwrap();
        }
        // File should be compacted; one live entry → header + 1 record.
        let post = j.file_size();
        // It's allowed to be a few records past the watermark mid-batch
        // (we only compact after a bump that *crosses* the watermark),
        // but it must never run away to 100 records.
        assert!(post <= 8 + 10 * RECORD_SIZE as u64);
        assert_eq!(j.floor(&id(0xAA)), 100);
    }

    /// `FsyncPolicy::Periodic` accepts writes without per-call fsync.
    /// Verifies the setter wires up and `bump` still succeeds.
    #[test]
    fn periodic_fsync_policy_smoke() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("periodic.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.set_fsync_policy(FsyncPolicy::Periodic(Duration::from_millis(100)));
        for s in 1..=20u64 {
            j.bump(&id(0xAA), s).unwrap();
        }
        assert_eq!(j.floor(&id(0xAA)), 20);

        // Drop + reopen still sees the writes (the OS write buffer is
        // flushed even without sync_data; on a tempfs that's plenty).
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 20);
    }

    /// CRC32 spot check — the table-driven implementation matches a
    /// known IEEE vector.
    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32_ieee(b""), 0);
        // CRC32("123456789") = 0xCBF43926.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    /// `entries()` returns every live (id, seq) pair, with the highest
    /// seq per id when many bumps land for the same session.
    #[test]
    fn entries_reports_live_state() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(0xAA), 1).unwrap();
        j.bump(&id(0xAA), 5).unwrap();
        j.bump(&id(0xBB), 100).unwrap();
        let mut got = j.entries();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(got, vec![(id(0xAA), 5), (id(0xBB), 100)]);
    }

    /// Async compaction: writes that land *during* the off-lock
    /// snapshot-write phase must survive the swap. We force a
    /// synthetic race by spawning `compact_async` then pounding
    /// `bump()` for the same session — after the join, the on-disk
    /// floor must reflect the post-bump value, not the snapshot's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn writes_during_async_compaction_are_not_lost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("race.bin");
        let j = std::sync::Arc::new(ReceiptJournal::open(&path).unwrap());
        // Pre-populate so the snapshot has real work to write.
        for s in 0..50u8 {
            j.bump(&id(s), 1).unwrap();
        }
        // Kick off compaction; while it's running, pound bumps on a
        // few sessions to land delta records the swap-phase must
        // replay.
        let compact_handle = j.compact_async();
        let mut bump_handles = Vec::new();
        for s in 0..10u8 {
            let j = j.clone();
            bump_handles.push(tokio::task::spawn_blocking(move || {
                // Each session: bump 100 times from seq=2..=101.
                for n in 2..=101u64 {
                    j.bump(&id(s), n).unwrap();
                }
            }));
        }
        for h in bump_handles {
            h.await.unwrap();
        }
        compact_handle.await.unwrap().unwrap();

        // In-memory state reflects the pounding.
        for s in 0..10u8 {
            assert_eq!(j.floor(&id(s)), 101, "in-mem floor for {s:#x}");
        }
        for s in 10..50u8 {
            assert_eq!(j.floor(&id(s)), 1, "untouched session {s:#x}");
        }

        // Critically: a fresh open of the journal file must agree —
        // i.e. the delta-replay phase actually persisted the post-
        // snapshot bumps. This is the invariant the snapshot/swap
        // protocol exists to preserve.
        // Drop the writer first so the OS flushes the append handle
        // (sync_data has already happened per policy, but dropping
        // makes the intent explicit).
        drop(j);
        let reader = ReceiptJournal::open(&path).unwrap();
        for s in 0..10u8 {
            assert_eq!(reader.floor(&id(s)), 101, "on-disk floor for {s:#x}");
        }
        for s in 10..50u8 {
            assert_eq!(reader.floor(&id(s)), 1, "on-disk untouched {s:#x}");
        }
    }

    /// Calling `compact_async` twice in rapid succession must not
    /// corrupt the journal. The second call returns a no-op handle
    /// (the in-flight compaction already covers the state) — both
    /// joins must succeed and the final on-disk state must match the
    /// live in-mem state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn double_compaction_is_safe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("double.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        for s in 0..30u8 {
            j.bump(&id(s), 7).unwrap();
        }
        // Fire two compactions back-to-back. The second should see
        // `compaction_inflight = true` and return a resolved no-op.
        let h1 = j.compact_async();
        let h2 = j.compact_async();
        h1.await.unwrap().unwrap();
        h2.await.unwrap().unwrap();
        // Now run another pair after the first one has finished —
        // this exercises the "second compaction *after* the first
        // settles" path too.
        let h3 = j.compact_async();
        h3.await.unwrap().unwrap();

        // State must be intact.
        for s in 0..30u8 {
            assert_eq!(j.floor(&id(s)), 7);
        }
        drop(j);
        let r = ReceiptJournal::open(&path).unwrap();
        for s in 0..30u8 {
            assert_eq!(r.floor(&id(s)), 7);
        }
    }

    /// A crash between phase 2 (tempfile write) and phase 3 (atomic
    /// swap) leaves the orphan `<journal>.compacting` file on disk.
    /// The live journal is still authoritative; the next `open()`
    /// must detect the orphan and remove it.
    #[test]
    fn partial_tempfile_on_crash_is_detected_on_next_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crash.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(0xAA), 5).unwrap();
        j.bump(&id(0xBB), 9).unwrap();
        drop(j);

        // Simulate a process crash mid-async-compaction: the worker
        // got as far as writing the tempfile (phase 2) and then
        // died before the atomic swap. Construct that scenario by
        // hand-writing a partial snapshot tempfile alongside the
        // journal.
        let tmp_path = compacting_tempfile_path(&path);
        // Plausible-but-wrong content (only `id(0xAA)`, missing
        // `id(0xBB)`) plus a torn tail to make sure `open` doesn't
        // accidentally adopt the file via some happy-path codec.
        let mut buf = MAGIC_V1.to_vec();
        let rec = encode_record(&id(0xAA), 5);
        buf.extend_from_slice(&rec);
        buf.extend_from_slice(&[0xFF; 13]); // half-record torn tail
        fs::write(&tmp_path, &buf).unwrap();
        assert!(tmp_path.exists(), "fixture should leave an orphan");

        // Open the journal: the orphan must be gone and the journal
        // state must still reflect the original two bumps (the
        // tempfile contents must NOT have been promoted).
        let r = ReceiptJournal::open(&path).unwrap();
        assert!(
            !tmp_path.exists(),
            "open() must scrub orphan tempfile"
        );
        assert_eq!(r.floor(&id(0xAA)), 5);
        assert_eq!(r.floor(&id(0xBB)), 9, "both bumps must survive");
    }

    /// The headline regression target for this PR: at the auto-
    /// compaction watermark, `bump()` must stay O(1) on the hot path
    /// — it spawns the slow snapshot-write onto a tokio task instead
    /// of holding the journal lock for the full rewrite + fsync.
    ///
    /// We spawn a small pool of concurrent bumpers, deliberately
    /// configure a low watermark so a compaction fires partway
    /// through, and assert that the whole batch completes in a sane
    /// wall-clock budget. Under the old synchronous-compaction path a
    /// 10 MB rewrite would block every concurrent bump for hundreds
    /// of ms; the bumpers in this test would serialise on that and
    /// take seconds at minimum.
    ///
    /// We do not assert a tight p99 latency target here — the
    /// swap-phase still holds the lock for the duration of one fsync
    /// (durably persisting the delta), and on macOS APFS / network
    /// FS hosts an fsync can take tens of ms by itself. The user
    /// originally suggested a ~200 µs p99 target but explicitly
    /// authorised the smoke-check fallback when the host's fsync
    /// floor makes that unstable — that's the regime we're in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn auto_compaction_does_not_block_bumps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonblock.bin");
        let j = std::sync::Arc::new(ReceiptJournal::open(&path).unwrap());
        // Loss-tolerant fsync so this test isn't gated on the host's
        // fsync latency (which is the dominant cost on real disks and
        // would swamp the signal we're measuring).
        j.set_fsync_policy(FsyncPolicy::Periodic(Duration::from_secs(60)));
        // Low watermark: ~50 records' worth, so a compaction fires
        // somewhere in the middle of each task's work.
        j.set_compaction_watermark(8 + 50 * RECORD_SIZE as u64);

        // Pre-fill a baseline so the compaction's snapshot has real
        // data to write.
        for s in 0..40u8 {
            j.bump(&id(s), 1).unwrap();
        }

        let n_tasks = 4;
        let bumps_per_task: u64 = 200;
        let start = Instant::now();
        let mut handles = Vec::new();
        for task in 0..n_tasks {
            let j = j.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                let mut latencies = Vec::with_capacity(bumps_per_task as usize);
                // Use a per-task session id so writes never conflict
                // on the monotonic guard.
                let sess = id(0x80 + task as u8);
                // Seed.
                j.bump(&sess, 1).unwrap();
                for n in 2..=(bumps_per_task + 1) {
                    let t0 = Instant::now();
                    j.bump(&sess, n).unwrap();
                    latencies.push(t0.elapsed());
                }
                latencies
            }));
        }

        let mut all_latencies: Vec<Duration> = Vec::new();
        for h in handles {
            all_latencies.extend(h.await.unwrap());
        }
        let wall = start.elapsed();
        all_latencies.sort();
        let p50 = all_latencies[all_latencies.len() / 2];
        let p99 = all_latencies[all_latencies.len() * 99 / 100];
        let max = *all_latencies.last().unwrap();
        eprintln!(
            "auto_compaction_does_not_block_bumps: wall={wall:?} \
             p50={p50:?} p99={p99:?} max={max:?} \
             (n={})",
            all_latencies.len()
        );

        // Smoke check #1: total bumps in a sane wall-clock budget.
        // Under the *synchronous* compaction path, the very first
        // bump that crossed the watermark would have stalled every
        // other task behind it for the duration of a full file
        // rewrite + fsync; with the watermark we picked here that's
        // not catastrophic at this scale, but at the production
        // 10 MB watermark it was hundreds of ms per stall. The
        // 10 s ceiling is generous enough to be stable on a loaded
        // CI host and tight enough to catch a regression to a
        // serialising compaction path (which would be wall-clock
        // ≥ n_tasks × compaction_cost).
        assert!(
            wall < Duration::from_secs(10),
            "auto-compaction blocked bumps: wall={wall:?} \
             p50={p50:?} p99={p99:?} max={max:?}"
        );

        // Smoke check #2: median bump latency is well below the
        // fsync floor. Under the async-compaction path, the *vast
        // majority* of bumps don't touch the disk under the lock at
        // all — only the swap-phase fsyncs, and only one bump per
        // compaction window observes that. So p50 stays microsecond-
        // scale even when p99/max spike from the fsync.
        assert!(
            p50 < Duration::from_millis(5),
            "p50 bump latency {p50:?} too high — even the median \
             bump appears to be blocking on compaction I/O \
             (p99={p99:?}, max={max:?})"
        );

        // Final state correctness.
        for task in 0..n_tasks {
            let sess = id(0x80 + task as u8);
            assert_eq!(j.floor(&sess), bumps_per_task + 1);
        }
    }

    /// `FsyncPolicy::Periodic(0)` always fsyncs (`elapsed >= 0`).
    /// Boundary check — a regression to `>` would skip every fsync.
    #[test]
    fn periodic_zero_duration_fsyncs_every_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero-dur.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.set_fsync_policy(FsyncPolicy::Periodic(Duration::from_secs(0)));
        j.bump(&id(0xAA), 1).unwrap();
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 1);
    }

    /// CRC32 differs for every single-bit flip in a 40-byte input.
    /// Discriminates torn-tail from corruption.
    #[test]
    fn crc32_sensitive_to_single_bit_flips() {
        let base = [0u8; 40];
        let baseline = crc32_ieee(&base);
        for byte_idx in 0..40 {
            for bit in 0..8 {
                let mut mutated = base;
                mutated[byte_idx] ^= 1 << bit;
                let c = crc32_ieee(&mutated);
                assert_ne!(c, baseline, "CRC32 collision: byte {byte_idx} bit {bit}");
            }
        }
    }

    /// A freshly-opened in-memory journal returns 0 for every byte.
    #[test]
    fn in_memory_journal_starts_clean() {
        let j = ReceiptJournal::in_memory();
        for b in 0u8..=255u8 {
            assert_eq!(j.floor(&id(b)), 0);
        }
    }

    /// In-memory mode never writes to disk.
    #[test]
    fn in_memory_bump_does_not_create_files() {
        let dir = tempfile::tempdir().unwrap();
        let before_count = fs::read_dir(dir.path()).unwrap().count();
        let j = ReceiptJournal::in_memory();
        for s in 1..=100u64 {
            j.bump(&id(0xAA), s).unwrap();
        }
        let after_count = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(before_count, after_count, "in-memory mode wrote files");
    }

    /// `compact()` on an in-memory journal is a no-op.
    #[test]
    fn compact_in_memory_is_noop() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(1), 5).unwrap();
        j.compact().unwrap();
        assert_eq!(j.floor(&id(1)), 5);
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Property: a strictly-monotonic bump sequence lands at the
        /// highest seq value.
        #[test]
        fn prop_monotonic_sequence_lands_at_max(
            session_byte in any::<u8>(),
            seqs in prop::collection::vec(1u64..1000, 1..50),
        ) {
            let j = ReceiptJournal::in_memory();
            let sess = id(session_byte);
            let mut sorted = seqs;
            sorted.sort_unstable();
            sorted.dedup();
            let max = *sorted.last().unwrap();
            for s in sorted {
                j.bump(&sess, s).unwrap();
            }
            prop_assert_eq!(j.floor(&sess), max);
        }

        /// Property: any bump with `proposed <= floor` rejects.
        #[test]
        fn prop_non_monotonic_bumps_always_reject(
            session_byte in any::<u8>(),
            floor in 1u64..1000,
            proposed in 0u64..1000,
        ) {
            prop_assume!(proposed <= floor);
            let j = ReceiptJournal::in_memory();
            let sess = id(session_byte);
            j.bump(&sess, floor).unwrap();
            let err = j.bump(&sess, proposed).unwrap_err();
            let is_nm = matches!(err, JournalError::SeqNotMonotonic { .. });
            prop_assert!(is_nm);
            prop_assert_eq!(j.floor(&sess), floor);
        }

        /// Property: bumping session A never affects session B.
        #[test]
        fn prop_per_session_isolation(
            a_byte in any::<u8>(),
            b_byte in any::<u8>(),
            a_seq in 1u64..1000,
            b_seq in 1u64..1000,
        ) {
            prop_assume!(a_byte != b_byte);
            let j = ReceiptJournal::in_memory();
            j.bump(&id(a_byte), a_seq).unwrap();
            j.bump(&id(b_byte), b_seq).unwrap();
            prop_assert_eq!(j.floor(&id(a_byte)), a_seq);
            prop_assert_eq!(j.floor(&id(b_byte)), b_seq);
        }

        /// Property: any torn tail (1..RECORD_SIZE-1 bytes) drops
        /// silently on replay.
        #[test]
        fn prop_torn_tail_is_silently_dropped(
            tail_len in 1usize..RECORD_SIZE,
        ) {
            use std::io::Write as _;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("torn-prop.bin");
            let j = ReceiptJournal::open(&path).unwrap();
            j.bump(&id(0x11), 1).unwrap();
            j.bump(&id(0x22), 2).unwrap();
            drop(j);

            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&vec![0xFFu8; tail_len]).unwrap();
            drop(f);

            let r = ReceiptJournal::open(&path).unwrap();
            prop_assert_eq!(r.floor(&id(0x11)), 1);
            prop_assert_eq!(r.floor(&id(0x22)), 2);
        }
    }
}
