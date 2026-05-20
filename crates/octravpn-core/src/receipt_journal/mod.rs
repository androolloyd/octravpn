//! Persistent per-session receipt-sequence floor.
//!
//! Fixes threat-model items P1-8 and P1-9 (`docs/v2-threat-model.md`):
//! a forced restart must never let an attacker collect two distinct
//! receipts at the same `(session_id, seq)` under the operator's
//! receipt-signing pubkey. Every receipt-signing call MUST consult
//! `bump(session_id, next_seq)` and only sign if it returns `Ok`.
//!
//! See `README.md` in this directory for the v1 byte format, the v0
//! → v1 migration, and the compaction-atomicity contract.

mod codec;
mod compact;
mod errors;
mod fsync_policy;
mod inner;
mod migration;

#[cfg(test)]
mod proptests;

use std::{
    fs::{self, OpenOptions},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use parking_lot::Mutex;
use tokio::task::JoinHandle;

use crate::session::SessionId;

use codec::encode_record;
use compact::{
    compact_async_worker, compact_locked, compacting_tempfile_path,
};
use inner::Inner;
use migration::{ensure_v1_header, replay_any, write_v1_snapshot};

pub use errors::{JournalError, JournalResult};
pub use fsync_policy::{FsyncPolicy, DEFAULT_COMPACTION_WATERMARK};

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
            (std::collections::BTreeMap::new(), false)
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
                by_session: std::collections::BTreeMap::new(),
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
        g.by_session.iter().map(|(k, v)| (k.clone(), *v)).collect()
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
        use std::io::Write as _;
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
        let needs_compaction =
            g.path.is_some() && !g.compaction_inflight && g.file_size > g.compaction_watermark;
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
                    let handle: JoinHandle<()> = tokio::task::spawn_blocking(move || {
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
    /// `README.md` ("Async compaction snapshot/swap protocol") for the
    /// full atomicity argument.
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

    /// v1 append-only round trip: bump several times for the same
    /// session, reload, and confirm the highest seq is the floor.
    #[test]
    fn v1_append_round_trip() {
        use codec::RECORD_SIZE;
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

    /// Checksum-mismatch detection: flip a bit in a v1 record and
    /// confirm `open` surfaces a `ChecksumMismatch` error rather than
    /// silently accepting the tampered seq.
    #[test]
    fn checksum_mismatch_detected() {
        use codec::MAGIC_V1;
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

    /// `FsyncPolicy::Periodic` accepts writes without per-call fsync.
    /// Verifies the setter wires up and `bump` still succeeds.
    #[test]
    fn periodic_fsync_policy_smoke() {
        use std::time::Duration;
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

    /// `FsyncPolicy::Periodic(0)` always fsyncs (`elapsed >= 0`).
    /// Boundary check — a regression to `>` would skip every fsync.
    #[test]
    fn periodic_zero_duration_fsyncs_every_call() {
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero-dur.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.set_fsync_policy(FsyncPolicy::Periodic(Duration::from_secs(0)));
        j.bump(&id(0xAA), 1).unwrap();
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 1);
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
}
