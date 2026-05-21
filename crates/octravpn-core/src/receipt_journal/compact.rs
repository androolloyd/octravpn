//! Synchronous + asynchronous journal compaction.
//!
//! * [`compact_locked`] — synchronous. Caller holds the inner lock.
//!   Rewrites the journal atomically (tempfile → rename → fsync).
//! * [`compact_async_worker`] — runs the slow snapshot-write off the
//!   journal lock, then reacquires for the bounded *single-tempfile*
//!   commit: append the deltas of bumps that landed during phase 2 into
//!   the same tempfile, fsync it, then a single atomic rename swaps in
//!   the complete (snapshot + deltas) journal. Keeps `bump` hot-path
//!   O(1) at the watermark.
//!
//! See `README.md` ("Atomicity contract") for the per-phase crash
//! semantics. The post-B-1 contract: the on-disk journal at the
//! authoritative path is **either** the full pre-compaction file
//! **or** the post-compaction file (snapshot + deltas, all durable
//! before the rename). There is no intermediate state visible to a
//! restart.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use parking_lot::Mutex;

use crate::session::SessionId;

use super::codec::{encode_record, MAGIC_V1};
use super::errors::JournalResult;
use super::inner::Inner;
use super::migration::write_v1_snapshot;

/// Suffix used for the in-progress async compaction tempfile. We use a
/// deterministic name so a crash mid-compaction leaves a single,
/// recognisable orphan that `open()` can scrub before re-opening the
/// authoritative journal file.
pub(crate) const COMPACTING_SUFFIX: &str = ".compacting";

/// Crash-injection hook for deterministic crash tests. Production code
/// never sets this; the `#[cfg(test)]` paths in this module flip it to
/// force a panic at a known phase so we can prove the on-disk state at
/// each crash point.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CrashPoint {
    /// Crash after the snapshot tempfile is written + fsync'd (phase 2)
    /// but before the lock is reacquired for phase 3. Models a crash
    /// during the lock-free window.
    AfterPhase2Snapshot,
    /// Crash after deltas have been written + fsync'd into the
    /// tempfile but BEFORE the atomic rename. Models the on-disk
    /// state where the old journal is still authoritative.
    AfterDeltasBeforeRename,
    /// Crash immediately after the atomic rename. Models the on-disk
    /// state where the new journal is durable and contains
    /// snapshot+deltas — the recovery path that the B-1 fix protects.
    AfterRename,
}

#[cfg(test)]
thread_local! {
    /// Per-thread crash injection. Set by tests before driving the
    /// worker; cleared on read so it only fires once.
    pub(crate) static CRASH_AT: std::cell::Cell<Option<CrashPoint>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn maybe_crash(at: CrashPoint) {
    CRASH_AT.with(|c| {
        if c.get() == Some(at) {
            c.set(None);
            panic!("crash injection: {at:?}");
        }
    });
}

/// Synchronous compaction routine. The lock is held by the caller;
/// this rewrites the journal in place via tempfile + rename and
/// re-opens the append handle.
///
/// Perf-8: compaction must merge the in-mem map with the on-disk
/// state — sessions that have been evicted from `by_session` are still
/// on disk and MUST survive the rewrite. We replay the live journal
/// file, then overlay `by_session` (taking the per-session max), and
/// write the merged map.
pub(crate) fn compact_locked(g: &mut Inner) -> JournalResult<()> {
    let path = g.path.clone().expect("compact_locked requires a path");
    // Build the merged map: start from the durable on-disk floor
    // (which includes evicted sessions), then overlay any in-mem
    // entries that are strictly higher.
    let merged = merged_floor_map(&path, &g.by_session)?;
    // Close the current handle before atomic rename (Windows would
    // refuse the rename otherwise; on Unix it's tidier).
    g.handle = None;
    write_v1_snapshot(&path, &merged)?;
    let h = OpenOptions::new().append(true).read(true).open(&path)?;
    g.file_size = h.metadata()?.len();
    g.handle = Some(h);
    g.last_fsync = Instant::now();
    // Perf-8: the merged write captured every evicted session.
    g.evictions_since_compaction = false;
    Ok(())
}

/// Replay the durable on-disk journal and overlay `in_mem` (max per
/// session). Used by `compact_locked` + `compact_async_worker` so the
/// rewritten file always includes evicted sessions' floors. Reads the
/// raw file from disk — the caller is expected to have fsync'd any
/// pending writes already (the compaction paths do this before
/// invoking the merger).
fn merged_floor_map(
    path: &Path,
    in_mem: &BTreeMap<SessionId, u64>,
) -> JournalResult<BTreeMap<SessionId, u64>> {
    let raw = std::fs::read(path)?;
    let mut merged: BTreeMap<SessionId, u64> = if raw.is_empty() {
        BTreeMap::new()
    } else if raw.starts_with(super::codec::MAGIC_V1) {
        super::codec::replay_v1(&raw, path)?
    } else {
        // Pre-v1 magic shouldn't be possible here — `open()` migrates
        // v0 to v1 on load before any compaction runs. Surface a hard
        // error rather than silently dropping data.
        return Err(super::errors::JournalError::BadMagic {
            path: path.display().to_string(),
        });
    };
    for (id, &seq) in in_mem {
        merged
            .entry(id.clone())
            .and_modify(|cur| {
                if seq > *cur {
                    *cur = seq;
                }
            })
            .or_insert(seq);
    }
    Ok(merged)
}

/// The async compaction worker. Runs *off* the journal lock for the
/// slow phase (writing + fsyncing the snapshot tempfile), then acquires
/// the lock to (a) append any post-snapshot delta records into the
/// **same** tempfile, (b) fsync it, and (c) atomically rename it over
/// the live journal. The atomic rename is the single commit point: the
/// on-disk authoritative journal moves from "pre-compaction" to
/// "post-compaction (snapshot + deltas)" in one step. No intermediate
/// state is ever visible.
///
/// Lock window is bounded by the number of bumps that landed during
/// phase 2 (one extra record per such bump in the delta append). At any
/// realistic compaction frequency this is single-digit records, so the
/// extra fsync covers a handful of bytes.
///
/// On any error, clears the `compaction_inflight` flag so future
/// compactions can retry. On failure before the rename, the tempfile is
/// removed (best effort). On failure after the rename — by construction
/// the only operation between rename and clearing the flag is the
/// reopen, which is local I/O on a freshly-renamed file — we leave the
/// new file in place (it is the durable post-compaction journal).
pub(crate) fn compact_async_worker(
    inner: &Arc<Mutex<Inner>>,
    snapshot: &BTreeMap<SessionId, u64>,
    path: &Path,
) -> JournalResult<()> {
    let tmp_path = compacting_tempfile_path(path);
    // Perf-8: capture the "needs disk merge" gate once, off-lock, by
    // peeking the inner flag. If false, we can stay on the fast path
    // (snapshot is a superset of disk state). If true, the merger
    // pulls in any evicted-session floors before writing the
    // tempfile.
    let need_phase2_merge = inner.lock().evictions_since_compaction;
    let result = (|| -> JournalResult<()> {
        // === Phase 2 (no lock held) ===
        // Write the snapshot to the tempfile and sync it. Concurrent
        // `bump()` keeps appending to the live (pre-compaction)
        // journal file. This is the slow part — for a 10 MB journal
        // it's ~100 ms of write + a full fsync round-trip.
        if need_phase2_merge {
            // Perf-8 slow path: merge the snapshot with the durable
            // on-disk state before writing the tempfile. Sessions
            // evicted from the in-mem mirror are still on disk;
            // without this merge they'd be silently dropped from the
            // rewritten journal.
            let merged = merged_floor_map(path, snapshot)?;
            write_v1_snapshot_at(&tmp_path, &merged)?;
        } else {
            // Fast path (pre-Perf-8 behaviour preserved): the
            // snapshot is a strict superset of the on-disk state.
            write_v1_snapshot_at(&tmp_path, snapshot)?;
        }
        #[cfg(test)]
        maybe_crash(CrashPoint::AfterPhase2Snapshot);

        // === Phase 3a (lock held): append deltas into the tempfile ===
        // Bumps that landed during phase 2 are still visible in
        // `by_session` — the fast path. Perf-8 wrinkle: if any
        // eviction has happened since the last compaction, a session
        // that was bumped + then evicted during phase 2 would have
        // its delta record on disk but NOT in `by_session`. In that
        // case we fall back to a (slower) live-disk re-read under
        // the lock. The `evictions_since_compaction` flag is the
        // gate: when `false` the disk read is skipped entirely (this
        // is the common case in production where evictions are rare).
        let mut g = inner.lock();
        let path = g.path.clone().expect("worker only runs with a path");
        let need_live_disk_merge = g.evictions_since_compaction;
        // Read the live journal under the lock ONLY when needed.
        // Single fsync first so the read sees the durable state
        // (required under `FsyncPolicy::Periodic`).
        let live_floor: BTreeMap<SessionId, u64> = if need_live_disk_merge {
            if let Some(h) = g.handle.as_ref() {
                h.sync_data()?;
                g.last_fsync = Instant::now();
            }
            match std::fs::read(&path) {
                Ok(raw) if raw.starts_with(super::codec::MAGIC_V1) => {
                    super::codec::replay_v1(&raw, &path)?
                }
                Ok(_) => BTreeMap::new(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
                Err(e) => return Err(e.into()),
            }
        } else {
            BTreeMap::new()
        };
        let mut tmp_handle = OpenOptions::new().append(true).read(true).open(&tmp_path)?;
        if need_live_disk_merge {
            // Compose the final delta set:
            // (a) per-session max over (in-mem `by_session`, live disk
            //     floor) — captures every bump that landed during phase
            //     2, including ones for sessions that have since been
            //     evicted from the in-mem mirror.
            // (b) any session whose final value strictly exceeds the
            //     phase-2 snapshot value gets a delta record (redundant
            //     records are harmless — `replay_v1` takes the max per
            //     id).
            let mut final_floor: BTreeMap<SessionId, u64> = live_floor;
            for (id, &seq) in &g.by_session {
                final_floor
                    .entry(id.clone())
                    .and_modify(|cur| {
                        if seq > *cur {
                            *cur = seq;
                        }
                    })
                    .or_insert(seq);
            }
            for (id, &final_seq) in &final_floor {
                let phase2_seq = snapshot.get(id).copied().unwrap_or(0);
                if final_seq > phase2_seq {
                    let record = encode_record(id, final_seq);
                    tmp_handle.write_all(&record)?;
                }
            }
        } else {
            // Fast path (no evictions since last compaction): the
            // in-mem map is the authoritative record of every bump
            // that happened during phase 2. Original pre-Perf-8
            // delta-iteration logic.
            for (id, &cur_seq) in &g.by_session {
                let snap_seq = snapshot.get(id).copied().unwrap_or(0);
                if cur_seq > snap_seq {
                    let record = encode_record(id, cur_seq);
                    tmp_handle.write_all(&record)?;
                }
            }
        }
        // Single fsync covers the entire delta append.
        tmp_handle.sync_data()?;
        // Drop the tempfile handle BEFORE the rename — on Windows a
        // rename over an open file fails; on Unix we want a clean
        // tempfile-side handle drop so the kernel can recycle the fd.
        drop(tmp_handle);
        #[cfg(test)]
        maybe_crash(CrashPoint::AfterDeltasBeforeRename);

        // === Phase 3b (lock held): atomic rename ===
        // Drop the live append handle before the rename so we don't
        // hold an open fd into the soon-to-be-replaced inode.
        g.handle = None;
        // Atomic rename: POSIX guarantees this is a single observable
        // step. After this line the journal file IS the snapshot +
        // deltas file we just fsync'd. Crash here-or-after leaves
        // the canonical path holding a durable, complete journal.
        fs::rename(&tmp_path, &path)?;
        #[cfg(test)]
        maybe_crash(CrashPoint::AfterRename);
        // fsync the parent directory so the rename itself is durable
        // (otherwise a power-loss could leave the dirent stale).
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        // Reopen the append handle on the freshly-swapped file.
        let handle = OpenOptions::new().append(true).read(true).open(&path)?;
        let size = handle.metadata()?.len();
        g.handle = Some(handle);
        g.file_size = size;
        g.last_fsync = Instant::now();
        // Perf-8: phase 3a's disk-merge has captured every evicted
        // session's floor; the new on-disk journal is now a complete
        // snapshot. Reset the flag — the next compaction can skip
        // the slow path until another eviction lands.
        g.evictions_since_compaction = false;
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
pub(crate) fn compacting_tempfile_path(journal_path: &Path) -> PathBuf {
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
fn write_v1_snapshot_at(dest: &Path, by_session: &BTreeMap<SessionId, u64>) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt_journal::codec::{replay_v1, RECORD_SIZE};
    use crate::receipt_journal::{JournalError, ReceiptJournal};
    use std::time::Duration;

    fn id(b: u8) -> SessionId {
        SessionId::new([b; 32])
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

    /// `compact()` on an in-memory journal is a no-op.
    #[test]
    fn compact_in_memory_is_noop() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(1), 5).unwrap();
        j.compact().unwrap();
        assert_eq!(j.floor(&id(1)), 5);
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

        // A fresh open must agree — the delta-replay phase persists
        // the post-snapshot bumps. Drop the writer first to flush.
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
        assert!(!tmp_path.exists(), "open() must scrub orphan tempfile");
        assert_eq!(r.floor(&id(0xAA)), 5);
        assert_eq!(r.floor(&id(0xBB)), 9, "both bumps must survive");
    }

    /// Regression target: `bump()` stays O(1) at the auto-compaction
    /// watermark because the slow snapshot-write runs on a tokio
    /// task, not under the journal lock. We assert wall-clock + p50
    /// smoke checks rather than a tight p99 (fsync floors on macOS/
    /// network FS hosts make a tight target unstable).
    ///
    /// **The p50 budget below (30ms) is deliberately loose.** The
    /// thing under test is "compaction does not block bumps" — i.e.
    /// the wall-clock budget at the top of the assertion block,
    /// which would be `n_tasks × compaction_cost` if compaction
    /// serialised under the lock. The per-bump p50 is a *secondary*
    /// signal: a regression that put compaction back under the lock
    /// would push p50 into the hundreds-of-milliseconds range, not
    /// the tens. Shared CI runners (especially the GitHub-hosted
    /// `ubuntu-latest` fleet) see scheduling jitter that pushes
    /// honest-but-slow runs into the 15-25 ms range under contention
    /// with sibling tests (the Perf-8 eviction suite landed alongside
    /// this fix and adds disk contention from the
    /// `compaction_interacts_correctly_with_eviction` +
    /// `eviction_under_concurrent_bumps_preserves_monotonicity`
    /// tests that run in parallel under `cargo test`). audit-10 R3
    /// measured 1/10 fail rate at the old 5ms target on shared
    /// runners; the Fix-4 audit independently observed 14.57ms on a
    /// contended host; Perf-8 measurements observed up to ~27ms in
    /// the worst contended cases. Widening the budget keeps the
    /// regression signal without flaking — a true regression
    /// (compaction back under the lock) blows through 30ms by an
    /// order of magnitude.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn auto_compaction_does_not_block_bumps() {
        use crate::receipt_journal::FsyncPolicy;
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

        // Smoke check #1: total wall in a sane budget. A serialising
        // compaction path would be wall ≥ n_tasks × compaction_cost.
        assert!(
            wall < Duration::from_secs(10),
            "auto-compaction blocked bumps: wall={wall:?} \
             p50={p50:?} p99={p99:?} max={max:?}"
        );
        // Smoke check #2: median bump latency below the fsync floor —
        // most bumps don't touch disk under the lock at all. See the
        // docstring above for why this budget is 30ms (shared-runner
        // scheduling jitter + Perf-8 sibling-test disk contention)
        // and not a tight per-bump latency target.
        assert!(
            p50 < Duration::from_millis(30),
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

    // -------------------------------------------------------------
    // B-1 fix: crash-injection tests for the new atomicity contract.
    //
    // The shape: drive `compact_async_worker` synchronously (via a
    // tokio spawn_blocking task) with `CRASH_AT` set to a specific
    // phase. The injection panics from inside the spawn-blocking
    // task — tokio catches the panic and returns `Err(JoinError)`
    // to the awaiter. After the join error, we simulate "fresh boot"
    // by dropping the journal and reopening from disk; the new state
    // must satisfy the contract for that crash point.
    //
    // Because `CRASH_AT` is a thread-local, we install it inside the
    // spawn-blocking closure itself rather than on the test thread.
    // -------------------------------------------------------------

    /// Helper: drive a single async compaction with a crash injection.
    /// Returns once the worker has either completed or panicked.
    /// The returned `Option` is `Some(result)` if the worker ran to
    /// completion (no crash), or `None` if the worker panicked.
    async fn compact_with_crash_at(
        j: &Arc<ReceiptJournal>,
        crash_at: CrashPoint,
    ) -> Option<JournalResult<()>> {
        // We can't reuse the public `compact_async` because we need
        // to install the crash injection on the worker thread. Build
        // the equivalent by hand, calling the worker directly.
        let (snapshot, path) = {
            let mut g = j.inner.lock();
            assert!(g.path.is_some(), "crash tests require a persistent journal");
            assert!(
                !g.compaction_inflight,
                "another compaction is already in flight"
            );
            g.compaction_inflight = true;
            (g.by_session.clone(), g.path.clone().unwrap())
        };
        let inner = j.inner.clone();
        let h: tokio::task::JoinHandle<JournalResult<()>> =
            tokio::task::spawn_blocking(move || {
                CRASH_AT.with(|c| c.set(Some(crash_at)));
                let r = compact_async_worker(&inner, &snapshot, &path);
                // Ensure inject is cleared even if the worker didn't
                // hit it (defensive).
                CRASH_AT.with(|c| c.set(None));
                r
            });
        match h.await {
            Ok(r) => Some(r),
            Err(e) => {
                // A panic in the worker: ensure the inflight flag is
                // cleared (the worker's deferred clear didn't run).
                j.inner.lock().compaction_inflight = false;
                assert!(e.is_panic(), "expected panic, got {e:?}");
                None
            }
        }
    }

    /// B-1 contract: a crash after deltas are written + fsync'd into
    /// the tempfile but BEFORE the atomic rename leaves the **pre-
    /// compaction** journal at the authoritative path. The next
    /// `open()` must replay the full pre-compaction file, including
    /// the bumps that landed during phase 2 (which were appended to
    /// the LIVE journal under the lock — i.e. the file we did NOT
    /// rename over yet).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn phase_3a_crash_leaves_pre_compaction_journal_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phase3a.bin");
        let j = Arc::new(ReceiptJournal::open(&path).unwrap());
        // Bumps before compaction starts. These are in the
        // pre-compaction file at `path`.
        for s in 0..5u8 {
            j.bump(&id(s), 1).unwrap();
        }
        let pre_size = j.file_size();

        // Inject crash at AfterDeltasBeforeRename.
        let res = compact_with_crash_at(&j, CrashPoint::AfterDeltasBeforeRename).await;
        assert!(res.is_none(), "worker should have panicked");

        // Drop the in-memory journal and reopen from disk to model a
        // process restart.
        drop(j);
        let r = ReceiptJournal::open(&path).unwrap();
        // All pre-compaction bumps must be present.
        for s in 0..5u8 {
            assert_eq!(r.floor(&id(s)), 1, "pre-compaction floor for {s:#x}");
        }
        // The file at `path` is the pre-compaction file — same size
        // as before the crash (open() unlinks the orphan tempfile but
        // doesn't touch the authoritative journal).
        assert_eq!(
            r.file_size(),
            pre_size,
            "pre-compaction journal must be untouched on phase-3a crash"
        );
    }

    /// B-1 contract: a crash IMMEDIATELY after the atomic rename
    /// leaves the **post-compaction** journal at the authoritative
    /// path. The tempfile (which is now `<path>` after the rename)
    /// holds the snapshot + deltas fully durable. Next `open()` must
    /// recover all entries with no loss.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn phase_3b_crash_leaves_post_compaction_journal_intact_with_deltas() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phase3b.bin");
        let j = Arc::new(ReceiptJournal::open(&path).unwrap());
        // Pre-compaction bumps.
        for s in 0..5u8 {
            j.bump(&id(s), 7).unwrap();
        }
        // Inject crash at AfterRename.
        let res = compact_with_crash_at(&j, CrashPoint::AfterRename).await;
        assert!(res.is_none(), "worker should have panicked");

        // Reopen and assert all pre-compaction floors survive in the
        // post-compaction file.
        drop(j);
        let tmp_path = compacting_tempfile_path(&path);
        assert!(
            !tmp_path.exists(),
            "tempfile name is now the journal (rename succeeded)"
        );
        let r = ReceiptJournal::open(&path).unwrap();
        for s in 0..5u8 {
            assert_eq!(r.floor(&id(s)), 7);
        }
        // File is compacted: header + 5 records (one per session).
        assert_eq!(r.file_size(), 8 + 5 * RECORD_SIZE as u64);
    }

    /// B-1: a bump that arrives during phase 3 (lock held by worker)
    /// is forced to wait for the lock and then writes to the
    /// post-rename file. The post-compaction journal therefore
    /// includes it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_bump_during_phase_3_lands_in_post_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phase3-concurrent.bin");
        let j = Arc::new(ReceiptJournal::open(&path).unwrap());
        // Pre-compaction bumps.
        for s in 0..3u8 {
            j.bump(&id(s), 1).unwrap();
        }
        // Start a compaction. While the worker is in phase 2 (off
        // lock, writing tempfile), fire bumps that update the in-mem
        // map; phase 3 must capture them as deltas in the tempfile.
        let h = j.compact_async();
        // We can't deterministically interleave without a sync hook;
        // instead, fire many bumps and rely on the BTreeMap delta
        // computation in phase 3 to pick up whatever made it in.
        for s in 0..3u8 {
            let j2 = j.clone();
            tokio::task::spawn_blocking(move || {
                for seq in 2..=50u64 {
                    j2.bump(&id(s), seq).unwrap();
                }
            })
            .await
            .unwrap();
        }
        h.await.unwrap().unwrap();

        // In-mem and on-disk floors must both reflect the latest
        // bump for each session.
        for s in 0..3u8 {
            assert_eq!(j.floor(&id(s)), 50);
        }
        drop(j);
        let r = ReceiptJournal::open(&path).unwrap();
        for s in 0..3u8 {
            assert_eq!(
                r.floor(&id(s)),
                50,
                "delta record for {s:#x} must be in the post-compaction file"
            );
        }
    }

    /// B-1: under crash injection at every phase, the on-disk floor
    /// for a session NEVER regresses below a value the daemon
    /// ack'd before the compaction started. Models the slashable
    /// invariant: an attacker forcing a restart cannot make us
    /// resign at an earlier seq.
    #[test]
    fn compaction_never_regresses_floor_under_crash() {
        // Standalone-runtime test (avoid #[tokio::test] so we can
        // build a fresh runtime per iteration and tear it down).
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        // Try all three crash points in a loop with varying bump
        // patterns. The floor for each session must be >= the
        // value we ack'd before the crash.
        let crash_points = [
            CrashPoint::AfterPhase2Snapshot,
            CrashPoint::AfterDeltasBeforeRename,
            CrashPoint::AfterRename,
        ];
        for crash_at in crash_points {
            for &acked_floor in &[1u64, 5, 50] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir
                    .path()
                    .join(format!("regress-{crash_at:?}-{acked_floor}.bin"));
                let j = Arc::new(ReceiptJournal::open(&path).unwrap());
                // Ack the floor.
                for s in 0..3u8 {
                    for n in 1..=acked_floor {
                        j.bump(&id(s), n).unwrap();
                    }
                }
                // Crash mid-compaction.
                let _ = runtime.block_on(compact_with_crash_at(&j, crash_at));
                drop(j);
                // Reopen and verify.
                let r = ReceiptJournal::open(&path).unwrap();
                for s in 0..3u8 {
                    assert!(
                        r.floor(&id(s)) >= acked_floor,
                        "floor regressed for {s:#x} under {crash_at:?}: \
                         got {}, expected >= {acked_floor}",
                        r.floor(&id(s))
                    );
                }
            }
        }
    }

    /// B-1: a leftover `<journal>.compacting` orphan from a phase-2
    /// crash gets removed by the next `open()`. The authoritative
    /// journal is unchanged.
    #[test]
    fn compacting_tempfile_orphan_removed_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("orphan-after-p2.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        for s in 0..3u8 {
            j.bump(&id(s), 11).unwrap();
        }
        let live_size = j.file_size();
        drop(j);

        // Fabricate a phase-2 orphan: a well-formed v1 snapshot of a
        // strictly-stale state (only id(0) at seq=11 — missing id(1),
        // id(2)). This is what a phase-2 crash *could* leave: the
        // snapshot was taken under the lock, before the other bumps,
        // and then the worker died before phase 3.
        let tmp_path = compacting_tempfile_path(&path);
        let mut stale_snap = MAGIC_V1.to_vec();
        stale_snap.extend_from_slice(&encode_record(&id(0), 11));
        fs::write(&tmp_path, &stale_snap).unwrap();
        assert!(tmp_path.exists());

        // Open the journal: the orphan is removed, the live journal
        // is untouched, all original bumps survive.
        let r = ReceiptJournal::open(&path).unwrap();
        assert!(!tmp_path.exists(), "open() must scrub the orphan");
        assert_eq!(r.file_size(), live_size);
        for s in 0..3u8 {
            assert_eq!(r.floor(&id(s)), 11);
        }
    }

    /// B-1: a tampered post-compaction journal (CRC byte flipped)
    /// is detected by codec validation on the next open — we MUST
    /// NOT silently accept a corrupt journal that an attacker has
    /// edited on disk to lower the floor.
    #[test]
    fn crc_failures_on_corrupted_post_compaction_journal_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("post-corrupt.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        for s in 0..3u8 {
            j.bump(&id(s), 9).unwrap();
        }
        // Compact synchronously to get a small post-compaction file
        // whose layout we know byte-for-byte: 8 bytes magic + 3 * 44
        // bytes records.
        j.compact().unwrap();
        drop(j);

        // Sanity-check the file size matches the post-compaction
        // expectation; also confirm a clean replay works first.
        let raw = fs::read(&path).unwrap();
        assert_eq!(raw.len(), 8 + 3 * RECORD_SIZE);
        let _ = replay_v1(&raw, &path).unwrap();

        // Flip a bit inside the seq field of the FIRST record (after
        // the 8-byte magic, skipping 32 bytes of session id).
        let mut tampered = raw;
        let seq_offset_first_record = MAGIC_V1.len() + 32;
        tampered[seq_offset_first_record] ^= 0x01;
        fs::write(&path, &tampered).unwrap();

        // The next open must surface ChecksumMismatch — silently
        // accepting the tampered seq would regress the floor and
        // expose us to slash_double_sign.
        let err = ReceiptJournal::open(&path).unwrap_err();
        assert!(
            matches!(err, JournalError::ChecksumMismatch { .. }),
            "expected ChecksumMismatch, got {err:?}"
        );
    }
}
