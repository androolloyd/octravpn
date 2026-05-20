//! Synchronous + asynchronous journal compaction.
//!
//! * [`compact_locked`] — synchronous. Caller holds the inner lock.
//!   Rewrites the journal atomically (tempfile → rename → fsync).
//! * [`compact_async_worker`] — runs the slow snapshot-write off the
//!   journal lock, then reacquires for the bounded atomic swap +
//!   delta replay. Keeps `bump` hot-path O(1) at the watermark.
//!
//! See `README.md` ("Atomicity contract") for the per-phase crash
//! semantics.

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

/// Synchronous compaction routine. The lock is held by the caller;
/// this rewrites the journal in place via tempfile + rename and
/// re-opens the append handle.
pub(crate) fn compact_locked(g: &mut Inner) -> JournalResult<()> {
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
pub(crate) fn compact_async_worker(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt_journal::codec::RECORD_SIZE;
    use crate::receipt_journal::ReceiptJournal;
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
        // most bumps don't touch disk under the lock at all.
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
}
