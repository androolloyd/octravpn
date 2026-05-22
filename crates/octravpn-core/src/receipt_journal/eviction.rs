//! Perf-8 (audit-8 OOM-1): in-mem mirror eviction policy.
//!
//! The journal's `by_session` BTreeMap is a cache of the durable
//! on-disk floor — without bounds, every session ever opened on the
//! node lives in it until process restart (88 B/entry × N forever,
//! which at 1M unique sessions is ~88 MB and at 100M is ~8.8 GB). This
//! module implements:
//!
//! 1. **Cap-overflow LRU eviction**: when `by_session.len()` exceeds
//!    `max_in_mem_sessions` after a bump, we pop the oldest
//!    `(last_seen, id)` from `lru_index` and drop the corresponding
//!    `by_session` entry. The evicted session_id is recorded in the
//!    bounded `recently_evicted` LRU so subsequent bumps know to
//!    consult disk (rather than treating it as a first-touch).
//!
//! 2. **TTL sweep**: a background task calls `sweep_ttl` on a timer
//!    (default 60 s). Any entry whose `last_seen` is older than
//!    `session_in_mem_ttl` is evicted, even if the mirror is below
//!    cap.
//!
//! 3. **Disk resurrect on miss**: a bump whose `session_id` is not in
//!    `by_session` BUT is in `recently_evicted` must read the durable
//!    on-disk state to recover the floor before the monotonicity
//!    check. **This is the load-bearing equivocation defence**: an
//!    attacker who forces an eviction (e.g. by flooding unique
//!    `session_id`s to overflow the cap) and then replays an earlier
//!    seq for the evicted session MUST be rejected by the on-disk
//!    floor, not silently allowed because the in-mem `prev = 0`.
//!
//! ## Hot-path cost
//!
//! Per-bump bookkeeping is `O(log n)`:
//! - `last_seen.insert/remove` — `HashMap` O(1) amortised
//! - `lru_index.insert/remove` — `BTreeSet<(Instant, SessionId)>`
//!   `O(log n)`. With n ≤ `max_in_mem_sessions = 100_000`,
//!   `log₂(100k) ≈ 17` comparisons per op — ~50 ns total. The
//!   journal fsync dominates by 4-5 orders of magnitude.
//!
//! ## Resurrect cost
//!
//! Worst-case `O(file_size / RECORD_SIZE)` linear scan of the journal
//! file, capped by the compaction watermark (10 MB / 44 B = ~240k
//! records). On warm-page-cache: ~5-10 ms per scan. On cold disk:
//! up to ~50 ms (one disk seek + sequential read).
//!
//! ## Why `BTreeSet<(Instant, SessionId)>` and not a linked-list LRU?
//!
//! A doubly-linked LRU would give O(1) bump bookkeeping but at the
//! cost of unsafe pointer-juggling or an `indexmap`-shaped crate. The
//! `BTreeSet` approach is `O(log n)` per bump — fine, because the
//! bump path is gated by fsync (~10 µs minimum on tmpfs, ~1 ms on a
//! real SSD), and the eviction path is cold. The auxiliary memory is
//! ~1.5× the primary `by_session` cost.

use std::{
    collections::BTreeMap,
    fs,
    sync::{atomic::Ordering, Arc},
    time::Instant,
};

use parking_lot::Mutex;

use crate::session::SessionId;

use super::codec::replay_v1;
use super::errors::{JournalError, JournalResult};
use super::inner::Inner;

/// Cap-overflow LRU eviction. Caller holds the lock. Pops the oldest
/// `(last_seen, id)` from `lru_index` until `by_session.len() <=
/// max_in_mem_sessions`. Each popped id is recorded in
/// `recently_evicted` + the metrics counter is bumped.
///
/// The cap is enforced *after* the bump path inserts into
/// `by_session`, so the freshly-bumped entry is at the head of the
/// LRU (just inserted with `Instant::now()`) and can never be the one
/// evicted. This is the property the
/// `mirror_cap_holds_under_burst_of_unique_sessions` test pins.
pub(super) fn enforce_cap_locked(g: &mut Inner) {
    while g.by_session.len() > g.max_in_mem_sessions {
        // `pop_first` on the BTreeSet gives the lexicographically
        // earliest `(Instant, SessionId)` — i.e. the oldest entry.
        // If two entries share an `Instant`, the SessionId tiebreak
        // is deterministic but arbitrary; either is a valid eviction
        // target.
        let Some((seen, id)) = g.lru_index.iter().next().cloned() else {
            break;
        };
        // Remove the LRU index entry first, then the `by_session`
        // entry, so the gauge update in `record_eviction` sees the
        // post-eviction len.
        g.lru_index.remove(&(seen, id.clone()));
        g.by_session.remove(&id);
        g.record_eviction(&id);
    }
}

/// TTL sweep. Returns the number of entries evicted. Called by the
/// background sweeper (`ReceiptJournal::spawn_ttl_sweeper`) on a
/// timer, and directly by tests. Scans the `lru_index` head-forward;
/// stops as soon as it finds an entry whose recency is younger than
/// the TTL (the BTreeSet is sorted by `Instant`, so everything past
/// that point is also younger).
pub(super) fn sweep_ttl(inner: &Arc<Mutex<Inner>>) -> usize {
    let now = Instant::now();
    let mut g = inner.lock();
    let ttl = g.session_in_mem_ttl;
    let mut evicted = 0usize;
    loop {
        let head = g.lru_index.iter().next().cloned();
        let Some((seen, id)) = head else { break };
        if now.duration_since(seen) < ttl {
            // The head of the LRU is still within TTL; everything
            // after it is too. Stop.
            break;
        }
        g.lru_index.remove(&(seen, id.clone()));
        g.by_session.remove(&id);
        g.record_eviction(&id);
        evicted += 1;
    }
    g.update_gauge();
    evicted
}

/// Disk-resurrect: read the durable on-disk journal and return the
/// floor for `session_id`. Re-populates `by_session` + the recency
/// indices so subsequent bumps in the same burst hit the cache. Bumps
/// the `disk_resurrect_total` counter on success.
///
/// **Durability contract**: the read MUST see the durable post-fsync
/// state, not the in-flight page-cache state. Under
/// `FsyncPolicy::Periodic` an attacker could otherwise wait for the
/// in-mem mirror to evict an entry, replay a seq that's in the page
/// cache but not yet fsync'd, and slip past the monotonicity check.
/// To avoid that, we force a `sync_data` before the read whenever any
/// receipts have landed since the last fsync.
pub(super) fn resurrect_floor_from_disk(
    g: &mut Inner,
    session_id: &SessionId,
) -> JournalResult<u64> {
    let Some(path) = g.path.clone() else {
        return Ok(0);
    };
    // Durability: flush any pending writes to disk so the read below
    // sees the post-fsync state. We do this unconditionally rather
    // than tracking "pending writes since last fsync" — the
    // resurrect path is cold (gated by an in-mem miss) and a single
    // `sync_data` on a small journal file is sub-millisecond on
    // warm SSDs.
    if let Some(h) = g.handle.as_ref() {
        h.sync_data().map_err(JournalError::from)?;
        g.last_fsync = Instant::now();
    }
    let raw = fs::read(&path)?;
    // `replay_v1` returns `BTreeMap<SessionId, u64>` of the highest
    // seq seen for each id in the file. Cheap to do — the file is
    // already bounded by the compaction watermark (10 MB ~ 240k
    // records).
    let map = if raw.is_empty() {
        BTreeMap::new()
    } else if raw.starts_with(super::codec::MAGIC_V1) {
        replay_v1(&raw, &path)?
    } else {
        // Any non-v1 prefix is a migration target (v0). The journal's
        // `open` path handles migration; we don't replay v0 from the
        // hot resurrect path. Returning 0 here would be unsafe under
        // an attacker (they could force resurrect against a v0 file),
        // so surface a clear error.
        return Err(JournalError::BadMagic {
            path: path.display().to_string(),
        });
    };
    let floor = map.get(session_id).copied().unwrap_or(0);
    // Re-populate the in-mem cache so subsequent bumps hit. Place at
    // the head of the LRU.
    let now = Instant::now();
    g.by_session.insert(session_id.clone(), floor);
    g.touch_recency(session_id, now);
    g.metrics
        .disk_resurrect_total
        .fetch_add(1, Ordering::Relaxed);
    g.update_gauge();
    // Disk-resurrect already paid for the slot — enforce the cap so
    // we don't leak above the max under a flapping-session attacker.
    enforce_cap_locked(g);
    Ok(floor)
}

/// Test-only helper: read the on-disk floor for `session_id` without
/// touching the in-mem mirror. Used by tests that want to assert the
/// disk floor independently of the in-mem cache.
#[cfg(test)]
pub(super) fn read_disk_floor(
    path: &std::path::Path,
    session_id: &SessionId,
) -> JournalResult<u64> {
    let raw = fs::read(path)?;
    if raw.is_empty() {
        return Ok(0);
    }
    if !raw.starts_with(super::codec::MAGIC_V1) {
        return Err(JournalError::BadMagic {
            path: path.display().to_string(),
        });
    }
    let map = replay_v1(&raw, path)?;
    Ok(map.get(session_id).copied().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt_journal::ReceiptJournal;
    use std::time::Duration;

    fn id(b: u8) -> SessionId {
        SessionId::new([b; 32])
    }

    /// LRU evicts the least recently bumped entry on cap overflow.
    /// Bump sessions A, B, C with cap=2; expect A evicted.
    #[test]
    fn eviction_lru_evicts_least_recently_bumped() {
        let j = ReceiptJournal::in_memory();
        j.set_max_in_mem_sessions(2);
        j.bump(&id(0xAA), 1).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        j.bump(&id(0xBB), 1).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        j.bump(&id(0xCC), 1).unwrap();
        // AA should have been evicted; BB and CC remain.
        let g = j.inner.lock();
        assert!(!g.by_session.contains_key(&id(0xAA)), "AA must be evicted");
        assert!(g.by_session.contains_key(&id(0xBB)), "BB must remain");
        assert!(g.by_session.contains_key(&id(0xCC)), "CC must remain");
        assert_eq!(g.by_session.len(), 2);
    }

    /// TTL sweep evicts entries idle longer than the TTL even when
    /// the mirror is below the hard cap.
    #[test]
    fn eviction_ttl_evicts_after_idle() {
        let j = ReceiptJournal::in_memory();
        j.set_max_in_mem_sessions(100);
        j.set_session_in_mem_ttl(Duration::from_millis(50));
        j.bump(&id(0xAA), 1).unwrap();
        j.bump(&id(0xBB), 1).unwrap();
        assert_eq!(j.inner.lock().by_session.len(), 2);
        // Idle long enough to age out, then sweep.
        std::thread::sleep(Duration::from_millis(80));
        let evicted = j.sweep_ttl();
        assert_eq!(evicted, 2, "both entries should age out");
        assert_eq!(j.inner.lock().by_session.len(), 0);
        // Counter reflects the sweep.
        let (gauge, total, _) = j.metrics_snapshot();
        assert_eq!(gauge, 0);
        assert_eq!(total, 2);
    }

    /// A bump that hits an evicted session_id resurrects the floor
    /// from disk; the in-mem cache is repopulated.
    #[test]
    fn evicted_session_resurrected_from_disk_on_bump() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resurrect.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.set_max_in_mem_sessions(2);
        // Sign AA at seq=5, then evict it by flooding the cap.
        j.bump(&id(0xAA), 5).unwrap();
        j.bump(&id(0xBB), 1).unwrap();
        j.bump(&id(0xCC), 1).unwrap();
        assert!(
            !j.inner.lock().by_session.contains_key(&id(0xAA)),
            "AA must have been evicted by the cap overflow"
        );
        // floor() must still observe 5 (read from disk).
        assert_eq!(
            j.floor(&id(0xAA)),
            5,
            "evicted session floor recovered from disk"
        );
        // Resurrect counter bumped.
        let (_g, _e, resurrects) = j.metrics_snapshot();
        assert!(
            resurrects >= 1,
            "disk_resurrect_total must have incremented"
        );
    }

    /// Equivocation defence: an evicted session cannot be bumped
    /// backward. The disk floor still rejects a replay attempt.
    /// **This is the load-bearing invariant of Perf-8.**
    #[test]
    fn evicted_session_rejects_replay_attempt_via_disk_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay-reject.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.set_max_in_mem_sessions(2);
        // Sign AA at seq=10, then force eviction.
        j.bump(&id(0xAA), 10).unwrap();
        j.bump(&id(0xBB), 1).unwrap();
        j.bump(&id(0xCC), 1).unwrap();
        assert!(!j.inner.lock().by_session.contains_key(&id(0xAA)));
        // Attempt to bump AA at seq=1 (replay). Must fail via the
        // disk-resurrect path.
        let err = j.bump(&id(0xAA), 1).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
        // seq=10 (exact replay) also rejected.
        let err = j.bump(&id(0xAA), 10).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
        // seq=11 (legitimate advance) accepted.
        j.bump(&id(0xAA), 11).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 11);
        // On-disk floor reflects the new advance.
        drop(j);
        let disk_floor = read_disk_floor(&path, &id(0xAA)).unwrap();
        assert_eq!(disk_floor, 11);
    }

    /// Insert N+10 unique sessions with cap=N; assert exactly N
    /// remain. Pins the bound under burst.
    #[test]
    fn mirror_cap_holds_under_burst_of_unique_sessions() {
        const N: usize = 32;
        let j = ReceiptJournal::in_memory();
        j.set_max_in_mem_sessions(N);
        for s in 0..(N + 10) as u64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&s.to_be_bytes());
            j.bump(&SessionId::new(bytes), 1).unwrap();
        }
        let g = j.inner.lock();
        assert_eq!(g.by_session.len(), N, "mirror must be capped at N");
        // Eviction count = 10 (every bump past cap evicts one).
        let (_gauge, total, _) = (
            g.metrics
                .in_mem_sessions
                .load(std::sync::atomic::Ordering::Relaxed),
            g.metrics
                .evictions_total
                .load(std::sync::atomic::Ordering::Relaxed),
            g.metrics
                .disk_resurrect_total
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        assert_eq!(total, 10, "expected 10 evictions for N+10 inserts at cap=N");
    }

    /// Compaction interacts correctly with eviction: a session that
    /// is evicted from the in-mem mirror but still on disk must NOT
    /// be lost when compaction rewrites the journal. Compaction must
    /// merge the disk-resident floor with the in-mem map.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compaction_interacts_correctly_with_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compact-evict.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.set_max_in_mem_sessions(2);
        // Sign three sessions; the cap=2 evicts the oldest.
        j.bump(&id(0xAA), 7).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        j.bump(&id(0xBB), 11).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        j.bump(&id(0xCC), 13).unwrap();
        assert!(
            !j.inner.lock().by_session.contains_key(&id(0xAA)),
            "AA must be evicted"
        );
        // Force a compaction. The disk floor for AA (=7) MUST
        // survive — the compaction merges in-mem with disk state.
        j.compact().unwrap();
        // Drop and reopen to confirm AA's floor wasn't lost.
        drop(j);
        let r = ReceiptJournal::open(&path).unwrap();
        assert_eq!(
            r.floor(&id(0xAA)),
            7,
            "AA's disk floor must survive compaction"
        );
        assert_eq!(r.floor(&id(0xBB)), 11);
        assert_eq!(r.floor(&id(0xCC)), 13);
    }

    /// `/metrics` handler sees the gauge update after a bump.
    /// Smoke test for the gauge wiring; the Prometheus serializer is
    /// pinned in `octravpn-node`.
    #[test]
    fn metric_journal_in_mem_size_visible_on_metrics_endpoint() {
        let j = ReceiptJournal::in_memory();
        let (g0, _e0, _r0) = j.metrics_snapshot();
        assert_eq!(g0, 0);
        j.bump(&id(0xAA), 1).unwrap();
        j.bump(&id(0xBB), 1).unwrap();
        let (g1, _e1, _r1) = j.metrics_snapshot();
        assert_eq!(g1, 2);
    }

    /// Proptest-style invariant under concurrent bumps: the on-disk
    /// floor for any session must be monotonic-non-decreasing across
    /// the test, regardless of eviction interleavings. We run a
    /// modest number of randomized bumps against a small cap so
    /// evictions fire frequently, then assert the disk floor matches
    /// the highest seq we successfully bumped for each session.
    #[test]
    fn eviction_under_concurrent_bumps_preserves_monotonicity() {
        use std::collections::HashMap;
        use std::sync::Arc as StdArc;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("concurrent.bin");
        let j = StdArc::new(ReceiptJournal::open(&path).unwrap());
        j.set_max_in_mem_sessions(4);
        // Avoid fsync per call to keep the test fast — durability
        // semantics under eviction are tested separately.
        j.set_fsync_policy(crate::receipt_journal::FsyncPolicy::Periodic(
            Duration::from_secs(60),
        ));

        // Modest scale — large enough to exercise the eviction
        // interleaving but small enough not to thrash the disk in
        // parallel with the timing-sensitive
        // `auto_compaction_does_not_block_bumps` test in the sibling
        // module. CI runs both at the same time and we want the
        // timing test's 15 ms p50 budget intact.
        const SESSIONS: usize = 8;
        const BUMPS_PER_SESSION: u64 = 16;
        let mut handles = Vec::new();
        let highest: StdArc<parking_lot::Mutex<HashMap<u8, u64>>> =
            StdArc::new(parking_lot::Mutex::new(HashMap::new()));
        for s in 0..SESSIONS as u8 {
            let j = j.clone();
            let highest = highest.clone();
            handles.push(std::thread::spawn(move || {
                for n in 1..=BUMPS_PER_SESSION {
                    // Some bumps will hit a resurrect path; some will
                    // race with eviction. All must either succeed or
                    // fail with `SeqNotMonotonic` (never a panic, never
                    // a corruption error).
                    match j.bump(&id(s), n) {
                        Ok(()) => {
                            highest.lock().insert(s, n);
                        }
                        Err(JournalError::SeqNotMonotonic { .. }) => {
                            // OK — racing thread already bumped past.
                        }
                        Err(e) => panic!("unexpected journal error: {e:?}"),
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Verify: on-disk floor for each session matches the highest
        // seq we successfully bumped.
        drop(j);
        let r = ReceiptJournal::open(&path).unwrap();
        let highs = highest.lock().clone();
        for s in 0..SESSIONS as u8 {
            let want = *highs.get(&s).expect("every session got at least one bump");
            assert_eq!(
                r.floor(&id(s)),
                want,
                "disk floor for session {s} regressed under concurrent eviction"
            );
        }
    }

    /// Sweep cost stays cheap when the mirror is almost-all hot.
    /// Sanity check on the BTreeSet head-walk early-out — we should
    /// stop at the first non-aged entry, not scan the full set.
    #[test]
    fn ttl_sweep_early_exit_when_head_within_ttl() {
        let j = ReceiptJournal::in_memory();
        j.set_max_in_mem_sessions(100);
        j.set_session_in_mem_ttl(Duration::from_secs(60));
        for s in 0..50u8 {
            j.bump(&id(s), 1).unwrap();
        }
        // No entry has aged out; sweep should return 0 and not
        // touch any of the 50 entries.
        let evicted = j.sweep_ttl();
        assert_eq!(evicted, 0);
        assert_eq!(j.inner.lock().by_session.len(), 50);
    }

    /// `recently_evicted` is bounded; flooding it doesn't OOM.
    #[test]
    fn recently_evicted_lru_is_bounded() {
        let j = ReceiptJournal::in_memory();
        j.set_max_in_mem_sessions(1);
        // Bump 4096 unique sessions; each will evict the previous.
        // The recently_evicted LRU must NOT grow unbounded.
        for s in 0..4096u64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&s.to_be_bytes());
            j.bump(&SessionId::new(bytes), 1).unwrap();
        }
        let g = j.inner.lock();
        assert!(
            g.recently_evicted.len() <= super::super::DEFAULT_RECENTLY_EVICTED_CAP,
            "recently_evicted unbounded: {}",
            g.recently_evicted.len()
        );
        assert!(g.recently_evicted_set.len() <= super::super::DEFAULT_RECENTLY_EVICTED_CAP);
    }
}
