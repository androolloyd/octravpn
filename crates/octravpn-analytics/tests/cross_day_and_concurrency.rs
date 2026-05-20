//! Cross-day audit folding + concurrent ingest tests for the analytics
//! indexer.
//!
//! Spec items covered:
//!
//!   - Cross-day audit log: a fixture spanning two YYYY-MM-DD files,
//!     both get folded into the indexer; midnight rollover doesn't
//!     double-count.
//!   - Concurrent ingest: 10 ingesting tasks + 100 query tasks → no
//!     panic, eventual consistency.

use std::{
    fs::File,
    io::Write,
    path::Path,
    sync::Arc,
    thread,
};

use octravpn_analytics::{
    bucket::BucketWidth,
    chain_step,
    event::AnalyticsEvent,
    indexer::{metric, Indexer},
};
use serde_json::json;

/// Same writer as `tests/e2e_audit_replay.rs` — vendored here to keep
/// this test module self-contained.
fn write_audit_file(path: &Path, key: &[u8; 32], records: &[serde_json::Value]) {
    let mut f = File::create(path).unwrap();
    let mut prev_mac = [0u8; 32];
    for rec in records {
        let canonical = serde_json::to_string(rec).unwrap();
        let mac = chain_step(key, &prev_mac, canonical.as_bytes());
        let env = json!({
            "record_json": canonical,
            "prev_mac": hex::encode(prev_mac),
            "mac": hex::encode(mac),
        });
        writeln!(f, "{}", serde_json::to_string(&env).unwrap()).unwrap();
        prev_mac = mac;
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Cross-day audit fold.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn cross_day_audit_files_fold_into_one_indexer_without_duplication() {
    let dir = tempfile::tempdir().unwrap();
    let key = [0x55u8; 32];

    // Day 1: 3 announce events.
    let day1: Vec<serde_json::Value> = (0..3)
        .map(|i| {
            json!({
                "ts_unix": 1_700_000_000_u64 + i,
                "kind": "announce",
                "session_id": format!("s{i}"),
                "extra": null,
            })
        })
        .collect();
    // Day 2: 2 announce events.
    let day2: Vec<serde_json::Value> = (0..2)
        .map(|i| {
            json!({
                "ts_unix": 1_700_086_400_u64 + i,
                "kind": "announce",
                "session_id": format!("d2s{i}"),
                "extra": null,
            })
        })
        .collect();
    write_audit_file(&dir.path().join("audit-2023-11-14.jsonl"), &key, &day1);
    write_audit_file(&dir.path().join("audit-2023-11-15.jsonl"), &key, &day2);

    let indexer = Indexer::new();
    let scans = indexer.ingest_audit_dir(&key, dir.path()).unwrap();
    assert_eq!(scans.len(), 2);
    for s in &scans {
        assert!(
            s.is_clean(),
            "file {} broke: {:?}",
            s.path.display(),
            s.break_reason
        );
    }

    // Total events MUST be exactly 5 — no double-counting across files.
    assert_eq!(indexer.state.total_events(), 5);
    assert_eq!(
        indexer.state.total(metric::SESSIONS_OPENED, BucketWidth::OneDay),
        5,
    );
    // chain_status::verified_lines should be 5 as well.
    let cs = indexer.state.chain_status();
    assert_eq!(cs.files, 2);
    assert_eq!(cs.verified_lines, 5);
}

#[test]
fn cross_day_two_files_in_distinct_1d_buckets() {
    let dir = tempfile::tempdir().unwrap();
    let key = [0x10u8; 32];

    // Day 1 ts = unix epoch day boundary, Day 2 ts = 1 day later.
    let day1 = vec![json!({
        "ts_unix": 86_400_u64,
        "kind": "announce",
        "session_id": "a",
        "extra": null,
    })];
    let day2 = vec![json!({
        "ts_unix": 86_400_u64 + 86_400,
        "kind": "announce",
        "session_id": "b",
        "extra": null,
    })];
    write_audit_file(&dir.path().join("audit-2026-01-01.jsonl"), &key, &day1);
    write_audit_file(&dir.path().join("audit-2026-01-02.jsonl"), &key, &day2);

    let indexer = Indexer::new();
    indexer.ingest_audit_dir(&key, dir.path()).unwrap();
    // At 1d width: 2 distinct buckets.
    let series = indexer
        .state
        .series(metric::SESSIONS_OPENED, BucketWidth::OneDay);
    assert_eq!(series.len(), 2);
    assert_eq!(series[0], (86_400, 1));
    assert_eq!(series[1], (86_400 * 2, 1));
}

#[test]
fn cross_day_chain_reset_per_file_is_independent() {
    // The HMAC chain resets at midnight (each file starts from
    // zero-prev_mac). Tampering with day 1 must NOT break day 2's
    // verification.
    let dir = tempfile::tempdir().unwrap();
    let key = [0x42u8; 32];
    let day1 = vec![json!({
        "ts_unix": 1, "kind": "announce", "session_id": "a", "extra": null,
    })];
    let day2 = vec![json!({
        "ts_unix": 100, "kind": "announce", "session_id": "b", "extra": null,
    })];
    write_audit_file(&dir.path().join("audit-2026-01-01.jsonl"), &key, &day1);
    write_audit_file(&dir.path().join("audit-2026-01-02.jsonl"), &key, &day2);

    // Overwrite day 1 with a bad MAC.
    let mut f = File::create(dir.path().join("audit-2026-01-01.jsonl")).unwrap();
    writeln!(
        f,
        r#"{{"record_json":"{{}}","prev_mac":"{}", "mac":"{}"}}"#,
        "0".repeat(64),
        "f".repeat(64),
    )
    .unwrap();

    let indexer = Indexer::new();
    let scans = indexer.ingest_audit_dir(&key, dir.path()).unwrap();
    assert_eq!(scans.len(), 2);
    assert!(!scans[0].is_clean(), "day 1 should have broken");
    assert!(
        scans[1].is_clean(),
        "day 2 should verify independently of day 1"
    );
    // Day 2's event made it in; day 1's didn't.
    assert_eq!(indexer.state.total_events(), 1);
    let cs = indexer.state.chain_status();
    assert_eq!(cs.files, 2);
    // first_break refers to day 1's filename.
    assert!(cs.first_break.is_some());
    let (file, _) = cs.first_break.unwrap();
    assert!(file.contains("01-01"), "first_break should be on day 1");
}

// ─────────────────────────────────────────────────────────────────────────
// Concurrent ingest.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_ingest_10_threads_100_queries_eventually_consistent() {
    let indexer = Arc::new(Indexer::new());
    let total_events_per_writer: u64 = 100;
    let writers = 10;

    let mut handles = Vec::new();
    for w in 0..writers {
        let idx = indexer.clone();
        handles.push(thread::spawn(move || {
            for i in 0..total_events_per_writer {
                idx.state.ingest(&AnalyticsEvent::SessionOpen {
                    ts_unix: (w * 1_000) + i,
                    session_id: format!("w{w}_i{i}"),
                });
            }
        }));
    }

    // 100 concurrent query tasks — no panic, just consistency on read.
    for _q in 0..100 {
        let idx = indexer.clone();
        handles.push(thread::spawn(move || {
            // Reads must never panic mid-ingest.
            let _ = idx.state.total(metric::SESSIONS_OPENED, BucketWidth::OneMinute);
            let _ = idx.state.series(metric::SESSIONS_OPENED, BucketWidth::OneMinute);
            let _ = idx.state.total_events();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let expected = writers * total_events_per_writer;
    assert_eq!(
        indexer.state.total_events(),
        expected,
        "expected {expected} total events after all writers finished",
    );
    // The per-metric total must also match (every event was a SessionOpen).
    assert_eq!(
        indexer.state.total(metric::SESSIONS_OPENED, BucketWidth::OneDay),
        expected,
    );
}

#[test]
fn concurrent_bytes_settled_dedupe_under_contention() {
    // 8 threads, each driving its own session id through a monotonic
    // receipt sequence. Final bytes_settled = sum of each thread's last
    // bytes_used (since they're disjoint sessions).
    let indexer = Arc::new(Indexer::new());
    let mut handles = Vec::new();
    let threads = 8;
    let receipts = 20u64;
    let step = 100u64;
    for t in 0..threads {
        let idx = indexer.clone();
        handles.push(thread::spawn(move || {
            for i in 1..=receipts {
                idx.state.ingest(&AnalyticsEvent::ReceiptSigned {
                    ts_unix: 100 + i,
                    session_id: format!("sess-{t}"),
                    seq: i,
                    bytes_used: i * step,
                });
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let expected = threads as u64 * receipts * step; // 8 * 20 * 100 = 16000
    assert_eq!(
        indexer.state.total(metric::BYTES_SETTLED, BucketWidth::OneDay),
        expected,
    );
    assert_eq!(
        indexer.state.total(metric::RECEIPTS_SIGNED, BucketWidth::OneDay),
        threads as u64 * receipts,
    );
}

#[test]
fn idle_indexer_chain_status_clone_is_stable() {
    // Cheap clone of chain_status under no writers — sanity check that
    // RwLock contention can't crash on read-only paths.
    let indexer = Arc::new(Indexer::new());
    let mut handles = Vec::new();
    for _ in 0..20 {
        let idx = indexer.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                let _ = idx.state.chain_status();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let cs = indexer.state.chain_status();
    assert_eq!(cs.files, 0);
    assert!(cs.first_break.is_none());
}
