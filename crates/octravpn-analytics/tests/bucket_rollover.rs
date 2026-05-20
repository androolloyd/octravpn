//! Bucket-rollover / cap-eviction / late-arrival tests for the analytics
//! indexer. These complement the inline `bucket::tests` module; the focus
//! here is **boundary behaviour** and the contract the `IndexerState`
//! upholds when events arrive out of order or evict older buckets.

use octravpn_analytics::{
    bucket::{BucketSeries, BucketWidth},
    event::AnalyticsEvent,
    indexer::{metric, Indexer},
};

// ─────────────────────────────────────────────────────────────────────────
// 1. Bucket boundary: width_secs - 1 and width_secs go to different buckets
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn bucket_boundary_t_minus_one_and_t_split_into_separate_buckets() {
    // The boundary contract: ts = (width - 1) and ts = width land in
    // adjacent buckets, never the same one. We exercise every width.
    for w in BucketWidth::all() {
        let mut s = BucketSeries::default();
        let secs = w.seconds();
        s.add(w, secs - 1, 1);
        s.add(w, secs, 1);
        assert_eq!(s.len(), 2, "width {w:?} should produce 2 buckets");
        let series = s.series();
        assert_eq!(series[0].0, 0, "first bucket starts at 0 for {w:?}");
        assert_eq!(series[1].0, secs, "second bucket at width boundary {w:?}");
        assert_eq!(series[0].1, 1);
        assert_eq!(series[1].1, 1);
    }
}

#[test]
fn bucket_boundary_exact_multiples_are_floor_of_themselves() {
    // For every multiple of width, the bucket_start function must be the
    // identity — this is a regression guard against off-by-one floor bugs.
    for w in BucketWidth::all() {
        let secs = w.seconds();
        for k in 0..4u64 {
            assert_eq!(w.bucket_start(k * secs), k * secs);
            assert_eq!(w.bucket_start(k * secs + 1), k * secs);
            if k * secs > 0 {
                assert_eq!(w.bucket_start(k * secs - 1), (k - 1) * secs);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Late arrival: event with ts=N delivered 5s later still lands in the
//    bucket for ts=N — and the freshness gauge MUST NOT roll backwards.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn late_arriving_event_back_fills_bucket_without_resetting_freshness() {
    let idx = Indexer::new();
    // First receive an event at ts = 1000.
    idx.state.ingest(&AnalyticsEvent::SessionOpen {
        ts_unix: 1000,
        session_id: "a".into(),
    });
    let freshness_after_first = idx.state.last_event_ts();
    assert_eq!(freshness_after_first, 1000);

    // Then a late event arrives whose ts is 5 seconds older.
    idx.state.ingest(&AnalyticsEvent::SessionOpen {
        ts_unix: 995,
        session_id: "b".into(),
    });

    // Freshness gauge must NOT roll backwards.
    assert_eq!(
        idx.state.last_event_ts(),
        1000,
        "last_event_ts must be monotonic"
    );

    // The late event must back-fill bucket [960, 1020) at 1m width.
    let s = idx.state.series(metric::SESSIONS_OPENED, BucketWidth::OneMinute);
    let totals: u64 = s.iter().map(|(_, v)| *v).sum();
    assert_eq!(totals, 2, "both events accounted for");
    // Both fall into the same 1m bucket [960, 1020).
    assert_eq!(s.len(), 1, "ts 995 and 1000 share the same 1m bucket");
    assert_eq!(s[0].0, 960);
}

#[test]
fn late_arrival_into_distinct_bucket_back_fills_correctly() {
    let idx = Indexer::new();
    idx.state.ingest(&AnalyticsEvent::SessionOpen {
        ts_unix: 1200, // bucket [1200, 1260)
        session_id: "a".into(),
    });
    // Late event from a different bucket.
    idx.state.ingest(&AnalyticsEvent::SessionOpen {
        ts_unix: 30, // bucket [0, 60)
        session_id: "b".into(),
    });

    let s = idx.state.series(metric::SESSIONS_OPENED, BucketWidth::OneMinute);
    assert_eq!(s.len(), 2);
    assert_eq!(s[0], (0, 1));
    assert_eq!(s[1], (1200, 1));
    // Monotonic freshness.
    assert_eq!(idx.state.last_event_ts(), 1200);
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Cap eviction: > cap_buckets buckets evicts oldest; queries against
//    the evicted timestamp return null/empty per the documented retention
//    semantics.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn cap_eviction_drops_oldest_bucket_when_exceeded() {
    let mut s = BucketSeries::default();
    let w = BucketWidth::OneMinute;
    let cap = w.cap_buckets();
    // Insert cap + 1 distinct buckets — exactly one eviction.
    for i in 0..=(cap as u64) {
        s.add(w, i * 60, 1);
    }
    assert_eq!(s.len(), cap);
    // The oldest survivor is bucket #1 (start = 60), not #0.
    let first = s.series()[0].0;
    assert_eq!(first, 60);
    // Querying the evicted bucket's exact range returns empty.
    let evicted = s.series_in(0, 60);
    assert!(
        evicted.is_empty(),
        "evicted bucket must not appear in query"
    );
}

#[test]
fn cap_eviction_240_buckets_at_1m_drops_origin() {
    // The 1m width has cap=240. After exactly 240 buckets we are at the
    // cap; the 241st kicks the origin point out.
    let mut s = BucketSeries::default();
    let w = BucketWidth::OneMinute;
    for i in 0..240u64 {
        s.add(w, i * 60, 1);
    }
    assert_eq!(s.len(), 240);
    assert_eq!(s.series()[0].0, 0, "still holding origin");
    // One more — origin point evicted.
    s.add(w, 240 * 60, 1);
    assert_eq!(s.len(), 240);
    assert_eq!(s.series()[0].0, 60);
    // Query for the evicted ts: no bucket at start=0 anymore.
    let q = s.series_in(0, 1);
    assert!(q.is_empty(), "query for evicted origin returns null");
}

#[test]
fn cap_eviction_indexer_wide_evicts_per_metric() {
    // End-to-end through `IndexerState.bump`: the indexer fans out into
    // every width, and the 1m width is the first to evict.
    let idx = Indexer::new();
    let w = BucketWidth::OneMinute;
    let cap = w.cap_buckets() as u64;
    for i in 0..(cap + 3) {
        idx.state.ingest(&AnalyticsEvent::SessionOpen {
            ts_unix: i * 60,
            session_id: format!("s{i}"),
        });
    }
    // total_events should be cap+3; series at 1m capped at cap.
    assert_eq!(idx.state.total_events(), cap + 3);
    let s = idx.state.series(metric::SESSIONS_OPENED, w);
    assert_eq!(s.len() as u64, cap);
    assert_eq!(s[0].0, 3 * 60, "3 oldest buckets evicted");
}

// ─────────────────────────────────────────────────────────────────────────
// 4. Bucket coalescing of multi-event bursts.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn many_events_in_same_minute_coalesce_to_one_bucket() {
    let mut s = BucketSeries::default();
    for ts in 0..60u64 {
        s.add(BucketWidth::OneMinute, ts, 1);
    }
    assert_eq!(s.len(), 1);
    assert_eq!(s.latest(), 60);
    assert_eq!(s.total(), 60);
}

#[test]
fn bytes_settled_delta_across_three_receipts() {
    // Regression: the de-dup logic must credit (500, 500, 1000) = 2000
    // across three monotonically-rising receipts with watermarks
    // (500, 1000, 2000).
    let idx = Indexer::new();
    let session_id = "session-x".to_string();
    let watermarks = [500u64, 1000, 2000];
    for (i, w) in watermarks.iter().enumerate() {
        idx.state.ingest(&AnalyticsEvent::ReceiptSigned {
            ts_unix: 100 + i as u64,
            session_id: session_id.clone(),
            seq: i as u64 + 1,
            bytes_used: *w,
        });
    }
    assert_eq!(
        idx.state.total(metric::BYTES_SETTLED, BucketWidth::OneMinute),
        2000,
    );
    assert_eq!(
        idx.state.total(metric::RECEIPTS_SIGNED, BucketWidth::OneMinute),
        3,
    );
}

#[test]
fn bytes_settled_multi_session_isolated_counters() {
    // Two sessions with overlapping seqs — each session's bytes_used is
    // tracked independently.
    let idx = Indexer::new();
    for (sid, watermarks) in &[("a", [100u64, 300]), ("b", [50, 80])] {
        for (i, w) in watermarks.iter().enumerate() {
            idx.state.ingest(&AnalyticsEvent::ReceiptSigned {
                ts_unix: 1000 + i as u64,
                session_id: (*sid).to_string(),
                seq: i as u64 + 1,
                bytes_used: *w,
            });
        }
    }
    // a: 100 + 200 = 300; b: 50 + 30 = 80. Total credited = 380.
    assert_eq!(
        idx.state.total(metric::BYTES_SETTLED, BucketWidth::OneMinute),
        380,
    );
    assert_eq!(
        idx.state.total(metric::RECEIPTS_SIGNED, BucketWidth::OneMinute),
        4,
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 5. Cross-width fanout invariant.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn cross_width_totals_are_equal_within_retention_window() {
    // For any event timestamp inside ALL retention windows, the total
    // counter at each width must agree (because each event is fanned out
    // once per width).
    let idx = Indexer::new();
    for i in 0..10u64 {
        idx.state.ingest(&AnalyticsEvent::SessionOpen {
            ts_unix: i * 60,
            session_id: format!("s{i}"),
        });
    }
    let t = idx
        .state
        .total(metric::SESSIONS_OPENED, BucketWidth::OneMinute);
    assert_eq!(t, 10);
    for w in BucketWidth::all() {
        assert_eq!(idx.state.total(metric::SESSIONS_OPENED, w), 10);
    }
}

#[test]
fn empty_series_for_unknown_metric_or_width() {
    let idx = Indexer::new();
    // Nothing ingested: series is empty for every width.
    for w in BucketWidth::all() {
        assert!(idx.state.series("sessions_opened", w).is_empty());
        assert_eq!(idx.state.total("sessions_opened", w), 0);
    }
    // Unknown metric: empty.
    assert!(idx
        .state
        .series("totally-bogus-metric", BucketWidth::OneMinute)
        .is_empty());
}
