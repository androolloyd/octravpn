//! Time-bucketed counters.
//!
//! ## Design: tumbling, coalesced buckets
//!
//! We use **tumbling** (non-overlapping, fixed-width) buckets, **not**
//! sliding windows. A tumbling bucket is just `floor(ts / width) *
//! width` — there is no per-event bookkeeping beyond a `(start ->
//! counter)` map per metric per width. Queries that want a sliding
//! window pick a width, fetch the relevant tumbling buckets, and sum
//! client-side (Grafana does this with `rate()` / `sum_over_time()`).
//!
//! Sliding windows would require either per-event timestamps (O(N)
//! memory per metric) or a ring of sub-buckets — neither is worth the
//! complexity for a single-binary in-memory indexer.
//!
//! ## Retention
//!
//! Each width has a cap on the number of buckets retained (the
//! `cap_buckets` field below). Once full, the oldest bucket is
//! evicted on the next bump. The defaults give:
//!
//!   - 1m × 240    = 4 hours
//!   - 5m × 288    = 24 hours
//!   - 1h × 720    = 30 days
//!   - 1d × 365    = 1 year
//!
//! For a single node that's ~1.6k buckets per metric × ~10 metrics =
//! 16k entries — every entry is a `(u64 start, u64 counter)` pair,
//! ~32 bytes incl. BTreeMap overhead = ~500 KB. Fits comfortably in
//! process memory.
//!
//! ## Late-arriving events
//!
//! An event whose `ts_unix` falls inside a still-retained bucket
//! correctly back-fills that bucket. An event whose timestamp is
//! older than the oldest retained bucket is **silently dropped** —
//! the indexer is a process-lifetime histogram, not a database.
//! Replays from an audit log file happen at boot, before any traffic,
//! so this dropping path is benign in production.
//!
//! ## Monotonic time
//!
//! Buckets are keyed by event `ts_unix`, not wall-clock — so a clock
//! skew on the writer side can't poison the indexer. The indexer
//! itself never reads the wall clock except in
//! [`Indexer::ingested_at_unix`] for the /analytics/health endpoint.

use std::collections::BTreeMap;

/// Width of a tumbling bucket. The five resolutions we expose to
/// callers are kept as a closed enum so the URL handler can validate
/// `?bucket=` without an open-ended string parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BucketWidth {
    /// 60 seconds.
    OneMinute,
    /// 300 seconds.
    FiveMinutes,
    /// 3 600 seconds.
    OneHour,
    /// 86 400 seconds.
    OneDay,
}

impl BucketWidth {
    /// Width in seconds.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        match self {
            Self::OneMinute => 60,
            Self::FiveMinutes => 300,
            Self::OneHour => 3_600,
            Self::OneDay => 86_400,
        }
    }

    /// How many buckets to retain per metric at this width. The
    /// product (`seconds * cap`) gives the maximum lookback window.
    #[must_use]
    pub const fn cap_buckets(self) -> usize {
        match self {
            Self::OneMinute => 240,   // 4h
            Self::FiveMinutes => 288, // 24h
            Self::OneHour => 720,     // 30d
            Self::OneDay => 365,      // 1y
        }
    }

    /// All widths in the canonical "fan out one event to every width"
    /// order. Stable; callers can rely on the slice index for parallel
    /// arrays.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::OneMinute,
            Self::FiveMinutes,
            Self::OneHour,
            Self::OneDay,
        ]
    }

    /// Parse a URL-friendly token (`1m`, `5m`, `1h`, `1d`). Lenient on
    /// case but not on extra whitespace.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "1m" | "60s" => Some(Self::OneMinute),
            "5m" | "300s" => Some(Self::FiveMinutes),
            "1h" | "60m" => Some(Self::OneHour),
            "1d" | "24h" => Some(Self::OneDay),
            _ => None,
        }
    }

    /// Canonical short label (`1m`, `5m`, etc.) used in Prometheus
    /// label values and in the JSON response.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OneMinute => "1m",
            Self::FiveMinutes => "5m",
            Self::OneHour => "1h",
            Self::OneDay => "1d",
        }
    }

    /// Bucket start time for a given `ts_unix`: floor to the width.
    #[must_use]
    pub const fn bucket_start(self, ts_unix: u64) -> u64 {
        (ts_unix / self.seconds()) * self.seconds()
    }
}

/// Per-metric per-width store. A `BTreeMap<bucket_start_unix, counter>`
/// trimmed to `width.cap_buckets()` on each bump.
#[derive(Debug, Default, Clone)]
pub struct BucketSeries {
    /// `bucket_start_unix -> counter`. Sorted by key so trimming the
    /// oldest is `pop_first`.
    buckets: BTreeMap<u64, u64>,
}

impl BucketSeries {
    /// Add `delta` to the bucket containing `ts_unix`, evicting the
    /// oldest bucket(s) until `len() <= cap`.
    pub fn add(&mut self, width: BucketWidth, ts_unix: u64, delta: u64) {
        let key = width.bucket_start(ts_unix);
        *self.buckets.entry(key).or_default() += delta;
        let cap = width.cap_buckets();
        while self.buckets.len() > cap {
            self.buckets.pop_first();
        }
    }

    /// Current value of the most-recent bucket (counter "now").
    /// Returns 0 if empty.
    #[must_use]
    pub fn latest(&self) -> u64 {
        self.buckets.last_key_value().map(|(_, v)| *v).unwrap_or(0)
    }

    /// All buckets in (start, value) order. Returned as a vector so
    /// JSON serialization is trivial.
    #[must_use]
    pub fn series(&self) -> Vec<(u64, u64)> {
        self.buckets.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Series filtered to `[from, to)` (exclusive `to` matches
    /// half-open Prometheus convention; pass `to = u64::MAX` for
    /// "everything from `from`").
    #[must_use]
    pub fn series_in(&self, from: u64, to: u64) -> Vec<(u64, u64)> {
        self.buckets
            .range(from..to)
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    /// Sum across all retained buckets — process-lifetime counter
    /// (capped at the retention window).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.buckets.values().sum()
    }

    /// Number of retained buckets. Exposed for tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// `len() == 0`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_start_floors_to_width() {
        let w = BucketWidth::OneMinute;
        assert_eq!(w.bucket_start(0), 0);
        assert_eq!(w.bucket_start(59), 0);
        assert_eq!(w.bucket_start(60), 60);
        assert_eq!(w.bucket_start(61), 60);
        assert_eq!(w.bucket_start(3_599), 3_540);
    }

    #[test]
    fn adds_coalesce_within_same_bucket() {
        let mut s = BucketSeries::default();
        s.add(BucketWidth::OneMinute, 0, 1);
        s.add(BucketWidth::OneMinute, 30, 2);
        s.add(BucketWidth::OneMinute, 59, 3);
        // All three fall in the [0, 60) bucket.
        assert_eq!(s.len(), 1);
        assert_eq!(s.latest(), 6);
    }

    #[test]
    fn rollover_starts_new_bucket() {
        let mut s = BucketSeries::default();
        s.add(BucketWidth::OneMinute, 0, 1);
        s.add(BucketWidth::OneMinute, 60, 1);
        s.add(BucketWidth::OneMinute, 120, 1);
        assert_eq!(s.len(), 3);
        // Latest is the most recent bucket; total spans all three.
        assert_eq!(s.latest(), 1);
        assert_eq!(s.total(), 3);
    }

    #[test]
    fn late_arriving_event_back_fills_old_bucket() {
        let mut s = BucketSeries::default();
        s.add(BucketWidth::OneMinute, 0, 1);
        s.add(BucketWidth::OneMinute, 60, 1);
        // Out-of-order event in the [0, 60) bucket.
        s.add(BucketWidth::OneMinute, 30, 5);
        assert_eq!(s.len(), 2);
        let series = s.series();
        assert_eq!(series[0], (0, 6));
        assert_eq!(series[1], (60, 1));
    }

    #[test]
    fn cap_evicts_oldest_bucket() {
        let mut s = BucketSeries::default();
        let w = BucketWidth::OneMinute;
        // Push cap + 5 distinct buckets.
        let cap = w.cap_buckets();
        for i in 0..(cap as u64 + 5) {
            s.add(w, i * 60, 1);
        }
        assert_eq!(s.len(), cap, "len must equal cap after over-fill");
        // The 5 oldest were evicted: the first surviving bucket is at
        // index 5 * width.
        let first = s.series()[0].0;
        assert_eq!(first, 5 * 60);
    }

    #[test]
    fn series_in_filters_to_range() {
        let mut s = BucketSeries::default();
        let w = BucketWidth::OneMinute;
        for i in 0..10u64 {
            s.add(w, i * 60, 1);
        }
        // [120, 300) ⇒ buckets at 120, 180, 240 (3 buckets).
        let sub = s.series_in(120, 300);
        assert_eq!(sub.len(), 3);
        assert_eq!(sub[0].0, 120);
        assert_eq!(sub[2].0, 240);
    }

    #[test]
    fn width_round_trip_via_label_and_from_str() {
        for w in BucketWidth::all() {
            assert_eq!(BucketWidth::from_str(w.label()), Some(w));
        }
        assert_eq!(BucketWidth::from_str("17m"), None);
    }
}
