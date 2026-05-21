//! [`FsyncPolicy`] for `bump` durability + the default auto-compaction
//! watermark. See `README.md` for the loss-window semantics.

use std::time::Duration;

/// Default loss-window for [`FsyncPolicy::Periodic`]. Bounds the
/// receipts-at-risk on a hard kernel/host crash to at most one second.
/// Within a process-only crash (no OS panic) every append survives —
/// `File::write_all` in append mode pushes straight to the page cache,
/// no user-space buffer is involved.
///
/// **Recovery from a torn-tail write inside this window:** the audit
/// log carries every `(session_id, seq)` the daemon committed before
/// signing, so `octravpn-node journal rebuild --from-audit <dir>
/// --output <path>` reconstructs the floor map verbatim. See
/// `crates/octravpn-node/src/cli/journal.rs` and audit-9 H-RTO. The
/// loss window therefore costs at most a `journal rebuild` step on
/// next boot — receipts already signed but not yet fsync'd are
/// recovered from the audit log's HMAC-chained record.
pub(crate) const DEFAULT_PERIODIC_FSYNC_INTERVAL: Duration = Duration::from_secs(1);

/// Durability policy for `bump`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsyncPolicy {
    /// `sync_data` after every append. Durable; slow — ~225 receipts/s
    /// on a typical NVMe host (audit-8 §3) because each bump pays one
    /// fsync round-trip. Financial-invariant operators (exit nodes
    /// with high-value sessions where even one second of replay-from-
    /// audit is unacceptable) opt back in via
    /// `[control].fsync_policy = "every_write"`.
    EveryWrite,
    /// `sync_data` only when the configured interval has elapsed since
    /// the last fsync. Bounded loss window across an OS-level crash =
    /// `Duration`. The OS write buffer still receives every append
    /// immediately (an `append`-mode `File::write_all` doesn't buffer
    /// in user space), so a process crash without an OS crash still
    /// preserves every record. Torn-tail writes inside the window are
    /// recoverable from the audit log via
    /// `octravpn-node journal rebuild --from-audit` (see audit-9
    /// H-RTO + `cli/journal.rs`).
    ///
    /// This is the default (`Periodic(Duration::from_secs(1))`,
    /// Perf-1) — see [`FsyncPolicy::default`].
    Periodic(Duration),
}

impl Default for FsyncPolicy {
    /// Perf-1: default to `Periodic(1s)` so a stock node clears the
    /// ~500k receipts/s ceiling instead of the ~225/s `EveryWrite`
    /// floor (audit-8 §3 table, `crates/octravpn-node/benches/
    /// settle_throughput.rs`). The 1s loss window is recoverable from
    /// the audit log via `journal rebuild --from-audit`; financial-
    /// invariant operators flip back to `EveryWrite` in their TOML
    /// (`[control].fsync_policy = "every_write"`).
    fn default() -> Self {
        Self::Periodic(DEFAULT_PERIODIC_FSYNC_INTERVAL)
    }
}

/// Compaction watermark: rewrite the journal once it grows past this
/// many bytes. 10 MB ≈ 240k records at v1 (44 B/record), well above any
/// realistic tailnet's live session count.
pub const DEFAULT_COMPACTION_WATERMARK: u64 = 10 * 1024 * 1024;

// ----------------------------------------------------------------------
// Perf-8 (audit-8 OOM-1): in-mem mirror cap + TTL eviction.
//
// The `by_session` map is a hot-path *cache* of the durable on-disk
// floor — the journal file is the source of truth for the
// seq-monotonic invariant. Without a cap, every session ever opened on
// the node lives in the mirror until process restart: 1M unique
// sessions × 88 B/entry ≈ 88 MB resident, 100M × 88 B ≈ 8.8 GB.
//
// Eviction is invariant-safe because every `bump` that hits an evicted
// entry re-reads the durable on-disk state before checking
// monotonicity — see `inner::Inner::record_eviction` and the
// `evicted_session_rejects_replay_attempt_via_disk_check` test.
// ----------------------------------------------------------------------

/// Default upper bound on the in-mem mirror. At 88 B/entry this caps
/// the steady-state RSS contribution of `by_session` at ~8.8 MB,
/// roughly the same RAM budget as the bounded audit-flusher queue
/// (audit-8 §7 OOM-3). Operators with bigger working sets raise this
/// in `[receipt_journal]`; the LRU eviction policy keeps the most
/// recently active sessions hot.
pub const DEFAULT_MAX_IN_MEM_SESSIONS: usize = 100_000;

/// Default TTL after which an idle session is evicted from the in-mem
/// mirror. One hour: long enough that a session whose receipts arrive
/// once-per-epoch (10 s in mainnet shape) keeps its hot-path slot
/// indefinitely, short enough that the mirror sheds dead sessions
/// within an operator's typical scrape window. The on-disk journal
/// retains the last-seq forever — eviction only frees the in-mem
/// cache slot.
pub const DEFAULT_SESSION_IN_MEM_TTL: Duration = Duration::from_secs(3600);

/// Default interval at which the background sweeper scans the mirror
/// for TTL-aged entries. The hot bump path already evicts on cap
/// overflow, so the sweeper is the *only* mechanism for shedding idle
/// sessions when the mirror is below cap — keep it cheap (60 s) so the
/// sweep cost stays a footnote even at 100k entries.
pub const DEFAULT_TTL_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Size of the "recently-evicted" LRU that dampens flapping. A session
/// kicked out within the last `RECENTLY_EVICTED_CAP` evictions hits
/// the disk-resurrect path on its next bump (mandatory for the
/// monotonicity check); the LRU is here so subsequent bumps within
/// the same burst don't repeat the disk scan. Bounded at 1024 entries
/// (~64 KB at SessionId size) so it can never itself become an OOM
/// vector.
pub const DEFAULT_RECENTLY_EVICTED_CAP: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    /// Perf-1: the journal default is `Periodic(1s)`. If a downstream
    /// regresses this back to `EveryWrite`, the audit-8 §3 throughput
    /// ceiling (~225 receipts/s/node) silently returns; pin the
    /// invariant here.
    #[test]
    fn default_is_periodic_one_second() {
        assert_eq!(
            FsyncPolicy::default(),
            FsyncPolicy::Periodic(Duration::from_secs(1))
        );
        assert_eq!(DEFAULT_PERIODIC_FSYNC_INTERVAL, Duration::from_secs(1));
    }

    /// `EveryWrite` MUST remain accessible — operators on financial-
    /// invariant exit nodes flip to it via TOML. The variant + its
    /// equality contract are part of the public API.
    #[test]
    fn every_write_variant_still_available() {
        let p = FsyncPolicy::EveryWrite;
        assert_ne!(p, FsyncPolicy::default());
        assert_eq!(p, FsyncPolicy::EveryWrite);
    }
}
