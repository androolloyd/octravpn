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
