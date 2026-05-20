//! [`FsyncPolicy`] for `bump` durability + the default auto-compaction
//! watermark. See `README.md` for the loss-window semantics.

use std::time::Duration;

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

/// Compaction watermark: rewrite the journal once it grows past this
/// many bytes. 10 MB ≈ 240k records at v1 (44 B/record), well above any
/// realistic tailnet's live session count.
pub const DEFAULT_COMPACTION_WATERMARK: u64 = 10 * 1024 * 1024;
