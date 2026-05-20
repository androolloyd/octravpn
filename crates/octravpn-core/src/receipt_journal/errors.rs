//! Error types. `JournalError::SeqNotMonotonic` is the threat-model
//! refusal-to-double-sign signal — callers MUST treat it as a hard
//! failure rather than "try a different seq".

/// Errors raised by [`ReceiptJournal`](super::ReceiptJournal) public
/// entry points.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad journal magic at {path} — refusing to clobber an unrelated file")]
    BadMagic { path: String },
    #[error("truncated journal at {path}: {detail}")]
    Truncated { path: String, detail: String },
    #[error("checksum mismatch in journal at {path} at offset {offset}")]
    ChecksumMismatch { path: String, offset: u64 },
    /// The caller's proposed `seq` does not exceed the on-disk floor.
    /// The threat model wants the daemon to surface this as a hard
    /// refusal — the alternative is silent double-signing.
    #[error("seq {proposed} <= journal floor {floor} for session {session}")]
    SeqNotMonotonic {
        session: String,
        floor: u64,
        proposed: u64,
    },
}

/// Local result alias.
pub type JournalResult<T> = std::result::Result<T, JournalError>;
