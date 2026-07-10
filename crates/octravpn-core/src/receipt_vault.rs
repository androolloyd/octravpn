//! Append-only vault for client-countersigned settlement receipts.
//!
//! This is intentionally separate from [`crate::receipt_journal`]. The
//! journal is a fixed-width per-session `u64` floor; the vault stores
//! variable-length `SignedReceipt` JSON records plus relay lifecycle
//! records so an operator can recover the exact settlement preimage
//! after a restart.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::{receipt::SignedReceipt, session::SessionId};

pub const MAGIC_V1: &[u8; 8] = b"OCRV1\0\0\0";
pub const MAGIC_V2: &[u8; 8] = b"OCRV2\0\0\0";

const RECORD_RECEIPT: u8 = 1;
const RECORD_LIFECYCLE: u8 = 2;
const V2_RECORD_HEADER_LEN: usize = 1 + 32 + 4;
const CRC_LEN: usize = 4;
const MAX_RECORD_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptVaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bad receipt-vault magic at {path} -- refusing to clobber an unrelated file")]
    BadMagic { path: String },
    #[error("truncated receipt vault at {path}: {detail}")]
    Truncated { path: String, detail: String },
    #[error("checksum mismatch in receipt vault at {path} at offset {offset}")]
    ChecksumMismatch { path: String, offset: u64 },
    #[error("bad receipt-vault record type {rec_type} at {path} offset {offset}")]
    BadRecordType {
        path: String,
        offset: u64,
        rec_type: u8,
    },
    #[error(
        "receipt session mismatch in vault at {path} at offset {offset}: record={record_session} receipt={receipt_session}"
    )]
    SessionMismatch {
        path: String,
        offset: u64,
        record_session: String,
        receipt_session: String,
    },
    #[error("receipt JSON record too large for vault: {len} bytes")]
    RecordTooLarge { len: usize },
    #[error("receipt seq {proposed} < vault floor {floor} for session {session}")]
    SeqRegressed {
        session: String,
        floor: u64,
        proposed: u64,
    },
    #[error("receipt seq {proposed} conflicts with vault floor {floor} for session {session}")]
    SeqConflict {
        session: String,
        floor: u64,
        proposed: u64,
    },
    #[error(
        "receipt vault entry for session {session} is frozen after arm: current_seq={current_seq} proposed_seq={proposed_seq}"
    )]
    ReceiptFrozen {
        session: String,
        current_seq: u64,
        proposed_seq: u64,
    },
    #[error("illegal receipt-vault lifecycle transition for session {session}: {from} -> {to}")]
    IllegalTransition {
        session: String,
        from: String,
        to: String,
    },
    #[error(
        "armed receipt hash mismatch for session {session}: pinned={pinned} receipt={receipt}"
    )]
    ArmedHashMismatch {
        session: String,
        pinned: String,
        receipt: String,
    },
}

pub type ReceiptVaultResult<T> = std::result::Result<T, ReceiptVaultError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LifecycleState {
    Proposed,
    Armed {
        deadline: u64,
        settlement_hash: String,
    },
    ClaimSubmitted {
        tx: String,
    },
    Claimed {
        tx: String,
    },
    Refunded {
        tx: String,
    },
    Expired,
}

impl LifecycleState {
    fn rank(&self) -> u8 {
        match self {
            Self::Proposed => 0,
            Self::Armed { .. } => 1,
            Self::ClaimSubmitted { .. } => 2,
            Self::Claimed { .. } | Self::Refunded { .. } | Self::Expired => 3,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Claimed { .. } | Self::Refunded { .. } | Self::Expired
        )
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Proposed => "Proposed",
            Self::Armed { .. } => "Armed",
            Self::ClaimSubmitted { .. } => "ClaimSubmitted",
            Self::Claimed { .. } => "Claimed",
            Self::Refunded { .. } => "Refunded",
            Self::Expired => "Expired",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArmedPin {
    deadline: u64,
    settlement_hash: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionEntry {
    pub receipt: SignedReceipt,
    pub state: LifecycleState,
    armed: Option<ArmedPin>,
}

impl SessionEntry {
    fn proposed(receipt: SignedReceipt) -> Self {
        Self {
            receipt,
            state: LifecycleState::Proposed,
            armed: None,
        }
    }

    fn is_frozen(&self) -> bool {
        self.state.rank() >= 1 || self.armed.is_some()
    }

    fn armed_pin_hash(&self) -> Option<&str> {
        match &self.state {
            LifecycleState::Armed {
                settlement_hash, ..
            } => Some(settlement_hash.as_str()),
            _ => self.armed.as_ref().map(|pin| pin.settlement_hash.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum VaultRecord {
    Receipt {
        session_id: SessionId,
        receipt: SignedReceipt,
    },
    Lifecycle {
        session_id: SessionId,
        state: LifecycleState,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedRecord {
    pub record: VaultRecord,
    pub bytes_consumed: usize,
}

#[derive(Debug)]
pub struct ReceiptVault {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    by_session: BTreeMap<SessionId, SessionEntry>,
    path: Option<PathBuf>,
    handle: Option<std::fs::File>,
    file_size: u64,
}

impl ReceiptVault {
    /// Open or initialise a vault at `path`. OCRV1 files are migrated
    /// once to OCRV2. On replay, the highest receipt sequence per
    /// session wins until the session is armed; after that the receipt
    /// is immutable. A torn tail is ignored and truncated before the
    /// next append, while a bad CRC is surfaced as corruption.
    pub fn open(path: impl Into<PathBuf>) -> ReceiptVaultResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let raw = if path.exists() {
            fs::read(&path)?
        } else {
            Vec::new()
        };

        let (by_session, good_len, needs_migration) = replay_any(&raw, &path)?;
        if needs_migration {
            write_v2_snapshot(&path, &by_session)?;
        } else if raw.is_empty() {
            ensure_v2_header(&path)?;
        }

        let mut handle = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;

        let file_size = if needs_migration || raw.is_empty() {
            handle.metadata()?.len()
        } else {
            crate::receipt_log::truncate_torn_tail(&handle, good_len)?;
            good_len
        };

        // Ensure a brand-new path has the magic even if it did not
        // exist when replay ran and the open call above created it.
        if file_size == 0 {
            handle.write_all(MAGIC_V2)?;
            handle.sync_data()?;
        }

        Ok(Self {
            inner: Mutex::new(Inner {
                by_session,
                path: Some(path),
                handle: Some(handle),
                file_size: file_size.max(MAGIC_V2.len() as u64),
            }),
        })
    }

    /// In-memory vault for tests and control-plane unit harnesses.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_session: BTreeMap::new(),
                path: None,
                handle: None,
                file_size: 0,
            }),
        }
    }

    pub fn get(&self, session_id: &SessionId) -> Option<SignedReceipt> {
        self.inner
            .lock()
            .by_session
            .get(session_id)
            .map(|entry| entry.receipt.clone())
    }

    pub fn entry(&self, session_id: &SessionId) -> Option<SessionEntry> {
        self.inner.lock().by_session.get(session_id).cloned()
    }

    pub fn state(&self, session_id: &SessionId) -> Option<LifecycleState> {
        self.inner
            .lock()
            .by_session
            .get(session_id)
            .map(|entry| entry.state.clone())
    }

    pub fn current_seq(&self, session_id: &SessionId) -> Option<u64> {
        self.inner
            .lock()
            .by_session
            .get(session_id)
            .map(|entry| entry.receipt.receipt.seq)
    }

    pub fn entries(&self) -> Vec<(SessionId, SessionEntry)> {
        self.inner
            .lock()
            .by_session
            .iter()
            .map(|(id, entry)| (id.clone(), entry.clone()))
            .collect()
    }

    pub fn armed_unclaimed(&self) -> Vec<(SessionId, SessionEntry)> {
        self.inner
            .lock()
            .by_session
            .iter()
            .filter(|(_, entry)| {
                matches!(
                    entry.state,
                    LifecycleState::Armed { .. } | LifecycleState::ClaimSubmitted { .. }
                )
            })
            .map(|(id, entry)| (id.clone(), entry.clone()))
            .collect()
    }

    /// Append `receipt` and fsync before returning. The store accepts a
    /// same-sequence replay only when it is byte-identical to the stored
    /// receipt; a conflicting equal-seq receipt is rejected. Once a
    /// lifecycle record has armed the session, any different receipt is
    /// rejected with [`ReceiptVaultError::ReceiptFrozen`].
    pub fn put(&self, session_id: &SessionId, receipt: &SignedReceipt) -> ReceiptVaultResult<()> {
        if receipt.receipt.session_id.as_bytes() != session_id.as_bytes() {
            return Err(ReceiptVaultError::SessionMismatch {
                path: self.display_path(),
                offset: 0,
                record_session: session_id.to_hex(),
                receipt_session: receipt.receipt.session_id.to_hex(),
            });
        }

        let mut g = self.inner.lock();
        match validate_put(&g.by_session, session_id, receipt)? {
            PutAction::Noop => return Ok(()),
            PutAction::Append => {}
        }

        let record = encode_receipt_record(session_id, receipt)?;
        if let Some(handle) = g.handle.as_mut() {
            handle.write_all(&record)?;
            handle.sync_data()?;
            g.file_size += record.len() as u64;
        }
        g.by_session
            .insert(session_id.clone(), SessionEntry::proposed(receipt.clone()));
        Ok(())
    }

    pub fn mark_armed(
        &self,
        session_id: &SessionId,
        deadline: u64,
        settlement_hash: String,
    ) -> ReceiptVaultResult<()> {
        let state = LifecycleState::Armed {
            deadline,
            settlement_hash,
        };
        self.mark_lifecycle(session_id, state)
    }

    pub fn mark_claim_submitted(
        &self,
        session_id: &SessionId,
        tx: String,
    ) -> ReceiptVaultResult<()> {
        self.mark_lifecycle(session_id, LifecycleState::ClaimSubmitted { tx })
    }

    pub fn mark_claimed(&self, session_id: &SessionId, tx: String) -> ReceiptVaultResult<()> {
        self.mark_lifecycle(session_id, LifecycleState::Claimed { tx })
    }

    pub fn mark_refunded(&self, session_id: &SessionId, tx: String) -> ReceiptVaultResult<()> {
        self.mark_lifecycle(session_id, LifecycleState::Refunded { tx })
    }

    pub fn mark_expired(&self, session_id: &SessionId) -> ReceiptVaultResult<()> {
        self.mark_lifecycle(session_id, LifecycleState::Expired)
    }

    pub fn compact(&self) -> ReceiptVaultResult<()> {
        let mut g = self.inner.lock();
        let live: BTreeMap<SessionId, SessionEntry> = g
            .by_session
            .iter()
            .filter(|(_, entry)| !entry.state.is_terminal())
            .map(|(id, entry)| (id.clone(), entry.clone()))
            .collect();

        let Some(path) = g.path.clone() else {
            g.by_session = live;
            return Ok(());
        };

        // Durability: do EVERY fallible step (snapshot write, open, metadata,
        // atomic rename) on a temp file and only commit `g` once they all
        // succeed. If anything fails, `g.handle`/`g.by_session` are UNTOUCHED --
        // so put()/mark_lifecycle() keep persisting to the existing file rather
        // than silently going in-memory-only (which would lose settlement
        // evidence on the next restart). The temp handle stays valid across the
        // rename (the fd follows the inode on unix).
        let tmp = path.with_extension("ocrv2-compacting");
        write_v2_snapshot(&tmp, &live)?;
        let new_handle = OpenOptions::new().append(true).read(true).open(&tmp)?;
        let new_size = new_handle.metadata()?.len();
        std::fs::rename(&tmp, &path)?;
        g.handle = Some(new_handle);
        g.file_size = new_size;
        g.by_session = live;
        Ok(())
    }

    pub fn file_size(&self) -> u64 {
        self.inner.lock().file_size
    }

    fn mark_lifecycle(
        &self,
        session_id: &SessionId,
        next: LifecycleState,
    ) -> ReceiptVaultResult<()> {
        let mut g = self.inner.lock();
        validate_lifecycle_transition(&g.by_session, session_id, &next)?;

        let record = encode_lifecycle_record(session_id, &next)?;
        if let Some(handle) = g.handle.as_mut() {
            handle.write_all(&record)?;
            handle.sync_data()?;
            g.file_size += record.len() as u64;
        }

        let entry = g
            .by_session
            .get_mut(session_id)
            .expect("validated lifecycle transition requires an entry");
        apply_lifecycle_to_entry(entry, next);
        Ok(())
    }

    fn display_path(&self) -> String {
        self.inner
            .lock()
            .path
            .as_ref()
            .map_or_else(|| "<in-memory>".to_string(), |p| p.display().to_string())
    }
}

enum PutAction {
    Noop,
    Append,
}

fn validate_put(
    by_session: &BTreeMap<SessionId, SessionEntry>,
    session_id: &SessionId,
    receipt: &SignedReceipt,
) -> ReceiptVaultResult<PutAction> {
    let Some(prev) = by_session.get(session_id) else {
        return Ok(PutAction::Append);
    };

    if prev.is_frozen() {
        let prev_json = serde_json::to_vec(&prev.receipt)?;
        let next_json = serde_json::to_vec(receipt)?;
        if prev_json == next_json {
            return Ok(PutAction::Noop);
        }
        return Err(ReceiptVaultError::ReceiptFrozen {
            session: session_id.to_hex(),
            current_seq: prev.receipt.receipt.seq,
            proposed_seq: receipt.receipt.seq,
        });
    }

    if receipt.receipt.seq < prev.receipt.receipt.seq {
        return Err(ReceiptVaultError::SeqRegressed {
            session: session_id.to_hex(),
            floor: prev.receipt.receipt.seq,
            proposed: receipt.receipt.seq,
        });
    }
    if receipt.receipt.seq == prev.receipt.receipt.seq {
        let prev_json = serde_json::to_vec(&prev.receipt)?;
        let next_json = serde_json::to_vec(receipt)?;
        if prev_json == next_json {
            return Ok(PutAction::Noop);
        }
        return Err(ReceiptVaultError::SeqConflict {
            session: session_id.to_hex(),
            floor: prev.receipt.receipt.seq,
            proposed: receipt.receipt.seq,
        });
    }

    Ok(PutAction::Append)
}

fn validate_lifecycle_transition(
    by_session: &BTreeMap<SessionId, SessionEntry>,
    session_id: &SessionId,
    next: &LifecycleState,
) -> ReceiptVaultResult<()> {
    let Some(entry) = by_session.get(session_id) else {
        return Err(ReceiptVaultError::IllegalTransition {
            session: session_id.to_hex(),
            from: "<missing>".to_string(),
            to: next.name().to_string(),
        });
    };

    if lifecycle_equivalent(&entry.state, next) {
        return Ok(());
    }

    if entry.state.is_terminal() {
        return Err(illegal_transition(session_id, &entry.state, next));
    }

    match (&entry.state, next) {
        (
            LifecycleState::Proposed,
            LifecycleState::Armed {
                settlement_hash, ..
            },
        ) => {
            let receipt_hash = entry.receipt.settlement_hash();
            if &receipt_hash != settlement_hash {
                return Err(ReceiptVaultError::ArmedHashMismatch {
                    session: session_id.to_hex(),
                    pinned: settlement_hash.clone(),
                    receipt: receipt_hash,
                });
            }
            Ok(())
        }
        (LifecycleState::Proposed, _) => Err(illegal_transition(session_id, &entry.state, next)),
        (
            LifecycleState::Armed { .. },
            LifecycleState::ClaimSubmitted { .. }
            | LifecycleState::Claimed { .. }
            | LifecycleState::Refunded { .. }
            | LifecycleState::Expired,
        )
        | (
            LifecycleState::ClaimSubmitted { .. },
            LifecycleState::Claimed { .. }
            | LifecycleState::Refunded { .. }
            | LifecycleState::Expired,
        ) => Ok(()),
        (LifecycleState::Armed { .. }, LifecycleState::Armed { .. })
        | (LifecycleState::ClaimSubmitted { .. }, LifecycleState::ClaimSubmitted { .. }) => {
            Err(illegal_transition(session_id, &entry.state, next))
        }
        (LifecycleState::ClaimSubmitted { .. }, LifecycleState::Armed { .. }) => {
            if entry.armed_pin_hash()
                == match next {
                    LifecycleState::Armed {
                        settlement_hash, ..
                    } => Some(settlement_hash.as_str()),
                    _ => None,
                }
            {
                Ok(())
            } else {
                Err(illegal_transition(session_id, &entry.state, next))
            }
        }
        _ => Err(illegal_transition(session_id, &entry.state, next)),
    }
}

fn lifecycle_equivalent(a: &LifecycleState, b: &LifecycleState) -> bool {
    a == b
}

fn illegal_transition(
    session_id: &SessionId,
    from: &LifecycleState,
    to: &LifecycleState,
) -> ReceiptVaultError {
    ReceiptVaultError::IllegalTransition {
        session: session_id.to_hex(),
        from: from.name().to_string(),
        to: to.name().to_string(),
    }
}

fn apply_lifecycle_to_entry(entry: &mut SessionEntry, next: LifecycleState) {
    if let LifecycleState::Armed {
        deadline,
        settlement_hash,
    } = &next
    {
        entry.armed = Some(ArmedPin {
            deadline: *deadline,
            settlement_hash: settlement_hash.clone(),
        });
    }
    if next.rank() >= entry.state.rank() {
        entry.state = next;
    }
}

fn encode_receipt_record(
    session_id: &SessionId,
    receipt: &SignedReceipt,
) -> ReceiptVaultResult<Vec<u8>> {
    let json = serde_json::to_vec(receipt)?;
    encode_v2_record(RECORD_RECEIPT, session_id, &json)
}

fn encode_lifecycle_record(
    session_id: &SessionId,
    state: &LifecycleState,
) -> ReceiptVaultResult<Vec<u8>> {
    let json = serde_json::to_vec(state)?;
    encode_v2_record(RECORD_LIFECYCLE, session_id, &json)
}

fn encode_v2_record(
    rec_type: u8,
    session_id: &SessionId,
    payload: &[u8],
) -> ReceiptVaultResult<Vec<u8>> {
    if payload.len() > MAX_RECORD_PAYLOAD_LEN {
        return Err(ReceiptVaultError::RecordTooLarge { len: payload.len() });
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| ReceiptVaultError::RecordTooLarge { len: payload.len() })?;
    let mut out = Vec::with_capacity(V2_RECORD_HEADER_LEN + payload.len() + CRC_LEN);
    out.push(rec_type);
    out.extend_from_slice(session_id.as_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    let crc = crate::receipt_log::crc32_ieee(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
fn encode_v1_record(
    session_id: &SessionId,
    receipt: &SignedReceipt,
) -> ReceiptVaultResult<Vec<u8>> {
    let json = serde_json::to_vec(receipt)?;
    if json.len() > MAX_RECORD_PAYLOAD_LEN {
        return Err(ReceiptVaultError::RecordTooLarge { len: json.len() });
    }
    let len = u32::try_from(json.len())
        .map_err(|_| ReceiptVaultError::RecordTooLarge { len: json.len() })?;
    let mut out = Vec::with_capacity(32 + 4 + json.len() + 4);
    out.extend_from_slice(session_id.as_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&json);
    let crc = crate::receipt_log::crc32_ieee(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out)
}

/// Decode one OCRV2 record from the start of `raw`. Returns `Ok(None)`
/// for an incomplete record prefix so fuzzing and torn-tail replay stay
/// total. The payload length is bounded before any JSON decode.
pub fn decode_record(raw: &[u8]) -> ReceiptVaultResult<Option<DecodedRecord>> {
    decode_record_at(raw, Path::new("<buffer>"), 0)
}

fn decode_record_at(
    raw: &[u8],
    path: &Path,
    record_offset: u64,
) -> ReceiptVaultResult<Option<DecodedRecord>> {
    if raw.len() < V2_RECORD_HEADER_LEN {
        return Ok(None);
    }

    let rec_type = raw[0];
    let mut id = [0u8; 32];
    id.copy_from_slice(&raw[1..33]);
    let session_id = SessionId::new(id);

    let mut len_arr = [0u8; 4];
    len_arr.copy_from_slice(&raw[33..37]);
    let payload_len = u32::from_be_bytes(len_arr) as usize;
    if payload_len > MAX_RECORD_PAYLOAD_LEN {
        return Err(ReceiptVaultError::RecordTooLarge { len: payload_len });
    }

    let Some(payload_end) = V2_RECORD_HEADER_LEN.checked_add(payload_len) else {
        return Err(ReceiptVaultError::RecordTooLarge { len: payload_len });
    };
    let Some(record_end) = payload_end.checked_add(CRC_LEN) else {
        return Err(ReceiptVaultError::RecordTooLarge { len: payload_len });
    };
    if raw.len() < record_end {
        return Ok(None);
    }

    let mut crc_arr = [0u8; 4];
    crc_arr.copy_from_slice(&raw[payload_end..record_end]);
    let got_crc = u32::from_be_bytes(crc_arr);
    let expected_crc = crate::receipt_log::crc32_ieee(&raw[..payload_end]);
    if expected_crc != got_crc {
        return Err(ReceiptVaultError::ChecksumMismatch {
            path: path.display().to_string(),
            offset: record_offset + payload_end as u64,
        });
    }

    let payload = &raw[V2_RECORD_HEADER_LEN..payload_end];
    let record = match rec_type {
        RECORD_RECEIPT => {
            let receipt: SignedReceipt = serde_json::from_slice(payload)?;
            if receipt.receipt.session_id.as_bytes() != session_id.as_bytes() {
                return Err(ReceiptVaultError::SessionMismatch {
                    path: path.display().to_string(),
                    offset: record_offset,
                    record_session: session_id.to_hex(),
                    receipt_session: receipt.receipt.session_id.to_hex(),
                });
            }
            VaultRecord::Receipt {
                session_id,
                receipt,
            }
        }
        RECORD_LIFECYCLE => {
            let state: LifecycleState = serde_json::from_slice(payload)?;
            VaultRecord::Lifecycle { session_id, state }
        }
        other => {
            return Err(ReceiptVaultError::BadRecordType {
                path: path.display().to_string(),
                offset: record_offset,
                rec_type: other,
            });
        }
    };

    Ok(Some(DecodedRecord {
        record,
        bytes_consumed: record_end,
    }))
}

fn replay_any(
    raw: &[u8],
    path: &Path,
) -> ReceiptVaultResult<(BTreeMap<SessionId, SessionEntry>, u64, bool)> {
    if raw.is_empty() {
        return Ok((BTreeMap::new(), 0, false));
    }
    if raw.len() < MAGIC_V1.len() {
        return Err(ReceiptVaultError::Truncated {
            path: path.display().to_string(),
            detail: "missing receipt vault header".to_string(),
        });
    }
    let magic = &raw[..MAGIC_V1.len()];
    if magic == MAGIC_V2 {
        let (entries, good_len) = replay_v2(raw, path)?;
        Ok((entries, good_len, false))
    } else if magic == MAGIC_V1 {
        let (entries, good_len) = replay_v1(raw, path)?;
        Ok((entries, good_len, true))
    } else {
        Err(ReceiptVaultError::BadMagic {
            path: path.display().to_string(),
        })
    }
}

fn replay_v1(
    raw: &[u8],
    path: &Path,
) -> ReceiptVaultResult<(BTreeMap<SessionId, SessionEntry>, u64)> {
    debug_assert!(raw.starts_with(MAGIC_V1));
    let mut out: BTreeMap<SessionId, SessionEntry> = BTreeMap::new();
    let mut cursor = MAGIC_V1.len();
    let mut good_len = MAGIC_V1.len() as u64;
    while cursor < raw.len() {
        if cursor + 32 + 4 > raw.len() {
            break;
        }

        let record_start = cursor;
        let mut id = [0u8; 32];
        id.copy_from_slice(&raw[cursor..cursor + 32]);
        cursor += 32;

        let mut len_arr = [0u8; 4];
        len_arr.copy_from_slice(&raw[cursor..cursor + 4]);
        cursor += 4;
        let json_len = u32::from_be_bytes(len_arr) as usize;
        if json_len > MAX_RECORD_PAYLOAD_LEN {
            return Err(ReceiptVaultError::RecordTooLarge { len: json_len });
        }

        if cursor + json_len + 4 > raw.len() {
            break;
        }
        let json_start = cursor;
        let json_end = cursor + json_len;
        cursor = json_end;

        let mut crc_arr = [0u8; 4];
        crc_arr.copy_from_slice(&raw[cursor..cursor + 4]);
        cursor += 4;
        let got_crc = u32::from_be_bytes(crc_arr);
        let expected_crc = crate::receipt_log::crc32_ieee(&raw[record_start..json_end]);
        if expected_crc != got_crc {
            return Err(ReceiptVaultError::ChecksumMismatch {
                path: path.display().to_string(),
                offset: cursor as u64 - 4,
            });
        }

        let session_id = SessionId::new(id);
        let receipt: SignedReceipt = serde_json::from_slice(&raw[json_start..json_end])?;
        if receipt.receipt.session_id.as_bytes() != session_id.as_bytes() {
            return Err(ReceiptVaultError::SessionMismatch {
                path: path.display().to_string(),
                offset: record_start as u64,
                record_session: session_id.to_hex(),
                receipt_session: receipt.receipt.session_id.to_hex(),
            });
        }

        fold_receipt_v1(&mut out, session_id, receipt)?;
        good_len = cursor as u64;
    }
    Ok((out, good_len))
}

fn fold_receipt_v1(
    out: &mut BTreeMap<SessionId, SessionEntry>,
    session_id: SessionId,
    receipt: SignedReceipt,
) -> ReceiptVaultResult<()> {
    match out.get(&session_id) {
        Some(cur) if receipt.receipt.seq < cur.receipt.receipt.seq => {}
        Some(cur) if receipt.receipt.seq == cur.receipt.receipt.seq => {
            let cur_json = serde_json::to_vec(&cur.receipt)?;
            let next_json = serde_json::to_vec(&receipt)?;
            if cur_json != next_json {
                return Err(ReceiptVaultError::SeqConflict {
                    session: session_id.to_hex(),
                    floor: cur.receipt.receipt.seq,
                    proposed: receipt.receipt.seq,
                });
            }
        }
        _ => {
            out.insert(session_id, SessionEntry::proposed(receipt));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ReplaySlot {
    receipt: Option<SignedReceipt>,
    state: LifecycleState,
    armed: Option<ArmedPin>,
}

impl ReplaySlot {
    fn empty() -> Self {
        Self {
            receipt: None,
            state: LifecycleState::Proposed,
            armed: None,
        }
    }

    fn is_frozen(&self) -> bool {
        self.state.rank() >= 1 || self.armed.is_some()
    }
}

fn replay_v2(
    raw: &[u8],
    path: &Path,
) -> ReceiptVaultResult<(BTreeMap<SessionId, SessionEntry>, u64)> {
    debug_assert!(raw.starts_with(MAGIC_V2));
    let mut slots: BTreeMap<SessionId, ReplaySlot> = BTreeMap::new();
    let mut cursor = MAGIC_V2.len();
    let mut good_len = MAGIC_V2.len() as u64;
    while cursor < raw.len() {
        let record_start = cursor;
        let Some(decoded) = decode_record_at(&raw[cursor..], path, cursor as u64)? else {
            break;
        };
        cursor += decoded.bytes_consumed;
        match decoded.record {
            VaultRecord::Receipt {
                session_id,
                receipt,
            } => fold_receipt_v2(&mut slots, &session_id, receipt)?,
            VaultRecord::Lifecycle { session_id, state } => {
                fold_lifecycle_v2(&mut slots, &session_id, state)?
            }
        }
        good_len = cursor as u64;
        debug_assert!(cursor > record_start);
    }

    let mut out = BTreeMap::new();
    for (session_id, slot) in slots {
        let Some(receipt) = slot.receipt else {
            continue;
        };
        if let Some(pin) = &slot.armed {
            let receipt_hash = receipt.settlement_hash();
            if receipt_hash != pin.settlement_hash {
                return Err(ReceiptVaultError::ArmedHashMismatch {
                    session: session_id.to_hex(),
                    pinned: pin.settlement_hash.clone(),
                    receipt: receipt_hash,
                });
            }
        }
        out.insert(
            session_id,
            SessionEntry {
                receipt,
                state: slot.state,
                armed: slot.armed,
            },
        );
    }
    Ok((out, good_len))
}

fn fold_receipt_v2(
    slots: &mut BTreeMap<SessionId, ReplaySlot>,
    session_id: &SessionId,
    receipt: SignedReceipt,
) -> ReceiptVaultResult<()> {
    let slot = slots
        .entry(session_id.clone())
        .or_insert_with(ReplaySlot::empty);

    if let Some(pin) = &slot.armed {
        let receipt_hash = receipt.settlement_hash();
        if receipt_hash != pin.settlement_hash {
            return Err(ReceiptVaultError::ArmedHashMismatch {
                session: session_id.to_hex(),
                pinned: pin.settlement_hash.clone(),
                receipt: receipt_hash,
            });
        }
    }

    let Some(prev) = slot.receipt.as_ref() else {
        slot.receipt = Some(receipt);
        return Ok(());
    };

    if slot.is_frozen() {
        let prev_json = serde_json::to_vec(prev)?;
        let next_json = serde_json::to_vec(&receipt)?;
        if prev_json != next_json {
            return Err(ReceiptVaultError::ReceiptFrozen {
                session: session_id.to_hex(),
                current_seq: prev.receipt.seq,
                proposed_seq: receipt.receipt.seq,
            });
        }
        return Ok(());
    }

    match receipt.receipt.seq.cmp(&prev.receipt.seq) {
        std::cmp::Ordering::Less => {}
        std::cmp::Ordering::Equal => {
            let prev_json = serde_json::to_vec(prev)?;
            let next_json = serde_json::to_vec(&receipt)?;
            if prev_json != next_json {
                return Err(ReceiptVaultError::SeqConflict {
                    session: session_id.to_hex(),
                    floor: prev.receipt.seq,
                    proposed: receipt.receipt.seq,
                });
            }
        }
        std::cmp::Ordering::Greater => {
            slot.receipt = Some(receipt);
        }
    }
    Ok(())
}

fn fold_lifecycle_v2(
    slots: &mut BTreeMap<SessionId, ReplaySlot>,
    session_id: &SessionId,
    state: LifecycleState,
) -> ReceiptVaultResult<()> {
    let slot = slots
        .entry(session_id.clone())
        .or_insert_with(ReplaySlot::empty);

    if let LifecycleState::Armed {
        deadline,
        settlement_hash,
    } = &state
    {
        if let Some(receipt) = &slot.receipt {
            let receipt_hash = receipt.settlement_hash();
            if &receipt_hash != settlement_hash {
                return Err(ReceiptVaultError::ArmedHashMismatch {
                    session: session_id.to_hex(),
                    pinned: settlement_hash.clone(),
                    receipt: receipt_hash,
                });
            }
        }
        match &slot.armed {
            Some(pin) if pin.settlement_hash != *settlement_hash || pin.deadline != *deadline => {
                return Err(ReceiptVaultError::IllegalTransition {
                    session: session_id.to_hex(),
                    from: "Armed".to_string(),
                    to: "Armed".to_string(),
                });
            }
            Some(_) => {}
            None => {
                slot.armed = Some(ArmedPin {
                    deadline: *deadline,
                    settlement_hash: settlement_hash.clone(),
                });
            }
        }
    }

    if state.rank() < slot.state.rank() {
        return Ok(());
    }
    if state.rank() == slot.state.rank() && !lifecycle_equivalent(&slot.state, &state) {
        return Err(ReceiptVaultError::IllegalTransition {
            session: session_id.to_hex(),
            from: slot.state.name().to_string(),
            to: state.name().to_string(),
        });
    }
    if state.rank() > slot.state.rank() {
        slot.state = state;
    }
    Ok(())
}

fn ensure_v2_header(path: &Path) -> std::io::Result<()> {
    if path.exists() && fs::metadata(path)?.len() > 0 {
        return Ok(());
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir_for_tmp = parent.unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(dir_for_tmp)?;
    {
        let mut handle = tmp.as_file();
        handle.write_all(MAGIC_V2)?;
        handle.sync_all()?;
    }
    tmp.persist(path).map_err(|e| {
        std::io::Error::other(format!("persist v2 header to {}: {e}", path.display()))
    })?;
    if let Some(parent) = parent {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn write_v2_snapshot(
    dest: &Path,
    by_session: &BTreeMap<SessionId, SessionEntry>,
) -> std::io::Result<()> {
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let dir_for_tmp = parent.unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(dir_for_tmp)?;
    {
        let mut handle = tmp.as_file();
        handle.write_all(MAGIC_V2)?;
        for (id, entry) in by_session {
            let rec = encode_receipt_record(id, &entry.receipt)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            handle.write_all(&rec)?;
            if let Some(pin) = &entry.armed {
                let armed = LifecycleState::Armed {
                    deadline: pin.deadline,
                    settlement_hash: pin.settlement_hash.clone(),
                };
                let rec = encode_lifecycle_record(id, &armed)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                handle.write_all(&rec)?;
            }
            if !matches!(
                entry.state,
                LifecycleState::Proposed | LifecycleState::Armed { .. }
            ) {
                let rec = encode_lifecycle_record(id, &entry.state)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                handle.write_all(&rec)?;
            } else if matches!(entry.state, LifecycleState::Armed { .. }) && entry.armed.is_none() {
                let rec = encode_lifecycle_record(id, &entry.state)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                handle.write_all(&rec)?;
            }
        }
        handle.sync_all()?;
    }
    tmp.persist(dest).map_err(|e| {
        std::io::Error::other(format!(
            "persist receipt-vault snapshot to {}: {e}",
            dest.display()
        ))
    })?;
    if let Some(parent) = parent {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::Address,
        receipt::{Receipt, ReceiptContext, CHAIN_ID_TEST},
        session::Blind,
        sig::KeyPair,
    };
    use proptest::prelude::*;

    fn signed(seq: u64, bytes_used: u64, session_id: SessionId) -> SignedReceipt {
        let client = KeyPair::from_secret_bytes(&[0x11; 32]);
        let node = KeyPair::from_secret_bytes(&[0x22; 32]);
        let ctx = ReceiptContext::v1_1(Address::from_pubkey(&[0x33; 32]), CHAIN_ID_TEST);
        SignedReceipt::build(
            Receipt::new(ctx, session_id, seq, bytes_used, Blind::new([0x44; 32])),
            &client,
            &node,
        )
    }

    #[test]
    fn put_get_and_reopen_keeps_highest_seq() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let id = SessionId::new([0xAA; 32]);

        let v = ReceiptVault::open(&path).unwrap();
        v.put(&id, &signed(1, 100, id.clone())).unwrap();
        v.put(&id, &signed(3, 300, id.clone())).unwrap();
        assert_eq!(v.current_seq(&id), Some(3));
        drop(v);

        let reopened = ReceiptVault::open(&path).unwrap();
        let got = reopened.get(&id).unwrap();
        assert_eq!(got.receipt.seq, 3);
        assert_eq!(got.receipt.bytes_used, 300);
        assert_eq!(reopened.state(&id), Some(LifecycleState::Proposed));
    }

    #[test]
    fn rejects_seq_below_current_floor() {
        let vault = ReceiptVault::in_memory();
        let id = SessionId::new([0xBB; 32]);
        vault.put(&id, &signed(5, 500, id.clone())).unwrap();
        let err = vault.put(&id, &signed(4, 400, id.clone())).unwrap_err();
        assert!(matches!(err, ReceiptVaultError::SeqRegressed { .. }));
        assert_eq!(vault.get(&id).unwrap().receipt.seq, 5);
    }

    #[test]
    fn lower_seq_replay_cannot_replace_latest_receipt() {
        let vault = ReceiptVault::in_memory();
        let id = SessionId::new([0xB1; 32]);
        let latest = signed(7, 700, id.clone());
        let latest_hash = latest.settlement_hash();
        vault.put(&id, &latest).unwrap();

        let replay = signed(6, 9_999, id.clone());
        let err = vault.put(&id, &replay).unwrap_err();

        assert!(matches!(
            err,
            ReceiptVaultError::SeqRegressed {
                floor: 7,
                proposed: 6,
                ..
            }
        ));
        let kept = vault.get(&id).unwrap();
        assert_eq!(kept.receipt.seq, 7);
        assert_eq!(kept.receipt.bytes_used, 700);
        assert_eq!(kept.settlement_hash(), latest_hash);
    }

    #[test]
    fn equal_seq_identical_replay_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let id = SessionId::new([0xB2; 32]);
        let receipt = signed(7, 700, id.clone());

        let vault = ReceiptVault::open(&path).unwrap();
        vault.put(&id, &receipt).unwrap();
        let size_after_first = vault.file_size();
        vault.put(&id, &receipt).unwrap();

        assert_eq!(vault.file_size(), size_after_first);
        assert_eq!(vault.get(&id), Some(receipt));
    }

    #[test]
    fn equal_seq_conflict_is_rejected() {
        let vault = ReceiptVault::in_memory();
        let id = SessionId::new([0xB3; 32]);
        let latest = signed(7, 700, id.clone());
        let latest_hash = latest.settlement_hash();
        vault.put(&id, &latest).unwrap();

        let conflict = signed(7, 701, id.clone());
        let err = vault.put(&id, &conflict).unwrap_err();

        assert!(matches!(err, ReceiptVaultError::SeqConflict { .. }));
        let kept = vault.get(&id).unwrap();
        assert_eq!(kept.receipt.seq, 7);
        assert_eq!(kept.receipt.bytes_used, 700);
        assert_eq!(kept.settlement_hash(), latest_hash);
    }

    #[test]
    fn cross_session_receipt_cannot_be_vaulted_under_another_session() {
        let vault = ReceiptVault::in_memory();
        let path_id = SessionId::new([0xA1; 32]);
        let receipt_id = SessionId::new([0xA2; 32]);
        let receipt = signed(1, 100, receipt_id.clone());

        let err = vault.put(&path_id, &receipt).unwrap_err();

        assert!(matches!(err, ReceiptVaultError::SessionMismatch { .. }));
        assert!(vault.get(&path_id).is_none());
        assert!(vault.get(&receipt_id).is_none());
    }

    #[test]
    fn put_after_armed_rejects_higher_seq_and_keeps_armed_receipt() {
        let vault = ReceiptVault::in_memory();
        let id = SessionId::new([0xC1; 32]);
        let armed_receipt = signed(10, 1_000, id.clone());
        let armed_hash = armed_receipt.settlement_hash();
        vault.put(&id, &armed_receipt).unwrap();
        vault.mark_armed(&id, 77, armed_hash.clone()).unwrap();

        let poison = signed(11, 2_000, id.clone());
        let err = vault.put(&id, &poison).unwrap_err();

        assert!(matches!(err, ReceiptVaultError::ReceiptFrozen { .. }));
        let kept = vault.get(&id).unwrap();
        assert_eq!(kept.receipt.seq, 10);
        assert_eq!(kept.receipt.bytes_used, 1_000);
        assert_eq!(kept.settlement_hash(), armed_hash);
    }

    #[test]
    fn lifecycle_persists_and_rank_never_regresses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let id = SessionId::new([0xC2; 32]);
        let receipt = signed(1, 100, id.clone());
        let hash = receipt.settlement_hash();

        let vault = ReceiptVault::open(&path).unwrap();
        vault.put(&id, &receipt).unwrap();
        vault.mark_armed(&id, 88, hash.clone()).unwrap();
        vault
            .mark_claim_submitted(&id, "claim-tx".to_string())
            .unwrap();
        vault.mark_claimed(&id, "claimed-tx".to_string()).unwrap();
        drop(vault);

        let reopened = ReceiptVault::open(&path).unwrap();
        assert_eq!(reopened.get(&id), Some(receipt));
        assert_eq!(
            reopened.state(&id),
            Some(LifecycleState::Claimed {
                tx: "claimed-tx".to_string()
            })
        );
        let err = reopened.mark_armed(&id, 88, hash).unwrap_err();
        assert!(matches!(err, ReceiptVaultError::IllegalTransition { .. }));
    }

    #[test]
    fn compaction_drops_terminal_preserves_live_and_shrinks_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let live = SessionId::new([0xC3; 32]);
        let terminal = SessionId::new([0xC4; 32]);

        let vault = ReceiptVault::open(&path).unwrap();
        vault.put(&live, &signed(1, 100, live.clone())).unwrap();
        let terminal_receipt = signed(1, 200, terminal.clone());
        let terminal_hash = terminal_receipt.settlement_hash();
        vault.put(&terminal, &terminal_receipt).unwrap();
        vault.mark_armed(&terminal, 99, terminal_hash).unwrap();
        vault
            .mark_refunded(&terminal, "refund-tx".to_string())
            .unwrap();
        let before = vault.file_size();

        vault.compact().unwrap();
        let after = vault.file_size();

        assert!(after < before, "after={after} before={before}");
        assert!(vault.get(&terminal).is_none());
        assert_eq!(vault.get(&live).unwrap().receipt.bytes_used, 100);
    }

    #[test]
    #[cfg(unix)]
    fn compact_failure_keeps_handle_so_later_writes_still_persist() {
        // Regression for the CRITICAL: a compaction whose snapshot write fails
        // must NOT drop the file handle -- otherwise every later put()/mark_*()
        // silently goes in-memory-only and settlement evidence vanishes on the
        // next restart.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let a = SessionId::new([0xA1; 32]);
        let b = SessionId::new([0xB2; 32]);

        let vault = ReceiptVault::open(&path).unwrap();
        vault.put(&a, &signed(1, 100, a.clone())).unwrap();

        // Read-only dir -> compact()'s temp-snapshot create fails.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let compacted = vault.compact();
        // Restore writability for the put + reopen + tempdir cleanup.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(compacted.is_err(), "compact should fail with a read-only dir");

        // The invariant: the failed compaction kept the handle, so this persists.
        vault.put(&b, &signed(1, 200, b.clone())).unwrap();
        drop(vault);

        let reopened = ReceiptVault::open(&path).unwrap();
        assert!(reopened.get(&a).is_some(), "pre-compact receipt must survive");
        assert!(
            reopened.get(&b).is_some(),
            "a put AFTER a failed compaction must persist (handle not dropped)"
        );
    }

    #[test]
    fn replay_drops_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let id = SessionId::new([0xCC; 32]);

        let vault = ReceiptVault::open(&path).unwrap();
        vault.put(&id, &signed(1, 100, id.clone())).unwrap();
        drop(vault);

        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[1, 2, 3, 4, 5]).unwrap();
        f.sync_data().unwrap();

        let reopened = ReceiptVault::open(&path).unwrap();
        assert_eq!(reopened.get(&id).unwrap().receipt.seq, 1);
    }

    #[test]
    fn torn_tail_is_truncated_so_next_put_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let id = SessionId::new([0xE7; 32]);

        let v = ReceiptVault::open(&path).unwrap();
        v.put(&id, &signed(1, 100, id.clone())).unwrap();
        drop(v);

        let mut torn = Vec::new();
        torn.push(RECORD_RECEIPT);
        torn.extend_from_slice(id.as_bytes());
        torn.extend_from_slice(&4096u32.to_be_bytes());
        torn.extend_from_slice(&[0xAB; 10]);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&torn).unwrap();
        f.sync_data().unwrap();

        let v2 = ReceiptVault::open(&path).unwrap();
        assert_eq!(v2.get(&id).unwrap().receipt.seq, 1);
        v2.put(&id, &signed(2, 200, id.clone())).unwrap();
        drop(v2);

        let v3 = ReceiptVault::open(&path).unwrap();
        let got = v3.get(&id).unwrap();
        assert_eq!(got.receipt.seq, 2);
        assert_eq!(got.receipt.bytes_used, 200);
    }

    #[test]
    fn torn_tail_after_lifecycle_record_next_mutator_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let id = SessionId::new([0xC5; 32]);
        let receipt = signed(1, 100, id.clone());
        let hash = receipt.settlement_hash();

        let vault = ReceiptVault::open(&path).unwrap();
        vault.put(&id, &receipt).unwrap();
        vault.mark_armed(&id, 42, hash.clone()).unwrap();
        drop(vault);

        let full = encode_lifecycle_record(
            &id,
            &LifecycleState::ClaimSubmitted {
                tx: "partial".to_string(),
            },
        )
        .unwrap();
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&full[..full.len() / 2]).unwrap();
        f.sync_data().unwrap();

        let reopened = ReceiptVault::open(&path).unwrap();
        assert_eq!(
            reopened.state(&id),
            Some(LifecycleState::Armed {
                deadline: 42,
                settlement_hash: hash
            })
        );
        reopened
            .mark_claim_submitted(&id, "claim-tx".to_string())
            .unwrap();
        drop(reopened);

        let final_open = ReceiptVault::open(&path).unwrap();
        assert_eq!(
            final_open.state(&id),
            Some(LifecycleState::ClaimSubmitted {
                tx: "claim-tx".to_string()
            })
        );
    }

    #[test]
    fn ocrv1_migration_round_trips_to_proposed_v2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-v1.bin");
        let id = SessionId::new([0xC6; 32]);
        let receipt = signed(3, 300, id.clone());

        let mut raw = MAGIC_V1.to_vec();
        raw.extend_from_slice(&encode_v1_record(&id, &receipt).unwrap());
        fs::write(&path, raw).unwrap();

        let vault = ReceiptVault::open(&path).unwrap();
        assert_eq!(vault.get(&id), Some(receipt.clone()));
        assert_eq!(vault.state(&id), Some(LifecycleState::Proposed));
        drop(vault);

        let migrated = fs::read(&path).unwrap();
        assert!(migrated.starts_with(MAGIC_V2));
        let reopened = ReceiptVault::open(&path).unwrap();
        assert_eq!(reopened.get(&id), Some(receipt));
        assert_eq!(reopened.state(&id), Some(LifecycleState::Proposed));
    }

    #[test]
    fn armed_hash_mismatch_on_disk_errors_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-armed.bin");
        let id = SessionId::new([0xC7; 32]);
        let receipt = signed(1, 100, id.clone());

        let mut raw = MAGIC_V2.to_vec();
        raw.extend_from_slice(&encode_receipt_record(&id, &receipt).unwrap());
        raw.extend_from_slice(
            &encode_lifecycle_record(
                &id,
                &LifecycleState::Armed {
                    deadline: 50,
                    settlement_hash: "00".repeat(32),
                },
            )
            .unwrap(),
        );
        fs::write(&path, raw).unwrap();

        let err = ReceiptVault::open(&path).unwrap_err();
        assert!(matches!(err, ReceiptVaultError::ArmedHashMismatch { .. }));
    }

    #[test]
    fn replay_rejects_bad_crc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let id = SessionId::new([0xDD; 32]);

        let vault = ReceiptVault::open(&path).unwrap();
        vault.put(&id, &signed(1, 100, id.clone())).unwrap();
        drop(vault);

        let mut raw = fs::read(&path).unwrap();
        let last = raw.last_mut().unwrap();
        *last ^= 0x01;
        fs::write(&path, raw).unwrap();

        let err = ReceiptVault::open(&path).unwrap_err();
        assert!(matches!(err, ReceiptVaultError::ChecksumMismatch { .. }));
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        #[test]
        fn rank_monotonic_reordered_records_replay_to_identical(
            seq in 1_u64..100,
            bytes in 1_u64..1_000_000,
            terminal in 0_u8..4,
        ) {
            let id = SessionId::new([0xE1; 32]);
            let receipt = signed(seq, bytes, id.clone());
            let hash = receipt.settlement_hash();
            let mut records = vec![
                encode_receipt_record(&id, &receipt).unwrap(),
                encode_lifecycle_record(&id, &LifecycleState::Armed {
                    deadline: 123,
                    settlement_hash: hash.clone(),
                }).unwrap(),
            ];
            if terminal == 1 {
                records.push(encode_lifecycle_record(&id, &LifecycleState::ClaimSubmitted {
                    tx: "claim-submitted".to_string(),
                }).unwrap());
            }
            if terminal == 2 {
                records.push(encode_lifecycle_record(&id, &LifecycleState::Claimed {
                    tx: "claimed".to_string(),
                }).unwrap());
            } else if terminal == 3 {
                records.push(encode_lifecycle_record(&id, &LifecycleState::Expired).unwrap());
            }

            let mut canonical = MAGIC_V2.to_vec();
            for rec in &records {
                canonical.extend_from_slice(rec);
            }
            let mut reversed = MAGIC_V2.to_vec();
            for rec in records.iter().rev() {
                reversed.extend_from_slice(rec);
            }

            let (a, _) = replay_v2(&canonical, Path::new("canonical")).unwrap();
            let (b, _) = replay_v2(&reversed, Path::new("reversed")).unwrap();
            prop_assert_eq!(a.get(&id).map(|e| (&e.receipt, &e.state)), b.get(&id).map(|e| (&e.receipt, &e.state)));
        }
    }
}
