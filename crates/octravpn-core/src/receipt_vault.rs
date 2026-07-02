//! Append-only vault for client-countersigned settlement receipts.
//!
//! This is intentionally separate from [`crate::receipt_journal`]. The
//! journal is a fixed-width per-session `u64` floor; the vault stores
//! variable-length `SignedReceipt` JSON records so an operator can
//! recover the exact settlement preimage after a restart.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use parking_lot::Mutex;

use crate::{receipt::SignedReceipt, session::SessionId};

pub const MAGIC_V1: &[u8; 8] = b"OCRV1\0\0\0";

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
}

pub type ReceiptVaultResult<T> = std::result::Result<T, ReceiptVaultError>;

#[derive(Debug)]
pub struct ReceiptVault {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    by_session: BTreeMap<SessionId, SignedReceipt>,
    path: Option<PathBuf>,
    handle: Option<std::fs::File>,
    file_size: u64,
}

impl ReceiptVault {
    /// Open or initialise a vault at `path`. Existing files must carry
    /// the `OCRV1` magic. On replay, the highest receipt sequence per
    /// session wins; a torn tail is ignored, while a bad CRC is surfaced
    /// as corruption.
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
        // `good_len` is the byte offset just past the last fully-written,
        // CRC-verified record. Anything after it is a torn tail from a
        // crash mid-append (a genuine bad CRC on a *complete* record still
        // surfaces as `ChecksumMismatch` and is not treated as torn).
        let (by_session, good_len) = replay_v1(&raw, &path)?;
        let mut handle = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;

        let file_size = if raw.is_empty() {
            handle.write_all(MAGIC_V1)?;
            handle.sync_data()?;
            MAGIC_V1.len() as u64
        } else {
            // Finding #2: truncate the torn tail BEFORE any append so the
            // next `put()` writes on a clean record boundary instead of
            // behind leftover partial bytes. Left in place, those bytes
            // are misread as a header on the next restart -> either the
            // fresh receipt is silently dropped (lost relay_claim
            // revenue) or `open` fails with ChecksumMismatch and the node
            // refuses to boot. Shared with the journal via `receipt_log`.
            crate::receipt_log::truncate_torn_tail(&handle, good_len)?;
            good_len
        };

        Ok(Self {
            inner: Mutex::new(Inner {
                by_session,
                path: Some(path),
                handle: Some(handle),
                file_size,
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
        self.inner.lock().by_session.get(session_id).cloned()
    }

    pub fn current_seq(&self, session_id: &SessionId) -> Option<u64> {
        self.inner
            .lock()
            .by_session
            .get(session_id)
            .map(|sr| sr.receipt.seq)
    }

    /// Append `receipt` and fsync before returning. The store accepts a
    /// same-sequence replay only when it is byte-identical to the stored
    /// receipt; a conflicting equal-seq receipt is rejected.
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
        if let Some(prev) = g.by_session.get(session_id) {
            if receipt.receipt.seq < prev.receipt.seq {
                return Err(ReceiptVaultError::SeqRegressed {
                    session: session_id.to_hex(),
                    floor: prev.receipt.seq,
                    proposed: receipt.receipt.seq,
                });
            }
            if receipt.receipt.seq == prev.receipt.seq {
                let prev_json = serde_json::to_vec(prev)?;
                let next_json = serde_json::to_vec(receipt)?;
                if prev_json == next_json {
                    return Ok(());
                }
                return Err(ReceiptVaultError::SeqConflict {
                    session: session_id.to_hex(),
                    floor: prev.receipt.seq,
                    proposed: receipt.receipt.seq,
                });
            }
        }

        let record = encode_record(session_id, receipt)?;
        if let Some(handle) = g.handle.as_mut() {
            handle.write_all(&record)?;
            handle.sync_data()?;
            g.file_size += record.len() as u64;
        }
        g.by_session.insert(session_id.clone(), receipt.clone());
        Ok(())
    }

    pub fn file_size(&self) -> u64 {
        self.inner.lock().file_size
    }

    fn display_path(&self) -> String {
        self.inner
            .lock()
            .path
            .as_ref()
            .map_or_else(|| "<in-memory>".to_string(), |p| p.display().to_string())
    }
}

fn encode_record(session_id: &SessionId, receipt: &SignedReceipt) -> ReceiptVaultResult<Vec<u8>> {
    let json = serde_json::to_vec(receipt)?;
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

/// Replay a v1 vault file. Returns the recovered `(session -> receipt)`
/// map and `good_len`: the byte offset just past the last fully-written,
/// CRC-verified record. A torn tail (short trailing bytes from a
/// crash mid-append) stops replay and is reflected as `good_len <
/// raw.len()` so the caller can truncate it; a bad CRC on a *complete*
/// record is real corruption and surfaces as `ChecksumMismatch`.
fn replay_v1(
    raw: &[u8],
    path: &Path,
) -> ReceiptVaultResult<(BTreeMap<SessionId, SignedReceipt>, u64)> {
    if raw.is_empty() {
        return Ok((BTreeMap::new(), 0));
    }
    let path_display = path.display().to_string();
    if raw.len() < MAGIC_V1.len() {
        return Err(ReceiptVaultError::Truncated {
            path: path_display,
            detail: "missing OCRV1 header".to_string(),
        });
    }
    if !raw.starts_with(MAGIC_V1) {
        return Err(ReceiptVaultError::BadMagic { path: path_display });
    }

    let mut out: BTreeMap<SessionId, SignedReceipt> = BTreeMap::new();
    let mut cursor = MAGIC_V1.len();
    // Offset past the last complete, CRC-verified record. Starts at the
    // header so a magic-only file reports `good_len == raw.len()`.
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

        match out.get(&session_id) {
            Some(cur) if receipt.receipt.seq < cur.receipt.seq => {}
            Some(cur) if receipt.receipt.seq == cur.receipt.seq => {
                let cur_json = serde_json::to_vec(cur)?;
                let next_json = serde_json::to_vec(&receipt)?;
                if cur_json != next_json {
                    return Err(ReceiptVaultError::SeqConflict {
                        session: session_id.to_hex(),
                        floor: cur.receipt.seq,
                        proposed: receipt.receipt.seq,
                    });
                }
            }
            _ => {
                out.insert(session_id, receipt);
            }
        }
        // This record is complete and CRC-verified: advance the
        // last-good boundary past it.
        good_len = cursor as u64;
    }
    Ok((out, good_len))
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

    /// Finding #2 regression: a torn tail present at open is truncated
    /// so a subsequent `put()` + reopen preserves the last good record
    /// with NO silent drop and NO ChecksumMismatch-on-boot. Before the
    /// fix, the leftover partial bytes sat in front of the freshly
    /// vaulted receipt: on the next restart replay either dropped that
    /// receipt (lost relay_claim revenue) or the node refused to boot.
    #[test]
    fn torn_tail_is_truncated_so_next_put_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt-vault.bin");
        let id = SessionId::new([0xE7; 32]);

        // Boot 1: one durable receipt.
        let v = ReceiptVault::open(&path).unwrap();
        v.put(&id, &signed(1, 100, id.clone())).unwrap();
        drop(v);

        // Simulate a crash mid-append: a partially written next record.
        // The 36-byte header (32-byte id + a 4-byte length claiming a
        // 4096-byte body) landed, but only 10 body bytes followed and
        // the CRC never made it to disk.
        let mut torn = Vec::new();
        torn.extend_from_slice(id.as_bytes());
        torn.extend_from_slice(&4096u32.to_be_bytes());
        torn.extend_from_slice(&[0xAB; 10]);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&torn).unwrap();
        f.sync_data().unwrap();

        // Boot 2: open must drop the torn tail (no ChecksumMismatch) and
        // recover seq=1, then a fresh put lands on a clean boundary.
        let v2 = ReceiptVault::open(&path).unwrap();
        assert_eq!(v2.get(&id).unwrap().receipt.seq, 1);
        v2.put(&id, &signed(2, 200, id.clone())).unwrap();
        drop(v2);

        // Boot 3: the freshly vaulted seq=2 survives (no drop) and open
        // succeeds (no ChecksumMismatch: the torn tail is gone, not
        // sitting behind the new record).
        let v3 = ReceiptVault::open(&path).unwrap();
        let got = v3.get(&id).unwrap();
        assert_eq!(got.receipt.seq, 2);
        assert_eq!(got.receipt.bytes_used, 200);
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
}
