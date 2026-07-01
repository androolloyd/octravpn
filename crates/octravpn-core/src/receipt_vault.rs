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
        let by_session = replay_v1(&raw, &path)?;
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
            raw.len() as u64
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
    /// same-sequence replay for idempotent POST retries and rejects only
    /// receipts below the current vault floor.
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
        if let Some(prev) = g.by_session.get(session_id).map(|sr| sr.receipt.seq) {
            if receipt.receipt.seq < prev {
                return Err(ReceiptVaultError::SeqRegressed {
                    session: session_id.to_hex(),
                    floor: prev,
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
    let crc = crc32_ieee(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out)
}

fn replay_v1(raw: &[u8], path: &Path) -> ReceiptVaultResult<BTreeMap<SessionId, SignedReceipt>> {
    if raw.is_empty() {
        return Ok(BTreeMap::new());
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
        let expected_crc = crc32_ieee(&raw[record_start..json_end]);
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

        let replace = match out.get(&session_id) {
            Some(cur) => receipt.receipt.seq >= cur.receipt.seq,
            None => true,
        };
        if replace {
            out.insert(session_id, receipt);
        }
    }
    Ok(out)
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = table[idx] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
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
