//! v1 append-only binary format: 8-byte magic + 44-byte records of
//! `[session_id:32][seq:u64 BE][crc32:u32 BE]`. See `README.md` for
//! the full byte spec. A truncated tail is silently dropped on replay
//! (the bumper fsyncs before signing, so no dropped record was ever
//! committed). A bad checksum is a corruption signal and surfaces as
//! [`JournalError::ChecksumMismatch`].

use std::{collections::BTreeMap, path::Path};

use crate::session::SessionId;

use super::errors::{JournalError, JournalResult};

/// Append-only v1 journal magic.
pub(crate) const MAGIC_V1: &[u8; 8] = b"OCRJ2\0\0\0";
/// Total size of a single v1 record in bytes.
pub(crate) const RECORD_SIZE: usize = 32 + 8 + 4;

/// Encode a single v1 record: `[id:32][seq:u64 BE][crc:u32 BE]`.
pub(crate) fn encode_record(session_id: &SessionId, seq: u64) -> [u8; RECORD_SIZE] {
    let mut out = [0u8; RECORD_SIZE];
    out[..32].copy_from_slice(session_id.as_bytes());
    out[32..40].copy_from_slice(&seq.to_be_bytes());
    let crc = crc32_ieee(&out[..40]);
    out[40..44].copy_from_slice(&crc.to_be_bytes());
    out
}

/// Replay a v1 append-only file. A truncated tail (the file ended
/// mid-record because of a crash during append) is **dropped silently**:
/// any record that didn't get fully written can never have been signed
/// because the caller fsyncs before signing, so dropping it is the
/// invariant-preserving choice. A *checksum-failed* record, by
/// contrast, is a real corruption signal and bubbles up as an error.
pub(crate) fn replay_v1(raw: &[u8], path: &Path) -> JournalResult<BTreeMap<SessionId, u64>> {
    debug_assert!(raw.starts_with(MAGIC_V1));
    let body = &raw[MAGIC_V1.len()..];
    let mut out: BTreeMap<SessionId, u64> = BTreeMap::new();
    let mut cursor = 0usize;
    while cursor + RECORD_SIZE <= body.len() {
        let record = &body[cursor..cursor + RECORD_SIZE];
        let expected_crc = crc32_ieee(&record[..40]);
        let mut crc_arr = [0u8; 4];
        crc_arr.copy_from_slice(&record[40..44]);
        let got_crc = u32::from_be_bytes(crc_arr);
        if expected_crc != got_crc {
            return Err(JournalError::ChecksumMismatch {
                path: path.display().to_string(),
                offset: (MAGIC_V1.len() + cursor) as u64,
            });
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&record[..32]);
        let mut seq_arr = [0u8; 8];
        seq_arr.copy_from_slice(&record[32..40]);
        let seq = u64::from_be_bytes(seq_arr);
        // Take the max — the journal is monotonic per session; later
        // records always supersede earlier ones for the same id.
        out.entry(SessionId::new(id))
            .and_modify(|cur| {
                if seq > *cur {
                    *cur = seq;
                }
            })
            .or_insert(seq);
        cursor += RECORD_SIZE;
    }
    // Trailing partial record (cursor < body.len()): silently dropped.
    // See the function doc above.
    Ok(out)
}

/// CRC-32 IEEE (the Ethernet / PNG / zip polynomial). Pulled inline so
/// we don't take a new dep for ~30 lines of code; the table is built
/// once on first call.
pub(crate) fn crc32_ieee(bytes: &[u8]) -> u32 {
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

    /// CRC32 spot check — the table-driven implementation matches a
    /// known IEEE vector.
    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32_ieee(b""), 0);
        // CRC32("123456789") = 0xCBF43926.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    /// CRC32 differs for every single-bit flip in a 40-byte input.
    /// Discriminates torn-tail from corruption.
    #[test]
    fn crc32_sensitive_to_single_bit_flips() {
        let base = [0u8; 40];
        let baseline = crc32_ieee(&base);
        for byte_idx in 0..40 {
            for bit in 0..8 {
                let mut mutated = base;
                mutated[byte_idx] ^= 1 << bit;
                let c = crc32_ieee(&mutated);
                assert_ne!(c, baseline, "CRC32 collision: byte {byte_idx} bit {bit}");
            }
        }
    }
}
