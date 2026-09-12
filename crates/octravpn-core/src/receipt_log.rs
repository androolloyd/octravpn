//! Shared append-log primitives for the money-path durable stores.
//!
//! Both [`crate::receipt_journal`] (fixed-width per-session floor) and
//! [`crate::receipt_vault`] (variable-length signed-receipt records) are
//! magic-headed, per-record-CRC append logs that must tolerate a torn
//! tail across a crash-during-append. They differ in record shape (so a
//! full merge doesn't fit), but they share two proven primitives that
//! used to be copy-pasted: the CRC-32 checksum and the
//! truncate-to-last-good-offset step. Factoring them here keeps the two
//! stores byte-for-byte consistent and gives finding #2's fix one
//! audited home.

use std::{fs::File, io};

/// Drop a torn tail so subsequent appends never sit behind leftover
/// partial bytes.
///
/// `good_len` is the byte offset just past the **last fully-written,
/// checksum-verified record** (the caller computes it during replay —
/// fixed-width for the journal, variable-length for the vault). If the
/// on-disk file is longer than that, a record was only partially
/// written before a crash: truncate it back to the boundary and fsync
/// so the next `append` lands on clean ground rather than behind
/// garbage that a later restart would misread as a record header.
///
/// Returns `Ok(true)` when it truncated, `Ok(false)` when the file was
/// already aligned. `file` must be opened for writing (append mode is
/// fine — `set_len`/`ftruncate` ignore the file position).
pub(crate) fn truncate_torn_tail(file: &File, good_len: u64) -> io::Result<bool> {
    let current = file.metadata()?.len();
    if current > good_len {
        file.set_len(good_len)?;
        file.sync_all()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// CRC-32 IEEE (the Ethernet / PNG / zip polynomial). Pulled inline so
/// we don't take a new dep for ~30 lines of code; the table is built
/// once on first call. Shared by the journal and vault record codecs so
/// they can never drift on the checksum that discriminates a torn tail
/// from real corruption.
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
    use std::io::Write;

    /// CRC32 spot check — matches known IEEE vectors.
    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    /// `truncate_torn_tail` cuts a file back to `good_len` and fsyncs,
    /// and is a no-op when the file is already at/under the boundary.
    #[test]
    fn truncate_torn_tail_drops_excess() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.bin");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(&[0xAB; 100]).unwrap();
        }
        let f = std::fs::OpenOptions::new()
            .append(true)
            .read(true)
            .open(&path)
            .unwrap();

        assert!(truncate_torn_tail(&f, 64).unwrap());
        assert_eq!(f.metadata().unwrap().len(), 64);
        // Already aligned -> no-op.
        assert!(!truncate_torn_tail(&f, 64).unwrap());
        assert_eq!(f.metadata().unwrap().len(), 64);
        // good_len above current size -> no-op (never grows the file).
        assert!(!truncate_torn_tail(&f, 128).unwrap());
        assert_eq!(f.metadata().unwrap().len(), 64);
    }
}
