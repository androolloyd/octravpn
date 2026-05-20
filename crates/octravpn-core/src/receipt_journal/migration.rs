//! v0 → v1 in-place migration on open. See `README.md` for the v0
//! byte layout. `replay_any` dispatches on magic; `write_v1_snapshot`
//! is the atomic tempfile+rename used both by migration and the sync
//! compaction path. `ensure_v1_header` stamps an empty file with the
//! v1 magic so the append handle sees a well-formed file.

use std::{collections::BTreeMap, fs, io::Write, path::Path};

use crate::session::SessionId;

use super::codec::{encode_record, replay_v1, MAGIC_V1};
use super::errors::{JournalError, JournalResult};

/// Legacy v0 (snapshot) journal magic — read for migration only.
const MAGIC_V0: &[u8; 8] = b"OCRJ1\0\0\0";
const V0_ENTRY_SIZE: usize = 32 + 8;

/// Replay either a v0 or v1 file. Returns `(map, needs_migration)`.
pub(crate) fn replay_any(
    raw: &[u8],
    path: &Path,
) -> JournalResult<(BTreeMap<SessionId, u64>, bool)> {
    if raw.is_empty() {
        return Ok((BTreeMap::new(), false));
    }
    if raw.len() < MAGIC_V1.len() {
        return Err(JournalError::Truncated {
            path: path.display().to_string(),
            detail: format!("file too short ({} bytes)", raw.len()),
        });
    }
    let magic = &raw[..MAGIC_V1.len()];
    if magic == MAGIC_V1 {
        Ok((replay_v1(raw, path)?, false))
    } else if magic == MAGIC_V0 {
        Ok((decode_v0(raw, path)?, true))
    } else {
        Err(JournalError::BadMagic {
            path: path.display().to_string(),
        })
    }
}

/// Decode a legacy v0 snapshot file. Used only by the migration path.
fn decode_v0(raw: &[u8], path: &Path) -> JournalResult<BTreeMap<SessionId, u64>> {
    debug_assert!(raw.starts_with(MAGIC_V0));
    if raw.len() < MAGIC_V0.len() + 4 {
        return Err(JournalError::Truncated {
            path: path.display().to_string(),
            detail: format!("v0 file too short ({} bytes)", raw.len()),
        });
    }
    let mut cursor = MAGIC_V0.len();
    let mut n_arr = [0u8; 4];
    n_arr.copy_from_slice(&raw[cursor..cursor + 4]);
    let n = u32::from_be_bytes(n_arr) as usize;
    cursor += 4;
    let expected = MAGIC_V0.len() + 4 + n * V0_ENTRY_SIZE;
    if raw.len() != expected {
        return Err(JournalError::Truncated {
            path: path.display().to_string(),
            detail: format!(
                "expected {expected} bytes for {n} v0 entries; got {} bytes",
                raw.len()
            ),
        });
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        let mut id = [0u8; 32];
        id.copy_from_slice(&raw[cursor..cursor + 32]);
        cursor += 32;
        let mut seq_arr = [0u8; 8];
        seq_arr.copy_from_slice(&raw[cursor..cursor + 8]);
        cursor += 8;
        out.insert(SessionId::new(id), u64::from_be_bytes(seq_arr));
    }
    Ok(out)
}

/// Atomically write a v1 journal snapshot at `dest`. One record per
/// live entry, in `BTreeMap` iteration order (lexicographic by
/// session id). The temp file is fsync'd before rename and the parent
/// directory is fsync'd after.
pub(crate) fn write_v1_snapshot(
    dest: &Path,
    by_session: &BTreeMap<SessionId, u64>,
) -> std::io::Result<()> {
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let dir_for_tmp = parent.unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(dir_for_tmp)?;
    {
        let mut handle = tmp.as_file();
        handle.write_all(MAGIC_V1)?;
        for (id, seq) in by_session {
            let rec = encode_record(id, *seq);
            handle.write_all(&rec)?;
        }
        handle.sync_all()?;
    }
    tmp.persist(dest).map_err(|e| {
        std::io::Error::other(format!("persist tempfile to {}: {e}", dest.display()))
    })?;
    if let Some(parent) = parent {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Ensure `path` exists and starts with v1 magic. Called from `open`
/// after `replay_any` has already validated any pre-existing content:
/// here we only handle the "absent" and "exists-but-empty" cases by
/// writing a magic-only header. A non-empty file is left as-is — by
/// construction it either starts with `MAGIC_V1` (we just wrote it via
/// `write_v1_snapshot` during v0 migration, or this is a normal reopen
/// of an existing journal) or `replay_any` would already have returned
/// an error.
pub(crate) fn ensure_v1_header(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        let len = fs::metadata(path)?.len();
        if len > 0 {
            return Ok(());
        }
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir_for_tmp = parent.unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(dir_for_tmp)?;
    {
        let mut handle = tmp.as_file();
        handle.write_all(MAGIC_V1)?;
        handle.sync_all()?;
    }
    tmp.persist(path).map_err(|e| {
        std::io::Error::other(format!("persist v1 header to {}: {e}", path.display()))
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
    use crate::receipt_journal::ReceiptJournal;

    fn id(b: u8) -> SessionId {
        SessionId::new([b; 32])
    }

    /// Bad magic on disk MUST error out rather than silently treat the
    /// file as empty. Protects against pointing the journal at the
    /// wrong file (e.g. swapping wg.key with receipts.bin in a config
    /// typo).
    #[test]
    fn bad_magic_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-journal.bin");
        // 16 bytes of "definitely-not-the-magic".
        fs::write(&path, b"NOTAJOURNAL\0\0\0\0\0\0").unwrap();
        let err = ReceiptJournal::open(&path).unwrap_err();
        assert!(matches!(err, JournalError::BadMagic { .. }));
    }

    /// Truncated v0 file is rejected (migration path). Catches crashes
    /// during the v0 era — not a current bug, but we'd rather reject
    /// than partial-decode.
    #[test]
    fn truncated_v0_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trunc.bin");
        // v0 magic + a count of 3 — but only one entry's worth of bytes.
        let mut buf = MAGIC_V0.to_vec();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; V0_ENTRY_SIZE]); // one entry
        fs::write(&path, &buf).unwrap();
        let err = ReceiptJournal::open(&path).unwrap_err();
        assert!(matches!(err, JournalError::Truncated { .. }));
    }

    /// Empty file (e.g. created by `touch`) opens as an empty journal.
    /// After open, the file holds at minimum the v1 header.
    #[test]
    fn empty_file_decodes_to_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        fs::write(&path, b"").unwrap();
        let j = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j.floor(&id(0)), 0);
        let raw = fs::read(&path).unwrap();
        assert_eq!(&raw, MAGIC_V1);
    }

    /// Verify v0 → v1 migration: write a hand-crafted v0 file, open
    /// through `ReceiptJournal::open`, confirm the entries replay, then
    /// confirm the on-disk file is now v1 magic-prefixed.
    #[test]
    fn migrates_v0_to_v1_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.bin");

        // Hand-roll a v0 fixture: magic + count + 2 entries.
        let mut buf = MAGIC_V0.to_vec();
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(id(0xAA).as_bytes());
        buf.extend_from_slice(&42u64.to_be_bytes());
        buf.extend_from_slice(id(0xBB).as_bytes());
        buf.extend_from_slice(&1000u64.to_be_bytes());
        fs::write(&path, &buf).unwrap();

        // Open through the public API — migration runs in `open`.
        let j = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 42);
        assert_eq!(j.floor(&id(0xBB)), 1000);

        // On-disk file is now v1.
        let raw = fs::read(&path).unwrap();
        assert!(raw.starts_with(MAGIC_V1));

        // And it round-trips: a second open sees the same entries.
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 42);
        assert_eq!(j2.floor(&id(0xBB)), 1000);
    }
}
