//! Persistent per-session receipt-sequence floor.
//!
//! Fixes threat model items P1-8 and P1-9 (`docs/v2-threat-model.md`).
//!
//! ## Problem
//!
//! `ControlSession.last_seq` lives in a `BoundedMap` whose state is
//! lost on daemon restart. An attacker (or an OOM-killer, or a transient
//! segfault) that forces the node to restart mid-session would then
//! see the node sign a *fresh* `seq=K' < K_previously_signed` receipt
//! at a different `bytes_used`. Two distinct receipts for the same
//! `(session_id, seq)` under the operator's receipt-signing pubkey are
//! exactly what `slash_double_sign` (program/main-v2.aml:382-418) needs
//! to burn the operator's bond — i.e. an honest operator loses money
//! from a forced restart.
//!
//! ## Fix
//!
//! Every receipt-signing decision is gated on a persistent floor
//! `journal[session_id]`. The flow is:
//!
//! 1. Acquire the journal mutex.
//! 2. Load `prev = journal.get(session_id).unwrap_or(0)`.
//! 3. Compute the seq we want to sign at; the caller computes
//!    `next = max(in_mem_last_seq, prev) + 1`.
//! 4. Bump `journal[session_id] = next`.
//! 5. Atomically write the journal to disk + fsync.
//! 6. Release the mutex.
//! 7. Sign the receipt.
//!
//! Step 5 is what makes the fix work: after the rename-and-fsync
//! returns, the on-disk journal records the highest seq we have ever
//! committed to signing for this session. A crash *before* step 5 means
//! we never signed anything; a crash *after* means the operator might
//! have signed but not transmitted — fine, because the floor is still
//! recorded and the next call will skip past it.
//!
//! ## File format
//!
//! Hand-rolled binary so we don't drag in bincode/postcard. Tiny by
//! design — a tailnet has tens of concurrent sessions, not millions —
//! so the whole journal is loaded into memory once and rewritten in
//! full on every update. The format:
//!
//! ```text
//!   "OCRJ1\0\0\0"      (8 bytes — magic + version)
//!   u32 BE             (entry count)
//!   { 32 bytes session_id, u64 BE last_seq } × N
//! ```
//!
//! The format is forward-compatible: a future v2 can change the magic
//! and old readers will refuse to load (instead of mis-parsing). Atomic
//! durability is implemented by `tempfile::NamedTempFile::persist` plus
//! `File::sync_all` on the tempfile *before* persist, plus a best-effort
//! `sync_all` on the parent dir after persist.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use parking_lot::Mutex;

use crate::session::SessionId;

const MAGIC: &[u8; 8] = b"OCRJ1\0\0\0";

/// Persistent floor for `(session_id → last_signed_seq)`.
///
/// Cheap to clone (it's an `Arc`-shaped facade — the lock + path live
/// behind a `parking_lot::Mutex` inside the struct).
#[derive(Debug)]
pub struct ReceiptJournal {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// In-memory snapshot. Always reflects the on-disk state because
    /// the only mutator (`bump`) flushes before releasing the lock.
    by_session: BTreeMap<SessionId, u64>,
    /// Persistent path. `None` ⇒ in-memory-only mode (test fixtures).
    path: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad journal magic at {path} — refusing to clobber an unrelated file")]
    BadMagic { path: String },
    #[error("truncated journal at {path}: {detail}")]
    Truncated { path: String, detail: String },
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

pub type JournalResult<T> = std::result::Result<T, JournalError>;

impl ReceiptJournal {
    /// Open or initialise a journal at `path`. If the file does not
    /// exist, an empty journal is returned (the file is created on
    /// the first `bump`). Caller must hold the journal for the life of
    /// the daemon — there's no concurrency-safe way to share a single
    /// path between multiple processes (file locks would be brittle).
    pub fn open(path: impl Into<PathBuf>) -> JournalResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let by_session = if path.exists() {
            let raw = fs::read(&path)?;
            decode(&raw, &path)?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            inner: Mutex::new(Inner {
                by_session,
                path: Some(path),
            }),
        })
    }

    /// In-memory journal — for tests / control-plane unit harness.
    /// Equivalent to `open()` on a path that's never written.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_session: BTreeMap::new(),
                path: None,
            }),
        }
    }

    /// Return the persistent floor for `session_id`. Used by the
    /// control plane to compute `next_seq = max(in_mem, journal_floor)
    /// + 1`. Returns 0 if the session has never been seen.
    pub fn floor(&self, session_id: &SessionId) -> u64 {
        let g = self.inner.lock();
        g.by_session.get(session_id).copied().unwrap_or(0)
    }

    /// Snapshot of every `(session_id, last_signed_seq)` pair in the
    /// journal. Used by the operator-facing `audit replay` / `audit
    /// verify` tooling — the journal is a per-session floor, so each
    /// session appears at most once.
    ///
    /// The lock is held only long enough to clone the in-memory map.
    pub fn entries(&self) -> Vec<(SessionId, u64)> {
        let g = self.inner.lock();
        g.by_session
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Commit `new_seq` as the new floor for `session_id`. The write
    /// is atomic (tempfile + rename) and fsync'd before return. Fails
    /// with `SeqNotMonotonic` if `new_seq <= journal[session_id]` —
    /// callers MUST handle this as a refusal-to-sign event, never as
    /// "try a different seq".
    ///
    /// Hold the lock across disk I/O so a concurrent `floor` call
    /// can't observe a half-written state.
    pub fn bump(&self, session_id: &SessionId, new_seq: u64) -> JournalResult<()> {
        let mut g = self.inner.lock();
        let prev = g.by_session.get(session_id).copied().unwrap_or(0);
        if new_seq <= prev {
            return Err(JournalError::SeqNotMonotonic {
                session: session_id.to_hex(),
                floor: prev,
                proposed: new_seq,
            });
        }
        g.by_session.insert(session_id.clone(), new_seq);
        if let Some(path) = g.path.clone() {
            // Snapshot under the lock so we never write a state that
            // diverges from the in-memory view.
            let snapshot = encode(&g.by_session);
            // Drop the lock guard while writing? No — see module doc.
            // Holding the lock across disk I/O matches the "sign only
            // after the journal flushes" invariant; a concurrent
            // signer waiting on the mutex blocks until the floor is
            // durable. The expected concurrency for receipt-signing
            // (a tailnet's worth of sessions per node) is low enough
            // that this serialization is irrelevant for throughput.
            atomic_write(&path, &snapshot)?;
        }
        Ok(())
    }

    /// Reopen the journal from disk. Used by tests to simulate a
    /// restart: drop the live journal, then `ReceiptJournal::open` the
    /// same path. Production code never calls this — restart is by
    /// process restart.
    #[cfg(test)]
    fn reload(&self) -> JournalResult<()> {
        let mut g = self.inner.lock();
        let path = g
            .path
            .clone()
            .expect("reload only valid on a persistent journal");
        let raw = fs::read(&path)?;
        g.by_session = decode(&raw, &path)?;
        Ok(())
    }
}

fn encode(by_session: &BTreeMap<SessionId, u64>) -> Vec<u8> {
    let n = by_session.len() as u32;
    // Capacity = magic + count + (id + seq) * N.
    let mut out = Vec::with_capacity(MAGIC.len() + 4 + by_session.len() * (32 + 8));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&n.to_be_bytes());
    for (id, seq) in by_session {
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
    }
    out
}

fn decode(raw: &[u8], path: &Path) -> JournalResult<BTreeMap<SessionId, u64>> {
    if raw.is_empty() {
        // Brand new file — treat as empty journal. Avoids a spurious
        // "truncated" error after `fs::write(path, b"")`.
        return Ok(BTreeMap::new());
    }
    if raw.len() < MAGIC.len() + 4 {
        return Err(JournalError::Truncated {
            path: path.display().to_string(),
            detail: format!("file too short ({} bytes)", raw.len()),
        });
    }
    if &raw[..MAGIC.len()] != MAGIC {
        return Err(JournalError::BadMagic {
            path: path.display().to_string(),
        });
    }
    let mut cursor = MAGIC.len();
    let mut n_arr = [0u8; 4];
    n_arr.copy_from_slice(&raw[cursor..cursor + 4]);
    let n = u32::from_be_bytes(n_arr) as usize;
    cursor += 4;
    let entry_size = 32 + 8;
    let expected = MAGIC.len() + 4 + n * entry_size;
    if raw.len() != expected {
        return Err(JournalError::Truncated {
            path: path.display().to_string(),
            detail: format!(
                "expected {expected} bytes for {n} entries; got {} bytes",
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

/// Atomic write: tempfile in the same directory, sync_all, persist,
/// sync the parent directory. Returns once the rename is durable.
fn atomic_write(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let dir_for_tmp = parent.unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(dir_for_tmp)?;
    {
        let mut handle = tmp.as_file();
        handle.write_all(bytes)?;
        handle.sync_all()?;
    }
    tmp.persist(dest)
        .map_err(|e| std::io::Error::other(format!("persist tempfile to {}: {e}", dest.display())))?;
    // Best-effort: fsync the parent directory so the rename is durable
    // across crash. Linux supports this; macOS' POSIX implementation
    // accepts it; Windows ignores File::open on a directory.
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

    fn id(b: u8) -> SessionId {
        SessionId::new([b; 32])
    }

    /// P1-8/9: fresh session_id starts at floor 0.
    #[test]
    fn fresh_session_floor_is_zero() {
        let j = ReceiptJournal::in_memory();
        assert_eq!(j.floor(&id(0xAA)), 0);
        assert_eq!(j.floor(&id(0xBB)), 0);
    }

    /// P1-8/9: bump increases the floor. Subsequent floor() reads see
    /// the new value.
    #[test]
    fn bump_records_floor() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(0xAA), 1).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 1);
        j.bump(&id(0xAA), 5).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 5);
    }

    /// P1-8/9 core: bumping with `seq <= prev` fails. This is the
    /// invariant that protects against forced-restart double-signing.
    #[test]
    fn bump_rejects_non_monotonic() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(0xAA), 7).unwrap();
        let err = j.bump(&id(0xAA), 7).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
        let err = j.bump(&id(0xAA), 3).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
    }

    /// P1-8/9 restart-replay rejection test. Sign N, drop the journal,
    /// reopen the same path, attempt to bump back to <=N. Must fail
    /// even though the in-memory state was lost.
    #[test]
    fn restart_replay_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipts.bin");
        let sess = id(0xCC);

        // Boot 1: sign up to seq=10.
        let j1 = ReceiptJournal::open(&path).unwrap();
        j1.bump(&sess, 1).unwrap();
        j1.bump(&sess, 7).unwrap();
        j1.bump(&sess, 10).unwrap();
        drop(j1);

        // Boot 2: fresh process, same disk.
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&sess), 10, "journal must persist across restart");
        // Attacker (or in-mem reset bug) tries to sign seq=1 again.
        let err = j2.bump(&sess, 1).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
        // Or seq=10 (replay of the last legitimate one).
        let err = j2.bump(&sess, 10).unwrap_err();
        assert!(matches!(err, JournalError::SeqNotMonotonic { .. }));
        // Floor must NOT have moved.
        assert_eq!(j2.floor(&sess), 10);
        // Legitimate next seq is OK.
        j2.bump(&sess, 11).unwrap();
        assert_eq!(j2.floor(&sess), 11);
    }

    /// P1-8/9: each session_id has an independent floor. Bumping one
    /// must not affect the floor of another.
    #[test]
    fn per_session_isolation() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(0xAA), 5).unwrap();
        j.bump(&id(0xBB), 3).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 5);
        assert_eq!(j.floor(&id(0xBB)), 3);
        // A previously-unseen session is still at zero.
        assert_eq!(j.floor(&id(0xCC)), 0);
        // Bumping BB must not move AA.
        j.bump(&id(0xBB), 9).unwrap();
        assert_eq!(j.floor(&id(0xAA)), 5);
        assert_eq!(j.floor(&id(0xBB)), 9);
    }

    /// The reload helper exercises the codec by writing through it
    /// once, dropping, and reading back. This is the "the file is
    /// actually durable" check.
    #[test]
    fn reload_reads_durable_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(1), 42).unwrap();
        j.bump(&id(2), 1000).unwrap();
        j.reload().unwrap();
        assert_eq!(j.floor(&id(1)), 42);
        assert_eq!(j.floor(&id(2)), 1000);
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

    /// Truncated file at a non-magic length is rejected too. Catches
    /// crashes during the v0 format-change era — not a current bug,
    /// but we'd rather reject than partial-decode.
    #[test]
    fn truncated_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trunc.bin");
        // Magic + a count of 3 — but only one entry's worth of bytes.
        let mut buf = MAGIC.to_vec();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 32 + 8]); // one entry
        fs::write(&path, &buf).unwrap();
        let err = ReceiptJournal::open(&path).unwrap_err();
        assert!(matches!(err, JournalError::Truncated { .. }));
    }

    /// P1-8/9: end-to-end durability — after `bump` returns, an
    /// independent reader sees the new floor. Equivalent to "the file
    /// is fsync'd to disk" without needing to inject a sync_all probe;
    /// we open a parallel ReceiptJournal pointed at the same path and
    /// read through it, which forces a real `fs::read` of the file
    /// (not the in-memory cache).
    #[test]
    fn bump_durable_for_independent_reader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dur.bin");
        let writer = ReceiptJournal::open(&path).unwrap();
        writer.bump(&id(0xEE), 99).unwrap();
        // Parallel reader, separate in-memory state.
        let reader = ReceiptJournal::open(&path).unwrap();
        assert_eq!(reader.floor(&id(0xEE)), 99);
    }

    /// Encoding round-trip: encode → decode → equal.
    #[test]
    fn encode_decode_round_trip() {
        let mut m = BTreeMap::new();
        m.insert(id(0), 0);
        m.insert(id(1), u64::MAX);
        m.insert(id(255), 42);
        let buf = encode(&m);
        let p = Path::new("test");
        let back = decode(&buf, p).unwrap();
        assert_eq!(back, m);
    }

    /// Empty file (e.g. created by `touch`) decodes to empty map.
    #[test]
    fn empty_file_decodes_to_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        fs::write(&path, b"").unwrap();
        let j = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j.floor(&id(0)), 0);
    }
}
