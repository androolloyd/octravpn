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
//! 5. Append the new record + (per policy) fsync.
//! 6. Release the mutex.
//! 7. Sign the receipt.
//!
//! Step 5 is what makes the fix work: after `sync_data` returns, the
//! on-disk journal records the highest seq we have ever committed to
//! signing for this session. A crash *before* step 5 means we never
//! signed anything; a crash *after* means the operator might have
//! signed but not transmitted — fine, because the floor is still
//! recorded and the next call will skip past it.
//!
//! ## File format (v1 — append-only)
//!
//! The original v0 format (`OCRJ1\0\0\0` magic, `BTreeMap` snapshot)
//! rewrote the entire file on every bump — O(N) bytes per write,
//! synchronous fsync, single mutex serialising every receipt. At 10k
//! sessions that's ~400 KB written and fsync'd per receipt. The new
//! v1 format is append-only:
//!
//! ```text
//!   "OCRJ2\0\0\0"        (8 bytes — magic + version)
//!   record × N
//! ```
//!
//! Each record:
//!
//! ```text
//!   [session_id: 32B][seq: u64 BE][checksum: u32 BE]
//! ```
//!
//! `checksum = crc32_ieee(session_id || seq_be)`. A truncated tail (the
//! last partial record after a crash mid-write) is detected and ignored
//! on replay — the floor advances only for fully-written records. The
//! in-memory `BTreeMap<SessionId, u64>` mirrors the on-disk authoritative
//! state and is rebuilt by replaying the file on open.
//!
//! Compaction: the journal supports manual `compact()` (and, optionally,
//! an automatic compaction when the file grows past `compaction_watermark`
//! bytes — default 10 MB). Compaction rewrites a snapshot of the live
//! map atomically (tempfile + rename + fsync) and replaces the journal
//! file in place. The append-only invariant is preserved across
//! compactions (the rewritten file is itself a sequence of records, just
//! one per live entry).
//!
//! ## Fsync policy
//!
//! `FsyncPolicy::EveryWrite` (default) calls `sync_data` after every
//! append — durable at the cost of one fsync round-trip per receipt.
//! `FsyncPolicy::Periodic(Duration)` defers `sync_data` to the
//! configured interval; the OS write buffer still receives every append
//! immediately. Throughput-mode for environments where the operator
//! accepts a bounded loss window across a crash.
//!
//! ## Backward compatibility
//!
//! On `open`, the file magic is inspected. A v0 (`OCRJ1`) file is read
//! once, every entry replayed into the new in-memory map, then a fresh
//! v1 journal is written atomically over the same path. The v0 → v1
//! migration is a one-shot cost paid on the first boot after this
//! change.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::session::SessionId;

/// Append-only v1 journal magic.
const MAGIC_V1: &[u8; 8] = b"OCRJ2\0\0\0";
/// Legacy v0 (snapshot) journal magic — read for migration only.
const MAGIC_V0: &[u8; 8] = b"OCRJ1\0\0\0";
const RECORD_SIZE: usize = 32 + 8 + 4;
const V0_ENTRY_SIZE: usize = 32 + 8;
/// Compaction watermark: rewrite the journal once it grows past this
/// many bytes. 10 MB ≈ 240k records at v1 (44 B/record), well above any
/// realistic tailnet's live session count.
pub const DEFAULT_COMPACTION_WATERMARK: u64 = 10 * 1024 * 1024;

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
    /// the only mutator (`bump`) appends before releasing the lock.
    by_session: BTreeMap<SessionId, u64>,
    /// Persistent path. `None` ⇒ in-memory-only mode (test fixtures).
    path: Option<PathBuf>,
    /// Open append handle. `None` for in-memory mode or when the path
    /// is set but the handle has been deliberately dropped (compaction
    /// re-opens it).
    handle: Option<File>,
    /// Current on-disk file size in bytes (header + records). Tracked
    /// so we can decide when to auto-compact without a `metadata()`
    /// syscall per call.
    file_size: u64,
    /// Live durability policy.
    fsync_policy: FsyncPolicy,
    /// Last `sync_data` instant — only consulted under
    /// `FsyncPolicy::Periodic`.
    last_fsync: Instant,
    /// Auto-compaction threshold in bytes. Bumps that cross this
    /// watermark trigger a synchronous in-place compaction before
    /// returning. The watermark is conservative enough that compaction
    /// remains rare; an operator running near it can call `compact()`
    /// explicitly during a maintenance window.
    compaction_watermark: u64,
}

#[derive(Debug, thiserror::Error)]
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

pub type JournalResult<T> = std::result::Result<T, JournalError>;

impl ReceiptJournal {
    /// Open or initialise a journal at `path`. If the file does not
    /// exist, an empty journal is returned (the file is created on
    /// the first `bump`). Caller must hold the journal for the life of
    /// the daemon — there's no concurrency-safe way to share a single
    /// path between multiple processes (file locks would be brittle).
    ///
    /// If `path` already exists and starts with the v0 (`OCRJ1`) magic,
    /// the file is migrated in place: every v0 entry is read, the new
    /// v1 journal is written atomically over the same path, then the
    /// fresh v1 file is opened in append mode.
    pub fn open(path: impl Into<PathBuf>) -> JournalResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let (by_session, needs_migration) = if path.exists() {
            let raw = fs::read(&path)?;
            replay_any(&raw, &path)?
        } else {
            (BTreeMap::new(), false)
        };

        if needs_migration {
            // One-shot v0 → v1 rewrite. After this returns the path
            // holds a fresh v1 file containing one record per live
            // entry; auditors can replay it without ever seeing v0
            // again.
            write_v1_snapshot(&path, &by_session)?;
        }

        // Ensure the file exists with the v1 header so the append
        // handle below sees a well-formed file. `replay_any` has
        // already validated any pre-existing content.
        ensure_v1_header(&path)?;
        let handle = OpenOptions::new().append(true).read(true).open(&path)?;
        let file_size = handle.metadata()?.len();

        Ok(Self {
            inner: Mutex::new(Inner {
                by_session,
                path: Some(path),
                handle: Some(handle),
                file_size,
                fsync_policy: FsyncPolicy::default(),
                last_fsync: Instant::now(),
                compaction_watermark: DEFAULT_COMPACTION_WATERMARK,
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
                handle: None,
                file_size: 0,
                fsync_policy: FsyncPolicy::default(),
                last_fsync: Instant::now(),
                compaction_watermark: DEFAULT_COMPACTION_WATERMARK,
            }),
        }
    }

    /// Swap the durability policy. `EveryWrite` is the default and
    /// matches the original v0 behaviour; `Periodic` defers fsyncs to
    /// the configured interval. Throughput-mode for operators who
    /// accept a bounded loss window.
    pub fn set_fsync_policy(&self, policy: FsyncPolicy) {
        self.inner.lock().fsync_policy = policy;
    }

    /// Configure the auto-compaction watermark. Mainly useful in tests
    /// (so they don't have to write 10 MB to trigger compaction); in
    /// production the default is the right call.
    pub fn set_compaction_watermark(&self, bytes: u64) {
        self.inner.lock().compaction_watermark = bytes;
    }

    /// Return the persistent floor for `session_id`. Used by the
    /// control plane to compute `next_seq = max(in_mem, journal_floor)
    /// + 1`. Returns 0 if the session has never been seen.
    pub fn floor(&self, session_id: &SessionId) -> u64 {
        let g = self.inner.lock();
        g.by_session.get(session_id).copied().unwrap_or(0)
    }

    /// Alias for `floor`. Matches the naming used in the v2 threat
    /// model doc (where the per-session floor is referred to as the
    /// "read floor" of the receipt sequence).
    pub fn read_floor(&self, session_id: &SessionId) -> u64 {
        self.floor(session_id)
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
    /// is durable (append + fsync per policy) and atomic per record
    /// (the on-disk format is a sequence of fixed-width self-checksumed
    /// records; a torn tail is rejected on replay). Fails with
    /// `SeqNotMonotonic` if `new_seq <= journal[session_id]` — callers
    /// MUST handle this as a refusal-to-sign event, never as "try a
    /// different seq".
    ///
    /// Hold the lock across the append so a concurrent `floor` call
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
        // Persist first, then update in-memory state — that way a
        // failing write doesn't leave us with an in-memory floor higher
        // than what's on disk.
        if g.path.is_some() {
            let record = encode_record(session_id, new_seq);
            {
                let handle = g
                    .handle
                    .as_mut()
                    .expect("path is Some so handle must be Some");
                handle.write_all(&record)?;
            }
            // Durability decision.
            let do_fsync = match g.fsync_policy {
                FsyncPolicy::EveryWrite => true,
                FsyncPolicy::Periodic(dt) => g.last_fsync.elapsed() >= dt,
            };
            if do_fsync {
                if let Some(h) = g.handle.as_ref() {
                    h.sync_data()?;
                }
                g.last_fsync = Instant::now();
            }
            g.file_size += record.len() as u64;
            // Auto-compact if the journal has grown beyond the
            // watermark. Cheap because compaction only runs when the
            // file is *already* pathologically large.
            if g.file_size > g.compaction_watermark {
                compact_locked(&mut g)?;
            }
        }
        g.by_session.insert(session_id.clone(), new_seq);
        Ok(())
    }

    /// Manually trigger a compaction pass. Rewrites the journal as a
    /// minimal sequence of records (one per live session), atomically
    /// replacing the previous file. The in-memory state is unchanged.
    ///
    /// Useful for operators who want to reclaim disk space after a
    /// burst of bumps without waiting for the auto-watermark.
    pub fn compact(&self) -> JournalResult<()> {
        let mut g = self.inner.lock();
        if g.path.is_none() {
            return Ok(());
        }
        compact_locked(&mut g)
    }

    /// Current on-disk file size in bytes. Test/inspection helper.
    pub fn file_size(&self) -> u64 {
        self.inner.lock().file_size
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
        // Drop the handle so the read below sees the post-rename file.
        g.handle = None;
        let raw = fs::read(&path)?;
        let (map, _migrate) = replay_any(&raw, &path)?;
        g.by_session = map;
        let h = OpenOptions::new().append(true).read(true).open(&path)?;
        g.file_size = h.metadata()?.len();
        g.handle = Some(h);
        Ok(())
    }
}

/// Compaction routine. The lock is held by the caller; this rewrites
/// the journal in place via tempfile + rename and re-opens the append
/// handle.
fn compact_locked(g: &mut Inner) -> JournalResult<()> {
    let path = g.path.clone().expect("compact_locked requires a path");
    // Close the current handle before atomic rename (Windows would
    // refuse the rename otherwise; on Unix it's tidier).
    g.handle = None;
    write_v1_snapshot(&path, &g.by_session)?;
    let h = OpenOptions::new().append(true).read(true).open(&path)?;
    g.file_size = h.metadata()?.len();
    g.handle = Some(h);
    g.last_fsync = Instant::now();
    Ok(())
}

/// Encode a single v1 record: `[id:32][seq:u64 BE][crc:u32 BE]`.
fn encode_record(session_id: &SessionId, seq: u64) -> [u8; RECORD_SIZE] {
    let mut out = [0u8; RECORD_SIZE];
    out[..32].copy_from_slice(session_id.as_bytes());
    out[32..40].copy_from_slice(&seq.to_be_bytes());
    let crc = crc32_ieee(&out[..40]);
    out[40..44].copy_from_slice(&crc.to_be_bytes());
    out
}

/// Replay either a v0 or v1 file. Returns `(map, needs_migration)`.
fn replay_any(raw: &[u8], path: &Path) -> JournalResult<(BTreeMap<SessionId, u64>, bool)> {
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

/// Replay a v1 append-only file. A truncated tail (the file ended
/// mid-record because of a crash during append) is **dropped silently**:
/// any record that didn't get fully written can never have been signed
/// because the caller fsyncs before signing, so dropping it is the
/// invariant-preserving choice. A *checksum-failed* record, by
/// contrast, is a real corruption signal and bubbles up as an error.
fn replay_v1(raw: &[u8], path: &Path) -> JournalResult<BTreeMap<SessionId, u64>> {
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
fn write_v1_snapshot(dest: &Path, by_session: &BTreeMap<SessionId, u64>) -> std::io::Result<()> {
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
    tmp.persist(dest)
        .map_err(|e| std::io::Error::other(format!("persist tempfile to {}: {e}", dest.display())))?;
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
fn ensure_v1_header(path: &Path) -> std::io::Result<()> {
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
    tmp.persist(path)
        .map_err(|e| std::io::Error::other(format!("persist v1 header to {}: {e}", path.display())))?;
    if let Some(parent) = parent {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// CRC-32 IEEE (the Ethernet / PNG / zip polynomial). Pulled inline so
/// we don't take a new dep for ~30 lines of code; the table is built
/// once on first call.
fn crc32_ieee(bytes: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
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

    fn id(b: u8) -> SessionId {
        SessionId::new([b; 32])
    }

    /// P1-8/9: fresh session_id starts at floor 0.
    #[test]
    fn fresh_session_floor_is_zero() {
        let j = ReceiptJournal::in_memory();
        assert_eq!(j.floor(&id(0xAA)), 0);
        assert_eq!(j.floor(&id(0xBB)), 0);
        // `read_floor` is the named alias.
        assert_eq!(j.read_floor(&id(0xAA)), 0);
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

    /// P1-8/9: end-to-end durability — after `bump` returns, an
    /// independent reader sees the new floor.
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

    /// v1 append-only round trip: bump several times for the same
    /// session, reload, and confirm the highest seq is the floor.
    #[test]
    fn v1_append_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rt.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(0xAA), 1).unwrap();
        j.bump(&id(0xAA), 2).unwrap();
        j.bump(&id(0xAA), 99).unwrap();
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 99);
        // 3 records of size 44, plus the 8-byte v1 header.
        assert_eq!(j2.file_size(), 8 + 3 * RECORD_SIZE as u64);
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

    /// Checksum-mismatch detection: flip a bit in a v1 record and
    /// confirm `open` surfaces a `ChecksumMismatch` error rather than
    /// silently accepting the tampered seq.
    #[test]
    fn checksum_mismatch_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(0xAA), 5).unwrap();
        drop(j);

        // Open the raw file and flip a bit inside the seq field of the
        // single record. The record starts immediately after the
        // 8-byte v1 magic.
        let mut raw = fs::read(&path).unwrap();
        let seq_off = MAGIC_V1.len() + 32; // skip magic + id
        raw[seq_off] ^= 0x01;
        fs::write(&path, &raw).unwrap();

        let err = ReceiptJournal::open(&path).unwrap_err();
        assert!(matches!(err, JournalError::ChecksumMismatch { .. }));
    }

    /// Torn-tail tolerance: a record that didn't fully write (e.g. the
    /// process crashed mid-append) appears as a short trailing tail in
    /// the file. Replay must drop it silently — the operator never
    /// signed at that seq, so dropping the bogus tail is safe.
    #[test]
    fn torn_tail_dropped_silently() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torn.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(0xAA), 5).unwrap();
        drop(j);

        // Append a half-written record (35 bytes, less than the 44-byte
        // record size).
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0xFF; 35]).unwrap();
        drop(f);

        let j2 = ReceiptJournal::open(&path).unwrap();
        // Only the original record survives.
        assert_eq!(j2.floor(&id(0xAA)), 5);
    }

    /// Compaction preserves all entries and shrinks the file to the
    /// minimum size (one record per live session + header).
    #[test]
    fn compaction_preserves_entries_and_shrinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compact.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        // Hammer one session with many bumps so the file grows.
        for s in 1..=50u64 {
            j.bump(&id(0xAA), s).unwrap();
        }
        // And add a few independent sessions.
        j.bump(&id(0xBB), 7).unwrap();
        j.bump(&id(0xCC), 100).unwrap();
        let pre_size = j.file_size();
        assert!(pre_size >= 8 + 52 * RECORD_SIZE as u64);

        j.compact().unwrap();

        // After compaction, file size should be 3 records + header.
        let post_size = j.file_size();
        assert_eq!(post_size, 8 + 3 * RECORD_SIZE as u64);
        assert!(post_size < pre_size);

        // Floors preserved.
        assert_eq!(j.floor(&id(0xAA)), 50);
        assert_eq!(j.floor(&id(0xBB)), 7);
        assert_eq!(j.floor(&id(0xCC)), 100);

        // And after a real reopen.
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 50);
        assert_eq!(j2.floor(&id(0xBB)), 7);
        assert_eq!(j2.floor(&id(0xCC)), 100);
    }

    /// Auto-compaction kicks in when the file crosses the watermark.
    /// Use a tiny watermark so the test runs fast.
    #[test]
    fn auto_compaction_at_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auto.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        // Set the watermark to ~10 records' worth so the auto-compact
        // path triggers quickly.
        j.set_compaction_watermark(8 + 10 * RECORD_SIZE as u64);
        for s in 1..=100u64 {
            j.bump(&id(0xAA), s).unwrap();
        }
        // File should be compacted; one live entry → header + 1 record.
        let post = j.file_size();
        // It's allowed to be a few records past the watermark mid-batch
        // (we only compact after a bump that *crosses* the watermark),
        // but it must never run away to 100 records.
        assert!(post <= 8 + 10 * RECORD_SIZE as u64);
        assert_eq!(j.floor(&id(0xAA)), 100);
    }

    /// `FsyncPolicy::Periodic` accepts writes without per-call fsync.
    /// Verifies the setter wires up and `bump` still succeeds.
    #[test]
    fn periodic_fsync_policy_smoke() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("periodic.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.set_fsync_policy(FsyncPolicy::Periodic(Duration::from_millis(100)));
        for s in 1..=20u64 {
            j.bump(&id(0xAA), s).unwrap();
        }
        assert_eq!(j.floor(&id(0xAA)), 20);

        // Drop + reopen still sees the writes (the OS write buffer is
        // flushed even without sync_data; on a tempfs that's plenty).
        drop(j);
        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&id(0xAA)), 20);
    }

    /// CRC32 spot check — the table-driven implementation matches a
    /// known IEEE vector.
    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32_ieee(b""), 0);
        // CRC32("123456789") = 0xCBF43926.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    /// `entries()` returns every live (id, seq) pair, with the highest
    /// seq per id when many bumps land for the same session.
    #[test]
    fn entries_reports_live_state() {
        let j = ReceiptJournal::in_memory();
        j.bump(&id(0xAA), 1).unwrap();
        j.bump(&id(0xAA), 5).unwrap();
        j.bump(&id(0xBB), 100).unwrap();
        let mut got = j.entries();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(got, vec![(id(0xAA), 5), (id(0xBB), 100)]);
    }
}
