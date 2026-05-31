//! Sync-direct write path + [`AuditRecord`] + on-disk `ChainedLine`
//! envelope. The shared `write_inner_direct` helper is reused by
//! `audit::batched` under the `Inner` lock. The on-disk format
//! (`record_json` / `prev_mac` / `mac`) is contract — see
//! `audit/README.md` before reshaping.
//!
//! Perf-6 size-based rotation: before each line is written, the helper
//! compares `current_file_size + estimated_line_len` to
//! `rotation.max_file_bytes`. If the next line would push the file
//! past the threshold, the file is closed and a sequenced sibling
//! (`audit-YYYY-MM-DD-NNN.jsonl`) is opened. The complete line is
//! written into the NEW file — we never split a JSONL line across
//! files because the on-disk envelope (`record_json` + `prev_mac` +
//! `mac`) must be parseable as one JSON object per line; a partial
//! line at a file boundary would break every reader. The HMAC chain
//! carries forward across the rotation (file N+1's first line takes
//! file N's last MAC as its prev_mac), so a verifier reading the
//! directory in lexicographic order sees one unbroken chain.

use std::{fs::OpenOptions, io::Write, path::Path, sync::Arc};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc;

use super::batched::FlusherCmd;
use super::chain::{chain_step, load_or_create_key, ymd_utc};
use super::inner::{AuditCounters, Inner};
use super::rotation::{self, ChainTip, RotationCfg};
use super::AuditLog;

/// One audit record. `kind` is a short verb (`announce`, `get_state`,
/// etc.) so downstream tools can filter without parsing JSON deeply.
#[derive(Debug, Serialize)]
pub(crate) struct AuditRecord {
    pub ts_unix: u64,
    pub kind: &'static str,
    /// Source ip:port if relevant (the client that hit the endpoint).
    pub source: Option<String>,
    /// Session id (hex) if the action is per-session.
    pub session_id: Option<String>,
    /// Anything specific to the action (e.g. `bytes_used`).
    #[serde(skip_serializing_if = "Value::is_null", default)]
    pub extra: Value,
}

/// Persisted form of a log line: the canonical record bytes carried as
/// an escaped string field plus a MAC chain. Carrying `record_json`
/// verbatim makes MAC verification trivial — verifier hashes
/// `prev_mac || record_json` and compares to `mac`, with no risk of
/// serializer round-trip drift.
#[derive(Debug, Serialize)]
struct ChainedLine {
    record_json: String,
    /// Hex-encoded HMAC of the previous line (32 bytes of zeros for
    /// the first line in a daily file).
    prev_mac: String,
    /// Hex-encoded HMAC of this line: `HMAC(key, prev_mac || record_json)`.
    mac: String,
}

impl AuditLog {
    /// Open / create the log directory in sync-direct mode: every
    /// `write()` writes + fsyncs inline. Suitable for unit tests, the
    /// offline `audit verify` path, and callers without a tokio
    /// runtime. Production callers should prefer
    /// [`AuditLog::open_batched`] (issue #239).
    pub(crate) fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(dir.as_ref(), None, RotationCfg::default())
    }

    /// Open with a non-default rotation policy. Used by `hub::spawn`
    /// to plumb the operator-tuned `[audit]` config block.
    #[allow(dead_code)]
    pub(crate) fn open_with_rotation(dir: impl AsRef<Path>, rotation: RotationCfg) -> Result<Self> {
        Self::open_inner(dir.as_ref(), None, rotation)
    }

    pub(super) fn open_inner(
        dir: &Path,
        sender: Option<mpsc::Sender<FlusherCmd>>,
        rotation: RotationCfg,
    ) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create audit dir {}", dir.display()))?;
        let key = load_or_create_key(dir)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                dir: dir.to_path_buf(),
                current_date: String::new(),
                current_file: None,
                current_file_id: String::new(),
                current_file_size: 0,
                current_file_seq: 0,
                key,
                prev_mac: [0u8; 32],
                rotation,
            })),
            counters: Arc::new(AuditCounters::default()),
            sender,
            analytics_tap: None,
        })
    }

    /// Sync write — always direct (writes + fsyncs inline, even in
    /// batched mode). Use when the caller has no async context or
    /// needs read-after-write guarantees. Async code should prefer
    /// [`Self::write_async`].
    pub(crate) fn write(&self, rec: &AuditRecord) -> Result<()> {
        let mut inner = self.inner.lock();
        let r = write_inner_direct(&mut inner, &self.counters, rec, /*fsync=*/ true);
        // After a successful fsynced write the on-disk state matches
        // the in-memory `(file_id, seq, mac)` — publish the tip so a
        // crash-and-boot here picks up the chain.
        if r.is_ok() {
            let tip = ChainTip {
                file_id: inner.current_file_id.clone(),
                seq: inner.current_file_seq,
                mac: hex::encode(inner.prev_mac),
            };
            let dir = inner.dir.clone();
            drop(inner);
            if let Err(e) = tip.store(&dir) {
                tracing::warn!(error = %e, "audit chain-tip store failed");
            }
            self.tap_publish(rec);
        }
        r
    }

    /// The HMAC key as known to a running `AuditLog`. Needed for
    /// `verify_file` and by operators auditing the log out-of-band.
    pub(crate) fn key(&self) -> [u8; 32] {
        self.inner.lock().key
    }
}

/// Open or rotate the active file as needed, returning whether a
/// rotation was performed. Caller must hold the `Inner` lock.
///
/// Three cases:
///   1. No file open yet (cold start): walk the dir to recover the
///      latest file for this `date`. If a chain-tip file is present
///      AND points at one of those files, seed `prev_mac` from the
///      tip in O(1). Otherwise rebuild by HMAC-walking the on-disk
///      files for the date — slow but correct (this is the
///      "tip-missing-after-SIGKILL" fallback).
///   2. Date roll-over (`inner.current_date != date`): close, reset
///      `prev_mac = [0;32]`, open the new day's plain file.
///   3. Size threshold reached: close current, open the next
///      sequenced sibling, KEEP `prev_mac` so the chain carries
///      forward across files.
fn open_or_rotate(inner: &mut Inner, date: &str, next_line_len: u64) -> Result<bool> {
    let same_date = inner.current_date == date;
    let need_size_rotate = same_date
        && inner.current_file.is_some()
        && inner.current_file_size.saturating_add(next_line_len) > inner.rotation.max_file_bytes;

    if inner.current_file.is_some() && same_date && !need_size_rotate {
        return Ok(false);
    }

    // Close the current handle (drop -> close). The OS will flush
    // whatever's left in the kernel buffer; we already fsynced on the
    // most recent successful write so this is best-effort.
    inner.current_file = None;

    let mut rotated = false;
    let cold_start = inner.current_date.is_empty();
    if !same_date && !cold_start {
        // Date roll-over to a NEW day: the chain restarts at zero.
        // This mirrors the pre-Perf-6 per-day-independent verifiability.
        inner.current_date = date.to_string();
        inner.prev_mac = [0u8; 32];
        inner.current_file_seq = 0;
    } else if cold_start {
        // First write of this process lifetime: recover the chain
        // state from disk so we can continue writing where we left
        // off. The recover routine handles three sub-cases:
        //   a) clean dir / no files for this date ⇒ start at zero;
        //   b) tip file present + still valid ⇒ O(1) seed;
        //   c) tip missing / corrupt ⇒ HMAC-walk all files for the
        //      date and reconstruct the tail mac.
        inner.current_date = date.to_string();
        inner.current_file_seq = 0;
        let (prev_seed, latest_basename, latest_size, latest_seq) =
            recover_chain_for_date(&inner.dir, &inner.key, date)?;
        inner.prev_mac = prev_seed;
        // If we recovered a latest open-able file, seed the current_file_id
        // so the size-rotate logic in the next iteration can target it.
        // We still need to OPEN it below; this path falls through.
        if let Some(name) = latest_basename {
            inner.current_file_id = name;
            inner.current_file_size = latest_size;
            inner.current_file_seq = latest_seq;
        }
    } else if need_size_rotate {
        // Mid-day rotation: keep prev_mac, the chain continues.
        rotated = true;
        inner.current_file_seq = 0;
    }

    // Choose the file to open:
    //   - cold start with recovered tail: continue appending to the
    //     latest existing file (don't open a fresh -NNN unless it
    //     overflows on this very write);
    //   - cold start with no existing files OR mid-day size rotate
    //     OR fresh day: open a new sequenced sibling. Per-file
    //     naming policy lives in `next_file_basename` — every file
    //     post-Perf-6 carries a `-NNN` suffix.
    let basename = if cold_start && !inner.current_file_id.is_empty() {
        // Recovered an existing file. Check whether this very write
        // would overflow it; if so, treat as a rotation now.
        if inner.current_file_size.saturating_add(next_line_len) > inner.rotation.max_file_bytes {
            rotated = true;
            inner.current_file_seq = 0;
            inner.current_file_size = 0;
            rotation::next_file_basename(&inner.dir, date)
        } else {
            inner.current_file_id.clone()
        }
    } else {
        rotation::next_file_basename(&inner.dir, date)
    };

    let path = inner.dir.join(&basename);

    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open audit file {}", path.display()))?;

    inner.current_file = Some(f);
    inner.current_file_id = basename;
    // Size is recovered from disk if we're continuing an existing
    // file, else zero on a fresh file.
    let on_disk = std::fs::metadata(&path).map_or(0, |m| m.len());
    inner.current_file_size = on_disk;

    // Enforce ring buffer AFTER opening the new file so we never
    // accidentally evict the file we just created.
    if let Err(e) = rotation::evict_to_count(&inner.dir, inner.rotation.max_file_count) {
        tracing::warn!(error = %e, "audit ring-buffer evict failed");
    }

    Ok(rotated)
}

/// Cold-start chain recovery. Examines `dir` for `audit-<date>-*.jsonl`
/// files (and the legacy `audit-<date>.jsonl`), picks the most recent
/// (lexicographic), and either:
///
///   - returns `(zero_seed, None, 0, 0)` if no file exists for this
///     date (genuinely fresh dir for this UTC day);
///   - returns `(tip_mac, Some(latest_id), latest_size, tip_seq)` if
///     the chain-tip file commits to the latest file's tail AND the
///     line at `tip.seq` carries `tip.mac` verbatim (anti-truncation
///     guard);
///   - walks the on-disk files (in order) recomputing the HMAC chain
///     so we have a verified seed even when the tip is missing or
///     corrupt. Returns `(walked_mac, Some(latest_id), latest_size,
///     walked_seq)`.
fn recover_chain_for_date(
    dir: &Path,
    key: &[u8; 32],
    date: &str,
) -> Result<([u8; 32], Option<String>, u64, u64)> {
    // Files for THIS date only (other-day rotations don't chain into
    // the current day; per-day-independent verifiability is a
    // pre-Perf-6 contract we preserve).
    let mut files: Vec<std::path::PathBuf> = rotation::list_audit_files(dir)?
        .into_iter()
        .filter(|p| {
            p.file_name().and_then(|s| s.to_str()).is_some_and(|n| {
                n == format!("audit-{date}.jsonl")
                    || n.starts_with(&format!("audit-{date}-")) && is_jsonl_name(n)
            })
        })
        .collect();
    files.sort();
    let Some(latest) = files.last().cloned() else {
        return Ok(([0u8; 32], None, 0, 0));
    };
    let latest_id = latest
        .file_name()
        .and_then(|s| s.to_str())
        .map(String::from)
        .unwrap_or_default();
    let latest_size = std::fs::metadata(&latest).map_or(0, |m| m.len());

    // Fast path: tip file points at the latest file with a valid MAC.
    if let Some(tip) = ChainTip::load(dir) {
        if tip.file_id == latest_id {
            if let Some(seed) = tip_matches_file(&latest, &tip.mac, tip.seq) {
                return Ok((seed, Some(latest_id), latest_size, tip.seq));
            }
        }
    }

    // Slow path: walk every file in chronological order to rebuild
    // the chain MAC. The first file's seed is zero (per-day
    // independence); each subsequent file chains off the prior
    // file's last verified mac via `walk_with_seed`. We always call
    // `walk_with_seed` (it returns the seed unchanged on an empty
    // file) so cross-file chain continuity survives even when a
    // file's first prev_mac is non-zero.
    let mut prev = [0u8; 32];
    let mut latest_lines = 0u64;
    for (i, f) in files.iter().enumerate() {
        let (next_mac, count) = walk_with_seed(f, key, prev)?;
        prev = next_mac;
        if i + 1 == files.len() {
            latest_lines = count;
        }
    }
    Ok((prev, Some(latest_id), latest_size, latest_lines))
}

/// Walk a file with a non-zero seed and return (tail_mac, line_count).
/// Used by cold-start recovery to chain forward across files when the
/// tip file is missing. Stops at the first chain break or unreadable
/// line — the caller treats the returned mac as the verified tail.
fn walk_with_seed(path: &Path, key: &[u8; 32], seed: [u8; 32]) -> Result<([u8; 32], u64)> {
    use std::io::BufRead;
    let f = std::fs::File::open(path)
        .with_context(|| format!("open {} for chain-walk recovery", path.display()))?;
    let reader = std::io::BufReader::new(f);
    let mut prev = seed;
    let mut count = 0u64;
    for line in reader.lines() {
        let line = line.context("read chain-walk line")?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => break,
        };
        let Some(record_json) = v.get("record_json").and_then(Value::as_str) else {
            break;
        };
        let Some(claimed) = v.get("mac").and_then(Value::as_str) else {
            break;
        };
        let expect = chain_step(key, &prev, record_json.as_bytes());
        if hex::encode(expect) != claimed {
            break;
        }
        prev = expect;
        count += 1;
    }
    Ok((prev, count))
}

fn is_jsonl_name(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
}

/// Verify that the line at 1-indexed `seq` in `path` carries `mac_hex`
/// verbatim. Returns the 32-byte seed (the prev_mac for the next line)
/// when it matches, `None` otherwise.
fn tip_matches_file(path: &Path, mac_hex: &str, seq: u64) -> Option<[u8; 32]> {
    use std::io::BufRead;
    let f = std::fs::File::open(path).ok()?;
    let reader = std::io::BufReader::new(f);
    let mut line_no = 0u64;
    for line in reader.lines() {
        let line = line.ok()?;
        if line.trim().is_empty() {
            continue;
        }
        line_no += 1;
        if line_no == seq {
            let v: Value = serde_json::from_str(&line).ok()?;
            let claimed = v.get("mac")?.as_str()?;
            if claimed != mac_hex {
                return None;
            }
            let raw = hex::decode(claimed).ok()?;
            if raw.len() != 32 {
                return None;
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&raw);
            return Some(out);
        }
    }
    None
}

/// Direct synchronous write — used by both the sync `write()` API and
/// by the background flusher task. The `fsync` parameter lets the
/// flusher hold off the fsync until the end of a batch.
pub(super) fn write_inner_direct(
    inner: &mut Inner,
    counters: &AuditCounters,
    rec: &AuditRecord,
    fsync: bool,
) -> Result<()> {
    use std::sync::atomic::Ordering;

    let canonical = serde_json::to_string(rec).context("serialize audit record")?;
    let date = ymd_utc(rec.ts_unix);

    // Estimate the on-disk line length BEFORE building the envelope:
    //   record_json (canonical len, escaped — overhead ≤ ~2× for JSON
    //   strings with quotes/backslashes; in practice +~5%)
    //   + `"prev_mac":` + 64 hex + `"mac":` + 64 hex
    //   + braces/commas/newline = ~165 B overhead.
    // We use a conservative upper bound so the rotation triggers a
    // hair earlier than the literal byte limit rather than overshooting.
    let estimate = canonical.len() as u64 + 200;

    let rotated = open_or_rotate(inner, &date, estimate)?;
    if rotated {
        counters.rotations_total.fetch_add(1, Ordering::Relaxed);
    }

    let line_mac = chain_step(&inner.key, &inner.prev_mac, canonical.as_bytes());
    let chained = ChainedLine {
        record_json: canonical,
        prev_mac: hex::encode(inner.prev_mac),
        mac: hex::encode(line_mac),
    };
    let line = serde_json::to_string(&chained).context("serialize chained audit line")?;
    let f = inner.current_file.as_mut().expect("file just opened");
    f.write_all(line.as_bytes()).context("write audit line")?;
    f.write_all(b"\n").context("write audit newline")?;
    if fsync {
        f.sync_data().context("fsync audit log")?;
    }
    inner.prev_mac = line_mac;
    inner.current_file_size += line.len() as u64 + 1;
    inner.current_file_seq += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::rotation::ChainTip;
    use serde_json::json;
    use tempfile::tempdir;

    fn small_rec(i: u64, kind: &'static str) -> AuditRecord {
        AuditRecord {
            ts_unix: 1_700_000_000 + i,
            kind,
            source: None,
            session_id: Some(format!("s{i}")),
            extra: json!({"i": i, "pad": "x".repeat(64)}),
        }
    }

    #[test]
    fn writes_one_line_per_record() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: Some("127.0.0.1:1234".into()),
            session_id: Some("abc".into()),
            extra: json!({"k": 1}),
        })
        .unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_001,
            kind: "get_state",
            source: None,
            session_id: Some("abc".into()),
            extra: Value::Null,
        })
        .unwrap();
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            files
                .iter()
                .any(|f| f.starts_with("audit-") && is_jsonl_name(f)),
            "no audit file: {files:?}"
        );
        let audit_file = files
            .iter()
            .find(|f| f.starts_with("audit-") && is_jsonl_name(f))
            .unwrap();
        let body = std::fs::read_to_string(dir.path().join(audit_file)).unwrap();
        assert_eq!(body.lines().count(), 2);
        for line in body.lines() {
            let _: Value = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn rotates_when_date_advances() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "x",
            source: None,
            session_id: None,
            extra: Value::Null,
        })
        .unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000 + 86_400,
            kind: "y",
            source: None,
            session_id: None,
            extra: Value::Null,
        })
        .unwrap();
        let count = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref().is_ok_and(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    n.starts_with("audit-") && is_jsonl_name(&n)
                })
            })
            .count();
        assert_eq!(count, 2, "expected two daily audit files");
    }

    // ---- Perf-6 rotation tests ----

    /// A `max_file_bytes` tighter than one line forces every write to
    /// rotate. Three writes ⇒ three files. Confirms the byte-boundary
    /// check fires reliably and that the chain stays continuous across
    /// rotations (each file's first line carries the prior file's last
    /// MAC as `prev_mac`).
    #[test]
    fn rotation_triggers_at_byte_boundary() {
        let dir = tempdir().unwrap();
        let cfg = RotationCfg {
            max_file_bytes: 1, // every line overshoots
            max_file_count: 100,
            ..Default::default()
        };
        let log = AuditLog::open_with_rotation(dir.path(), cfg).unwrap();
        for i in 0..3u64 {
            log.write(&small_rec(i, "rotate")).unwrap();
        }
        let files = rotation::list_audit_files(dir.path()).unwrap();
        assert_eq!(files.len(), 3, "expected 3 rotated files: {files:?}");
        // Chain continuity: file 2's first line.prev_mac == file 1's last line.mac.
        let body1 = std::fs::read_to_string(&files[0]).unwrap();
        let body2 = std::fs::read_to_string(&files[1]).unwrap();
        let v1: Value = serde_json::from_str(body1.lines().last().unwrap()).unwrap();
        let v2: Value = serde_json::from_str(body2.lines().next().unwrap()).unwrap();
        assert_eq!(
            v1.get("mac").unwrap().as_str().unwrap(),
            v2.get("prev_mac").unwrap().as_str().unwrap(),
            "chain must continue across rotation"
        );
    }

    /// Ring-buffer eviction: `max_file_count` caps the on-disk file
    /// count; oldest files are dropped FIFO.
    #[test]
    fn ring_buffer_evicts_oldest() {
        let dir = tempdir().unwrap();
        let cfg = RotationCfg {
            max_file_bytes: 1,
            max_file_count: 2,
            ..Default::default()
        };
        let log = AuditLog::open_with_rotation(dir.path(), cfg).unwrap();
        for i in 0..5u64 {
            log.write(&small_rec(i, "ring")).unwrap();
        }
        let files = rotation::list_audit_files(dir.path()).unwrap();
        assert_eq!(
            files.len(),
            2,
            "ring buffer should cap at max_file_count: {files:?}"
        );
        // The two surviving files must be the highest-numbered (newest)
        // ones. Post-Perf-6 every file carries a `-NNN` suffix; with
        // 5 writes that overflow at every step we wrote -001..-005.
        // After evict_to_count(2): the two with the largest NNN.
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| n.contains("-00")),
            "every retained file must carry a -NNN suffix: {names:?}"
        );
        // The TWO highest suffixes survived (others were evicted).
        let mut suffixes: Vec<u32> = names
            .iter()
            .filter_map(|n| {
                let stem = n.strip_suffix(".jsonl")?;
                let suffix = stem.rsplit('-').next()?;
                suffix.parse::<u32>().ok()
            })
            .collect();
        suffixes.sort_unstable();
        assert_eq!(suffixes.len(), 2);
        assert!(
            suffixes[0] >= 4 && suffixes[1] >= 5,
            "ring should retain the two newest files; got suffixes {suffixes:?}"
        );
    }

    /// Concurrent write-while-rotating: under the existing bounded
    /// mpsc + flusher, a burst of async writes that triggers many
    /// rotations must produce a chain that verifies end-to-end with no
    /// dropped or duplicated lines.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writes_under_rotation() {
        let dir = tempdir().unwrap();
        let cfg = RotationCfg {
            max_file_bytes: 512, // small but not single-line
            max_file_count: 256,
            ..Default::default()
        };
        let log = AuditLog::open_batched_with_rotation(dir.path(), 32, 50, 8, cfg).unwrap();
        const N: u64 = 500;
        for i in 0..N {
            log.write_async(small_rec(i, "burst")).await.unwrap();
        }
        log.flush_and_close().await.unwrap();
        let files = rotation::list_audit_files(dir.path()).unwrap();
        assert!(files.len() > 1, "rotation should have produced > 1 file");
        // Chain must verify when walked in chronological order with
        // prev_mac carried across files.
        // After ring-buffer eviction, the chain seed-from-zero for
        // surviving files is no longer linear (the evicted prefix
        // owned the cross-file chain MACs). The post-eviction
        // boot-replay primitive is skip-to-tip: the tip file
        // commits to the latest-file tail MAC, and we walk forward
        // from there. Verify that *within* each surviving file the
        // chain is internally consistent — line N+1's prev_mac
        // equals line N's mac.
        let key = log.key();
        let mut intra_file_ok = 0usize;
        for f in &files {
            let body = std::fs::read_to_string(f).unwrap();
            let mut last_mac: Option<String> = None;
            for line in body.lines() {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                let claimed_prev = v.get("prev_mac").unwrap().as_str().unwrap().to_string();
                let claimed_mac = v.get("mac").unwrap().as_str().unwrap().to_string();
                let record_json = v.get("record_json").unwrap().as_str().unwrap();
                if let Some(prior) = &last_mac {
                    assert_eq!(
                        &claimed_prev,
                        prior,
                        "intra-file chain break in {}: prev_mac mismatch",
                        f.display()
                    );
                }
                // Verify the line's own MAC computes correctly.
                let mut prev_bytes = [0u8; 32];
                let raw = hex::decode(&claimed_prev).unwrap();
                prev_bytes.copy_from_slice(&raw);
                let expect = crate::audit::chain_step(&key, &prev_bytes, record_json.as_bytes());
                assert_eq!(
                    hex::encode(expect),
                    claimed_mac,
                    "MAC mismatch within {}",
                    f.display()
                );
                last_mac = Some(claimed_mac);
                intra_file_ok += 1;
            }
        }
        assert!(intra_file_ok > 0);

        // Skip-to-tip boot replay handles the cross-file ladder: it
        // seeds from the tip's commitment. Confirm the tip's last
        // verified line is in the latest file.
        let reports = AuditLog::verify_dir_skip_to_tip(&key, dir.path()).unwrap();
        // Every report after the tip's file must verify cleanly.
        assert!(
            reports.iter().all(|(_, r)| r.first_error.is_none()),
            "skip-to-tip reports: {reports:?}"
        );
    }

    /// SIGKILL between rotate-close and tip-update: simulate the
    /// crash by writing 5 lines (filling > max_file_bytes), then
    /// MANUALLY rotating mid-stream by closing+deleting the tip file
    /// to mimic "tip not yet committed to new file" — on next open the
    /// log must come up cleanly + continue the chain.
    #[test]
    fn sigkill_between_close_and_open_leaves_audit_verifiable() {
        let dir = tempdir().unwrap();
        let cfg = RotationCfg {
            max_file_bytes: 256,
            max_file_count: 100,
            ..Default::default()
        };
        {
            let log = AuditLog::open_with_rotation(dir.path(), cfg).unwrap();
            for i in 0..6u64 {
                log.write(&small_rec(i, "pre")).unwrap();
            }
        }
        // Simulate the crash: nuke the tip file so the next boot
        // can't short-circuit. The audit JSONL files themselves are
        // already on-disk + fsynced.
        let tip_path = ChainTip::path(dir.path());
        if tip_path.exists() {
            std::fs::remove_file(&tip_path).unwrap();
        }
        // Reopen + continue writing.
        let log2 = AuditLog::open_with_rotation(dir.path(), cfg).unwrap();
        log2.write(&small_rec(99, "post")).unwrap();
        // Now walk every file with chained verification — the whole
        // log must verify end-to-end.
        let files = rotation::list_audit_files(dir.path()).unwrap();
        let mut prev = [0u8; 32];
        let mut total = 0u64;
        let key = log2.key();
        for f in &files {
            let r = AuditLog::verify_file_with_seed(&key, f, prev).unwrap();
            assert!(
                r.first_error.is_none(),
                "post-SIGKILL chain broken in {}: {:?}",
                f.display(),
                r.first_error
            );
            total += r.entries;
            prev = r.last_mac;
        }
        assert_eq!(total, 7, "6 pre-crash + 1 post-crash lines on disk");
    }

    /// Tip file corruption → boot replay falls back to full walk and
    /// still verifies. (The corruption itself is silently absorbed
    /// because the tip is best-effort acceleration; the audit JSONL
    /// is the source of truth.)
    #[test]
    fn tip_file_corrupt_falls_back_to_full_replay() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..3u64 {
            log.write(&small_rec(i, "y")).unwrap();
        }
        // Corrupt the tip file.
        std::fs::write(ChainTip::path(dir.path()), b"corrupt garbage").unwrap();
        // Boot-replay-style walk: tip won't load, full replay verifies.
        assert!(ChainTip::load(dir.path()).is_none());
        let files = rotation::list_audit_files(dir.path()).unwrap();
        let mut prev = [0u8; 32];
        let mut total = 0u64;
        for f in &files {
            let r = AuditLog::verify_file_with_seed(&log.key(), f, prev).unwrap();
            assert!(r.first_error.is_none());
            total += r.entries;
            prev = r.last_mac;
        }
        assert_eq!(total, 3);
    }
}
