//! Audit-log rotation policy + chain-tip persistence (Perf-6).
//!
//! Today's audit log writes one file per UTC day (`audit-YYYY-MM-DD.jsonl`).
//! On a high-traffic node (100 receipts/s × 86400 s) a single day's file
//! grows to ~260M lines = ~26 s of HMAC-chain replay at boot — the
//! cold-start budget audit-8 §5.2 flagged.
//!
//! This module adds two knobs:
//!
//!   1. `RotationCfg::max_file_bytes` — when the active file would
//!      exceed this size, the writer closes it and opens a new file
//!      with the same date but a `-NNN` sequence suffix
//!      (`audit-2026-05-21-001.jsonl`). The HMAC chain continues
//!      across the rotation — the last MAC of file N is the prev_mac
//!      for line 1 of file N+1.
//!   2. `RotationCfg::max_file_count` — ring-buffer eviction. Once
//!      this many `audit-*.jsonl` files exist in the directory, the
//!      oldest one is deleted. Default 32 — operators with strict
//!      retention requirements should bump this or ship files to cold
//!      storage out-of-band.
//!
//! The **chain-tip** file (`<dir>/audit-chain.tip`) is a tiny JSON
//! commitment to `(file_id, seq, mac)` updated after every successful
//! fsync. On boot, the analytics indexer (and any future verifier)
//! uses the tip to **skip** re-verifying the already-verified prefix
//! — a 100k-line file replays in ~µs rather than ms.
//!
//! ## On-disk-backward-compat
//!
//! A node booting against a pre-Perf-6 single-file log:
//!
//!   - has no `audit-chain.tip` file ⇒ skip-to-tip degrades to full
//!     replay (no MAC is being committed to).
//!   - has `audit-YYYY-MM-DD.jsonl` files (no `-NNN` suffix) ⇒ accepted
//!     verbatim; the rotation suffix only appears on files born
//!     post-upgrade.
//!
//! On the first rotation post-upgrade the tip file is written; from
//! then on cold-start is fast.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Default `max_file_bytes` (256 MiB). Trade-off: smaller files ⇒
/// more rotations + more open-fd churn; larger files ⇒ if skip-to-tip
/// ever falls back, a slower full replay. 256 MiB ≈ 1M audit lines
/// ≈ 100 ms full replay on commodity SSD.
pub(crate) const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Default `max_file_count` (32 files). At 256 MiB/file that's an 8 GiB
/// retention ceiling — comfortable for a node ingesting 100 receipts/s
/// for a couple of weeks before the operator must ship files off.
pub(crate) const DEFAULT_MAX_FILE_COUNT: usize = 32;

/// Rotation policy. Owned by `Inner`; read on every write to decide
/// whether to roll over before appending the next line.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RotationCfg {
    pub max_file_bytes: u64,
    pub max_file_count: usize,
    pub boot_replay: BootReplayMode,
}

impl Default for RotationCfg {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_file_count: DEFAULT_MAX_FILE_COUNT,
            boot_replay: BootReplayMode::default(),
        }
    }
}

/// `[audit].boot_replay` selector.
///
///   - `Full` walks every line on every cold start (the pre-Perf-6
///     behaviour; available as a recovery tool via
///     `octravpn-node audit verify --full <dir>`).
///   - `SkipToTip` (default) uses the persisted chain-tip to skip
///     already-verified lines. **The tip's MAC commitment guarantees
///     a tampered prefix can't slip through:** if the line at the
///     tip's seq doesn't carry the tip's MAC verbatim, skip-to-tip
///     refuses to skip and falls back to full replay.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BootReplayMode {
    Full,
    #[default]
    SkipToTip,
}

/// Persisted chain-tip — committed AFTER every successful fsync so a
/// SIGKILL between line-write and tip-update simply forces a (still
/// correct) full replay on the next boot.
///
/// `file_id` is the file's basename (no directory). `seq` is the
/// 1-indexed line number within `file_id`. `mac` is hex(32) of that
/// line's MAC — the prev_mac for the first un-skipped line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ChainTip {
    pub file_id: String,
    pub seq: u64,
    pub mac: String,
}

impl ChainTip {
    /// On-disk path for the tip file. Co-located with the audit JSONLs
    /// so the verifier can find both via a single `dir` argument.
    /// **Filename intentionally hidden (`.`-prefix)** so the existing
    /// `read_dir` filter in upstream tests (and operator scripts) that
    /// gloms onto `starts_with("audit-")` to enumerate audit files
    /// doesn't sweep up the tip too. The legacy `.audit.key` already
    /// follows this convention.
    pub(crate) fn path(dir: &Path) -> PathBuf {
        dir.join(".audit-chain.tip")
    }

    /// Load the tip if present. Returns `Ok(None)` if the file is
    /// absent, corrupt, or otherwise unparseable — callers MUST treat
    /// any of those as "fall back to full replay". This is the
    /// graceful-degrade requirement from the Perf-6 brief.
    pub(crate) fn load(dir: &Path) -> Option<Self> {
        let p = Self::path(dir);
        let raw = std::fs::read(&p).ok()?;
        serde_json::from_slice::<Self>(&raw).ok()
    }

    /// Atomic-replace store: write to a `<path>.tmp` sibling, fsync,
    /// rename. The tip is small (~80 B) so a single write is atomic on
    /// every sane fs, but the explicit fsync + rename buys us a clean
    /// post-crash invariant: the on-disk tip either points at a fully
    /// fsynced line or doesn't exist.
    pub(crate) fn store(&self, dir: &Path) -> Result<()> {
        use std::io::Write;
        let p = Self::path(dir);
        let tmp = dir.join(".audit-chain.tip.tmp");
        let body = serde_json::to_vec(self).context("serialise chain tip")?;
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .with_context(|| format!("open tmp tip {}", tmp.display()))?;
            f.write_all(&body).context("write tip body")?;
            f.sync_data().context("fsync tip body")?;
        }
        std::fs::rename(&tmp, &p)
            .with_context(|| format!("rename {} -> {}", tmp.display(), p.display()))?;
        Ok(())
    }
}

/// Pick the next file basename for a given UTC date.
///
/// **Post-Perf-6 every newly-created file carries a `-NNN` suffix**,
/// starting at `-001`. A pre-Perf-6 node may have left an
/// `audit-YYYY-MM-DD.jsonl` (no suffix) on disk; we keep reading +
/// recovering from it but never write to it again. The reason is
/// lex-order: `'-'` (0x2D) sorts BEFORE `'.'` (0x2E), so a plain
/// file lex-sorts AFTER every suffixed file for the same date. If
/// the ring-buffer eviction ever evicted by lex-order while the
/// plain file was the oldest write, it would wrongly retain it as
/// "newest". Forcing the suffix from the very first write of a date
/// (after upgrade) keeps chronological == lexicographic.
pub(crate) fn next_file_basename(dir: &Path, date: &str) -> String {
    let mut highest: u32 = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(seq) = parse_rotation_suffix(&name, date) {
                if seq > highest {
                    highest = seq;
                }
            }
        }
    }
    format!("audit-{date}-{:03}.jsonl", highest + 1)
}

/// Parse `audit-<date>-NNN.jsonl` → `Some(NNN)`; everything else
/// (including the legacy suffix-less form) → `None`.
fn parse_rotation_suffix(name: &str, date: &str) -> Option<u32> {
    let prefix = format!("audit-{date}-");
    let rest = name.strip_prefix(&prefix)?;
    let stem = rest.strip_suffix(".jsonl")?;
    stem.parse::<u32>().ok()
}

/// All `audit-*.jsonl` files in `dir`, in chronological order.
/// `audit-chain.tip` + `.audit.key` are excluded.
///
/// Chronological order = `(date, suffix)` where:
///   - the legacy suffix-less `audit-YYYY-MM-DD.jsonl` is treated as
///     suffix 0 (the FIRST file for its date — it predates rotation);
///   - subsequent files for the same date carry their `-NNN` suffix.
///
/// This deviates from raw lexicographic order because `'-'` < `'.'`,
/// which would otherwise put `-001` before the plain file. The
/// dedicated sort gives operators the file order they actually expect.
pub(crate) fn list_audit_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read_dir {}", dir.display()))?
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_string_lossy().into_owned();
            let is_jsonl = Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));
            (name.starts_with("audit-") && is_jsonl).then_some(p)
        })
        .collect();
    paths.sort_by_key(|p| file_sort_key(p));
    Ok(paths)
}

/// `(date_str, suffix_seq)` sort key for `audit-*.jsonl` files. The
/// plain `audit-DATE.jsonl` form is `(DATE, 0)` so it sorts before
/// any `audit-DATE-NNN.jsonl` (which becomes `(DATE, NNN)`). Files
/// that don't parse fall to the end with an empty date + max seq.
fn file_sort_key(p: &Path) -> (String, u32) {
    let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
        return (String::new(), u32::MAX);
    };
    let Some(rest) = name
        .strip_prefix("audit-")
        .and_then(|s| s.strip_suffix(".jsonl"))
    else {
        return (String::new(), u32::MAX);
    };
    // `rest` is either `YYYY-MM-DD` (plain) or `YYYY-MM-DD-NNN`.
    // The date is always 10 chars (`YYYY-MM-DD`); anything longer
    // has a `-NNN` suffix.
    if rest.len() == 10 {
        (rest.to_string(), 0)
    } else if rest.len() >= 14 && rest.as_bytes()[10] == b'-' {
        let date = rest[..10].to_string();
        let seq = rest[11..].parse::<u32>().unwrap_or(u32::MAX);
        (date, seq)
    } else {
        (rest.to_string(), u32::MAX)
    }
}

/// Enforce `max_file_count` by deleting oldest files until at most
/// `max_file_count` remain. Best-effort: an unlink failure is logged
/// upstream but never aborts the write that triggered the rotation.
pub(crate) fn evict_to_count(dir: &Path, max_file_count: usize) -> Result<()> {
    let files = list_audit_files(dir)?;
    if files.len() <= max_file_count {
        return Ok(());
    }
    let drop_n = files.len() - max_file_count;
    for p in files.into_iter().take(drop_n) {
        if let Err(e) = std::fs::remove_file(&p) {
            tracing::warn!(path = %p.display(), error = %e, "audit ring-buffer evict failed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn next_basename_starts_at_001_when_dir_empty() {
        let dir = tempdir().unwrap();
        let name = next_file_basename(dir.path(), "2026-05-21");
        assert_eq!(name, "audit-2026-05-21-001.jsonl");
    }

    #[test]
    fn next_basename_increments_when_suffixed_exists() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("audit-2026-05-21-001.jsonl"), b"").unwrap();
        let n2 = next_file_basename(dir.path(), "2026-05-21");
        assert_eq!(n2, "audit-2026-05-21-002.jsonl");
        std::fs::write(dir.path().join(&n2), b"").unwrap();
        let n3 = next_file_basename(dir.path(), "2026-05-21");
        assert_eq!(n3, "audit-2026-05-21-003.jsonl");
    }

    #[test]
    fn next_basename_after_legacy_plain_starts_at_001() {
        // Pre-Perf-6 leftover: a plain `audit-DATE.jsonl` already on
        // disk. Next file picks up at -001 (the plain stays alongside
        // for backward-compat reads).
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("audit-2026-05-21.jsonl"), b"").unwrap();
        let n = next_file_basename(dir.path(), "2026-05-21");
        assert_eq!(n, "audit-2026-05-21-001.jsonl");
    }

    #[test]
    fn next_basename_unrelated_files_ignored() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("audit-2026-05-21-002.jsonl"), b"").unwrap();
        // From a previous date — must not affect today's counter.
        std::fs::write(dir.path().join("audit-2026-05-20-007.jsonl"), b"").unwrap();
        let n = next_file_basename(dir.path(), "2026-05-21");
        assert_eq!(n, "audit-2026-05-21-003.jsonl");
    }

    #[test]
    fn list_audit_files_excludes_tip_and_key() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".audit.key"), b"k").unwrap();
        std::fs::write(dir.path().join(".audit-chain.tip"), b"t").unwrap();
        std::fs::write(dir.path().join("audit-2026-05-21.jsonl"), b"").unwrap();
        let names: Vec<String> = list_audit_files(dir.path())
            .unwrap()
            .into_iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["audit-2026-05-21.jsonl".to_string()]);
    }

    #[test]
    fn evict_drops_oldest_first() {
        let dir = tempdir().unwrap();
        for n in [
            "audit-2026-05-19.jsonl",
            "audit-2026-05-20.jsonl",
            "audit-2026-05-21.jsonl",
        ] {
            std::fs::write(dir.path().join(n), b"x").unwrap();
        }
        evict_to_count(dir.path(), 2).unwrap();
        let remaining: Vec<String> = list_audit_files(dir.path())
            .unwrap()
            .into_iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            remaining,
            vec![
                "audit-2026-05-20.jsonl".to_string(),
                "audit-2026-05-21.jsonl".to_string(),
            ]
        );
    }

    #[test]
    fn tip_round_trip() {
        let dir = tempdir().unwrap();
        let t = ChainTip {
            file_id: "audit-2026-05-21.jsonl".into(),
            seq: 42,
            mac: "ab".repeat(32),
        };
        t.store(dir.path()).unwrap();
        let loaded = ChainTip::load(dir.path()).expect("tip loads");
        assert_eq!(loaded, t);
    }

    #[test]
    fn tip_missing_returns_none() {
        let dir = tempdir().unwrap();
        assert!(ChainTip::load(dir.path()).is_none());
    }

    #[test]
    fn tip_corrupt_returns_none() {
        let dir = tempdir().unwrap();
        std::fs::write(ChainTip::path(dir.path()), b"this is not json").unwrap();
        assert!(ChainTip::load(dir.path()).is_none());
    }
}
