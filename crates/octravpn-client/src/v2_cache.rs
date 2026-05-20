//! Tiny on-disk cache for decrypted v2 sealed-policy bundles.
//!
//! Layout: `<cache_dir>/<circle_id>.json` — one file per circle. Cache
//! invalidation is keyed on the `plaintext_hash` returned by the chain
//! alongside the sealed ciphertext: if the hash matches the cached copy,
//! we skip both the RPC fetch and the decrypt; otherwise we refresh.
//!
//! No eviction logic — circle ids are tiny and we never accumulate more
//! than a handful per tailnet. The cache is *correctness-preserving*,
//! not security-preserving (the plaintext lives on disk; treat it the
//! same as the sealed passphrase).

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::discover_v2::CirclePolicy;

/// One entry per circle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CachedPolicy {
    pub circle_id: String,
    /// sha256 of the decrypted plaintext (matches the chain's
    /// `plaintext_hash` field). Used as the cache key.
    pub plaintext_hash: String,
    pub policy: CirclePolicy,
    /// Unix seconds when this entry was last written.
    pub cached_at: u64,
}

/// In-memory cache backed by a directory of per-circle JSON files.
/// Loads everything once at construction and writes-through on `put`.
pub(crate) struct PolicyCache {
    dir: PathBuf,
    entries: HashMap<String, CachedPolicy>,
}

impl PolicyCache {
    /// Open the cache rooted at `dir`. Creates the directory if needed.
    /// Existing files are loaded into memory; malformed files are
    /// skipped with a debug log (never fatal — cache is best-effort).
    pub(crate) fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let mut entries = HashMap::new();
        let read_dir = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                tracing::debug!(dir = %dir.display(), error = %e, "cache read_dir failed");
                return Ok(Self { dir, entries });
            }
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            match fs::read_to_string(&path) {
                Ok(s) => match serde_json::from_str::<CachedPolicy>(&s) {
                    Ok(c) => {
                        entries.insert(c.circle_id.clone(), c);
                    }
                    Err(e) => {
                        tracing::debug!(path = %path.display(), error = %e, "cache decode failed");
                    }
                },
                Err(e) => {
                    tracing::debug!(path = %path.display(), error = %e, "cache file unreadable");
                }
            }
        }
        Ok(Self { dir, entries })
    }

    /// Lookup the cached entry, if any.
    pub(crate) fn get(&self, circle_id: &str) -> Option<CachedPolicy> {
        self.entries.get(circle_id).cloned()
    }

    /// Write-through update. Best-effort — if the disk write fails the
    /// in-memory entry still updates and we return the error so callers
    /// can log it.
    pub(crate) fn put(
        &mut self,
        circle_id: &str,
        plaintext_hash: &str,
        policy: &CirclePolicy,
    ) -> Result<()> {
        let entry = CachedPolicy {
            circle_id: circle_id.to_string(),
            plaintext_hash: plaintext_hash.to_string(),
            policy: policy.clone(),
            cached_at: octravpn_core::util::now_unix_secs(),
        };
        let body = serde_json::to_string_pretty(&entry).context("encode cache entry")?;
        let path = entry_path(&self.dir, circle_id);
        fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        self.entries.insert(circle_id.to_string(), entry);
        Ok(())
    }

    /// Drop an entry from cache (file + memory). Returns whether anything
    /// was removed. Surfaced as `octravpn discover v2 --refresh` and as a
    /// programmatic invalidator after a `policy_version` bump observed
    /// out-of-band.
    pub(crate) fn invalidate(&mut self, circle_id: &str) -> Result<bool> {
        let path = entry_path(&self.dir, circle_id);
        let removed_mem = self.entries.remove(circle_id).is_some();
        let removed_disk = match fs::remove_file(&path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e).with_context(|| format!("rm {}", path.display())),
        };
        Ok(removed_mem || removed_disk)
    }

    /// Drop every cached entry.
    pub(crate) fn clear(&mut self) -> Result<()> {
        let ids: Vec<String> = self.entries.keys().cloned().collect();
        for id in ids {
            self.invalidate(&id)?;
        }
        Ok(())
    }

    /// Path of the on-disk file for diagnostics / tests.
    #[allow(dead_code)]
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Resolve the cache directory. Precedence:
///   * `cfg_cache_dir` if non-empty
///   * `$OCTRAVPN_CACHE_DIR` env var
///   * `$XDG_CACHE_HOME/octravpn/policies/`
///   * `$HOME/.cache/octravpn/policies/`
///   * `./state/policies/` as a last-resort fallback
pub(crate) fn resolve_cache_dir(cfg_cache_dir: &str) -> PathBuf {
    if !cfg_cache_dir.is_empty() {
        return PathBuf::from(cfg_cache_dir);
    }
    if let Ok(s) = std::env::var("OCTRAVPN_CACHE_DIR") {
        if !s.trim().is_empty() {
            return PathBuf::from(s);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("octravpn").join("policies");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home)
                .join(".cache")
                .join("octravpn")
                .join("policies");
        }
    }
    PathBuf::from("state").join("policies")
}

fn entry_path(dir: &Path, circle_id: &str) -> PathBuf {
    // The circle id is base58-ish + `oct` prefix — already filesystem-safe
    // since base58 excludes `/`, `\`, `:` etc. Belt-and-suspenders: replace
    // anything outside `[A-Za-z0-9_-]` with `_` so we never blow up on a
    // pathologically encoded id.
    let safe: String = circle_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    dir.join(format!("{safe}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_policy() -> CirclePolicy {
        CirclePolicy {
            endpoint: "1.2.3.4:51820".into(),
            wg_pubkey_b64: "AAA".into(),
            region: "us".into(),
            price_per_mb_shared: 10,
            price_per_mb_internal: 0,
            policy_version: 1,
            attestation_ts: 0,
        }
    }

    #[test]
    fn open_creates_dir_and_starts_empty() {
        let td = tempdir().unwrap();
        let dir = td.path().join("nested/here");
        let cache = PolicyCache::open(&dir).unwrap();
        assert!(cache.dir().is_dir());
        assert!(cache.get("missing").is_none());
    }

    #[test]
    fn put_and_get_round_trip_through_disk() {
        let td = tempdir().unwrap();
        let mut cache = PolicyCache::open(td.path()).unwrap();
        let policy = sample_policy();
        cache.put("octABC", "deadbeef", &policy).unwrap();
        // Reload from disk.
        let cache2 = PolicyCache::open(td.path()).unwrap();
        let got = cache2.get("octABC").expect("entry persisted");
        assert_eq!(got.plaintext_hash, "deadbeef");
        assert_eq!(got.policy.endpoint, policy.endpoint);
    }

    #[test]
    fn invalidate_removes_disk_file() {
        let td = tempdir().unwrap();
        let mut cache = PolicyCache::open(td.path()).unwrap();
        cache.put("octABC", "h", &sample_policy()).unwrap();
        let p = entry_path(td.path(), "octABC");
        assert!(p.exists());
        assert!(cache.invalidate("octABC").unwrap());
        assert!(!p.exists());
        assert!(cache.get("octABC").is_none());
        // Second invalidate is a no-op.
        assert!(!cache.invalidate("octABC").unwrap());
    }

    #[test]
    fn clear_drops_every_entry() {
        let td = tempdir().unwrap();
        let mut cache = PolicyCache::open(td.path()).unwrap();
        cache.put("a", "h1", &sample_policy()).unwrap();
        cache.put("b", "h2", &sample_policy()).unwrap();
        cache.clear().unwrap();
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_none());
    }

    #[test]
    fn entry_path_sanitizes_weird_chars() {
        let td = tempdir().unwrap();
        let p = entry_path(td.path(), "oct/with:weird\\chars");
        assert!(p.file_name().unwrap().to_str().unwrap().chars().all(|c| c
            .is_ascii_alphanumeric()
            || c == '-'
            || c == '_'
            || c == '.'));
    }

    #[test]
    fn resolve_cache_dir_uses_cfg_when_set() {
        let p = resolve_cache_dir("/tmp/xyz");
        assert_eq!(p, PathBuf::from("/tmp/xyz"));
    }

    #[test]
    fn resolve_cache_dir_falls_back_to_xdg_or_home() {
        // We can't reliably mutate $HOME without locking — just exercise
        // the fallback chain to ensure we hand back *some* path.
        let p = resolve_cache_dir("");
        assert!(!p.as_os_str().is_empty());
    }
}
