//! Append-only audit log for the node's control plane.
//!
//! Every state-changing request (announce session, settle, etc.) writes
//! a JSON Lines record to a rotating file. The log is the operator's
//! evidence trail for forensics, dispute resolution, and the "what
//! happened during the incident" question.
//!
//! ## Tamper detection
//!
//! Each line carries a `prev_mac` chained from the prior line, where
//! `mac_n = HMAC-SHA256(key, prev_mac || canonical_line_n)`. A
//! verifier walks the file and reports the first index where the chain
//! breaks. Without the key an attacker can append plausible-looking
//! lines, but cannot rewrite or delete history undetectably.
//!
//! ## Layout
//!
//!   - One file per UTC day: `<dir>/audit-YYYY-MM-DD.jsonl`
//!   - HMAC key persisted as `<dir>/.audit.key` (chmod 0600)
//!   - Synchronous writes; flush after every line so a crash never
//!     loses more than the in-flight record.
//!   - Tokio-friendly: actual file I/O happens inside
//!     `tokio::task::spawn_blocking`.

use std::{
    fs::OpenOptions,
    io::{BufRead, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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

#[derive(Clone)]
pub(crate) struct AuditLog {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    dir: PathBuf,
    current_date: String,
    current_file: Option<std::fs::File>,
    /// HMAC key persisted at `<dir>/.audit.key`.
    key: [u8; 32],
    /// Running MAC chain. Reset at midnight (the prev-mac for the
    /// first line of a new day file is `[0u8; 32]`, hex-encoded).
    prev_mac: [u8; 32],
}

impl AuditLog {
    /// Open / create the audit log directory. The directory and any
    /// daily file inside it will be created on first write.
    pub(crate) fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| {
            format!("create audit dir {}", dir.display())
        })?;
        let key = load_or_create_key(&dir)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                dir,
                current_date: String::new(),
                current_file: None,
                key,
                prev_mac: [0u8; 32],
            })),
        })
    }

    /// Write a record. Returns an error only if the underlying I/O
    /// fails (rare; callers typically log the error and continue
    /// since dropping an audit record is worse than failing the
    /// caller).
    pub(crate) fn write(&self, rec: &AuditRecord) -> Result<()> {
        let canonical = serde_json::to_string(rec).context("serialize audit record")?;
        let mut inner = self.inner.lock();
        let date = ymd_utc(rec.ts_unix);
        if inner.current_file.is_none() || inner.current_date != date {
            let path = inner.dir.join(format!("audit-{date}.jsonl"));
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .with_context(|| format!("open audit file {}", path.display()))?;
            inner.current_date = date;
            inner.current_file = Some(f);
            inner.prev_mac = [0u8; 32]; // new file resets the chain
        }
        // mac = HMAC(key, prev_mac || canonical_bytes)
        let mut mac =
            <HmacSha256 as hmac::Mac>::new_from_slice(&inner.key).expect("HMAC accepts any key");
        mac.update(&inner.prev_mac);
        mac.update(canonical.as_bytes());
        let line_mac: [u8; 32] = mac.finalize().into_bytes().into();

        let chained = ChainedLine {
            record_json: canonical.clone(),
            prev_mac: hex::encode(inner.prev_mac),
            mac: hex::encode(line_mac),
        };
        let line =
            serde_json::to_string(&chained).context("serialize chained audit line")?;

        let f = inner
            .current_file
            .as_mut()
            .expect("file just opened");
        f.write_all(line.as_bytes()).context("write audit line")?;
        f.write_all(b"\n").context("write audit newline")?;
        f.flush().context("flush audit log")?;
        inner.prev_mac = line_mac;
        Ok(())
    }

    /// Verify the integrity of an audit file. Returns
    /// `Ok(line_count)` if every line's MAC chain checks out, or an
    /// error describing the first broken position.
    pub(crate) fn verify_file(key: &[u8; 32], path: &Path) -> Result<usize> {
        let f = std::fs::File::open(path)
            .with_context(|| format!("open {}", path.display()))?;
        let reader = std::io::BufReader::new(f);
        let mut prev_mac = [0u8; 32];
        let mut count = 0usize;
        for (i, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("read line {}", i + 1))?;
            if line.trim().is_empty() {
                continue;
            }
            let v: Value =
                serde_json::from_str(&line).with_context(|| format!("parse line {}", i + 1))?;
            let claimed_prev = v
                .get("prev_mac")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow::anyhow!("line {} missing prev_mac", i + 1))?;
            let claimed_mac = v
                .get("mac")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow::anyhow!("line {} missing mac", i + 1))?;
            if hex::encode(prev_mac) != claimed_prev {
                anyhow::bail!(
                    "audit chain break at line {}: prev_mac {} != expected {}",
                    i + 1,
                    claimed_prev,
                    hex::encode(prev_mac)
                );
            }
            let canonical = v
                .get("record_json")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow::anyhow!("line {} missing record_json", i + 1))?
                .to_string();
            let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key)
                .expect("HMAC accepts any key");
            mac.update(&prev_mac);
            mac.update(canonical.as_bytes());
            let expect: [u8; 32] = mac.finalize().into_bytes().into();
            if hex::encode(expect) != claimed_mac {
                anyhow::bail!(
                    "audit MAC mismatch at line {}: log mac {} != recomputed {}",
                    i + 1,
                    claimed_mac,
                    hex::encode(expect)
                );
            }
            prev_mac = expect;
            count += 1;
        }
        Ok(count)
    }

    /// The HMAC key as known to a running `AuditLog`. Needed for
    /// `verify_file` and by operators auditing the log out-of-band
    /// (e.g. shipping the chain to a separate auditor).
    pub(crate) fn key(&self) -> [u8; 32] {
        self.inner.lock().key
    }

    /// Async wrapper that bounces the blocking write off the tokio
    /// thread pool. Callers in async contexts should prefer this.
    pub(crate) async fn write_async(&self, rec: AuditRecord) -> Result<()> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.write(&rec))
            .await
            .context("spawn_blocking audit write")?
    }
}

fn load_or_create_key(dir: &Path) -> Result<[u8; 32]> {
    let p = dir.join(".audit.key");
    if p.exists() {
        let raw = std::fs::read(&p)
            .with_context(|| format!("read {}", p.display()))?;
        if raw.len() != 32 {
            anyhow::bail!(
                "audit key file {} has wrong size ({}); expected 32",
                p.display(),
                raw.len()
            );
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        Ok(k)
    } else {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        std::fs::write(&p, k)
            .with_context(|| format!("write {}", p.display()))?;
        // Best-effort chmod 0600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &p,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        Ok(k)
    }
}

fn ymd_utc(ts_unix: u64) -> String {
    // Trivial UTC date conversion — gives a stable YYYY-MM-DD without
    // pulling in chrono. Days since epoch.
    let days = (ts_unix / 86_400) as i64;
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert days-since-1970-01-01 to (year, month, day). Standard
/// Howard Hinnant algorithm — fast and exact.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

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
        // 2 audit lines + 1 .audit.key file = 2 files in dir.
        assert!(files.iter().any(|f| f.starts_with("audit-")), "no audit file: {files:?}");
        let audit_file = files.iter().find(|f| f.starts_with("audit-")).unwrap();
        let body = std::fs::read_to_string(dir.path().join(audit_file)).unwrap();
        assert_eq!(body.lines().count(), 2);
        // Parses cleanly.
        for line in body.lines() {
            let _: Value = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn ymd_conversion_known_dates() {
        // 1970-01-01: ts_unix=0
        assert_eq!(ymd_utc(0), "1970-01-01");
        // 2000-01-01: 30 years × ~365 days
        assert_eq!(ymd_utc(946_684_800), "2000-01-01");
        // 2024-01-01
        assert_eq!(ymd_utc(1_704_067_200), "2024-01-01");
    }

    #[test]
    fn rotates_when_date_advances() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        // Day 1.
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "x",
            source: None,
            session_id: None,
            extra: Value::Null,
        })
        .unwrap();
        // Day 2 (+86400s).
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
                e.as_ref()
                    .map(|e| e.file_name().to_string_lossy().starts_with("audit-"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(count, 2, "expected two daily audit files");
    }

    #[test]
    fn verify_file_passes_clean_chain() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..5 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: None,
                extra: json!({"i": i}),
            })
            .unwrap();
        }
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let key = log.key();
        let n = AuditLog::verify_file(&key, &audit_file).unwrap();
        assert_eq!(n, 5);
    }

    #[test]
    fn verify_file_detects_tampered_line() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..3 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "x",
                source: None,
                session_id: None,
                extra: json!({"i": i}),
            })
            .unwrap();
        }
        let key = log.key();
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let original = std::fs::read_to_string(&audit_file).unwrap();
        let mut lines: Vec<String> = original.lines().map(String::from).collect();
        // Mutate the middle line's embedded record. `record_json` is
        // an escaped string inside the outer JSON, so the actual `i`
        // value appears as `\"i\":1` (escaped quotes). After this edit
        // the line is still parseable; the canonical record bytes
        // shift but the stored MAC was computed over the OLD bytes.
        lines[1] = lines[1].replacen("\\\"i\\\":1", "\\\"i\\\":99", 1);
        std::fs::write(&audit_file, lines.join("\n") + "\n").unwrap();
        let r = AuditLog::verify_file(&key, &audit_file);
        assert!(r.is_err(), "tampered line should fail verification");
    }
}
