//! Sync-direct write path + [`AuditRecord`] + on-disk `ChainedLine`
//! envelope. The shared `write_inner_direct` helper is reused by
//! `audit::batched` under the `Inner` lock. The on-disk format
//! (`record_json` / `prev_mac` / `mac`) is contract — see
//! `audit/README.md` before reshaping.

use std::{fs::OpenOptions, io::Write, path::Path, sync::Arc};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc;

use super::batched::FlusherCmd;
use super::chain::{chain_step, load_or_create_key, ymd_utc};
use super::inner::{AuditCounters, Inner};
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
        Self::open_inner(dir.as_ref(), None)
    }

    pub(super) fn open_inner(
        dir: &Path,
        sender: Option<mpsc::Sender<FlusherCmd>>,
    ) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create audit dir {}", dir.display()))?;
        let key = load_or_create_key(dir)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                dir: dir.to_path_buf(),
                current_date: String::new(),
                current_file: None,
                key,
                prev_mac: [0u8; 32],
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
        let r = write_inner_direct(&mut inner, rec, /*fsync=*/ true);
        drop(inner);
        // Fan out to the analytics indexer (mirror of `write_async`)
        // so callers that bypass the async path still hit it.
        if r.is_ok() {
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

/// Direct synchronous write — used by both the sync `write()` API and
/// by the background flusher task. The `fsync` parameter lets the
/// flusher hold off the fsync until the end of a batch.
pub(super) fn write_inner_direct(
    inner: &mut Inner,
    rec: &AuditRecord,
    fsync: bool,
) -> Result<()> {
    let canonical = serde_json::to_string(rec).context("serialize audit record")?;
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
    Ok(())
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
        assert!(
            files.iter().any(|f| f.starts_with("audit-")),
            "no audit file: {files:?}"
        );
        let audit_file = files.iter().find(|f| f.starts_with("audit-")).unwrap();
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
                e.as_ref()
                    .map(|e| e.file_name().to_string_lossy().starts_with("audit-"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(count, 2, "expected two daily audit files");
    }
}
