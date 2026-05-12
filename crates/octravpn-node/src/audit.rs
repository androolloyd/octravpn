//! Append-only audit log for the node's control plane.
//!
//! Every state-changing request (announce session, settle, etc.) writes
//! a JSON Lines record to a rotating file. The log is the operator's
//! evidence trail for forensics, dispute resolution, and the "what
//! happened during the incident" question.
//!
//! Design:
//!   - One file per UTC day: `<dir>/audit-YYYY-MM-DD.jsonl`
//!   - Synchronous writes; flush after every line so a crash never
//!     loses more than the in-flight record.
//!   - Tokio-friendly: the actual file I/O is bounced through
//!     `tokio::task::spawn_blocking`, so writes don't stall the reactor.
//!   - No automatic deletion; ops rotate via logrotate or equivalent.

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;

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

#[derive(Clone)]
pub(crate) struct AuditLog {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    dir: PathBuf,
    current_date: String,
    current_file: Option<std::fs::File>,
}

impl AuditLog {
    /// Open / create the audit log directory. The directory and any
    /// daily file inside it will be created on first write.
    pub(crate) fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| {
            format!("create audit dir {}", dir.display())
        })?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                dir,
                current_date: String::new(),
                current_file: None,
            })),
        })
    }

    /// Write a record. Returns an error only if the underlying I/O
    /// fails (rare; callers typically log the error and continue
    /// since dropping an audit record is worse than failing the
    /// caller).
    pub(crate) fn write(&self, rec: &AuditRecord) -> Result<()> {
        let line = serde_json::to_string(rec).context("serialize audit record")?;
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
        }
        let f = inner
            .current_file
            .as_mut()
            .expect("file just opened");
        f.write_all(line.as_bytes()).context("write audit line")?;
        f.write_all(b"\n").context("write audit newline")?;
        f.flush().context("flush audit log")?;
        Ok(())
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
        assert_eq!(files.len(), 1, "expected one daily file; got {files:?}");
        let body = std::fs::read_to_string(dir.path().join(&files[0])).unwrap();
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
        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 2, "expected two daily files");
    }
}
