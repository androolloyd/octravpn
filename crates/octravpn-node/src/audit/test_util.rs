//! Shared test helpers for the per-submodule `#[cfg(test)] mod tests`
//! blocks. Keeping these here keeps each test module focused on its
//! own assertions rather than copies of `read_dir + filter + .first()`
//! boilerplate.

use std::path::{Path, PathBuf};

use super::log::AuditRecord;
use super::AuditLog;

/// Return the single `audit-YYYY-MM-DD.jsonl` file in `dir`. Panics if
/// none is found.
pub(super) fn audit_file_in(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
        .expect("at least one audit-*.jsonl file in dir")
        .path()
}

/// Write `n` minimal `kind="x"` records via the sync path.
pub(super) fn write_n_x(log: &AuditLog, n: u64) {
    for i in 0..n {
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000 + i,
            kind: "x",
            source: None,
            session_id: None,
            extra: serde_json::json!({ "i": i }),
        })
        .unwrap();
    }
}
