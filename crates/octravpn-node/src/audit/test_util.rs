//! Shared test helpers for the per-submodule `#[cfg(test)] mod tests`
//! blocks. Keeping these here keeps each test module focused on its
//! own assertions rather than copies of `read_dir + filter + .first()`
//! boilerplate.

use std::path::{Path, PathBuf};

use super::log::AuditRecord;
use super::AuditLog;

/// Return the (chronologically first) `audit-*.jsonl` file in `dir`.
/// Panics if none is found. Skips the tip file + key file. Pre-Perf-6
/// there was only one such file per day; the multi-file rotation case
/// is handled by [`crate::audit::rotation::list_audit_files`] directly.
pub(super) fn audit_file_in(dir: &Path) -> PathBuf {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_jsonl = Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));
            (name.starts_with("audit-") && is_jsonl).then_some(e.path())
        })
        .collect();
    paths.sort();
    paths
        .into_iter()
        .next()
        .expect("at least one audit-*.jsonl file in dir")
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
