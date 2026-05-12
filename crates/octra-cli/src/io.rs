//! Small IO helpers shared by subcommands.
//!
//! Pulled out so we can override stdout in integration tests without
//! depending on `assert_cmd`'s subprocess plumbing for every case.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

/// Read a 32-byte hex-encoded secret from `path` (with optional `0x` prefix).
pub fn read_secret_hex(path: &Path) -> Result<[u8; 32]> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("read key file: {}", path.display()))?;
    let stripped = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(stripped).context("key file is not hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "key file must be 32 bytes (got {} bytes)",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Pretty-print a JSON value with two-space indent.
pub fn dump_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

/// Convenience: write a string to a path, creating parent dirs.
pub fn write_to(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create dir: {}", parent.display()))?;
    }
    fs::write(path, contents)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Best-effort: parse a `"name=value"` arg as JSON, falling back to a
/// JSON string. Used by `cast send`/`cast call` to accept either raw
/// JSON literals or plain string args interchangeably.
pub fn parse_arg_token(tok: &str) -> Value {
    serde_json::from_str(tok).unwrap_or_else(|_| Value::String(tok.to_string()))
}

/// Wall-clock timestamp matching the Octra wallet's `time.time()`
/// representation: seconds since UNIX epoch with sub-second precision.
pub fn current_timestamp() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
