//! IPC-boundary test harness for `octra-pvac-sidecar`.
//!
//! ## License boundary
//!
//! The sidecar binary itself is GPL-2+ (with OpenSSL exemption); see
//! `pvac-sidecar/LICENSE`. **This Rust crate is MIT/Apache** — it only
//! talks to the sidecar over JSON-over-stdio via `std::process::Command`,
//! so no GPL symbols are linked into Rust at compile or run time. The
//! IPC boundary is what keeps the workspace's permissive license intact.
//!
//! ## Locating the binary
//!
//! Tests look up the binary in this order:
//!
//!   1. The `PVAC_SIDECAR_BIN` env var (absolute path).
//!   2. `<workspace_root>/pvac-sidecar/octra-pvac-sidecar` next to the
//!      source — produced by `make` in that directory.
//!
//! If neither exists, every test that needs the binary is *skipped*
//! (returns early with a `tracing` line). This keeps the test crate
//! cheap to run in CI environments that don't bundle a C++ toolchain
//! while still gating actual binary integration.
//!
//! ## What the harness does
//!
//! It owns a long-lived child process (`Sidecar`) with line-buffered
//! stdin/stdout pipes. Each round-trip is one `request()` call, which
//! serialises a JSON value, writes a newline-terminated request, and
//! reads exactly one newline-terminated response. This matches the
//! sidecar's `while (std::getline(std::cin, line))` loop and lets a
//! single test thread drive thousands of round-trips without paying
//! the process-spawn cost per call.

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::OnceLock,
};

use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────
// Binary discovery
// ─────────────────────────────────────────────────────────────────────────

/// Returns `Some(path)` to the sidecar binary if it exists, or `None`.
/// Computed once per process for cheap repeat lookups.
pub fn sidecar_binary() -> Option<PathBuf> {
    static FOUND: OnceLock<Option<PathBuf>> = OnceLock::new();
    FOUND
        .get_or_init(|| {
            if let Ok(p) = std::env::var("PVAC_SIDECAR_BIN") {
                let pb = PathBuf::from(p);
                if pb.is_file() {
                    return Some(pb);
                }
            }
            // crate dir is .../pvac-sidecar/ipc-tests; binary one up.
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let candidate = manifest
                .parent()
                .map(|p| p.join("octra-pvac-sidecar"))
                .filter(|p| p.is_file());
            candidate
        })
        .clone()
}

/// Helper: most tests want "either the binary is present, in which case
/// run the test, or skip cleanly." The `#[track_caller]` keeps the
/// skipped-test report pointing at the call site instead of this helper.
#[track_caller]
pub fn skip_if_no_binary() -> Option<PathBuf> {
    let Some(p) = sidecar_binary() else {
        eprintln!(
            "[pvac-sidecar-ipc-tests] octra-pvac-sidecar not found — skipping. \
             Build it with `cd pvac-sidecar && make` or set PVAC_SIDECAR_BIN."
        );
        return None;
    };
    Some(p)
}

// ─────────────────────────────────────────────────────────────────────────
// Sidecar process wrapper
// ─────────────────────────────────────────────────────────────────────────

/// Long-lived sidecar subprocess. Drop kills it.
pub struct Sidecar {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Sidecar {
    /// Spawn the sidecar. Returns an error if the binary isn't on disk
    /// or fails to start.
    pub fn spawn(bin: &PathBuf) -> anyhow::Result<Self> {
        let mut child = Command::new(bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout piped"));
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }

    /// Round-trip one request → response. Returns the parsed JSON
    /// response from a single newline-terminated line. The sidecar
    /// guarantees one response line per request line.
    pub fn request(&mut self, req: &Value) -> anyhow::Result<Value> {
        let line = serde_json::to_string(req)?;
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        let mut resp = String::new();
        let n = self.stdout.read_line(&mut resp)?;
        if n == 0 {
            anyhow::bail!("sidecar closed stdout (EOF) before responding");
        }
        let v: Value = serde_json::from_str(resp.trim_end_matches('\n'))?;
        Ok(v)
    }

    /// Send a raw newline-terminated line; useful for negative tests
    /// where the request shape isn't a valid JSON value.
    pub fn write_raw_line(&mut self, line: &str) -> anyhow::Result<()> {
        self.stdin.write_all(line.as_bytes())?;
        if !line.ends_with('\n') {
            self.stdin.write_all(b"\n")?;
        }
        self.stdin.flush()?;
        Ok(())
    }

    /// Read one line of response (with newline trimmed) as raw bytes.
    pub fn read_raw_line(&mut self) -> anyhow::Result<String> {
        let mut s = String::new();
        let n = self.stdout.read_line(&mut s)?;
        if n == 0 {
            anyhow::bail!("sidecar EOF");
        }
        Ok(s.trim_end_matches('\n').to_string())
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        // Best-effort terminate. The sidecar exits naturally on EOF
        // from stdin, so dropping `stdin` first usually does the job.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Common request builders
// ─────────────────────────────────────────────────────────────────────────

/// 32-byte hex seed of all-`b` (e.g. `b=0x01`).
#[must_use]
pub fn seed_hex(b: u8) -> String {
    hex::encode([b; 32])
}

/// 32-byte base64 blinding factor of all-`b`.
#[must_use]
pub fn blinding_b64(b: u8) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([b; 32])
}

/// Decode an `hfhe_v1|<b64>` or `zkzp_v2|<b64>` blob into raw bytes.
/// Returns `(prefix, bytes)`.
pub fn split_prefixed(blob: &str) -> anyhow::Result<(String, Vec<u8>)> {
    use base64::Engine as _;
    let (prefix, rest) = blob
        .split_once('|')
        .ok_or_else(|| anyhow::anyhow!("missing `|` in blob: {blob}"))?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(rest)?;
    Ok((prefix.to_string(), bytes))
}
