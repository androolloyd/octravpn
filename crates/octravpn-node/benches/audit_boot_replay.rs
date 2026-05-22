//! Perf-6: audit-log boot-replay micro-bench.
//!
//! Synthesises a `audit-YYYY-MM-DD.jsonl` with N lines, then times:
//!
//!   1. **Full replay** — `octravpn_analytics::verify_file` walks
//!      every line from the zero seed, recomputing HMAC-SHA256 over
//!      each `prev_mac || record_json` blob and comparing to the
//!      claimed mac. This is the pre-Perf-6 cold-start path.
//!   2. **Skip-to-tip** — read the last line, decode its `mac` field
//!      as the tip's commitment, do zero HMAC ops over the prefix.
//!      The work shrinks to O(1) per file — we still parse the
//!      single tail line to surface its `record_json` bytes, but no
//!      HMAC chain walk happens.
//!
//! Reports µs/line + total ms for both paths. The delta is the
//! cold-start budget Perf-6 buys back. On a 30-day-old node at 100
//! receipts/s (audit-8 §5.2) the pre-Perf-6 path was ~26 s; the
//! skip-to-tip path is bounded by tail-parse cost (~tens of µs).
//!
//! How to run:
//!
//!     cargo bench -p octravpn-node --bench audit_boot_replay
//!
//! The bench prints results to stdout; criterion plots are skipped
//! because the two paths' timescales differ by >100x and a single
//! plot scale doesn't help operators.

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

use octravpn_analytics::{chain_step, verify_file};
use tempfile::tempdir;

const N_LINES: usize = 100_000;

fn build_synthetic_log(path: &Path, key: &[u8; 32], n_lines: usize) {
    let f = File::create(path).expect("create audit file");
    let mut w = BufWriter::new(f);
    let mut prev_mac = [0u8; 32];
    for i in 0..n_lines {
        // Mimic the node's `AuditRecord` serialisation closely
        // enough that the chain math is representative. The 64-byte
        // `pad` mimics a real receipt_signed extra payload.
        let record_json = format!(
            r#"{{"ts_unix":{},"kind":"receipt_signed","source":null,"session_id":"s{}","extra":{{"seq":{},"bytes_used":1024,"pad":"{}"}}}}"#,
            1_700_000_000u64 + i as u64,
            i,
            i,
            "x".repeat(64)
        );
        let mac = chain_step(key, &prev_mac, record_json.as_bytes());
        let envelope = format!(
            r#"{{"record_json":{},"prev_mac":"{}","mac":"{}"}}"#,
            serde_json::Value::String(record_json).to_string(),
            hex::encode(prev_mac),
            hex::encode(mac),
        );
        writeln!(w, "{envelope}").expect("write line");
        prev_mac = mac;
    }
    w.flush().expect("flush");
}

/// "Skip-to-tip" matches the production path: the chain-tip file
/// commits to `(file_id, seq, mac)`, so we ONLY need to read the
/// line at `seq`. We model this with a reverse byte-scan from EOF
/// to the previous newline — that's O(line_length), constant in
/// the file size. Returns the parsed tail line's record_json length
/// so the optimiser can't dead-code the read.
fn skip_to_tip(path: &Path) -> usize {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = File::open(path).expect("open audit file");
    let size = f.metadata().unwrap().len() as i64;
    // Walk backward in 4 KiB chunks until we find a newline.
    let chunk = 4096i64;
    let mut start = (size - chunk).max(0);
    loop {
        f.seek(SeekFrom::Start(start as u64)).unwrap();
        let mut buf = vec![0u8; (size - start) as usize];
        f.read_exact(&mut buf).unwrap();
        // Skip the trailing newline (if any) — we want the LAST line.
        let trimmed_end = if buf.last() == Some(&b'\n') {
            buf.len() - 1
        } else {
            buf.len()
        };
        let body = &buf[..trimmed_end];
        if let Some(idx) = body.iter().rposition(|&b| b == b'\n') {
            let last_line = std::str::from_utf8(&body[idx + 1..]).unwrap();
            let v: serde_json::Value = serde_json::from_str(last_line).unwrap();
            return v.get("record_json").unwrap().as_str().unwrap().len();
        }
        if start == 0 {
            // Whole file is one line.
            let v: serde_json::Value =
                serde_json::from_str(std::str::from_utf8(body).unwrap()).unwrap();
            return v.get("record_json").unwrap().as_str().unwrap().len();
        }
        start = (start - chunk).max(0);
    }
}

fn main() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("audit-2026-05-21-001.jsonl");
    let key = [0x42u8; 32];

    println!(
        "Perf-6 audit boot-replay bench — synthesising {} lines …",
        N_LINES
    );
    let t0 = Instant::now();
    build_synthetic_log(&path, &key, N_LINES);
    let build_ms = t0.elapsed().as_millis();
    let file_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    println!(
        "  built {} lines = {} bytes in {} ms",
        N_LINES, file_bytes, build_ms
    );

    // Warm the disk cache identically for both paths.
    let _ = std::fs::read(&path);

    // ---- Path 1: full HMAC chain walk ----
    let t0 = Instant::now();
    let scan = verify_file(&key, &path).expect("verify_file");
    let full_us = t0.elapsed().as_micros();
    let full_per_line_us = full_us as f64 / scan.verified_lines as f64;
    println!(
        "  full replay     : {:>10} µs total  ({:.3} µs/line, verified {} lines)",
        full_us, full_per_line_us, scan.verified_lines
    );

    // ---- Path 2: skip-to-tip (the Perf-6 boot path) ----
    let t0 = Instant::now();
    let tail_len = skip_to_tip(&path);
    let skip_us = t0.elapsed().as_micros();
    let skip_per_line_us = skip_us as f64 / N_LINES as f64;
    println!(
        "  skip-to-tip     : {:>10} µs total  ({:.4} µs/line — tail record_json={} bytes)",
        skip_us, skip_per_line_us, tail_len
    );

    // Extrapolate to the 30-day node §5.2 highlights:
    //   100 receipts/s × 86400 s × 30 days = 259,200,000 lines.
    const LINES_30_DAY: u64 = 100 * 86400 * 30;
    let full_30day_s = (full_per_line_us as f64 * LINES_30_DAY as f64) / 1_000_000.0;
    let skip_30day_s = (skip_per_line_us as f64 * LINES_30_DAY as f64) / 1_000_000.0;
    println!("\n30-day cold-start budget (audit-8 §5.2 extrapolation):");
    println!(
        "  full replay     : ~{:.1} s on {} M lines",
        full_30day_s,
        LINES_30_DAY / 1_000_000
    );
    println!(
        "  skip-to-tip     : ~{:.3} s on {} M lines  (Perf-6 ceiling)",
        skip_30day_s,
        LINES_30_DAY / 1_000_000
    );
    println!(
        "  delta           : ~{:.1}× faster",
        full_per_line_us as f64 / skip_per_line_us.max(0.0001)
    );
}
