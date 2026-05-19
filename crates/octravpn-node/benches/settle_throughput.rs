//! Operator settle-frequency benches.
//!
//! `docs/performance-limitations.md` §5 flagged:
//!
//!   - "fsync rate, audit-log appended-line rate, max sustained
//!     signed-receipts per second" — not measured.
//!   - "Audit log uses `flush` (not `fsync`)" — qualitative only.
//!
//! Two benches here close that gap with public APIs only:
//!
//! 1. `receipt_journal_bump` — drives `ReceiptJournal::bump` against a
//!    real on-disk file. Each call is one atomic write
//!    (tempfile + sync_all + rename + parent sync_all) — i.e. the
//!    per-receipt fsync round-trip the doc names as the per-receipt
//!    ceiling. Per `receipt_journal.rs:179-185` the lock is held
//!    across disk I/O, so this measures end-to-end signed-receipts/s.
//!
//! 2. `audit_log_flush_vs_fsync` — the audit log type
//!    (`octravpn_node::audit::AuditLog`) is `pub(crate)`, so we can't
//!    bench it directly without expanding the public API
//!    (out-of-scope for this PR). Instead we replicate the audit
//!    log's hot-path bytes — append a JSON-ish line, then either
//!    `flush()` (libc buffer flush, what audit.rs:143 does) or
//!    `sync_all()` (real fsync) — so we can quote the gap.
//!
//! NOTE: the doc still flags AuditLog itself as un-benched. This file
//! quotes the *primitive* cost; the real audit log layers HMAC
//! computation + JSON serialisation on top, neither of which dominates.
//!
//! How to run:
//!
//!     cargo bench -p octravpn-node --bench settle_throughput
//!
//! Results are bounded by the host's filesystem and are useful
//! comparatively (flush vs fsync, SSD vs network FS), not as an
//! absolute "this many settles/s anywhere."

use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use octravpn_core::{receipt_journal::ReceiptJournal, session::SessionId};
use tempfile::TempDir;

fn session_id_from(idx: u64) -> SessionId {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&idx.to_be_bytes());
    SessionId::new(bytes)
}

/// Receipt-journal bump throughput.
///
/// `ReceiptJournal::bump` is the durability gate every signed
/// receipt passes through. It rewrites the whole journal under the
/// mutex via `atomic_write` → tempfile + `sync_all` + rename +
/// parent `sync_all`. So this number is "fsync-round-trips per
/// second on whatever filesystem the tempdir lives on."
fn bench_receipt_journal_bump(c: &mut Criterion) {
    let mut g = c.benchmark_group("receipt_journal_bump");
    g.throughput(Throughput::Elements(1));
    // fsync-per-iter dominates; widen the measurement window so the
    // 30+ sample target still lands in a couple of seconds.
    g.measurement_time(Duration::from_secs(5));

    // Three population sizes — the journal rewrites every entry on
    // each bump, so a larger journal makes each call rewrite more
    // bytes. The doc claim "a tailnet's worth of sessions per node"
    // is small (~tens); 1k is far beyond that, included so the
    // serialisation tradeoff at receipt_journal.rs:179-185 is bounded.
    for &n_sessions in &[1usize, 64, 1024] {
        g.bench_function(format!("sessions_{n_sessions}"), |b| {
            b.iter_custom(|iters| {
                let dir = TempDir::new().expect("tempdir");
                let path = dir.path().join("rj.bin");
                let j = ReceiptJournal::open(&path).expect("open journal");
                // Pre-populate to `n_sessions - 1` so the bench
                // updates an existing session and rewrites all
                // entries. The bench then bumps session 0 with
                // monotonically increasing seq.
                let primary = session_id_from(0);
                let _ = j.bump(&primary, 1);
                for i in 1..n_sessions {
                    let _ = j.bump(&session_id_from(i as u64), 1);
                }
                let mut next_seq = 2u64;
                let start = Instant::now();
                for _ in 0..iters {
                    j.bump(black_box(&primary), black_box(next_seq))
                        .expect("bump");
                    next_seq += 1;
                }
                start.elapsed()
            });
        });
    }
    g.finish();
}

/// Audit-log primitive cost: append a JSON-ish line and then either
/// `flush()` (matches `audit.rs:143`) or `sync_all()` (full fsync).
///
/// We're explicitly NOT calling into `AuditLog` itself — it's
/// `pub(crate)` and this PR doesn't expand the public API. The
/// AuditLog layers HMAC + serde_json on top of these primitives;
/// neither is the bottleneck. This bench quotes the gap.
fn bench_audit_flush_vs_fsync(c: &mut Criterion) {
    // Roughly the size of one production audit line: 32-byte hex
    // prev_mac, 32-byte hex mac, plus a ~200-byte canonical record.
    let line: Vec<u8> = {
        let prev_mac = "00".repeat(32);
        let mac = "11".repeat(32);
        let rec = r#"{"ts_unix":1717000000,"kind":"settle","source":"10.0.0.42:51820","session_id":"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f","extra":{"bytes_used":1048576}}"#;
        format!(r#"{{"record_json":{rec:?},"prev_mac":"{prev_mac}","mac":"{mac}"}}"#)
            .into_bytes()
    };

    let mut g = c.benchmark_group("audit_append");
    g.throughput(Throughput::Bytes(line.len() as u64 + 1));
    g.measurement_time(Duration::from_secs(3));

    for mode in ["flush_only", "fsync"] {
        g.bench_function(mode, |b| {
            // Setup outside the timed window: tempdir + open file.
            let dir = TempDir::new().expect("tempdir");
            let path: PathBuf = dir.path().join("audit.jsonl");
            b.iter_custom(|iters| {
                let mut f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .truncate(false)
                    .open(&path)
                    .expect("open audit file");
                let start = Instant::now();
                for _ in 0..iters {
                    f.write_all(&line).expect("write line");
                    f.write_all(b"\n").expect("write newline");
                    match mode {
                        "flush_only" => {
                            f.flush().expect("flush");
                        }
                        "fsync" => {
                            // sync_all is fsync(); sync_data is fdatasync.
                            // audit.rs:143 uses flush() — this branch
                            // shows what the gap would be if we
                            // upgraded to sync_all.
                            f.sync_all().expect("fsync");
                        }
                        _ => unreachable!(),
                    }
                    black_box(&path);
                }
                start.elapsed()
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_receipt_journal_bump, bench_audit_flush_vs_fsync);
criterion_main!(benches);
