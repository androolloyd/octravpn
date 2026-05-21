//! Operator settle-frequency benches.
//!
//! `docs/performance-limitations.md` §5 flagged:
//!
//!   - "fsync rate, audit-log appended-line rate, max sustained
//!     signed-receipts per second" — not measured.
//!   - "Audit log uses `flush` (not `fsync`)" — qualitative only.
//!
//! Three benches here close that gap with public APIs only:
//!
//! 1. `receipt_journal_bump` — drives `ReceiptJournal::bump` against a
//!    real on-disk file under `FsyncPolicy::EveryWrite`. Pre-Perf-1
//!    this was the journal default; post-Perf-1 it is the policy
//!    financial-invariant operators opt back into.
//!    Since #235 the journal is **append-only** + per-record fsync,
//!    so each call is a single 44-byte append + `sync_data`. The cost
//!    is dominated by the fsync round-trip, not by serialisation
//!    width. Compare against the legacy v0 ceiling (~96 receipts/s at
//!    1k sessions on this host, where every bump rewrote the whole
//!    file) — the append-only path should hold flat at any session
//!    count.
//!
//! 2. `receipt_journal_bump_periodic` — same workload under
//!    `FsyncPolicy::Periodic(1s)`. Each bump still pushes through the
//!    OS write buffer (no user-space buffer in append mode), but
//!    `sync_data` is deferred. This is the throughput-mode ceiling
//!    operators get when they accept a bounded loss window.
//!
//! 3. `audit_log_flush_vs_fsync` — the audit log type
//!    (`octravpn_node::audit::AuditLog`) is `pub(crate)`, so we can't
//!    bench it directly without expanding the public API
//!    (out-of-scope for this PR). Instead we replicate the audit
//!    log's hot-path bytes — append a JSON-ish line, then either
//!    `flush()` (libc buffer flush, what audit.rs:143 does) or
//!    `sync_all()` (real fsync) — so we can quote the gap.
//!
//! ## Headline numbers
//!
//! Measured on Apple Silicon (macOS APFS, `cargo bench --quick`, 2 s
//! measurement window; SSD/ext4 hosts will be in the same order of
//! magnitude, NFS/network FS will be slower).
//!
//! Pre-#235 (v0 snapshot rewrite, default fsync per bump):
//!   - `sessions_1`     ≈ 100 receipts/s
//!   - `sessions_64`    ≈ 98  receipts/s
//!   - `sessions_1024`  ≈ 96  receipts/s   ← the ceiling the doc flagged
//!
//! Post-#235 (v1 append-only, `EveryWrite` policy):
//!   - `sessions_1`     ≈ 235 receipts/s
//!   - `sessions_64`    ≈ 235 receipts/s
//!   - `sessions_1024`  ≈ 225 receipts/s   ← **flat in N**
//!
//!   The per-call work is one 44-byte append + one `sync_data`. On
//!   this host the fsync round-trip dominates; the journal is no
//!   longer O(N) in session count. SSD/ext4 hosts typically clear
//!   1 000+ receipts/s here.
//!
//! Post-#235 (`Periodic(1s)` policy, no per-bump fsync):
//!   - `sessions_1`     ≈ 522 000 receipts/s
//!   - `sessions_64`    ≈ 532 000 receipts/s
//!   - `sessions_1024`  ≈ 557 000 receipts/s
//!
//!   Per-call cost collapses to the syscall + write() path (~1.9 µs).
//!   This is the "loss-tolerant" mode an operator opts into by
//!   `journal.set_fsync_policy(FsyncPolicy::Periodic(_))`.
//!
//! Run `cargo bench --bench settle_throughput` on the target host for
//! the authoritative values; the numbers above are the post-#235
//! commit's measured ceiling. See `docs/performance-limitations.md`
//! for the published comparison.
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
use octravpn_core::{
    receipt_journal::{FsyncPolicy, ReceiptJournal},
    session::SessionId,
};
use tempfile::TempDir;

fn session_id_from(idx: u64) -> SessionId {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&idx.to_be_bytes());
    SessionId::new(bytes)
}

/// Receipt-journal bump throughput under `FsyncPolicy::EveryWrite` —
/// pre-Perf-1 default, post-Perf-1 the durability-first opt-in. Each
/// iteration is one append of a 44-byte record + one `sync_data`.
/// Population size is varied to confirm the new append-only path is
/// **flat** in the live session count (the v0 snapshot path was O(N)
/// per call and degraded at 1k sessions to ~96 receipts/s).
fn bench_receipt_journal_bump(c: &mut Criterion) {
    let mut g = c.benchmark_group("receipt_journal_bump");
    g.throughput(Throughput::Elements(1));
    // fsync-per-iter dominates; widen the measurement window so the
    // 30+ sample target still lands in a couple of seconds.
    g.measurement_time(Duration::from_secs(5));

    for &n_sessions in &[1usize, 64, 1024] {
        g.bench_function(format!("sessions_{n_sessions}"), |b| {
            b.iter_custom(|iters| {
                let dir = TempDir::new().expect("tempdir");
                let path = dir.path().join("rj.bin");
                let j = ReceiptJournal::open(&path).expect("open journal");
                // Perf-1: pin `EveryWrite` so this bench keeps
                // measuring the per-fsync ceiling even after the
                // default flipped to `Periodic(1s)`.
                j.set_fsync_policy(FsyncPolicy::EveryWrite);
                // Pre-populate to `n_sessions - 1` so the bench
                // appends past a non-trivial baseline. With the
                // append-only format the population size doesn't
                // change per-call cost, but we keep the parameterisation
                // so the comparison vs the v0 numbers in the doc is
                // apples-to-apples.
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

/// Receipt-journal bump throughput under
/// `FsyncPolicy::Periodic(1s)`. The append still pushes through to
/// the OS write buffer, but `sync_data` is deferred. Expected to be
/// 1–2 orders of magnitude faster than `EveryWrite` — useful for
/// operators who accept a bounded loss window.
fn bench_receipt_journal_bump_periodic(c: &mut Criterion) {
    let mut g = c.benchmark_group("receipt_journal_bump_periodic");
    g.throughput(Throughput::Elements(1));
    g.measurement_time(Duration::from_secs(5));

    for &n_sessions in &[1usize, 64, 1024] {
        g.bench_function(format!("sessions_{n_sessions}"), |b| {
            b.iter_custom(|iters| {
                let dir = TempDir::new().expect("tempdir");
                let path = dir.path().join("rj.bin");
                let j = ReceiptJournal::open(&path).expect("open journal");
                j.set_fsync_policy(FsyncPolicy::Periodic(Duration::from_secs(1)));
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
        format!(r#"{{"record_json":{rec:?},"prev_mac":"{prev_mac}","mac":"{mac}"}}"#).into_bytes()
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

criterion_group!(
    benches,
    bench_receipt_journal_bump,
    bench_receipt_journal_bump_periodic,
    bench_audit_flush_vs_fsync,
);
criterion_main!(benches);
