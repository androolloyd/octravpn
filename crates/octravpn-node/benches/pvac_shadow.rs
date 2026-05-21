//! Perf-4 microbench: HFHE-2 shadow-blob batched-IPC win.
//!
//! Measures the IPC-framing delta between two ways of producing the
//! three blobs (`enc_bytes_used`, `enc_net`, `pvac_zero_proof`) the
//! `control/handlers/receipt.rs::get_state` path attaches to every
//! signed receipt when `[pvac].enabled = true`:
//!
//!   1. **Legacy serial path** — 2× `encrypt_const` + 1×
//!      `make_zero_proof`, three separate IPC round-trips through the
//!      PVAC sidecar FIFO. Audit-8 §6 quoted this at ~900 µs/receipt
//!      (200 µs + 200 µs + 500 µs) on the docstring numbers.
//!   2. **Batched receipt_shadow path** — one IPC round-trip. The
//!      sidecar does the same libpvac math internally (same
//!      `pvac_enc_value_seeded` calls under the same seeds, same
//!      `pvac_make_zero_proof_bound` call), so the **CPU work doesn't
//!      shrink** — the win is purely in the wire framing (one
//!      syscall round-trip, one JSON parse, one JSON serialize
//!      instead of three of each).
//!
//! The bench reports the µs delta per-receipt; expected drop on a
//! local-disk Apple Silicon dev box is ~400-500 µs (the bulk of the
//! removed cost is two FIFO read+write round-trips at ~150-200 µs
//! each plus two JSON parse passes).
//!
//! ## Skip-if-no-binary
//!
//! Same convention as the `octra-pvac-sidecar` IPC tests in
//! `crates/octravpn-node/src/pvac.rs::tests` — if the binary at
//! `pvac-sidecar/octra-pvac-sidecar` (or `$PVAC_SIDECAR_BIN`) is
//! missing, the bench skips with a stderr note. This keeps the
//! workspace's `cargo bench` green on a host without the C++
//! toolchain.

use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::io::{BufRead, BufReader, Write};
use std::time::{Duration, Instant};

use base64::Engine as _;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use serde_json::{json, Value};

/// Locate the sidecar binary the same way `pvac::tests::sidecar_binary`
/// does. Returns `None` so the bench can skip cleanly.
fn sidecar_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PVAC_SIDECAR_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("pvac-sidecar").join("octra-pvac-sidecar"))
        .filter(|p| p.is_file())
}

/// Hand-rolled blocking sidecar driver. We deliberately do NOT use
/// `PvacClient` here because it's tokio-async and we want a tight
/// single-threaded loop with no runtime overhead between request and
/// response — that's the fairest comparison for the IPC-framing
/// delta we're measuring.
struct Sidecar {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Sidecar {
    fn spawn(bin: &PathBuf) -> Self {
        let mut child = Command::new(bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sidecar");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn call(&mut self, req: &Value) -> Value {
        let mut line = serde_json::to_string(req).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
        let mut resp = String::new();
        self.stdout.read_line(&mut resp).unwrap();
        serde_json::from_str(resp.trim_end()).expect("sidecar response is json")
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        // Closing stdin is the sidecar's documented graceful-stop
        // signal; if it doesn't exit promptly, kill it so the bench
        // process doesn't linger.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex32(b: u8) -> String {
    hex::encode([b; 32])
}

fn pvac_shadow_bench(c: &mut Criterion) {
    let Some(bin) = sidecar_binary() else {
        eprintln!(
            "[pvac_shadow bench] octra-pvac-sidecar binary not found — skipping. \
             Build with `cd pvac-sidecar && make` or set PVAC_SIDECAR_BIN."
        );
        return;
    };

    // One sidecar process is shared across both benches: it's
    // stateless, so the per-request cost is what we want to measure.
    let mut sc = Sidecar::spawn(&bin);

    // Pre-keygen so the per-iteration loop only exercises the receipt
    // ops, not the (one-off, ~ms) keygen cost. Real receipts reuse
    // the same operator key for the lifetime of the process.
    let kp = sc.call(&json!({"op":"keygen","seed": hex32(0xa5)}));
    let pk = kp["pk"].as_str().unwrap().to_owned();
    let sk = kp["sk"].as_str().unwrap().to_owned();
    let seed_b = hex32(0x10);
    let seed_n = hex32(0x11);
    let blinding = base64::engine::general_purpose::STANDARD.encode([0x42u8; 32]);
    let bytes_used = 12_345_u64;
    let net = 123_450_u64;

    // ── Sanity check: legacy and batched ciphertexts MUST agree ──────
    let legacy_b = sc
        .call(&json!({
            "op":"encrypt_const","pk":pk,"sk":sk,
            "value": bytes_used.to_string(), "seed": seed_b,
        }))["ct"]
        .as_str()
        .unwrap()
        .to_owned();
    let legacy_n = sc
        .call(&json!({
            "op":"encrypt_const","pk":pk,"sk":sk,
            "value": net.to_string(), "seed": seed_n,
        }))["ct"]
        .as_str()
        .unwrap()
        .to_owned();
    let _legacy_proof = sc.call(&json!({
        "op":"make_zero_proof","pk":pk,"sk":sk,
        "ct": legacy_b, "amount": bytes_used.to_string(),
        "blinding": blinding,
    }));
    let batched = sc.call(&json!({
        "op":"receipt_shadow","pk":pk,"sk":sk,
        "bytes_used": bytes_used.to_string(),
        "net": net.to_string(),
        "seed_bytes": seed_b,
        "seed_net": seed_n,
        "blinding": blinding,
    }));
    assert_eq!(batched["enc_bytes_used"].as_str().unwrap(), legacy_b);
    assert_eq!(batched["enc_net"].as_str().unwrap(), legacy_n);

    let mut group = c.benchmark_group("pvac_shadow");
    group.throughput(Throughput::Elements(1));
    // Each iteration is one receipt's worth of IPC: heavy on the
    // sidecar (HFHE encrypt + Bulletproof) so we keep sample_size +
    // measurement_time modest to keep wall-clock under a minute.
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(20);

    // (a) Legacy: 3 IPC round-trips per receipt.
    group.bench_function("legacy_serial_3_calls", |b| {
        b.iter(|| {
            let r1 = sc.call(&json!({
                "op":"encrypt_const","pk":pk,"sk":sk,
                "value": bytes_used.to_string(), "seed": seed_b,
            }));
            let ct = r1["ct"].as_str().unwrap().to_owned();
            let _r2 = sc.call(&json!({
                "op":"encrypt_const","pk":pk,"sk":sk,
                "value": net.to_string(), "seed": seed_n,
            }));
            let _r3 = sc.call(&json!({
                "op":"make_zero_proof","pk":pk,"sk":sk,
                "ct": ct, "amount": bytes_used.to_string(),
                "blinding": blinding,
            }));
        });
    });

    // (b) Batched: 1 IPC round-trip per receipt.
    group.bench_function("batched_receipt_shadow", |b| {
        b.iter(|| {
            let _r = sc.call(&json!({
                "op":"receipt_shadow","pk":pk,"sk":sk,
                "bytes_used": bytes_used.to_string(),
                "net": net.to_string(),
                "seed_bytes": seed_b,
                "seed_net": seed_n,
                "blinding": blinding,
            }));
        });
    });

    // Also emit a wall-clock µs-per-receipt summary so a CI log
    // reader doesn't have to dig through criterion's HTML report.
    let n: u32 = 200;
    let t0 = Instant::now();
    for _ in 0..n {
        let r1 = sc.call(&json!({
            "op":"encrypt_const","pk":pk,"sk":sk,
            "value": bytes_used.to_string(), "seed": seed_b,
        }));
        let ct = r1["ct"].as_str().unwrap().to_owned();
        let _r2 = sc.call(&json!({
            "op":"encrypt_const","pk":pk,"sk":sk,
            "value": net.to_string(), "seed": seed_n,
        }));
        let _r3 = sc.call(&json!({
            "op":"make_zero_proof","pk":pk,"sk":sk,
            "ct": ct, "amount": bytes_used.to_string(),
            "blinding": blinding,
        }));
    }
    #[allow(clippy::cast_precision_loss)]
    let legacy_us = t0.elapsed().as_micros() as f64 / f64::from(n);

    let t1 = Instant::now();
    for _ in 0..n {
        let _ = sc.call(&json!({
            "op":"receipt_shadow","pk":pk,"sk":sk,
            "bytes_used": bytes_used.to_string(),
            "net": net.to_string(),
            "seed_bytes": seed_b,
            "seed_net": seed_n,
            "blinding": blinding,
        }));
    }
    #[allow(clippy::cast_precision_loss)]
    let batched_us = t1.elapsed().as_micros() as f64 / f64::from(n);

    eprintln!(
        "[pvac_shadow summary] legacy_serial_3_calls = {:.1} µs/receipt, \
         batched_receipt_shadow = {:.1} µs/receipt, delta = {:.1} µs \
         ({:.1}× faster)",
        legacy_us,
        batched_us,
        legacy_us - batched_us,
        legacy_us / batched_us,
    );

    group.finish();
}

criterion_group!(benches, pvac_shadow_bench);
criterion_main!(benches);
