//! Mesh control-plane benches.
//!
//! Measured:
//!   - `PeerRegistry::publish_unverified` throughput at varying
//!     registry sizes (10, 100, 1k, 10k peers).
//!   - `MeshManager::tick` latency at the same scales.
//!
//! These are the two numbers `docs/performance-limitations.md` §2
//! flagged as "not measured" — concurrency-only stress lives in
//! `crates/octravpn-node/tests/stress.rs:96`.
//!
//! How to run:
//!
//!     cargo bench -p octravpn-mesh --bench peer_publish \
//!         --features test-helpers
//!
//! Reads existing public APIs only; `publish_unverified` is gated
//! behind the crate-local `test-helpers` feature (declared in
//! `crates/octravpn-mesh/Cargo.toml`).
//!
//! What "good" looks like:
//!   - publish_unverified should be sub-microsecond up to ~1k peers
//!     (single RwLock write into a HashMap).
//!   - tick scales linearly with peers-in-tailnet because
//!     `peers_in` does a `HashMap::retain` + filter walk per call.

use std::net::SocketAddr;
use std::time::Instant;

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use octravpn_mesh::{MeshManager, PeerCandidate, PeerSnapshot};

fn fake_snapshot(tid: &str, idx: u64) -> PeerSnapshot {
    // Vary the LAN address per peer so the candidate set doesn't
    // collapse to the same entry under hashing.
    let octet_a = (idx >> 8) as u8;
    let octet_b = (idx & 0xff) as u8;
    let sa: SocketAddr = format!("10.0.{octet_a}.{octet_b}:51820").parse().unwrap();
    PeerSnapshot {
        tailnet_id: tid.into(),
        // 40-hex-char synthetic Octra address; uniqueness is what we
        // care about, not on-chain validity.
        addr: format!("oct{idx:040x}"),
        wg_pubkey: [9u8; 32],
        candidates: vec![PeerCandidate::Lan(sa)],
        hostname: None,
        last_refresh: Instant::now(),
    }
}

/// Single-publisher publish throughput. We use `iter_custom` to
/// amortize the prefill cost across many measured inserts:
///
///   - Setup once per measured chunk: build a registry holding
///     `prefill` peers.
///   - Inside the timed window: insert `INSERTS_PER_CHUNK` fresh
///     snapshots with rolling indices so we never collide.
///
/// Reported throughput is per-element (one insert), the registry
/// size stays in the `prefill .. prefill + INSERTS_PER_CHUNK` band
/// across the chunk so we measure steady-state cost at that scale.
fn bench_publish_unverified(c: &mut Criterion) {
    const INSERTS_PER_CHUNK: u64 = 512;
    let mut g = c.benchmark_group("publish_unverified");
    g.throughput(Throughput::Elements(INSERTS_PER_CHUNK));
    for &prefill in &[10usize, 100, 1_000, 10_000] {
        g.bench_function(format!("prefill_{prefill}"), |b| {
            b.iter_custom(|iters| {
                // One registry; we keep inserting fresh keys.
                let mgr = MeshManager::new("octSELF", [1u8; 32]);
                let reg = mgr.peers();
                for i in 0..prefill {
                    reg.publish_unverified(fake_snapshot("t", i as u64));
                }
                let mut next: u64 = prefill as u64;
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    for _ in 0..INSERTS_PER_CHUNK {
                        reg.publish_unverified(fake_snapshot("t", black_box(next)));
                        next += 1;
                    }
                }
                start.elapsed()
            });
        });
    }
    g.finish();
}

/// Tick latency at varying tailnet sizes. Each measured iteration
/// is one call to `MeshManager::tick`; setup (registry fill + FSM
/// warm-up) happens once, outside the timed window.
fn bench_tick_latency(c: &mut Criterion) {
    let mut g = c.benchmark_group("mesh_tick");
    for &n in &[10usize, 100, 1_000, 10_000] {
        g.throughput(Throughput::Elements(n as u64));
        // Tick cost grows ~linearly in N. At 10k peers a single tick
        // is ~10ms; widen the measurement window so criterion can
        // still collect a reasonable sample count.
        g.measurement_time(Duration::from_secs(if n >= 10_000 { 6 } else { 3 }));
        g.bench_function(format!("peers_{n}"), |b| {
            b.iter_custom(|iters| {
                let mgr = MeshManager::new("octSELF", [1u8; 32]);
                mgr.set_self_candidates(vec![PeerCandidate::Lan(
                    "10.0.0.1:51820".parse().unwrap(),
                )]);
                let reg = mgr.peers();
                for i in 0..n {
                    reg.publish_unverified(fake_snapshot("t", i as u64));
                }
                // Drive every per-peer FSM out of Init/Probing so the
                // measured tick reflects the steady-state cost, not
                // the cold-open candidate sweep.
                let _ = mgr.tick("t");
                let _ = mgr.tick("t");
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let acts = mgr.tick(black_box("t"));
                    black_box(acts);
                }
                start.elapsed()
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_publish_unverified, bench_tick_latency);
criterion_main!(benches);
