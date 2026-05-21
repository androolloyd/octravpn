//! WireGuard data-plane throughput.
//!
//! `docs/performance-limitations.md` §1 flagged: no end-to-end Mbps
//! number, only qualitative notes. This bench targets the
//! data-plane primitives that fall under the public API surface:
//!
//!   - ChaCha20-Poly1305 AEAD over 1380-byte payloads (the default
//!     TUN MTU, `octravpn-tun/src/lib.rs:58`). This is the per-packet
//!     cost WireGuard pays once for encap and once for decap on a
//!     relay hop, plus once more if the onion layer is applied.
//!   - X25519 ECDH (the Noise IKpsk2 handshake's expensive step).
//!
//! End-to-end Mbps with two real `boringtun::Tunn` instances is not
//! benched here. Reasoning, mirroring the comment in
//! `docs/performance-limitations.md` §1:
//!
//!   - The node's `tunnel.rs` wires `Tunn` against UDP sockets +
//!     per-peer keys; nothing on the public API of `octravpn-node`
//!     gives a bench harness a `(Tunn, Tunn)` pair without
//!     duplicating that wire-up.
//!   - `boringtun` itself is a dependency; we don't bench third-party
//!     crates here.
//!
//! From the primitive numbers a reader can extrapolate the WG ceiling:
//! one ChaCha20-Poly1305 seal + one open per 1380-byte packet → about
//! `8 * 1380 / (2 * aead_seal_ns)` Gbps single-core. Onion adds one
//! more peel per relay hop. Use the numbers committed under
//! `bench-snapshots/core.json` (`onion_peel_layer`) for the
//! per-onion-layer cost.
//!
//! How to run:
//!
//!     cargo bench -p octravpn-node --bench wireguard_throughput

use std::time::{Duration, Instant};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use octravpn_core::{
    aead::AeadKey,
    onion::{build_onion, peel_layer, peel_with_pinned_key, HopBuildInput, OnionSessionKeys},
    session::SessionId,
};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// MTU bumped to 1420 by Perf-Data-Plane #3 (octravpn-tun::MTU_DEFAULT).
/// We bench both 1380 (legacy / PMTUD-fallback) and 1420 (the new
/// default) so the headline shows the goodput delta on 1500-byte paths.
const PAYLOAD_LEGACY: usize = 1380;
const PAYLOAD_BUMPED: usize = 1420;
/// Retain the historical constant so existing snapshots match.
const PAYLOAD_BYTES: usize = PAYLOAD_LEGACY;

/// AEAD seal of an MTU-sized payload. This is the per-packet cost
/// WireGuard's encap step pays.
///
/// Two backends are benched side-by-side so the regression-gate can
/// quote a delta directly:
///
/// - `seal_1380B` / `open_1380B`: the portable RustCrypto
///   `chacha20poly1305 = "0.10"` crate. This is the historical Audit-8
///   §1 number (4.43 µs / 4.53 µs → ~2.49 Gbps encap, ~1.23 Gbps
///   relay-hop).
/// - `seal_1380B_hwaccel` / `open_1380B_hwaccel`: the Perf-5
///   `aws-lc-rs`-backed shim from `octravpn_core::aead::AeadKey`.
///   `aws-lc-rs` ships an assembly-tuned ChaCha20-Poly1305 with AVX2
///   on x86_64 and NEON on aarch64. Output bytes are byte-identical
///   (same RFC 8439 standard); see
///   `octravpn_core::aead::tests::cross_impl_compatibility`.
fn bench_aead_seal_mtu(c: &mut Criterion) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from([0u8; 12]);
    let payload = vec![0xABu8; PAYLOAD_BYTES];

    let mut g = c.benchmark_group("wg_aead");
    g.throughput(Throughput::Bytes(PAYLOAD_BYTES as u64));
    g.measurement_time(Duration::from_secs(3));
    g.bench_function("seal_1380B", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let ct = cipher
                    .encrypt(&nonce, black_box(payload.as_slice()))
                    .expect("seal");
                black_box(ct);
            }
            start.elapsed()
        });
    });

    // Pre-encrypt once for the open path.
    let ct = cipher.encrypt(&nonce, payload.as_slice()).expect("seal");
    g.bench_function("open_1380B", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let pt = cipher
                    .decrypt(&nonce, black_box(ct.as_slice()))
                    .expect("open");
                black_box(pt);
            }
            start.elapsed()
        });
    });

    // ----------------- Perf-5: hardware-accelerated path -----------------
    //
    // The shim pre-expands the key once (just like `ChaCha20Poly1305::new`
    // above), so the per-iteration work is the same kind: one AEAD pass
    // over a 1380-byte buffer. The delta over the portable path is the
    // expected Perf-5 win.
    let hw_key = AeadKey::new(&key).expect("32-byte key always expands");
    let hw_nonce = [0u8; 12];
    g.bench_function("seal_1380B_hwaccel", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let ct = hw_key
                    .seal(&hw_nonce, &[], black_box(payload.as_slice()))
                    .expect("seal");
                black_box(ct);
            }
            start.elapsed()
        });
    });

    let hw_ct = hw_key.seal(&hw_nonce, &[], &payload).expect("seal");
    g.bench_function("open_1380B_hwaccel", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let pt = hw_key
                    .open(&hw_nonce, &[], black_box(hw_ct.as_slice()))
                    .expect("open");
                black_box(pt);
            }
            start.elapsed()
        });
    });
    g.finish();
}

/// X25519 ECDH — the expensive step of the Noise IKpsk2 handshake.
/// Not in the per-packet path, but bounds the cold-tunnel-bringup
/// cost (relevant to §6 "client connect time").
fn bench_x25519_dh(c: &mut Criterion) {
    let a_sec = StaticSecret::random_from_rng(OsRng);
    let b_sec = StaticSecret::random_from_rng(OsRng);
    let b_pub = PublicKey::from(&b_sec);
    let mut g = c.benchmark_group("wg_handshake");
    g.throughput(Throughput::Elements(1));
    g.bench_function("x25519_ecdh", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let shared = a_sec.diffie_hellman(black_box(&b_pub));
                black_box(shared);
            }
            start.elapsed()
        });
    });
    g.finish();
}

/// Perf-Data-Plane #3 — MTU 1420 path. Same AEAD primitive, 40 bytes
/// more per packet. Used in the headline goodput-on-1500-MTU
/// calculation (goodput% = payload / (payload + 80 WG header)).
fn bench_aead_seal_bumped_mtu(c: &mut Criterion) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from([0u8; 12]);
    let payload = vec![0xABu8; PAYLOAD_BUMPED];

    let mut g = c.benchmark_group("wg_aead_mtu_bumped");
    g.throughput(Throughput::Bytes(PAYLOAD_BUMPED as u64));
    g.measurement_time(Duration::from_secs(3));
    g.bench_function("seal_1420B", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let ct = cipher
                    .encrypt(&nonce, black_box(payload.as_slice()))
                    .expect("seal");
                black_box(ct);
            }
            start.elapsed()
        });
    });
    g.finish();
}

/// Perf-Data-Plane #9 — pinned-key peel vs full peel_layer. This is
/// the core onion-peel-cost-reduction benchmark. Pre-fix:
/// `onion_peel_layer` at 31.7 µs (X25519 + HKDF + AEAD). Post-fix:
/// AEAD-only ≈ open-1380B (~4.5 µs).
fn bench_onion_peel_paths(c: &mut Criterion) {
    let static_secret = StaticSecret::random_from_rng(OsRng);
    let static_pub = PublicKey::from(&static_secret);
    let onion = build_onion(
        &[HopBuildInput {
            static_pubkey: static_pub.to_bytes(),
            endpoint: "x".into(),
        }],
        &vec![0xCDu8; 1380],
    )
    .unwrap();
    let mut eph_pk = [0u8; 32];
    eph_pk.copy_from_slice(&onion[..32]);
    let keys = OnionSessionKeys::from_ephemeral_pubkeys(&static_secret, &[eph_pk]).unwrap();

    let mut g = c.benchmark_group("onion_peel");
    g.throughput(Throughput::Bytes(onion.len() as u64));
    g.measurement_time(Duration::from_secs(3));

    g.bench_function("peel_layer_slow", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let p = peel_layer(black_box(&static_secret), black_box(&onion)).unwrap();
                black_box(p);
            }
            start.elapsed()
        });
    });

    g.bench_function("peel_with_pinned_key_fast", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let p = peel_with_pinned_key(black_box(&keys), 0, black_box(&onion)).unwrap();
                black_box(p);
            }
            start.elapsed()
        });
    });
    g.finish();
    // Reference the SessionId path to keep the dep meaningful even if
    // a future refactor stops importing it directly.
    let _ = SessionId::new([0u8; 32]);
}

/// Combined-path estimates. We can't bench end-to-end (`Tunn` is
/// module-private) but we CAN model the per-packet cost of each
/// combo by summing the right primitives. Each bench function below
/// runs the per-packet ops that would fire in that mode; the
/// criterion mean × cost-per-packet → Gbps/core ceiling.
fn bench_perf_combos(c: &mut Criterion) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from([0u8; 12]);
    let payload = vec![0xABu8; PAYLOAD_BUMPED];
    let ct = cipher.encrypt(&nonce, payload.as_slice()).unwrap();

    let static_secret = StaticSecret::random_from_rng(OsRng);
    let static_pub = PublicKey::from(&static_secret);
    let onion = build_onion(
        &[HopBuildInput {
            static_pubkey: static_pub.to_bytes(),
            endpoint: "x".into(),
        }],
        &payload,
    )
    .unwrap();
    let mut eph_pk = [0u8; 32];
    eph_pk.copy_from_slice(&onion[..32]);
    let keys = OnionSessionKeys::from_ephemeral_pubkeys(&static_secret, &[eph_pk]).unwrap();

    let mut g = c.benchmark_group("perf_combos");
    g.throughput(Throughput::Bytes(PAYLOAD_BUMPED as u64));
    g.measurement_time(Duration::from_secs(3));

    // Baseline: single Tunn, single queue — one encap + one decap per
    // relay-hop packet (no onion overhead since baseline only counts
    // WG itself).
    g.bench_function("single_tunn_single_queue", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let c = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
                let p = cipher.decrypt(&nonce, c.as_slice()).unwrap();
                black_box(p);
            }
            start.elapsed()
        });
    });

    // #2 + #7 combined: same per-packet ops as baseline (the wins are
    // throughput-scaling, not per-packet-cost). We add a SipHash13
    // 4-tuple shard select to capture the cost the multi-tunnel
    // dispatch pays per packet.
    g.bench_function("multi_tunn_multi_queue", |b| {
        b.iter_custom(|iters| {
            use std::hash::{Hash, Hasher};
            let start = Instant::now();
            for i in 0..iters {
                // 4-tuple shard select (mirrors tunnel.rs::shard_for_4tuple).
                let mut h = std::collections::hash_map::DefaultHasher::new();
                std::net::IpAddr::from([10, 0, 0, 1]).hash(&mut h);
                (i as u16).hash(&mut h);
                std::net::IpAddr::from([10, 0, 0, 2]).hash(&mut h);
                51820u16.hash(&mut h);
                let _shard = (h.finish() as usize) % 8;
                let c = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
                let p = cipher.decrypt(&nonce, c.as_slice()).unwrap();
                black_box(p);
            }
            start.elapsed()
        });
    });

    // #2 + #7 + #3 (direct, no onion): one encap + one decap, NO onion
    // peel. The onion-skip path's per-packet cost.
    g.bench_function("direct_no_onion", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let c = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
                let p = cipher.decrypt(&nonce, c.as_slice()).unwrap();
                black_box(p);
            }
            start.elapsed()
        });
    });

    // #2 + #7 + #3 (relay) + #9 pinned: one encap + one decap + one
    // pinned-key AEAD-only peel. The peel cost is added on top of
    // WG; this is the relay path with the per-session pinned key.
    g.bench_function("pinned_onion_keys_relay", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let c = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
                let p = cipher.decrypt(&nonce, c.as_slice()).unwrap();
                let pl = peel_with_pinned_key(&keys, 0, &onion).unwrap();
                black_box((p, pl));
            }
            start.elapsed()
        });
    });
    g.finish();
    let _ = ct; // keep ct in scope
}

criterion_group!(
    benches,
    bench_aead_seal_mtu,
    bench_aead_seal_bumped_mtu,
    bench_x25519_dh,
    bench_onion_peel_paths,
    bench_perf_combos,
);
criterion_main!(benches);
