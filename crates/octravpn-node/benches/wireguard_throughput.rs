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
use octravpn_core::aead::AeadKey;
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// MTU set in `octravpn-tun/src/lib.rs:58`. WG header is 80 B on top.
const PAYLOAD_BYTES: usize = 1380;

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

criterion_group!(benches, bench_aead_seal_mtu, bench_x25519_dh);
criterion_main!(benches);
