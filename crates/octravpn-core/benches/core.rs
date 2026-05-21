//! Per-primitive benchmarks. Run with:
//!
//!     cargo bench -p octravpn-core --bench core
//!
//! CI snapshot lives at `bench-snapshots/core.json` (gitignored output
//! is `target/criterion/`). For regression detection: compare the
//! committed snapshot against a fresh run.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use octravpn_core::{
    address::Address,
    commit::{commit, fresh_blind, verify_open, Opening},
    earnings,
    onion::{build_onion, peel_layer, HopBuildInput},
    receipt::{Receipt, ReceiptContext, SignedReceipt, CHAIN_ID_TEST},
    receipt_journal::{FsyncPolicy, ReceiptJournal},
    session::{Blind, SessionId},
    sig::KeyPair,
    tx::{canonical_bytes, sign_call},
    wallet_enc,
};
use serde_json::json;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

fn bench_receipt(c: &mut Criterion) {
    let client = KeyPair::generate();
    let node = KeyPair::generate();
    let ctx = ReceiptContext::v1_1(Address::from_pubkey(&[7u8; 32]), CHAIN_ID_TEST);
    let r = Receipt {
        context: ctx,
        session_id: SessionId::new([7u8; 32]),
        seq: 1,
        bytes_used: 1024 * 1024,
        blind: Blind::new([9u8; 32]),
    };

    c.bench_function("receipt_build_sign", |b| {
        b.iter(|| {
            let sr = SignedReceipt::build(r.clone(), &client, &node);
            black_box(sr);
        });
    });

    let signed = SignedReceipt::build(r, &client, &node);
    c.bench_function("receipt_verify_dual", |b| {
        b.iter(|| {
            signed.verify().unwrap();
        });
    });
}

fn bench_commit(c: &mut Criterion) {
    let addr = Address::from_pubkey(&[1u8; 32]);
    let blind = fresh_blind();
    let commitment = commit(&addr, &blind);

    c.bench_function("pedersen_commit", |b| {
        b.iter(|| black_box(commit(&addr, &blind)));
    });
    c.bench_function("pedersen_verify_open", |b| {
        b.iter(|| {
            black_box(verify_open(
                &commitment,
                &Opening {
                    addr: addr.clone(),
                    blind,
                },
            ))
        });
    });
}

fn bench_earnings(c: &mut Criterion) {
    let blind = earnings::fresh_blind();
    let point = earnings::commit(1_000_000, &blind);

    c.bench_function("earnings_commit", |b| {
        b.iter(|| black_box(earnings::commit(1_000_000, &blind)));
    });
    c.bench_function("earnings_verify_claim", |b| {
        b.iter(|| black_box(earnings::verify_claim(point, 1_000_000, &blind)));
    });
}

fn bench_onion(c: &mut Criterion) {
    let s = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let pk = X25519Pub::from(&s).to_bytes();
    let inputs = vec![
        HopBuildInput {
            static_pubkey: pk,
            endpoint: "n1:51820".into(),
        };
        3
    ];
    let packet = build_onion(&inputs, b"payload").unwrap();

    c.bench_function("onion_build_3hop", |b| {
        b.iter(|| black_box(build_onion(&inputs, b"payload").unwrap()));
    });
    c.bench_function("onion_peel_layer", |b| {
        b.iter(|| black_box(peel_layer(&s, &packet).unwrap()));
    });
}

fn bench_tx(c: &mut Criterion) {
    let kp = KeyPair::generate();
    let tx = json!({
        "kind": "contract_call",
        "from": "octFROM",
        "to": "octTO",
        "method": "register_validator",
        "params": ["192.168.1.1:51820", "00".repeat(32), "11".repeat(32), "22".repeat(32), "eu-west", 100u64, "33".repeat(64)],
        "value": 1_000_000u64,
        "fee": 1000u64,
        "nonce": 1u64,
        "timestamp": 1.23,
    });

    c.bench_function("tx_canonical_bytes", |b| {
        b.iter(|| black_box(canonical_bytes(&tx).unwrap()));
    });
    c.bench_function("tx_sign_call", |b| {
        b.iter_batched(
            || tx.clone(),
            |t| black_box(sign_call(&kp, t).unwrap()),
            BatchSize::SmallInput,
        );
    });
}

fn bench_wallet_enc(c: &mut Criterion) {
    let secret = [7u8; 32];
    let pass = "correct horse battery staple";
    let enc = wallet_enc::encrypt_secret_with_iters(&secret, pass, 1000);

    // 1k iter to keep the benchmark sub-second; production uses 200k.
    c.bench_function("wallet_encrypt_1k_iters", |b| {
        b.iter(|| black_box(wallet_enc::encrypt_secret_with_iters(&secret, pass, 1000)));
    });
    c.bench_function("wallet_decrypt_1k_iters", |b| {
        b.iter(|| black_box(wallet_enc::decrypt_secret(&enc, pass).unwrap()));
    });
}

/// Perf-8: receipt-journal bump hot-path with the cap+TTL eviction
/// bookkeeping in play. Uses `FsyncPolicy::Periodic(60s)` so the
/// fsync floor doesn't swamp the signal — we're measuring the cost
/// of the in-mem map mutations + LRU/recency bookkeeping, not the
/// disk-side fsync (already characterised by audit-8 §3).
///
/// Two paths:
/// - `journal_bump_hot_path` — bumps for a small fixed working set
///   (mirror well below cap; no evictions). This is the baseline
///   the Perf-8 LRU bookkeeping adds cost to.
/// - `journal_bump_at_cap_with_evictions` — bumps with unique
///   session_ids beyond the cap, forcing cap-overflow eviction on
///   every call. Measures the steady-state cost when an attacker
///   floods unique IDs (the OOM-1 attack shape).
/// - `journal_disk_resurrect` — bumps where the in-mem entry was
///   evicted and the floor must be read from disk before the
///   monotonicity check. This is the Perf-8 worst-case hot-path
///   cost.
fn bench_journal(c: &mut Criterion) {
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.bin");
    let j = ReceiptJournal::open(&path).unwrap();
    // Keep fsyncs off the hot path so the measurement is the
    // in-mem work, not the disk cost.
    j.set_fsync_policy(FsyncPolicy::Periodic(Duration::from_secs(60)));

    // Hot path: small working set, no evictions. Single session,
    // ascending seq.
    let sess = SessionId::new([0x77; 32]);
    let n_pre: u64 = 16;
    for s in 1..=n_pre {
        j.bump(&sess, s).unwrap();
    }
    let counter = Arc::new(AtomicU64::new(n_pre));
    c.bench_function("journal_bump_hot_path", |b| {
        b.iter(|| {
            let next = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            j.bump(&sess, next).unwrap();
            black_box(next);
        });
    });

    // Steady-state at cap: every iteration evicts the LRU entry.
    // Use a tight cap so eviction fires every bump.
    let dir2 = tempfile::tempdir().unwrap();
    let path2 = dir2.path().join("evict.bin");
    let j2 = ReceiptJournal::open(&path2).unwrap();
    j2.set_fsync_policy(FsyncPolicy::Periodic(Duration::from_secs(60)));
    j2.set_max_in_mem_sessions(8);
    // Pre-fill at cap.
    for s in 0u64..8 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&s.to_be_bytes());
        j2.bump(&SessionId::new(bytes), 1).unwrap();
    }
    let counter2 = Arc::new(AtomicU64::new(100));
    c.bench_function("journal_bump_at_cap_with_evictions", |b| {
        b.iter(|| {
            // Each iteration uses a fresh session_id so the bump
            // always overflows the cap.
            let n = counter2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&n.to_be_bytes());
            j2.bump(&SessionId::new(bytes), 1).unwrap();
            black_box(n);
        });
    });

    // Disk resurrect path: an evicted session whose seq we want to
    // advance. Setup: large pre-populated journal so the resurrect
    // path does a real scan. Cap of 1 means every bump evicts the
    // previous; resurrecting `target` then writing the next seq.
    let dir3 = tempfile::tempdir().unwrap();
    let path3 = dir3.path().join("resurrect.bin");
    let j3 = ReceiptJournal::open(&path3).unwrap();
    j3.set_fsync_policy(FsyncPolicy::Periodic(Duration::from_secs(60)));
    // Pre-populate the disk with ~1000 sessions so the resurrect
    // scan has real work to do (~44 KB linear read).
    for s in 0u64..1000 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&s.to_be_bytes());
        j3.bump(&SessionId::new(bytes), 1).unwrap();
    }
    j3.set_max_in_mem_sessions(1);
    let target = SessionId::new({
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&7u64.to_be_bytes());
        b
    });
    // Use a base of 10_000 to comfortably exceed both the unique
    // session_id space (0..1000) and the initial target seq=1, so
    // every `bump(target, ...)` is strictly monotonic.
    let counter3 = Arc::new(AtomicU64::new(10_000));
    c.bench_function("journal_disk_resurrect", |b| {
        b.iter(|| {
            // Bump a placeholder to evict `target` from in-mem. The
            // placeholder id encodes `n` so each iteration uses a
            // fresh id and never trips the monotonicity guard.
            let n = counter3.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut other = [0u8; 32];
            other[..8].copy_from_slice(&n.to_be_bytes());
            // The placeholder bump must also be monotonic; first
            // touch for a fresh id starts at seq=1 (in-mem floor 0,
            // disk floor 0 because we never wrote that id).
            j3.bump(&SessionId::new(other), 1).unwrap();
            // Now bump `target` to a strictly-increasing seq — must
            // resurrect from disk because the cap=1 eviction kicked
            // it out.
            j3.bump(&target, n).unwrap();
            black_box(n);
        });
    });
}

criterion_group!(
    benches,
    bench_receipt,
    bench_commit,
    bench_earnings,
    bench_onion,
    bench_tx,
    bench_wallet_enc,
    bench_journal,
);
criterion_main!(benches);
