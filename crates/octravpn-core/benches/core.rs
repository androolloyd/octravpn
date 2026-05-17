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

criterion_group!(
    benches,
    bench_receipt,
    bench_commit,
    bench_earnings,
    bench_onion,
    bench_tx,
    bench_wallet_enc,
);
criterion_main!(benches);
