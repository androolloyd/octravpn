//! Kani harnesses for the OctraVPN crypto / parsing surface.
//!
//! Kani is a bounded model checker for Rust. The harnesses here treat
//! input bytes as nondeterministic and verify properties (panics, slack
//! invariants, round-trips) hold across all bounded inputs.
//!
//! Run with:
//!     cargo kani --harness round_trip_signed_receipt
//!
//! For CI we keep harness sizes small so verification finishes in
//! seconds; the full unbounded versions of these properties live in the
//! companion proptest suite (`crates/octravpn-core/tests/`).

#![cfg_attr(kani, no_std)]

#[cfg(kani)]
extern crate alloc;

#[cfg(kani)]
use alloc::vec::Vec;

#[cfg(kani)]
use octravpn_core::{
    receipt::{Receipt, SignedReceipt, canonical_payload},
    session::SessionId,
    sig::KeyPair,
};

/// `Receipt::signing_payload` is deterministic and canonical: same input
/// → same bytes. Verified bounded-symbolically over a small ciphertext.
#[cfg(kani)]
#[kani::proof]
fn payload_deterministic() {
    let session: [u8; 32] = kani::any();
    let seq: u64 = kani::any();
    let len: usize = kani::any_where(|n: &usize| *n <= 16);
    let mut ct = Vec::with_capacity(len);
    for _ in 0..len {
        ct.push(kani::any::<u8>());
    }
    let a = canonical_payload(&SessionId(session), seq, &ct).unwrap();
    let b = canonical_payload(&SessionId(session), seq, &ct).unwrap();
    assert!(a == b);
}

/// Sign-then-verify round-trip never panics and always succeeds.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(4)]
fn round_trip_signed_receipt() {
    let session: [u8; 32] = kani::any();
    let seq: u64 = kani::any();
    let secret: [u8; 32] = kani::any();
    let kp = KeyPair::from_secret_bytes(&secret);
    let r = Receipt {
        session_id: SessionId(session),
        seq,
        ciphertext: alloc::vec::Vec::new(),
    };
    let sr = SignedReceipt::sign(r, &kp).unwrap();
    assert!(sr.verify().is_ok());
}

/// `check_monotonic` accepts iff seq strictly increases.
#[cfg(kani)]
#[kani::proof]
fn monotonic_iff_strictly_greater() {
    let session: [u8; 32] = kani::any();
    let prev: u64 = kani::any();
    let seq: u64 = kani::any();
    let secret: [u8; 32] = kani::any();
    let kp = KeyPair::from_secret_bytes(&secret);
    let r = Receipt {
        session_id: SessionId(session),
        seq,
        ciphertext: alloc::vec::Vec::new(),
    };
    let sr = SignedReceipt::sign(r, &kp).unwrap();
    let res = sr.check_monotonic(prev);
    assert!(res.is_ok() == (seq > prev));
}

// Stub crate-level item so `cargo build` still succeeds without kani:
// the harness functions are only compiled under `cfg(kani)`.
pub fn build_marker() -> &'static str {
    "octravpn-kani"
}
