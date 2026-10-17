// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Authenticated native P2P transport primitives; consensus messages stay opaque.
pub mod accept;
pub mod budget;
pub mod endpoint;
pub mod frame;
pub mod gossip_guard;
pub mod guard;
pub mod handshake;
pub mod peer_diag;
pub mod peer_record;
pub mod proxy;
pub mod session;
pub mod swarm;
pub mod swarm_policy;
pub mod transaction_gossip;
pub mod upgrade;

pub use crate::oce1::Error;

pub fn domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(payload);
    hash.finalize().into()
}

/// Matches the native canonical-y and X25519 low-order public-key guard.
pub fn public_key_safe(public: &[u8]) -> bool {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let Ok(bytes) = <&[u8; 32]>::try_from(public) else {
        return false;
    };
    let mut y = *bytes;
    y[31] &= 0x7f;
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    if y.iter().rev().cmp(prime.iter().rev()) != std::cmp::Ordering::Less {
        return false;
    }
    CompressedEdwardsY(*bytes)
        .decompress()
        .is_some_and(|point| !point.is_small_order())
}

pub fn verify_ed25519(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if !public_key_safe(public) {
        return false;
    }
    let Ok(public) = <&[u8; 32]>::try_from(public) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    // Native Mirage checks the canonical scalar and exact encoded equation,
    // without verify_strict's additional rejection of small-order R.
    key.verify(message, &signature).is_ok()
}
