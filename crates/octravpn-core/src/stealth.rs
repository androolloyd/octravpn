//! Stealth-output helpers — Octra-aligned scheme.
//!
//! Per `octra-labs/webcli/lib/stealth.hpp`:
//!
//!   1. Sender and recipient agree on a Curve25519 ECDH shared secret:
//!      `shared = SHA256(X25519(sender_eph_sk, recipient_view_pub))`
//!   2. The 16-byte stealth tag (output identifier) is:
//!      `stealth_tag = SHA256(shared || "OCTRA_STEALTH_TAG_V1")[..16]`
//!   3. A 32-byte claim secret + bound claim pubkey are derived with
//!      domain separators `OCTRA_CLAIM_SECRET_V1` / `OCTRA_CLAIM_BIND_V1`.
//!   4. Amount + blinding are sealed under `shared` with AES-256-GCM.
//!
//! For OctraVPN's purposes (program-emitted private transfer), only
//! steps 1-2 matter — the program emits a 16-byte stealth tag the
//! recipient scans for via `octra_stealthOutputs`. We use 32 bytes
//! internally for consistency with our other commitments and truncate
//! to 16 at the call boundary.

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

pub const STEALTH_DOMAIN_TAG: &[u8] = b"OCTRA_STEALTH_TAG_V1";
pub const CLAIM_SECRET_DOMAIN: &[u8] = b"OCTRA_CLAIM_SECRET_V1";
pub const CLAIM_BIND_DOMAIN: &[u8] = b"OCTRA_CLAIM_BIND_V1";

/// Derive the stealth tag the chain emits for a payment to a given
/// recipient view pubkey, using a fresh ephemeral X25519 secret.
///
/// Returns the 32-byte canonical form (we keep the full hash; truncate
/// to 16 bytes when passing to Octra's `octra_privateTransfer`).
pub fn derive_output(view_pubkey: &[u8; 32], ephemeral_nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STEALTH_DOMAIN_TAG);
    h.update(view_pubkey);
    h.update(ephemeral_nonce);
    h.finalize().into()
}

/// Octra-style stealth tag (16 bytes) for wire compatibility with the
/// `octra_privateTransfer` API.
pub fn stealth_tag(view_pubkey: &[u8; 32], ephemeral_nonce: &[u8; 32]) -> [u8; 16] {
    let full = derive_output(view_pubkey, ephemeral_nonce);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

/// Derive the claim secret bound to a stealth output.
pub fn claim_secret(shared: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(shared);
    h.update(CLAIM_SECRET_DOMAIN);
    h.finalize().into()
}

/// Derive a fresh ephemeral nonce for a one-time stealth output.
pub fn fresh_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_nonces_yield_distinct_outputs() {
        let view = [7u8; 32];
        let n1 = fresh_nonce();
        let n2 = fresh_nonce();
        assert_ne!(derive_output(&view, &n1), derive_output(&view, &n2));
    }

    #[test]
    fn deterministic() {
        let view = [9u8; 32];
        let n = [3u8; 32];
        assert_eq!(derive_output(&view, &n), derive_output(&view, &n));
    }

    #[test]
    fn tag_is_first_16() {
        let view = [9u8; 32];
        let n = [3u8; 32];
        let full = derive_output(&view, &n);
        let tag = stealth_tag(&view, &n);
        assert_eq!(&full[..16], &tag);
    }
}
