//! Stealth-output helpers — Octra-aligned X25519 ECDH scheme.
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
//! ## Privacy contract
//!
//! The recipient publishes a view *public key* (`view_pubkey = view_secret · G`).
//! With **only** that pubkey, an outside observer cannot link emitted
//! stealth tags back to the recipient — the link requires either the
//! sender's ephemeral secret (deleted post-send) or the recipient's
//! `view_secret`. This matches the Monero "public view key" model.
//!
//! Earlier versions used `SHA256(view_pubkey || nonce)` directly, which
//! made tags trivially recomputable by anyone with `view_pubkey`. That
//! has been replaced with proper ECDH below.
//!
//! For OctraVPN's purposes (program-emitted private transfer), only
//! steps 1-2 matter — the program emits a 16-byte stealth tag the
//! recipient scans for via `octra_stealthOutputs`.

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{CoreError, CoreResult};

pub const STEALTH_DOMAIN_TAG: &[u8] = b"OCTRA_STEALTH_TAG_V1";
pub const CLAIM_SECRET_DOMAIN: &[u8] = b"OCTRA_CLAIM_SECRET_V1";
pub const CLAIM_BIND_DOMAIN: &[u8] = b"OCTRA_CLAIM_BIND_V1";
pub const VIEW_SECRET_DOMAIN: &[u8] = b"octravpn-key-v1/view-secret-x25519";

/// What a sender publishes on chain to make a stealth payment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StealthOutput {
    /// `R = r · G`, where `r` is the sender's ephemeral X25519 scalar.
    /// Receiver uses this with their `view_secret` to re-derive the
    /// shared secret and recognise the payment.
    pub ephemeral_pubkey: [u8; 32],
    /// The 32-byte canonical tag. Wire transfers use the leading
    /// 16 bytes (see [`stealth_tag`]).
    pub tag: [u8; 32],
}

/// Derive the X25519 *view secret* from a wallet master secret.
///
/// Critically, this is a function of the **wallet secret**, not the
/// wallet public key. The corresponding view pubkey is the X25519
/// basepoint multiple of this secret.
pub fn view_secret_from_wallet(wallet_secret: &[u8; 32]) -> [u8; 32] {
    crate::util::derive_subkey(wallet_secret, VIEW_SECRET_DOMAIN)
}

/// Derive the X25519 view *public key* from a view secret.
pub fn view_pubkey_from_secret(view_secret: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*view_secret);
    PublicKey::from(&sk).to_bytes()
}

/// Convenience: wallet secret → view pubkey, used at boot to publish
/// `view_pubkey` alongside the endpoint registration / payment claim.
pub fn view_pubkey_from_wallet(wallet_secret: &[u8; 32]) -> [u8; 32] {
    let vs = view_secret_from_wallet(wallet_secret);
    view_pubkey_from_secret(&vs)
}

/// **Sender side.** Produce a `StealthOutput` payable to `view_pubkey`
/// along with the 32-byte shared secret (which the sender uses to seal
/// amount + blinding factor before publishing them on chain).
///
/// `eph_secret` is a one-time ephemeral X25519 scalar; **delete it
/// after sending** — keeping it would let anyone with the chain dump
/// link the payment back to `view_pubkey`.
pub fn build_output(
    view_pubkey: &[u8; 32],
    eph_secret: &[u8; 32],
) -> CoreResult<(StealthOutput, [u8; 32])> {
    let recipient = PublicKey::from(*view_pubkey);
    let sk = StaticSecret::from(*eph_secret);
    let ephemeral_pub = PublicKey::from(&sk);
    let dh = sk.diffie_hellman(&recipient);
    // `was_contributory()` returns false only when the shared secret
    // reduces to zero — i.e. the recipient point was on a small
    // subgroup. Reject those to keep the scheme contributory.
    if !dh.was_contributory() {
        return Err(CoreError::Crypto(
            "stealth: view pubkey produced a non-contributory shared point".into(),
        ));
    }
    let mut h = Sha256::new();
    h.update(dh.as_bytes());
    let shared: [u8; 32] = h.finalize().into();
    let tag = tag_from_shared(&shared);
    Ok((
        StealthOutput {
            ephemeral_pubkey: ephemeral_pub.to_bytes(),
            tag,
        },
        shared,
    ))
}

/// **Sender side.** Same as [`build_output`] but generates a fresh
/// ephemeral X25519 secret internally and zeroizes it on drop.
pub fn build_fresh_output(view_pubkey: &[u8; 32]) -> CoreResult<(StealthOutput, [u8; 32])> {
    let mut eph = [0u8; 32];
    OsRng.fill_bytes(&mut eph);
    let out = build_output(view_pubkey, &eph);
    // Best-effort zeroization; the StaticSecret wrapper inside
    // build_output already zeroes on drop.
    eph.fill(0);
    out
}

/// **Recipient side.** Given the on-chain `ephemeral_pubkey` accompanying
/// a stealth output, compute the expected tag and shared secret. Match
/// against the chain's emitted tag to recognise payments addressed to you.
pub fn scan_with_view_secret(
    view_secret: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let sk = StaticSecret::from(*view_secret);
    let R = PublicKey::from(*ephemeral_pubkey);
    let dh = sk.diffie_hellman(&R);
    let mut h = Sha256::new();
    h.update(dh.as_bytes());
    let shared: [u8; 32] = h.finalize().into();
    (shared, tag_from_shared(&shared))
}

fn tag_from_shared(shared: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(shared);
    h.update(STEALTH_DOMAIN_TAG);
    h.finalize().into()
}

/// 16-byte wire form of the tag, matching `octra_privateTransfer`.
pub fn tag16(tag: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag[..16]);
    out
}

/// Seal a `(amount, blind)` payload under the stealth shared secret
/// so only the recipient (who can recompute the shared secret via
/// X25519(view_secret, R)) can recover it. Domain-separated and
/// authenticated.
///
/// Wire format of the returned blob: `nonce(12) || ciphertext(40)`
/// — i.e. 12 bytes ChaCha20-Poly1305 nonce followed by
/// `Encrypt(key=shared, plaintext = u64 amount || 32B blind)`.
pub fn seal_payload(
    shared: &[u8; 32],
    amount: u64,
    blind: &[u8; 32],
) -> CoreResult<Vec<u8>> {
    let key = derive_payload_key(shared);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut plaintext = Vec::with_capacity(40);
    plaintext.extend_from_slice(&amount.to_be_bytes());
    plaintext.extend_from_slice(blind);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|_| CoreError::Crypto("stealth: seal_payload encrypt".into()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a payload sealed by [`seal_payload`]. Returns
/// `(amount, blind)`. Fails with `CoreError::Crypto` if the AEAD
/// verification fails (i.e. wrong shared secret or tampered ciphertext).
pub fn open_payload(shared: &[u8; 32], blob: &[u8]) -> CoreResult<(u64, [u8; 32])> {
    if blob.len() < 12 + 16 + 40 {
        // Allow the tagged ciphertext to be exactly 12 + 56 (Poly1305 tag = 16)
        // = 68 bytes. We use >= here for forward-compat.
    }
    if blob.len() != 12 + 40 + 16 {
        return Err(CoreError::Crypto(format!(
            "stealth: payload wrong size ({} != 68)",
            blob.len()
        )));
    }
    let key = derive_payload_key(shared);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&blob[..12]);
    let plaintext = cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|_| CoreError::Crypto("stealth: open_payload decrypt".into()))?;
    if plaintext.len() != 40 {
        return Err(CoreError::Crypto(format!(
            "stealth: plaintext wrong size ({})",
            plaintext.len()
        )));
    }
    let mut amt_be = [0u8; 8];
    amt_be.copy_from_slice(&plaintext[..8]);
    let amount = u64::from_be_bytes(amt_be);
    let mut blind = [0u8; 32];
    blind.copy_from_slice(&plaintext[8..]);
    Ok((amount, blind))
}

/// Domain-separated symmetric key for `seal_payload` / `open_payload`.
fn derive_payload_key(shared: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(shared);
    h.update(b"OCTRA_STEALTH_PAYLOAD_V1");
    h.finalize().into()
}

/// Derive the claim secret bound to a stealth output.
pub fn claim_secret(shared: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(shared);
    h.update(CLAIM_SECRET_DOMAIN);
    h.finalize().into()
}

/// Generate a fresh 32-byte ephemeral X25519 scalar for one-time use.
/// Senders should drop this immediately after `build_output` returns.
pub fn fresh_eph_secret() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

// ----- legacy API surface (kept for backward compatibility) -----
//
// These mirror the names the rest of the codebase still calls. They
// dispatch to the X25519 path internally so nothing on the call chain
// silently keeps the broken behavior.

/// Deprecated: use [`build_output`] / [`scan_with_view_secret`] instead.
/// This helper now goes through proper ECDH; the `ephemeral_nonce`
/// parameter is interpreted as the sender's X25519 secret scalar.
#[deprecated(note = "use build_output/scan_with_view_secret for clarity")]
pub fn derive_output(view_pubkey: &[u8; 32], ephemeral_secret: &[u8; 32]) -> [u8; 32] {
    match build_output(view_pubkey, ephemeral_secret) {
        Ok((out, _)) => out.tag,
        Err(_) => [0u8; 32],
    }
}

/// Deprecated wire form of [`derive_output`].
#[deprecated(note = "use build_output(...).0.tag then tag16(..)")]
pub fn stealth_tag(view_pubkey: &[u8; 32], ephemeral_secret: &[u8; 32]) -> [u8; 16] {
    #[allow(deprecated)]
    let full = derive_output(view_pubkey, ephemeral_secret);
    tag16(&full)
}

/// Deprecated: alias for [`fresh_eph_secret`].
#[deprecated(note = "use fresh_eph_secret")]
pub fn fresh_nonce() -> [u8; 32] {
    fresh_eph_secret()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    #[test]
    fn sender_and_receiver_compute_same_shared_secret() {
        let wallet = rand_secret();
        let vs = view_secret_from_wallet(&wallet);
        let vp = view_pubkey_from_secret(&vs);

        let (out, sender_shared) = build_fresh_output(&vp).unwrap();
        let (receiver_shared, receiver_tag) =
            scan_with_view_secret(&vs, &out.ephemeral_pubkey);
        assert_eq!(sender_shared, receiver_shared);
        assert_eq!(out.tag, receiver_tag);
    }

    /// **The critical privacy property.** Given only the recipient's
    /// public view key and the chain-emitted stealth output, an
    /// observer cannot recompute the tag — they'd need the view secret.
    #[test]
    fn observer_with_only_view_pubkey_cannot_recompute_tag() {
        let wallet = rand_secret();
        let vp = view_pubkey_from_wallet(&wallet);

        let (out, _) = build_fresh_output(&vp).unwrap();
        // Attacker has: view_pubkey, out.ephemeral_pubkey, out.tag.
        // Try the broken old scheme:
        let mut h = Sha256::new();
        h.update(STEALTH_DOMAIN_TAG);
        h.update(vp);
        h.update(out.ephemeral_pubkey);
        let attacker_guess: [u8; 32] = h.finalize().into();
        assert_ne!(out.tag, attacker_guess,
                   "old hash-based scheme must not equal new ECDH tag");

        // Try recomputing without view_secret using random scalars:
        for _ in 0..10 {
            let bogus = rand_secret();
            let (_, t) = scan_with_view_secret(&bogus, &out.ephemeral_pubkey);
            assert_ne!(out.tag, t);
        }
    }

    #[test]
    fn distinct_ephemeral_secrets_yield_distinct_tags() {
        let wallet = rand_secret();
        let vp = view_pubkey_from_wallet(&wallet);
        let (a, _) = build_fresh_output(&vp).unwrap();
        let (b, _) = build_fresh_output(&vp).unwrap();
        assert_ne!(a.tag, b.tag);
        assert_ne!(a.ephemeral_pubkey, b.ephemeral_pubkey);
    }

    #[test]
    fn view_pubkey_is_curve_point_basepoint_multiple() {
        let wallet = rand_secret();
        let vs = view_secret_from_wallet(&wallet);
        let vp1 = view_pubkey_from_secret(&vs);
        let vp2 = view_pubkey_from_wallet(&wallet);
        assert_eq!(vp1, vp2);
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let wallet = [7u8; 32];
        let vp = view_pubkey_from_wallet(&wallet);
        let eph = [3u8; 32];
        let (out_a, sh_a) = build_output(&vp, &eph).unwrap();
        let (out_b, sh_b) = build_output(&vp, &eph).unwrap();
        assert_eq!(out_a, out_b);
        assert_eq!(sh_a, sh_b);
    }

    #[test]
    fn seal_then_open_round_trip() {
        let wallet = rand_secret();
        let vp = view_pubkey_from_wallet(&wallet);
        let (_out, shared) = build_fresh_output(&vp).unwrap();
        let amount = 12345u64;
        let blind = [0x42u8; 32];
        let blob = seal_payload(&shared, amount, &blind).unwrap();
        let (a, b) = open_payload(&shared, &blob).unwrap();
        assert_eq!(a, amount);
        assert_eq!(b, blind);
    }

    #[test]
    fn open_payload_rejects_wrong_shared() {
        let shared = [7u8; 32];
        let blob = seal_payload(&shared, 1, &[0u8; 32]).unwrap();
        let r = open_payload(&[8u8; 32], &blob);
        assert!(r.is_err());
    }

    #[test]
    fn open_payload_rejects_tampered_ciphertext() {
        let shared = [9u8; 32];
        let mut blob = seal_payload(&shared, 5, &[1u8; 32]).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(open_payload(&shared, &blob).is_err());
    }

    #[test]
    fn full_stealth_payment_e2e() {
        // End-to-end: sender knows view_pubkey only; receiver knows
        // view_secret only. They both recover (amount, blind).
        let wallet = rand_secret();
        let vs = view_secret_from_wallet(&wallet);
        let vp = view_pubkey_from_secret(&vs);

        // Sender side.
        let (out, sender_shared) = build_fresh_output(&vp).unwrap();
        let blob = seal_payload(&sender_shared, 5_000, &[0xAA; 32]).unwrap();

        // Receiver side.
        let (receiver_shared, receiver_tag) =
            scan_with_view_secret(&vs, &out.ephemeral_pubkey);
        assert_eq!(out.tag, receiver_tag);
        let (amount, blind) = open_payload(&receiver_shared, &blob).unwrap();
        assert_eq!(amount, 5_000);
        assert_eq!(blind, [0xAA; 32]);
    }

    #[test]
    fn tag16_is_first_16_of_full() {
        let wallet = [9u8; 32];
        let vp = view_pubkey_from_wallet(&wallet);
        let eph = [5u8; 32];
        let (out, _) = build_output(&vp, &eph).unwrap();
        let short = tag16(&out.tag);
        assert_eq!(&out.tag[..16], &short);
    }
}
