//! Stealth-output helpers.
//!
//! Octra exposes stealth view pubkeys per address (`octra_viewPubkey`) and
//! a `octra_privateTransfer` RPC. From the OctraVPN program's perspective,
//! a stealth output is a 32-byte commitment that the program emits via
//! `emit_private_transfer(stealth_output, amount)`. Its construction is
//! the responsibility of the receiving party — node operators when they
//! claim earnings, clients when they pre-commit a refund target.
//!
//! For v1, we provide a deterministic derivation that any wallet with the
//! receiver's view pubkey can reproduce. The actual binding to a usable
//! Octra UTXO/account is enforced when the receiver scans
//! `octra_stealthOutputs(from_epoch)`.

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

pub const STEALTH_DOMAIN: &[u8] = b"octravpn-stealth-v1";

/// Derive a one-time stealth output token from the receiver's view pubkey
/// and a fresh ephemeral nonce. The receiver scans the chain for this
/// 32-byte token to pick up the payment.
///
/// `ephemeral_nonce` is sent alongside (off-chain or via an event) so the
/// receiver can recompute the same value.
pub fn derive_output(view_pubkey: &[u8; 32], ephemeral_nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STEALTH_DOMAIN);
    h.update(view_pubkey);
    h.update(ephemeral_nonce);
    h.finalize().into()
}

/// Generate a fresh ephemeral nonce.
pub fn fresh_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}
