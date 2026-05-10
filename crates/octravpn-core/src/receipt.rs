//! Dual-signed receipts.
//!
//! Each receipt carries a *plaintext* `bytes_used` count plus signatures
//! from both the client's ephemeral session key and the exit node's WG
//! key. The dual-signature is what makes equivocation slashable: if the
//! exit node ever signs two different `bytes_used` values for the same
//! `(session_id, seq)`, anyone can submit both signatures as evidence
//! and slash the validator's bond.
//!
//! Canonical signing payload (binary, deterministic):
//!
//! ```text
//! domain_tag      = "octravpn-receipt-v1"  (19 bytes)
//! session_id      = 32 bytes
//! seq             = u64 big-endian
//! bytes_used      = u64 big-endian
//! blind           = 32 bytes (Curve25519 scalar canonical form)
//! ```
//!
//! The `blind` is the Pedersen blinding the client commits to at session
//! open; the chain uses it during settlement to update each hop's
//! earnings ledger via curve-point addition.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    session::SessionId,
    sig::{verify, KeyPair, PublicKey, Signature},
    CoreError, CoreResult,
};

pub const DOMAIN_RECEIPT: &[u8] = b"octravpn-receipt-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub session_id: SessionId,
    pub seq: u64,
    pub bytes_used: u64,
    /// Pedersen blinding scalar for the earnings-ledger update at settle
    /// time. Each receipt carries a fresh, independent blind so the chain
    /// can credit each hop's ledger with `bytes_used*price*split * G + b*H`.
    pub blind: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub client_pubkey: PublicKey,
    pub client_sig: Signature,
    pub node_pubkey: PublicKey,
    pub node_sig: Signature,
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("non-monotonic seq: prev={prev} new={next}")]
    NonMonotonicSeq { prev: u64, next: u64 },
    #[error("client signature invalid")]
    BadClientSig,
    #[error("node signature invalid")]
    BadNodeSig,
    #[error(transparent)]
    Core(#[from] CoreError),
}

impl Receipt {
    pub fn signing_payload(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_RECEIPT);
        h.update(self.session_id.0);
        h.update(self.seq.to_be_bytes());
        h.update(self.bytes_used.to_be_bytes());
        h.update(self.blind);
        h.finalize().into()
    }
}

impl SignedReceipt {
    /// Construct a fully-signed receipt. Both the client and the node
    /// sign the same canonical payload.
    pub fn build(
        receipt: Receipt,
        client_kp: &KeyPair,
        node_kp: &KeyPair,
    ) -> Self {
        let payload = receipt.signing_payload();
        Self {
            receipt,
            client_pubkey: client_kp.public,
            client_sig: client_kp.sign(&payload),
            node_pubkey: node_kp.public,
            node_sig: node_kp.sign(&payload),
        }
    }

    pub fn verify(&self) -> Result<(), ReceiptError> {
        let payload = self.receipt.signing_payload();
        verify(&self.client_pubkey, &payload, &self.client_sig)
            .map_err(|_| ReceiptError::BadClientSig)?;
        verify(&self.node_pubkey, &payload, &self.node_sig)
            .map_err(|_| ReceiptError::BadNodeSig)?;
        Ok(())
    }

    pub fn check_monotonic(&self, prev: u64) -> Result<(), ReceiptError> {
        if self.receipt.seq <= prev {
            return Err(ReceiptError::NonMonotonicSeq {
                prev,
                next: self.receipt.seq,
            });
        }
        Ok(())
    }
}

/// Public helper for the on-chain program model: reproduces the exact
/// canonical signing bytes given the same inputs.
pub fn canonical_payload(
    session_id: &SessionId,
    seq: u64,
    bytes_used: u64,
    blind: &[u8; 32],
) -> CoreResult<[u8; 32]> {
    Ok(Receipt {
        session_id: session_id.clone(),
        seq,
        bytes_used,
        blind: *blind,
    }
    .signing_payload())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_kp() -> KeyPair {
        KeyPair::generate()
    }

    #[test]
    fn dual_signed_round_trip() {
        let client = fresh_kp();
        let node = fresh_kp();
        let r = Receipt {
            session_id: SessionId([7u8; 32]),
            seq: 1,
            bytes_used: 1024 * 1024,
            blind: [9u8; 32],
        };
        let sr = SignedReceipt::build(r, &client, &node);
        sr.verify().unwrap();
    }

    #[test]
    fn tampered_bytes_fails_both_sigs() {
        let client = fresh_kp();
        let node = fresh_kp();
        let r = Receipt {
            session_id: SessionId([0u8; 32]),
            seq: 1,
            bytes_used: 100,
            blind: [1u8; 32],
        };
        let mut sr = SignedReceipt::build(r, &client, &node);
        sr.receipt.bytes_used = 200;
        // Both sigs were over the original payload; any tampering invalidates.
        assert!(sr.verify().is_err());
    }

    #[test]
    fn forged_node_sig_fails() {
        let client = fresh_kp();
        let node = fresh_kp();
        let attacker = fresh_kp();
        let r = Receipt {
            session_id: SessionId([3u8; 32]),
            seq: 1,
            bytes_used: 50,
            blind: [2u8; 32],
        };
        let mut sr = SignedReceipt::build(r, &client, &node);
        // Replace node's pubkey with attacker's — sig won't verify against it.
        sr.node_pubkey = attacker.public;
        assert!(matches!(sr.verify().unwrap_err(), ReceiptError::BadNodeSig));
    }

    #[test]
    fn monotonic_seq_check() {
        let r = Receipt {
            session_id: SessionId([0u8; 32]),
            seq: 5,
            bytes_used: 0,
            blind: [0u8; 32],
        };
        let sr = SignedReceipt::build(r, &fresh_kp(), &fresh_kp());
        assert!(sr.check_monotonic(4).is_ok());
        assert!(sr.check_monotonic(5).is_err());
    }
}
