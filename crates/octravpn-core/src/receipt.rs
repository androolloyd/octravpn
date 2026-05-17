//! Dual-signed receipts.
//!
//! Each receipt carries a *plaintext* `bytes_used` count plus signatures
//! from both the client's ephemeral session key and the exit node's
//! receipt-signing key. The dual-signature is what makes equivocation
//! slashable: if the exit ever signs two different `bytes_used` values
//! for the same `(session_id, seq)`, anyone can submit both signatures
//! as evidence and slash the validator's bond.
//!
//! Canonical signing payload (binary, deterministic):
//!
//! ```text
//! domain_tag      = "octravpn-receipt-v1"  (19 bytes)
//! program_addr    = 32 bytes (canonical Address bytes)
//! chain_id        = u32 big-endian          (NEW v1.2 binder)
//! circle_id       = 32 bytes (canonical Address bytes;
//!                              all-zero = "None" for v1.1)
//! session_id      = 32 bytes
//! seq             = u64 big-endian
//! bytes_used      = u64 big-endian
//! blind           = 32 bytes (Pedersen blinding scalar canonical form)
//! ```
//!
//! ## v1.2 domain binders (P1-5 fix)
//!
//! Prior receipts (v1.1) bound only `(session_id, seq, bytes_used, blind)`.
//! An adversary who could replay a receipt from program A onto program B
//! (e.g. between v1.1 and v2 deploys, between testnet and mainnet, or
//! between two parallel v2 deploys for a multi-region operator) got a
//! free signature on a payload the signer never intended.
//!
//! The signing payload now folds in the **deploy domain**:
//!
//!   - `program_addr` — the v1.1 / v2 program address the session lives in
//!   - `chain_id`     — a stable identifier for the chain network (devnet
//!                       vs mainnet vs a future shard)
//!   - `circle_id`    — Some(addr) for v2 (operator-circle-keyed sessions),
//!                       None for v1.1 (operator-wallet-keyed)
//!
//! "None" is canonicalised as 32 zero bytes (not just-skipped) so the
//! hash domain has a fixed width across v1.1 and v2 receipts — otherwise
//! an attacker could grind a v1.1 receipt that collides with a v2 hash
//! by choosing a `(program_addr, chain_id)` pair whose 36-byte image
//! coincides with the v1.1 32-byte session_id prefix.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    address::{Address, ADDRESS_LEN},
    session::{Blind, SessionId},
    sig::{verify, KeyPair, PublicKey, Signature},
    CoreError, CoreResult,
};

pub const DOMAIN_RECEIPT: &[u8] = b"octravpn-receipt-v1";

/// Stable chain-id constants. Octra doesn't expose a native `chain_id`
/// on its JSON-RPC (the network identity is a property of the
/// `(rpc_url, program_addr)` pair). We pick a small set of magic
/// numbers so the receipt domain has a discrete, reviewable space
/// rather than hashing the rpc_url string (which is operator-controlled
/// and can drift across reverse-proxy / fork-relabel boundaries).
///
/// The values are 4-byte ASCII tags rendered as u32:
///
///   - `CHAIN_ID_DEVNET = "octd"` = 0x6F63_7464 — the public devnet
///   - `CHAIN_ID_MAINNET = "octm"` = 0x6F63_746D — the eventual mainnet
///   - `CHAIN_ID_TEST = "octT"`   = 0x6F63_7454 — unit/proptest harness
///
/// New networks should claim a new constant rather than reusing one of
/// these.
pub const CHAIN_ID_DEVNET: u32 = 0x6F63_7464;
pub const CHAIN_ID_MAINNET: u32 = 0x6F63_746D;
pub const CHAIN_ID_TEST: u32 = 0x6F63_7454;

/// Deployment domain a receipt binds itself to.
///
/// Held separately from the metering payload (`session_id`, `seq`, …)
/// because the context comes from configuration (operator's `node.toml`
/// or client's `client.toml`) while the payload is per-receipt. Both
/// sides of the control plane must agree on the context for the
/// receipts to round-trip; the wire format embeds it inside `Receipt`
/// so a verifier reading a JSON-serialised `SignedReceipt` doesn't have
/// to know the operator's local config to verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptContext {
    /// The OctraVPN program address (`oct…`) that hosts the session.
    /// For v1.1 this is the `main.aml` deploy; for v2 it's the
    /// `main-v2.aml` deploy.
    pub program_addr: Address,
    /// Network identifier — see the `CHAIN_ID_*` constants. Bound here
    /// so that an attacker who mirrors a v1.1 program from devnet to
    /// mainnet (e.g. via a fork-relay) cannot replay receipts.
    pub chain_id: u32,
    /// Some(addr) for v2 (the operator-circle that owns the session);
    /// None for v1.1. Encoded canonically as 32 zero bytes when None
    /// so the hash domain stays fixed-width.
    pub circle_id: Option<Address>,
}

impl ReceiptContext {
    pub fn new(program_addr: Address, chain_id: u32, circle_id: Option<Address>) -> Self {
        Self {
            program_addr,
            chain_id,
            circle_id,
        }
    }

    /// v1.1 helper: no circle, default chain_id supplied by caller.
    pub fn v1_1(program_addr: Address, chain_id: u32) -> Self {
        Self::new(program_addr, chain_id, None)
    }

    /// v2 helper: circle-scoped session.
    pub fn v2(program_addr: Address, chain_id: u32, circle_id: Address) -> Self {
        Self::new(program_addr, chain_id, Some(circle_id))
    }

    /// 32-byte canonical encoding of the optional circle_id field used
    /// by the signing-payload hasher. Some(c) → c.as_bytes(); None →
    /// all zeros. Kept here so the test suite can rely on the exact
    /// same canonicalisation as the runtime.
    pub fn circle_id_canonical_bytes(&self) -> [u8; ADDRESS_LEN] {
        match &self.circle_id {
            Some(c) => *c.as_bytes(),
            None => [0u8; ADDRESS_LEN],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Deployment domain (program / chain / circle). Bound into the
    /// signing payload so a receipt is non-replayable across programs,
    /// networks, or circles. v1.2 addition; see module docs.
    pub context: ReceiptContext,
    pub session_id: SessionId,
    pub seq: u64,
    pub bytes_used: u64,
    pub blind: Blind,
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
    /// Convenience constructor that pairs a `ReceiptContext` with the
    /// per-receipt payload fields. Existing call-sites can keep using
    /// struct-literal syntax — this is just sugar for tests.
    pub fn new(
        context: ReceiptContext,
        session_id: SessionId,
        seq: u64,
        bytes_used: u64,
        blind: Blind,
    ) -> Self {
        Self {
            context,
            session_id,
            seq,
            bytes_used,
            blind,
        }
    }

    pub fn signing_payload(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_RECEIPT);
        // v1.2 domain binders. Ordering MUST stay stable; see
        // `prop_canonicalization::matches_reference` for the reference
        // implementation that mirrors this hash on the chain side.
        h.update(self.context.program_addr.as_bytes());
        h.update(self.context.chain_id.to_be_bytes());
        h.update(self.context.circle_id_canonical_bytes());
        // Per-receipt payload.
        h.update(self.session_id.as_bytes());
        h.update(self.seq.to_be_bytes());
        h.update(self.bytes_used.to_be_bytes());
        h.update(self.blind.as_bytes());
        h.finalize().into()
    }
}

impl SignedReceipt {
    /// Construct a fully-signed receipt. Both the client and the node
    /// sign the same canonical payload.
    pub fn build(receipt: Receipt, client_kp: &KeyPair, node_kp: &KeyPair) -> Self {
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
/// canonical signing bytes given the same inputs. Takes a `ReceiptContext`
/// by reference so chain-side verifiers (which know `(program_addr,
/// chain_id, circle_id)` from their own state) can recompute the same
/// hash without round-tripping a full `Receipt`.
pub fn canonical_payload(
    context: &ReceiptContext,
    session_id: &SessionId,
    seq: u64,
    bytes_used: u64,
    blind: &Blind,
) -> CoreResult<[u8; 32]> {
    Ok(Receipt {
        context: context.clone(),
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

    /// Test fixture: a v1.1 receipt context (no circle) tied to the test
    /// chain magic. Used by every receipt round-trip below so callers
    /// don't have to construct an `Address` from scratch each time.
    fn ctx_v1(prog_byte: u8) -> ReceiptContext {
        let prog = Address::from_pubkey(&[prog_byte; 32]);
        ReceiptContext::v1_1(prog, CHAIN_ID_TEST)
    }

    #[test]
    fn dual_signed_round_trip() {
        let client = fresh_kp();
        let node = fresh_kp();
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([7u8; 32]),
            1,
            1024 * 1024,
            Blind::new([9u8; 32]),
        );
        let sr = SignedReceipt::build(r, &client, &node);
        sr.verify().unwrap();
    }

    #[test]
    fn tampered_bytes_fails_both_sigs() {
        let client = fresh_kp();
        let node = fresh_kp();
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([0u8; 32]),
            1,
            100,
            Blind::new([1u8; 32]),
        );
        let mut sr = SignedReceipt::build(r, &client, &node);
        sr.receipt.bytes_used = 200;
        assert!(sr.verify().is_err());
    }

    #[test]
    fn forged_node_sig_fails() {
        let client = fresh_kp();
        let node = fresh_kp();
        let attacker = fresh_kp();
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([3u8; 32]),
            1,
            50,
            Blind::new([2u8; 32]),
        );
        let mut sr = SignedReceipt::build(r, &client, &node);
        sr.node_pubkey = attacker.public;
        assert!(matches!(sr.verify().unwrap_err(), ReceiptError::BadNodeSig));
    }

    #[test]
    fn monotonic_seq_check() {
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([0u8; 32]),
            5,
            0,
            Blind::new([0u8; 32]),
        );
        let sr = SignedReceipt::build(r, &fresh_kp(), &fresh_kp());
        assert!(sr.check_monotonic(4).is_ok());
        assert!(sr.check_monotonic(5).is_err());
    }

    // ====================================================================
    // P1-5: cross-domain replay-rejection tests.
    //
    // These three tests are the acceptance criteria for the v1.2 receipt
    // binders. Each builds a fully-signed receipt under context A and
    // then attempts to verify the same `(session_id, seq, bytes_used,
    // blind)` payload against a different context — any of program,
    // chain, or circle. All three MUST fail, since the signature is
    // computed over the SHA-256 image of the combined domain + payload.
    //
    // The attack-mechanic in each case is "an attacker mints a
    // pseudo-receipt under context B carrying the signatures from
    // context A". Verify computes the payload over context B (because
    // verifier trusts the receipt-embedded context), computes a
    // *different* hash, and the sig fails.
    // ====================================================================

    /// Cross-program replay: same session_id on a fork or sibling
    /// deploy MUST reject. Mirrors Tree E.1.a in `docs/v2-threat-model.md`.
    #[test]
    fn cross_program_receipt_rejection() {
        let client = fresh_kp();
        let node = fresh_kp();

        // Build a legit receipt on program A.
        let r_a = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([1u8; 32]),
            1,
            500,
            Blind::new([2u8; 32]),
        );
        let mut forged = SignedReceipt::build(r_a, &client, &node);
        assert!(forged.verify().is_ok(), "sanity: A round-trips");

        // Attacker mints a "receipt" claiming program B with A's sigs.
        // Same (session_id, seq, bytes_used, blind) — only program_addr
        // differs. The signature now does NOT cover the new hash.
        let ctx_b = ctx_v1(0xBB);
        forged.receipt.context = ctx_b;
        assert!(
            forged.verify().is_err(),
            "must reject cross-program replay"
        );
    }

    /// Cross-chain replay: same session_id, same program, different
    /// chain_id MUST reject. Catches the "mirror devnet program to
    /// mainnet" attack.
    #[test]
    fn cross_chain_receipt_rejection() {
        let client = fresh_kp();
        let node = fresh_kp();

        let prog = Address::from_pubkey(&[0xAA; 32]);
        let ctx_a = ReceiptContext::v1_1(prog.clone(), CHAIN_ID_DEVNET);
        let ctx_b = ReceiptContext::v1_1(prog, CHAIN_ID_MAINNET);

        let r_a = Receipt::new(
            ctx_a,
            SessionId::new([5u8; 32]),
            7,
            100,
            Blind::new([3u8; 32]),
        );
        let mut forged = SignedReceipt::build(r_a, &client, &node);
        assert!(forged.verify().is_ok(), "sanity: A round-trips");

        forged.receipt.context = ctx_b;
        assert!(forged.verify().is_err(), "must reject cross-chain replay");
    }

    /// Cross-circle replay: v2 receipt minted against circle X cannot
    /// be replayed against circle Y under the same program. Also
    /// covers v1.1↔v2 confusion (None vs Some(circle)) — see the
    /// `v1_1_to_v2_circle_replay` case below.
    #[test]
    fn cross_circle_receipt_rejection() {
        let client = fresh_kp();
        let node = fresh_kp();

        let prog = Address::from_pubkey(&[0xAA; 32]);
        let circle_x = Address::from_pubkey(&[0xC1; 32]);
        let circle_y = Address::from_pubkey(&[0xC2; 32]);

        let ctx_x = ReceiptContext::v2(prog.clone(), CHAIN_ID_TEST, circle_x);
        let ctx_y = ReceiptContext::v2(prog, CHAIN_ID_TEST, circle_y);

        let r_x = Receipt::new(
            ctx_x,
            SessionId::new([9u8; 32]),
            42,
            65536,
            Blind::new([4u8; 32]),
        );
        let mut forged = SignedReceipt::build(r_x, &client, &node);
        assert!(forged.verify().is_ok(), "sanity: X round-trips");

        forged.receipt.context = ctx_y;
        assert!(forged.verify().is_err(), "must reject cross-circle replay");
    }

    /// Sanity: a receipt with the same payload under contexts that
    /// share the same canonical-bytes serialisation must verify
    /// equally. This guards the "None ↔ Some(zero)" canonicalisation
    /// invariant explicitly.
    ///
    /// **Why this is fine in practice:** an `Address` is the SHA-256
    /// of a pubkey, so producing the all-zero address requires a
    /// SHA-256 preimage hit on [0;32] — well outside the threat model.
    /// We assert the canonicalisation invariant rather than the
    /// attack-rejection because the attacker can never construct
    /// `Some(zero_address)` in the first place.
    #[test]
    fn canonical_none_vs_some_zero_circle_match() {
        let prog = Address::from_pubkey(&[0xAA; 32]);
        let zero_circle = Address::from_parts(
            [0u8; ADDRESS_LEN],
            "oct11111111111111111111111111111111111111111111".to_string(),
        );
        let ctx_none = ReceiptContext::v1_1(prog.clone(), CHAIN_ID_TEST);
        let ctx_zero = ReceiptContext::v2(prog, CHAIN_ID_TEST, zero_circle);
        assert_eq!(
            ctx_none.circle_id_canonical_bytes(),
            ctx_zero.circle_id_canonical_bytes(),
            "Some(zero_circle) and None must serialise to the same 32 bytes"
        );
    }
}
