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
    /// HFHE-2 "shadow blob": optional homomorphically-encrypted
    /// `bytes_used` ciphertext, base64 over the PVAC sidecar's wire
    /// format (`hfhe_v1|<b64>`). Emitted by the receipt-signing path
    /// only when the operator has the PVAC sidecar enabled AND the
    /// circle pubkey loaded; absent otherwise. Travels alongside the
    /// today's sha256 commitment so that when Octra unblocks
    /// `fhe_load_pk` the on-chain verify can flip from
    /// "sha256-equality" to "sha256-AND-HFHE-equality" via a single
    /// AML-side diff — historical receipts already carry the blob.
    ///
    /// **NOT** folded into the signing payload — verifying the
    /// existing dual-sig MUST keep working unchanged for every
    /// receipt ever emitted. The encrypted blob is an *additive*
    /// commitment; integrity is enforced by the ciphertext being
    /// produced under a public key the chain knows about (the
    /// `circle_id`'s registered PVAC pubkey).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_bytes_used: Option<String>,
    /// HFHE-2 shadow blob: optional encrypted `net = bytes_used *
    /// price` value. Same wire format + same emission gating as
    /// `enc_bytes_used`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_net: Option<String>,
    /// HFHE-2 shadow blob: optional `zkzp_v2|<b64>` zero-proof bound
    /// to a Pedersen opening of `(bytes_used, blind)`. Emitted by
    /// the receipt-signing path when the sidecar can produce one;
    /// the chain-side verifier ignores it until HFHE-3 swaps in the
    /// AML `fhe_verify` line. Caller-only field — no impact on
    /// receipt signature validity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pvac_zero_proof: Option<String>,
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

/// HFHE-2 shadow-blob bundle a receipt may carry in addition to its
/// today's sha256 commitment. Produced by the operator's
/// receipt-signing path when `Hub::pvac()` is `Some` AND the circle
/// pubkey has been loaded at boot. The three fields are `None` on
/// every path that doesn't have the sidecar wired up — receipts
/// remain wire-compatible across the schema bump.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShadowBlob {
    pub enc_bytes_used: Option<String>,
    pub enc_net: Option<String>,
    pub pvac_zero_proof: Option<String>,
}

impl ShadowBlob {
    /// Empty bundle — no encrypted fields populated. The receipt
    /// serialises identically to a pre-HFHE-2 receipt under this
    /// configuration.
    pub fn empty() -> Self {
        Self::default()
    }

    /// True iff every field is `None`. Used by the test suite to
    /// pin "sidecar disabled ⇒ no synthetic data on the wire".
    pub fn is_empty(&self) -> bool {
        self.enc_bytes_used.is_none() && self.enc_net.is_none() && self.pvac_zero_proof.is_none()
    }
}

impl SignedReceipt {
    /// Construct a fully-signed receipt with NO shadow blob. Both
    /// the client and the node sign the same canonical payload.
    /// Equivalent to `build_with_shadow(receipt, ..., ShadowBlob::empty())`.
    pub fn build(receipt: Receipt, client_kp: &KeyPair, node_kp: &KeyPair) -> Self {
        Self::build_with_shadow(receipt, client_kp, node_kp, ShadowBlob::empty())
    }

    /// Construct a fully-signed receipt and attach the given shadow
    /// blob. Signatures cover only the (pre-existing) signing
    /// payload — the blob is wire-additive, never folded into the
    /// hash. That way verifiers that don't understand HFHE keep
    /// round-tripping receipts byte-for-byte, and the existing
    /// dual-sig invariants are untouched.
    pub fn build_with_shadow(
        receipt: Receipt,
        client_kp: &KeyPair,
        node_kp: &KeyPair,
        shadow: ShadowBlob,
    ) -> Self {
        let payload = receipt.signing_payload();
        Self {
            receipt,
            client_pubkey: client_kp.public,
            client_sig: client_kp.sign(&payload),
            node_pubkey: node_kp.public,
            node_sig: node_kp.sign(&payload),
            enc_bytes_used: shadow.enc_bytes_used,
            enc_net: shadow.enc_net,
            pvac_zero_proof: shadow.pvac_zero_proof,
        }
    }

    /// Return the shadow-blob fields as a borrowed bundle. Cheap —
    /// just three Option<&String> wrapped together. `None` for
    /// receipts emitted without the sidecar enabled.
    pub fn shadow(&self) -> ShadowBlob {
        ShadowBlob {
            enc_bytes_used: self.enc_bytes_used.clone(),
            enc_net: self.enc_net.clone(),
            pvac_zero_proof: self.pvac_zero_proof.clone(),
        }
    }

    /// True iff the receipt carries any HFHE-2 shadow blob fields.
    pub fn has_shadow(&self) -> bool {
        self.enc_bytes_used.is_some() || self.enc_net.is_some() || self.pvac_zero_proof.is_some()
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

    /// Forging the client signature alone (with attacker-controlled pk)
    /// surfaces `BadClientSig`, not `BadNodeSig` — failure ordering must
    /// be stable for diags.
    #[test]
    fn forged_client_sig_fails_with_correct_variant() {
        let client = fresh_kp();
        let node = fresh_kp();
        let attacker = fresh_kp();
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([1u8; 32]),
            2,
            10,
            Blind::new([0u8; 32]),
        );
        let mut sr = SignedReceipt::build(r, &client, &node);
        sr.client_pubkey = attacker.public;
        assert!(matches!(sr.verify().unwrap_err(), ReceiptError::BadClientSig));
    }

    /// Tampering with the blind scalar (without re-signing) rejects.
    /// Blind is part of the signing payload.
    #[test]
    fn tampered_blind_rejects() {
        let c = fresh_kp();
        let n = fresh_kp();
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([0u8; 32]),
            3,
            42,
            Blind::new([0xAA; 32]),
        );
        let mut sr = SignedReceipt::build(r, &c, &n);
        sr.receipt.blind = Blind::new([0xBB; 32]);
        assert!(sr.verify().is_err());
    }

    /// Tampering with seq alone (seq rewind) rejects.
    #[test]
    fn tampered_seq_rejects() {
        let c = fresh_kp();
        let n = fresh_kp();
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([0u8; 32]),
            5,
            10,
            Blind::new([0; 32]),
        );
        let mut sr = SignedReceipt::build(r, &c, &n);
        sr.receipt.seq = 6;
        assert!(sr.verify().is_err());
    }

    /// Tampering with session_id rejects (cross-session replay
    /// rejection).
    #[test]
    fn tampered_session_id_rejects() {
        let c = fresh_kp();
        let n = fresh_kp();
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([0u8; 32]),
            1,
            10,
            Blind::new([0; 32]),
        );
        let mut sr = SignedReceipt::build(r, &c, &n);
        sr.receipt.session_id = SessionId::new([0xFF; 32]);
        assert!(sr.verify().is_err());
    }

    /// `check_monotonic` boundary: prev=0 rejects seq=0.
    #[test]
    fn check_monotonic_zero_boundary() {
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([0u8; 32]),
            0,
            0,
            Blind::new([0; 32]),
        );
        let sr = SignedReceipt::build(r, &fresh_kp(), &fresh_kp());
        assert!(matches!(
            sr.check_monotonic(0).unwrap_err(),
            ReceiptError::NonMonotonicSeq { prev: 0, next: 0 }
        ));
    }

    /// `check_monotonic` near u64::MAX: no overflow shenanigans.
    #[test]
    fn check_monotonic_u64_max_edge() {
        let r = Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([0u8; 32]),
            u64::MAX,
            0,
            Blind::new([0; 32]),
        );
        let sr = SignedReceipt::build(r, &fresh_kp(), &fresh_kp());
        assert!(sr.check_monotonic(u64::MAX - 1).is_ok());
        assert!(sr.check_monotonic(u64::MAX).is_err());
    }

    /// `canonical_payload` helper agrees with `Receipt::signing_payload`
    /// — chain and client hash the same bytes.
    #[test]
    fn canonical_payload_helper_matches_receipt_payload() {
        let ctx = ctx_v1(0x42);
        let sid = SessionId::new([7u8; 32]);
        let blind = Blind::new([3u8; 32]);
        let receipt = Receipt::new(ctx.clone(), sid.clone(), 100, 9999, blind);
        let helper = canonical_payload(&ctx, &sid, 100, 9999, &blind).unwrap();
        assert_eq!(helper, receipt.signing_payload());
    }

    /// Distinct `bytes_used` yields distinct signing payload (metering
    /// is genuinely covered).
    #[test]
    fn distinct_bytes_used_distinct_payload() {
        let ctx = ctx_v1(0xAA);
        let sid = SessionId::new([0u8; 32]);
        let blind = Blind::new([0u8; 32]);
        let a = Receipt::new(ctx.clone(), sid.clone(), 1, 100, blind).signing_payload();
        let b = Receipt::new(ctx, sid, 1, 200, blind).signing_payload();
        assert_ne!(a, b);
    }

    /// JSON round-trip preserves verifiability — chain-side JSON
    /// readers reach the same verdict as in-memory.
    #[test]
    fn signed_receipt_json_round_trip_preserves_verify() {
        let c = fresh_kp();
        let n = fresh_kp();
        let r = Receipt::new(
            ctx_v1(0xCC),
            SessionId::new([4u8; 32]),
            7,
            512,
            Blind::new([5u8; 32]),
        );
        let sr = SignedReceipt::build(r, &c, &n);
        let j = serde_json::to_string(&sr).unwrap();
        let parsed: SignedReceipt = serde_json::from_str(&j).unwrap();
        parsed.verify().unwrap();
        assert_eq!(sr, parsed);
    }

    /// Single-bit chain_id flip changes the signing payload (cross-
    /// chain replay rejection mechanic).
    #[test]
    fn chain_id_bit_flip_changes_payload() {
        let prog = Address::from_pubkey(&[0xAA; 32]);
        let ctx_a = ReceiptContext::v1_1(prog.clone(), 0x1234_5678);
        let ctx_b = ReceiptContext::v1_1(prog, 0x1234_5679);
        let sid = SessionId::new([0u8; 32]);
        let blind = Blind::new([0u8; 32]);
        let a = Receipt::new(ctx_a, sid.clone(), 1, 0, blind).signing_payload();
        let b = Receipt::new(ctx_b, sid, 1, 0, blind).signing_payload();
        assert_ne!(a, b);
    }

    /// Signing payload is 32 bytes (SHA-256). Catches accidental codec
    /// drift if the type ever loosens.
    #[test]
    fn signing_payload_is_thirty_two_bytes() {
        let r = Receipt::new(
            ctx_v1(0),
            SessionId::new([0u8; 32]),
            0,
            0,
            Blind::new([0u8; 32]),
        );
        assert_eq!(r.signing_payload().len(), 32);
    }

    // ====================================================================
    // HFHE-2 shadow-blob tests.
    // ====================================================================

    fn sample_receipt() -> Receipt {
        Receipt::new(
            ctx_v1(0xAA),
            SessionId::new([7u8; 32]),
            3,
            1_048_576,
            Blind::new([9u8; 32]),
        )
    }

    #[test]
    fn shadow_blob_absent_by_default() {
        let sr = SignedReceipt::build(sample_receipt(), &fresh_kp(), &fresh_kp());
        assert!(!sr.has_shadow());
        assert!(sr.enc_bytes_used.is_none());
        assert!(sr.enc_net.is_none());
        assert!(sr.pvac_zero_proof.is_none());
        assert!(sr.shadow().is_empty());
    }

    #[test]
    fn shadow_blob_empty_equals_no_shadow() {
        let client = fresh_kp();
        let node = fresh_kp();
        let b = SignedReceipt::build(sample_receipt(), &client, &node);
        let c = SignedReceipt::build_with_shadow(
            sample_receipt(),
            &client,
            &node,
            ShadowBlob::empty(),
        );
        assert!(!b.has_shadow());
        assert!(!c.has_shadow());
        assert_eq!(b, c);
    }

    #[test]
    fn shadow_blob_present_carries_fields() {
        let shadow = ShadowBlob {
            enc_bytes_used: Some("hfhe_v1|AAAA".into()),
            enc_net: Some("hfhe_v1|BBBB".into()),
            pvac_zero_proof: Some("zkzp_v2|CCCC".into()),
        };
        let sr = SignedReceipt::build_with_shadow(
            sample_receipt(),
            &fresh_kp(),
            &fresh_kp(),
            shadow.clone(),
        );
        assert!(sr.has_shadow());
        assert_eq!(sr.enc_bytes_used.as_deref(), Some("hfhe_v1|AAAA"));
        assert_eq!(sr.enc_net.as_deref(), Some("hfhe_v1|BBBB"));
        assert_eq!(sr.pvac_zero_proof.as_deref(), Some("zkzp_v2|CCCC"));
        assert_eq!(sr.shadow(), shadow);
    }

    #[test]
    fn shadow_blob_does_not_change_signing_payload() {
        let client = fresh_kp();
        let node = fresh_kp();
        let plain = SignedReceipt::build(sample_receipt(), &client, &node);
        let shadowed = SignedReceipt::build_with_shadow(
            sample_receipt(),
            &client,
            &node,
            ShadowBlob {
                enc_bytes_used: Some("hfhe_v1|AAAA".into()),
                enc_net: Some("hfhe_v1|BBBB".into()),
                pvac_zero_proof: None,
            },
        );
        plain.verify().unwrap();
        shadowed.verify().unwrap();
        assert_eq!(plain.client_sig, shadowed.client_sig);
        assert_eq!(plain.node_sig, shadowed.node_sig);
    }

    #[test]
    fn signed_receipt_with_shadow_json_round_trip() {
        let sr = SignedReceipt::build_with_shadow(
            sample_receipt(),
            &fresh_kp(),
            &fresh_kp(),
            ShadowBlob {
                enc_bytes_used: Some("hfhe_v1|ZZZ".into()),
                enc_net: Some("hfhe_v1|YYY".into()),
                pvac_zero_proof: Some("zkzp_v2|XXX".into()),
            },
        );
        let j = serde_json::to_string(&sr).unwrap();
        let parsed: SignedReceipt = serde_json::from_str(&j).unwrap();
        parsed.verify().unwrap();
        assert_eq!(sr, parsed);
    }

    #[test]
    fn legacy_signed_receipt_json_deserialises() {
        let pre_hfhe2 = SignedReceipt::build(sample_receipt(), &fresh_kp(), &fresh_kp());
        let j = serde_json::to_string(&pre_hfhe2).unwrap();
        assert!(!j.contains("enc_bytes_used"));
        assert!(!j.contains("enc_net"));
        assert!(!j.contains("pvac_zero_proof"));
        let parsed: SignedReceipt = serde_json::from_str(&j).unwrap();
        assert!(!parsed.has_shadow());
        parsed.verify().unwrap();
        assert_eq!(pre_hfhe2, parsed);
    }

    #[test]
    fn explicit_null_shadow_fields_decode_as_none() {
        let r = sample_receipt();
        let kp_c = fresh_kp();
        let kp_n = fresh_kp();
        let payload = r.signing_payload();
        let cs = kp_c.sign(&payload);
        let ns = kp_n.sign(&payload);
        let j = serde_json::json!({
            "receipt": r,
            "client_pubkey": kp_c.public,
            "client_sig": cs,
            "node_pubkey": kp_n.public,
            "node_sig": ns,
            "enc_bytes_used": serde_json::Value::Null,
            "enc_net": serde_json::Value::Null,
            "pvac_zero_proof": serde_json::Value::Null,
        });
        let parsed: SignedReceipt = serde_json::from_value(j).unwrap();
        assert!(!parsed.has_shadow());
        parsed.verify().unwrap();
    }

    #[test]
    fn tampered_shadow_blob_does_not_fail_verify() {
        let mut sr = SignedReceipt::build_with_shadow(
            sample_receipt(),
            &fresh_kp(),
            &fresh_kp(),
            ShadowBlob {
                enc_bytes_used: Some("hfhe_v1|AAAA".into()),
                enc_net: Some("hfhe_v1|BBBB".into()),
                pvac_zero_proof: None,
            },
        );
        sr.verify().unwrap();
        sr.enc_bytes_used = Some("hfhe_v1|ZZZZ".into());
        sr.enc_net = Some("hfhe_v1|YYYY".into());
        sr.verify().unwrap();
    }

    #[test]
    fn shadow_blob_is_empty_only_when_all_none() {
        assert!(ShadowBlob::empty().is_empty());
        assert!(ShadowBlob::default().is_empty());
        let one = ShadowBlob {
            enc_bytes_used: Some("x".into()),
            enc_net: None,
            pvac_zero_proof: None,
        };
        assert!(!one.is_empty());
        let two = ShadowBlob {
            enc_bytes_used: None,
            enc_net: Some("x".into()),
            pvac_zero_proof: None,
        };
        assert!(!two.is_empty());
        let three = ShadowBlob {
            enc_bytes_used: None,
            enc_net: None,
            pvac_zero_proof: Some("x".into()),
        };
        assert!(!three.is_empty());
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        /// Property: any well-formed receipt signed with any keypair
        /// pair verifies.
        #[test]
        fn prop_any_well_formed_receipt_verifies(
            sid in prop::array::uniform32(any::<u8>()),
            blind in prop::array::uniform32(any::<u8>()),
            seq in any::<u64>(),
            bytes in any::<u64>(),
            prog_byte in any::<u8>(),
            chain in any::<u32>(),
        ) {
            let prog = Address::from_pubkey(&[prog_byte; 32]);
            let ctx = ReceiptContext::v1_1(prog, chain);
            let r = Receipt::new(ctx, SessionId::new(sid), seq, bytes, Blind::new(blind));
            let sr = SignedReceipt::build(r, &fresh_kp(), &fresh_kp());
            sr.verify().expect("well-formed receipt must verify");
        }

        /// Property: changing the session_id yields distinct payload.
        #[test]
        fn prop_session_id_change_yields_distinct_payload(
            sid_a in prop::array::uniform32(any::<u8>()),
            sid_b in prop::array::uniform32(any::<u8>()),
            blind in prop::array::uniform32(any::<u8>()),
            seq in any::<u64>(),
            bytes in any::<u64>(),
        ) {
            prop_assume!(sid_a != sid_b);
            let ctx = ctx_v1(0xAA);
            let a = Receipt::new(
                ctx.clone(),
                SessionId::new(sid_a),
                seq,
                bytes,
                Blind::new(blind),
            ).signing_payload();
            let b = Receipt::new(
                ctx,
                SessionId::new(sid_b),
                seq,
                bytes,
                Blind::new(blind),
            ).signing_payload();
            prop_assert_ne!(a, b);
        }
    }
}
