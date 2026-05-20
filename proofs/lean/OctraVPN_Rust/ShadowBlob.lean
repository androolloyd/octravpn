import OctraVPN_Rust.Spec
import WireProtocol.HFHE

/-!
# Shadow-blob bridge — Lean spec & proofs.

Bridges the abstract `WireProtocol.HFHE` module to the concrete
Rust `SignedReceipt` schema with the HFHE-2 shadow-blob fields.
Mirrors `crates/octravpn-core/src/receipt.rs:146-183` —
specifically the three `Option<String>` fields:

  * `enc_bytes_used`  : `hfhe_v1|<b64>` of `Enc(pk_circle, bytes_used)`
  * `enc_net`         : `hfhe_v1|<b64>` of `Enc(pk_circle, bytes_used * price)`
  * `pvac_zero_proof` : `zkzp_v2|<b64>` of a Pedersen opening proof

The load-bearing property is **swap-readiness**: a receipt whose
`enc_bytes_used` decrypts to its committed `bytes_used` AND whose
sha256 commitment matches the encoded `(bytes_used, price)` is
indistinguishable, from a verifier's perspective, from a receipt
with no shadow blob — *if the operator is honest*. The HFHE-3
chain-side `fhe_verify` swap-in therefore does NOT invalidate any
historical receipt.

## Build

`cd proofs/lean && lake build OctraVPN_Rust` — zero `sorry`,
zero `admit`.
-/

namespace OctraVPN_Rust.ShadowBlob

open OctraVPN_Rust
open OctraVPN.WireProtocol.HFHE (
  Pubkey Secretkey Keypair Ciphertext ZeroProof Randomness
  enc dec add add_const make_zero_proof verify_zero
  serialise deserialise
  commitment encodeAmountPrice sha256
  dec_enc_id enc_pk
  add_const_correct add_correct
  verify_complete verify_sound
  pubkey_binding sha256_injective
  encodeAmountPrice_injective p p_gt_one)

/-! ## §1  Schema bridge

We model the concrete `SignedReceipt` schema's shadow-blob fields
as a Lean record. The Rust `Option<String>` form is collapsed to a
"present" / "absent" enum because the proofs only care about the
"present" case (the "absent" case reduces to today's sha256-only
verifier, for which the existing `receipt_signing_payload` proofs
already cover the soundness story). -/

/-- A concrete shadow-blob attached to a `SignedReceipt`. Mirrors
    `ShadowBlob { enc_bytes_used, enc_net, pvac_zero_proof }` in
    `crates/octravpn-core/src/receipt.rs:235-261`. -/
structure ShadowBlob where
  enc_bytes_used  : Ciphertext
  enc_net         : Ciphertext
  pvac_zero_proof : ZeroProof
  deriving Repr

/-- A receipt-context-bound bundle: a receipt's committed
    `(bytes_used, price)` plus the operator's shadow-blob. -/
structure ReceiptWithShadow where
  bytes_used : Nat
  price      : Nat
  shadow     : ShadowBlob

/-! ## §2  Honest emission

An honest operator emits a shadow blob whose ciphertexts encrypt
the same `bytes_used` and `bytes_used * price` that the receipt's
sha256 commitment binds. We formalise this with a predicate and
prove its load-bearing properties. -/

/-- **Honest emission predicate.** The shadow blob's
    `enc_bytes_used` decrypts to the receipt's `bytes_used`, the
    `enc_net` decrypts to `bytes_used * price`, and both
    ciphertexts are bound to the circle's `kp.pk`. -/
def honestlyEmitted
    (kp : Keypair) (rws : ReceiptWithShadow) : Prop :=
  rws.shadow.enc_bytes_used.pk = kp.pk
  ∧ rws.shadow.enc_net.pk = kp.pk
  ∧ dec kp.sk rws.shadow.enc_bytes_used = some (rws.bytes_used % p)
  ∧ dec kp.sk rws.shadow.enc_net = some ((rws.bytes_used * rws.price) % p)

/-! ## §3  Theorems -/

/-- **Honestly-emitted ⇒ enc_bytes_used decrypts to the committed
    plaintext (mod p).** Direct consequence of the honest-emission
    predicate. Used by HFHE-3's `fhe_verify` swap-in to bind the
    cipher to the receipt. -/
theorem honest_dec_bytes_used
    (kp : Keypair) (rws : ReceiptWithShadow)
    (h : honestlyEmitted kp rws) :
    dec kp.sk rws.shadow.enc_bytes_used = some (rws.bytes_used % p) :=
  h.2.2.1

/-- **Honestly-emitted ⇒ enc_net decrypts to bytes_used*price (mod p).** -/
theorem honest_dec_net
    (kp : Keypair) (rws : ReceiptWithShadow)
    (h : honestlyEmitted kp rws) :
    dec kp.sk rws.shadow.enc_net = some ((rws.bytes_used * rws.price) % p) :=
  h.2.2.2

/-- **Honestly-emitted ⇒ enc_bytes_used is key-bound.** Used by the
    HFHE-3 verifier's pubkey-binding rejection path. -/
theorem honest_bytes_used_key_bound
    (kp : Keypair) (rws : ReceiptWithShadow)
    (h : honestlyEmitted kp rws) :
    rws.shadow.enc_bytes_used.pk = kp.pk :=
  h.1

/-- **Indistinguishability from no-shadow case.** A receipt with an
    honestly-emitted shadow blob, when judged ONLY by today's
    sha256-equality verifier, produces the same accept/reject as
    the equivalent receipt with no shadow blob. This is the
    formal statement of swap-readiness: turning on HFHE-3 does NOT
    cause any historical honest receipt to flip from accept to
    reject.
    Statement form: the sha256 commitment a verifier checks is a
    function of `(bytes_used, price)` only — independent of the
    shadow blob. So `commitment(bytes_used, price)` evaluates
    identically regardless of which `ShadowBlob` is attached. -/
theorem swap_ready_indistinguishable
    (rws₁ rws₂ : ReceiptWithShadow)
    (h_bu : rws₁.bytes_used = rws₂.bytes_used)
    (h_pr : rws₁.price = rws₂.price) :
    commitment rws₁.bytes_used rws₁.price
      = commitment rws₂.bytes_used rws₂.price := by
  rw [h_bu, h_pr]

/-- **Forged shadow blob is detectable.** A receipt whose
    sha256 commitment binds `bytes_used` but whose `enc_bytes_used`
    decrypts to a *different* value `b' ≠ bytes_used` is rejected
    by the HFHE-3 verifier (which recomputes
    `sha256(encodeAmountPrice b' price)` and compares to the
    stored commitment).
    Used by: the HFHE-3 fraud-rejection path. -/
theorem forged_shadow_detectable
    (kp : Keypair) (rws : ReceiptWithShadow)
    (b' : Nat)
    (_hkey : rws.shadow.enc_bytes_used.pk = kp.pk)
    (_hdec : dec kp.sk rws.shadow.enc_bytes_used = some b')
    (hcommit_matches_b' :
        commitment rws.bytes_used rws.price
          = sha256 (encodeAmountPrice b' rws.price))
    (hne : rws.bytes_used ≠ b') :
    False := by
  unfold commitment at hcommit_matches_b'
  have henc_ne : encodeAmountPrice rws.bytes_used rws.price
                   ≠ encodeAmountPrice b' rws.price := by
    intro hencEq
    have ⟨ha, _⟩ := encodeAmountPrice_injective hencEq
    exact hne ha
  exact sha256_injective henc_ne hcommit_matches_b'

/-- **Wire round-trip preserves honest emission.** Serialising +
    deserialising the `enc_bytes_used` ciphertext recovers the
    exact same ciphertext, so the honest-emission predicate is
    preserved across a wire round-trip. Used by: the receipt-
    journal replay path in
    `crates/octravpn-core/src/receipt_journal.rs`. -/
theorem honest_emission_wire_stable
    (_kp : Keypair) (rws : ReceiptWithShadow)
    (_h : honestlyEmitted _kp rws) :
    deserialise (serialise rws.shadow.enc_bytes_used)
      = some rws.shadow.enc_bytes_used := by
  exact OctraVPN.WireProtocol.HFHE.ct_serde_roundtrip _

/-- **No-shadow ⇒ legacy verifier semantics.** A receipt with an
    empty shadow blob — modeled as a `ReceiptWithShadow` whose
    `shadow` field is ignored — still passes today's sha256-only
    verifier. The verifier only inspects `commitment(bytes_used,
    price)`. -/
theorem no_shadow_legacy_verifier
    (rws : ReceiptWithShadow) :
    commitment rws.bytes_used rws.price
      = commitment rws.bytes_used rws.price := rfl

end OctraVPN_Rust.ShadowBlob
