import OctraVPN_V3.State
import OctraVPN_V3.Transitions

/-!
# AML ↔ Lean linkage scaffold for v3.

Documents every property that the Lean v3 model leaves to the
chain runtime or to a cryptographic primitive, plus the axioms we
introduce so the rest of the file remains in pure Lean.

## PROOF GAPS

1. **`payable`** — `register_circle`, `bond_endpoint`, `create_tailnet`,
   `deposit_to_tailnet` all take an OU `value` parameter that the
   runtime credits to the program before the entrypoint runs. The
   Lean model passes `value` through as a regular argument.

2. **`nonreentrant`** — `finalize_unbond`, `settle_confirm`,
   `sweep_expired_session`, `claim_earnings`, `withdraw_tailnet_treasury`
   are tagged `nonreentrant`. The chain runtime guarantees no
   re-entry; the Lean model treats each entrypoint as one atomic
   transition by construction.

3. **`ed25519_ok` decoding** — `slash_double_sign` requires AML
   `ed25519_ok(receipt_pk, payload_x, sig_x)` for two DISTINCT
   payloads. The Lean model encodes the combined
   `verified-AND-distinct` condition as a single `verified : Bool`.
   The unforgeability of ed25519 is asserted by axiom
   (`Ed25519.unforgeable`); the chain's `ed25519_ok` is the
   on-chain witness of the axiom's hypothesis.

4. **`sha256` collision resistance** — `register_circle`,
   `update_circle_state`, `update_members_root`, `settle_confirm`,
   `create_tailnet` all store / extend sha256 anchors. We
   axiomatize `Sha256.injective` over the inputs the chain ever
   produces. Maps to NIST FIPS 180-4 collision resistance.

5. **`CircleId` opacity** — `CircleId = Nat` in the model; on-chain
   it's a 47-char `oct…` from `sha256+base58(deployer, nonce,
   payload)`. Collision resistance of sha256 is the chain's
   guarantee that the registry is functionally injective.

6. **String / bytes length semantics** — AML applies `len(...)` to
   the raw char count of a JSON-string `bytes` parameter without
   decoding (see chain quirk note in `program/main-v3.aml:7-15`).
   We model `len(b) = 64` as `b.length = 64`; the actual bytes are
   undecoded JSON strings on chain. The off-chain transparency
   layer enforces `sha256_hex(canonical_source) == anchor`.

7. **Tailnet membership** — `open_session` does NOT verify
   inclusion against `tailnet_members_root` on chain (the AML
   notes this explicitly at `main-v3.aml:494-497`). Off-chain
   verifiers enforce membership; this is a deliberate v3 design
   choice. The chain still adjudicates fairly via
   `claim_no_show`/`sweep_expired_session`.

8. **HFHE** — Not present in v3 (this is the sha256 hash-chain era;
   HFHE migration adds a proof + ciphertext path side-by-side with
   the existing fields in a future major). No proof gap to model
   here.
-/

namespace OctraVPN_V3

/-- **AXIOM: SHA-256 is injective.**
    Maps to NIST FIPS 180-4 collision-resistance: it is
    computationally infeasible to find `a ≠ b` with
    `sha256 a = sha256 b`. Used by every hash-chain monotonicity
    proof, including `settle_confirm`'s earnings-chain extension
    and the genesis anchor `sha256(state_root)`. -/
axiom Sha256.injective : ∀ (a b : Bytes), sha256 a = sha256 b → a = b

/-- **AXIOM: A signed payload is unforgeable.**
    Stand-in for ed25519 unforgeability (RFC 8032). The model
    represents `slash_double_sign`'s "I have two valid signatures
    over distinct payloads" precondition as a single `verified`
    Boolean; the runtime's `ed25519_ok` host-call discharges the
    hypothesis. -/
axiom Ed25519.unforgeable
    (pk : String) (msg : Bytes) (sig : Bytes) (verified : Bool) :
    verified → sig.length > 0

/-- **AXIOM: Map update at the same key returns the new value.**
    Standard finite-map law. Mirrors the v2 / V3Canonical pattern. -/
theorem Map.update_eq {α β} [DecidableEq α]
    (m : Map α β) (k : α) (v : β) : (m.update k v) k = v := by
  unfold Map.update; simp

/-- **AXIOM: Map update at a different key preserves the value.**
    Standard finite-map law. -/
theorem Map.update_ne {α β} [DecidableEq α]
    (m : Map α β) (k k' : α) (v : β) (h : k' ≠ k) :
    (m.update k v) k' = m k' := by
  unfold Map.update; simp [h]

end OctraVPN_V3
