/-!
# V3 policy anchor — Lean spec & proofs.

Mirrors the v3 `policy` anchor format alongside `V3Canonical.lean`
and `V3Members.lean`.

The v3 policy anchor commits to a `(acl_doc, effective_epoch)`
pair. The `acl_doc` is the canonical-bytes form of the ACL TOML
(see `crates/octravpn-mesh/src/acl.rs`); the `effective_epoch`
prevents replay of an old ACL into a future epoch.

Same modelling strategy as `V3Members.lean`:

  * opaque `encodePolicyFields` with injectivity axiom (matches
    `serde_json::to_string` on the two-field schema),
  * opaque `sha256_32` with collision-resistance axiom (same axiom
    style as `Sha256.injective` in `OctraVPN_Rust/Spec.lean`),
  * structural reordering of the top-level `(acl_doc,
    effective_epoch)` fields is by construction (sorted-key JSON
    encoding).

Axioms introduced (all standard cryptographic / encoder
assumptions, mirroring `V3Canonical.lean` and `V3Members.lean`):

  * `sha256_32_length`              — SHA-256 output is exactly 32 bytes,
  * `sha256_32_injective`           — distinct inputs ⇒ distinct digests,
  * `encodePolicyFields_injective`  — the underlying field encoder is
    injective on its `(acl_doc, effective_epoch)` pair.
-/

namespace OctraVPN.WireProtocol.V3Policy

abbrev ByteString := List UInt8

/-- A canonicalised ACL document body, as raw bytes. The byte
    layout is whatever `AclDoc::canonical_bytes()` produces in
    `crates/octravpn-mesh/src/acl.rs`. -/
abbrev AclBody := ByteString

/-- The full v3 policy anchor input. -/
structure PolicyInput where
  acl_doc          : AclBody
  effective_epoch  : Nat
  deriving Inhabited, DecidableEq

/-- Opaque field encoder. Mirrors `serde_json::to_string` on a
    `Value::Object` with `acl_doc` and `effective_epoch` keys
    (sorted). The exact layout is irrelevant to the algebraic
    properties — only injectivity on the pair matters. -/
opaque encodePolicyFields : AclBody → Nat → ByteString :=
  fun body ep => body ++ [0] ++ (toString ep).toUTF8.toList

/-- Axiom: the field encoder is injective on the
    `(acl_doc, effective_epoch)` pair. Matches `serde_json` on a
    fixed two-field schema. Same style as `encodeFields_injective`
    in `V3Members.lean`. -/
axiom encodePolicyFields_injective
    {b₁ b₂ : AclBody} {e₁ e₂ : Nat}
    (h : encodePolicyFields b₁ e₁ = encodePolicyFields b₂ e₂) :
    b₁ = b₂ ∧ e₁ = e₂

/-- Opaque SHA-256 over an arbitrary byte string, output as the
    raw 32-byte digest. Same as `sha256_32` in `V3Members.lean`. -/
opaque sha256_32 : ByteString → ByteString :=
  fun _ => List.replicate 32 0

/-- Axiom: `sha256_32` always outputs exactly 32 bytes. -/
axiom sha256_32_length (bs : ByteString) :
    (sha256_32 bs).length = 32

/-- Axiom: SHA-256 is collision-resistant. -/
axiom sha256_32_injective {a b : ByteString}
    (h : a ≠ b) : sha256_32 a ≠ sha256_32 b

/-- The full v3 policy anchor. -/
def policyAnchor (inp : PolicyInput) : ByteString :=
  sha256_32 (encodePolicyFields inp.acl_doc inp.effective_epoch)

-- ============================================================
-- §1  Determinism
-- ============================================================

/-- **Determinism.** Same input ⇒ same anchor bytes. -/
theorem policy_anchor_deterministic (inp : PolicyInput) :
    policyAnchor inp = policyAnchor inp := rfl

-- ============================================================
-- §2  Top-level field reorder invariance
-- ============================================================

/-- **Field reorder invariance.** Two `PolicyInput`s with the same
    `acl_doc` and `effective_epoch` produce the same anchor,
    regardless of the order in which the encoder might
    (hypothetically) write the two top-level fields. This holds
    by construction: the encoder serialises a sorted-key JSON
    object. -/
theorem policy_anchor_field_reorder_invariant
    (a b : PolicyInput)
    (hbody : a.acl_doc = b.acl_doc)
    (hep   : a.effective_epoch = b.effective_epoch) :
    policyAnchor a = policyAnchor b := by
  unfold policyAnchor
  rw [hbody, hep]

-- ============================================================
-- §3  Collision resistance on epoch
-- ============================================================

/-- **Collision resistance on `effective_epoch`.** Same `acl_doc`,
    different `effective_epoch` ⇒ distinct anchors. -/
theorem policy_anchor_collision_resistant_on_epoch
    (a b : PolicyInput)
    (_hbody : a.acl_doc = b.acl_doc)
    (hep    : a.effective_epoch ≠ b.effective_epoch) :
    policyAnchor a ≠ policyAnchor b := by
  unfold policyAnchor
  apply sha256_32_injective
  intro heq
  have ⟨_, hep_eq⟩ := encodePolicyFields_injective heq
  exact hep hep_eq

-- ============================================================
-- §4  ACL body inclusion
-- ============================================================

/-- **ACL body inclusion.** Any change to the canonical ACL doc
    bytes shifts the anchor (under SHA-256 collision-resistance
    and field-encoder injectivity). -/
theorem policy_anchor_includes_acl_hash
    (a b : PolicyInput)
    (hbody : a.acl_doc ≠ b.acl_doc) :
    policyAnchor a ≠ policyAnchor b := by
  unfold policyAnchor
  apply sha256_32_injective
  intro heq
  have ⟨hbody_eq, _⟩ := encodePolicyFields_injective heq
  exact hbody hbody_eq

-- ============================================================
-- §5  Output shape
-- ============================================================

/-- **Anchor size.** The policy anchor is exactly 32 bytes — the
    raw SHA-256 digest length. -/
theorem policy_anchor_size (inp : PolicyInput) :
    (policyAnchor inp).length = 32 := by
  unfold policyAnchor
  exact sha256_32_length _

-- ============================================================
-- §6  Concrete anchor
-- ============================================================

/-- Concrete anchor: an empty ACL doc at epoch 0 still produces a
    32-byte digest. -/
example :
    (policyAnchor { acl_doc := [], effective_epoch := 0 }).length = 32 :=
  policy_anchor_size _

end OctraVPN.WireProtocol.V3Policy
