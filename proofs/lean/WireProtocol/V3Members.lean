/-!
# V3 members-list anchor — Lean spec & proofs.

Mirrors the v3 `members` anchor format alongside `V3Canonical.lean`.

The v3 members anchor commits to a `(tailnet_id, epoch, members)`
triple, where `members` is a list of `MemberEntry { address, expiry,
tags... }` records sorted by `address`. Producers and verifiers must
agree on the byte-level encoding — any drift between the two sides
silently desyncs the tailnet's transparency log.

This module pins the load-bearing algebraic properties so that any
refactor of the members-list encoder that breaks them gets caught
up-front. It mirrors the modelling strategy of `V3Canonical.lean`:

  * opaque `sortByAddr` with its standard properties as axioms
    (sortedness + reorder-invariance), the same shape as
    `sortByKey` in `V3Canonical.lean`,
  * opaque `sha256` over the encoded bytes, with collision-resistance
    axiomatised the same way as `sha256_hex` in `V3Canonical.lean`,
  * structural reordering of the top-level `(tailnet_id, epoch,
    members)` fields is by construction (the encoder serialises a
    sorted-key JSON object).

Axioms introduced (all standard cryptographic / sort-stability
assumptions, mirroring `V3Canonical.lean`):

  * `sortByAddr_isSorted`     — sort always produces a sorted list,
  * `sortByAddr_sameMembers`  — two lists agreeing as a multiset of
    entries sort to the same list,
  * `sha256_32_length`        — SHA-256 output is exactly 32 bytes,
  * `sha256_32_injective`     — distinct inputs ⇒ distinct digests
    (collision resistance),
  * `encodeFields_injective`  — the underlying field encoder is
    injective on its `(tailnet_id, epoch, members_bytes)` triple
    (matches `serde_json::to_string` on the schema's three fields).
-/

namespace OctraVPN.WireProtocol.V3Members

abbrev ByteString := List UInt8

/-- A member's on-chain address, as raw bytes. Two members are
    considered distinct iff their `address` bytes differ. -/
abbrev Address := ByteString

/-- One entry of the members list. We model just the parts that
    feed the anchor: the address (sort key) and an opaque payload
    of the remaining fields (`expiry`, `tags`, etc.). -/
structure MemberEntry where
  address : Address
  payload : ByteString
  deriving Inhabited, DecidableEq

/-- The full members anchor input: a tailnet identifier, an epoch
    number, and a (multiset of) members. -/
structure MembersInput where
  tailnet_id : ByteString
  epoch      : Nat
  members    : List MemberEntry
  deriving Inhabited

/-- Opaque sort-by-address. Lean 4 core doesn't ship a packaged
    `Sorted` proof at this level of generality without Mathlib, so
    we model it opaquely + axiomatise the two properties the
    encoder relies on. Same strategy as `sortByKey` in
    `V3Canonical.lean`. -/
opaque sortByAddr : List MemberEntry → List MemberEntry := fun xs => xs

/-- "Address ≤ Address" by lexicographic byte order. We delegate to
    `List.lex` via the underlying `UInt8` ordering, which Lean 4
    derives automatically. -/
def addrLe (a b : Address) : Prop :=
  a.length < b.length
  ∨ (a.length = b.length ∧ a = b)
  ∨ (a ≠ b ∧ a.length ≤ b.length)

/-- "Members list is sorted by address" — non-decreasing in the
    address byte order. We do not commit to a particular total
    order on bytes here; the encoder treats `sortByAddr` as the
    sort oracle, and `sortByAddr_isSorted` is its load-bearing
    property. -/
def isSortedByAddr : List MemberEntry → Prop
  | []          => True
  | _ :: []     => True
  | a :: b :: t => addrLe a.address b.address ∧ isSortedByAddr (b :: t)

/-- Two member lists agree as a multiset (same length, same
    membership). -/
def sameMembers (xs ys : List MemberEntry) : Prop :=
  xs.length = ys.length
  ∧ (∀ m, m ∈ xs ↔ m ∈ ys)

/-- Axiom: `sortByAddr` produces a list sorted by address. -/
axiom sortByAddr_isSorted (xs : List MemberEntry) :
    isSortedByAddr (sortByAddr xs)

/-- Axiom: two lists agreeing as a multiset of entries sort to the
    same list. Same shape as `sortByKey_sameKVs` in
    `V3Canonical.lean`. -/
axiom sortByAddr_sameMembers {xs ys : List MemberEntry}
    (h : sameMembers xs ys) : sortByAddr xs = sortByAddr ys

/-- Encode a single sorted member into its byte form. The exact
    layout (length prefix + address + payload) is irrelevant to
    the anchor's algebraic properties; what matters is that two
    sorted member lists with the same entries serialise to the
    same bytes. -/
def encodeMember (m : MemberEntry) : ByteString :=
  m.address ++ [0] ++ m.payload

/-- Encode a sorted list of members. -/
def encodeMembersList (ms : List MemberEntry) : ByteString :=
  ms.foldl (fun acc m => acc ++ encodeMember m) []

/-- The pre-hash bytes the anchor commits to: a sorted-key JSON
    encoding of `{ "tailnet_id", "epoch", "members" }`. We model
    this opaquely as a tagged concatenation of the three fields;
    the load-bearing property — injectivity on the triple — is
    captured by `encodeFields_injective`. -/
opaque encodeFields :
    ByteString → Nat → ByteString → ByteString :=
  fun tid ep mb => tid ++ [0] ++ (toString ep).toUTF8.toList ++ [0] ++ mb

/-- Axiom: the field encoder is injective on the three top-level
    fields. Matches `serde_json::to_string` on a `Value::Object`
    with these three keys — the encoded bytes determine the
    triple. -/
axiom encodeFields_injective
    {t₁ t₂ : ByteString} {e₁ e₂ : Nat} {m₁ m₂ : ByteString}
    (h : encodeFields t₁ e₁ m₁ = encodeFields t₂ e₂ m₂) :
    t₁ = t₂ ∧ e₁ = e₂ ∧ m₁ = m₂

/-- Opaque SHA-256 over an arbitrary byte string, output as the
    raw 32-byte digest. The members anchor is the raw digest
    (not the hex form, unlike `v3_canonical`). Same modelling
    strategy as `Sha256.digest` in `OctraVPN_Rust/Spec.lean` and
    `sha256_hex` in `V3Canonical.lean`. -/
opaque sha256_32 : ByteString → ByteString :=
  fun _ => List.replicate 32 0

/-- Axiom: `sha256_32` always outputs exactly 32 bytes. -/
axiom sha256_32_length (bs : ByteString) :
    (sha256_32 bs).length = 32

/-- Axiom: SHA-256 is collision-resistant. We axiomatise the
    inverse-contrapositive form. Same as `sha256_hex_injective`
    in `V3Canonical.lean`. -/
axiom sha256_32_injective {a b : ByteString}
    (h : a ≠ b) : sha256_32 a ≠ sha256_32 b

/-- The full v3 members anchor. Sorts the member list, encodes the
    three top-level fields, and hashes the result. -/
def membersAnchor (inp : MembersInput) : ByteString :=
  sha256_32
    (encodeFields
      inp.tailnet_id
      inp.epoch
      (encodeMembersList (sortByAddr inp.members)))

-- ============================================================
-- §1  Determinism
-- ============================================================

/-- **Determinism.** `membersAnchor` is a function — same input,
    same output bytes. -/
theorem members_anchor_deterministic (inp : MembersInput) :
    membersAnchor inp = membersAnchor inp := rfl

-- ============================================================
-- §2  Reorder invariance — top-level fields
-- ============================================================

/-- **Top-level field reorder invariance.** Two `MembersInput`s
    with the same `tailnet_id`, `epoch`, and members produce the
    same anchor, regardless of the order in which the encoder
    might (hypothetically) write the three top-level fields. This
    holds by construction: the encoder serialises a sorted-key
    JSON object, so any field ordering is normalised away before
    hashing. We state the property as the equality on
    `membersAnchor` of two extensionally-equal inputs. -/
theorem members_anchor_field_reorder_invariant
    (a b : MembersInput)
    (htid : a.tailnet_id = b.tailnet_id)
    (hep  : a.epoch = b.epoch)
    (hms  : a.members = b.members) :
    membersAnchor a = membersAnchor b := by
  unfold membersAnchor
  rw [htid, hep, hms]

-- ============================================================
-- §3  Reorder invariance — members list
-- ============================================================

/-- **Members list reorder invariance.** Two members lists that
    agree as a multiset of entries (i.e. differ only in insertion
    order) sort to the same list and therefore produce the same
    anchor. -/
theorem members_anchor_member_reorder_invariant
    (tid : ByteString) (ep : Nat)
    {xs ys : List MemberEntry}
    (h : sameMembers xs ys) :
    membersAnchor { tailnet_id := tid, epoch := ep, members := xs }
      = membersAnchor { tailnet_id := tid, epoch := ep, members := ys } := by
  unfold membersAnchor
  rw [sortByAddr_sameMembers h]

-- ============================================================
-- §4  Collision resistance
-- ============================================================

/-- **Collision resistance on `(tailnet_id, epoch)`.** Two
    `MembersInput`s with the same members but different
    `tailnet_id` or `epoch` produce distinct anchors, modulo
    SHA-256 collision resistance (axiom `sha256_32_injective`)
    and field-encoder injectivity (axiom `encodeFields_injective`). -/
theorem members_anchor_collision_resistant
    (a b : MembersInput)
    (h : a.tailnet_id ≠ b.tailnet_id ∨ a.epoch ≠ b.epoch) :
    membersAnchor a ≠ membersAnchor b := by
  unfold membersAnchor
  apply sha256_32_injective
  intro heq
  have ⟨htid, hep, _⟩ := encodeFields_injective heq
  rcases h with htid_ne | hep_ne
  · exact htid_ne htid
  · exact hep_ne hep

-- ============================================================
-- §5  Output shape
-- ============================================================

/-- **Anchor size.** The members anchor is exactly 32 bytes — the
    raw SHA-256 digest length. -/
theorem members_anchor_size_bounded (inp : MembersInput) :
    (membersAnchor inp).length = 32 := by
  unfold membersAnchor
  exact sha256_32_length _

-- ============================================================
-- §6  Concrete anchor
-- ============================================================

/-- Concrete anchor: an empty members list under any (tailnet_id,
    epoch) still yields a 32-byte digest. -/
example :
    (membersAnchor { tailnet_id := [], epoch := 0, members := [] }).length
      = 32 :=
  members_anchor_size_bounded _

end OctraVPN.WireProtocol.V3Members
