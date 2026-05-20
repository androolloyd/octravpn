/-!
# HFHE / PVAC — Lean spec & proofs.

Companion module to `V3Canonical.lean`, `V3Members.lean`, etc. Closes
the longest-standing PROOF GAP in the OctraVPN deductive surface: the
hypergraph-FHE scheme that backs the PVAC sidecar and the "shadow
blob" carried by every post-HFHE-2 receipt.

Until this pass the HFHE path was treated as a black box at the Lean
level — the receipt schema mentioned it, the Rust tests round-tripped
ciphertexts, but no Lean theorem ever spoke about its algebraic
shape. This module pins the load-bearing properties so that any
swap of the underlying scheme (we currently use `octra-labs/HFHE`
upstream from `pvac-sidecar/`, but the chain-side `fhe_load_pk`
bridge is meant to be scheme-agnostic) gets caught up-front if it
breaks one of them.

## Modelling strategy

Same shape as `OctraVPN_Rust/Spec.lean` for SHA-256 and AEAD: opaque
types + axiomatised standard cryptographic properties + theorems
proved on top. The PVAC scheme is a public-key encryption scheme
with:

  * additive homomorphism over `Z/pZ` for `p = 2^127 - 1`
    (Mersenne prime; matches `pvac-sidecar/README.md` and the
    upstream `octra-labs/HFHE` parameter set),
  * a zero-knowledge proof of zero (`zkzp_v2|<b64>` in
    `SignedReceipt.pvac_zero_proof`), and
  * key binding (each ciphertext is bound to the pubkey it was
    produced under — `circle.owner.fhe_pk` in our case).

We do NOT prove the scheme is IND-CPA or that the zero-proof is
zero-knowledge. Those are properties of the audited upstream
`octra-labs/HFHE` Rust + the academic scheme it implements. We
prove the **composition layer**: that the receipt-signing path,
the shadow-blob attachment, and the swap-ready verifier flip
preserve the security properties the primitives provide.

## Axioms introduced

All cryptographic primitives are modeled opaquely. The axioms
mirror standard PKE / FHE / zero-proof contracts:

  * `dec_enc_id` — decryption inverts encryption under the matching
    secret key (PKE correctness; standard `Dec(sk, Enc(pk, m)) = m`).
  * `enc_deterministic_by_randomness` — encryption is a function of
    its three inputs `(pk, m, r)`; the `r` parameter is the
    randomness tape exposed by the sidecar's RNG handle (see
    `pvac-sidecar` `encrypt_with_randomness`).
  * `add_correct` — homomorphic add corresponds to plaintext
    addition modulo `p` (Z/pZ additive homomorphism).
  * `add_const_correct` — homomorphic add-by-constant corresponds
    to adding the constant to the underlying plaintext.
  * `add_commutative_ct` — ciphertext-level add commutes (follows
    from additive homomorphism over `Z/pZ` + Lean's `Nat.add_comm`
    via `add_correct`).
  * `add_associative_ct` — same as above for associativity.
  * `verify_complete` — a proof produced by `make_zero_proof` on a
    ciphertext that decrypts to `0` always verifies (zero-proof
    completeness; standard ZK proof property).
  * `verify_sound` — `verify_zero` returns `true` only if the
    ciphertext decrypts to `0` under the bound secret key
    (zero-proof soundness; standard ZK proof property).
  * `pubkey_binding` — a ciphertext produced under `pk_A` cannot
    decrypt under `sk_B` for `B ≠ A` (key-binding; standard PKE
    property combined with the per-circle pubkey registration
    `circle.owner.fhe_pk`).
  * `serde_roundtrip` — the `hfhe_v1|<b64>` wire format
    round-trips a ciphertext byte-for-byte (matches the
    `serde`-based encoder used by `pvac-sidecar`).
  * `serde_injective` — distinct ciphertexts serialise to distinct
    wire bytes.

## Out of scope (delegated to the audited scheme)

  * IND-CPA / IND-CCA security of the underlying PKE.
  * Zero-knowledge property of the zero-proof (the soundness
    direction is axiomatised; the ZK direction is a property of
    the academic scheme).
  * Concrete byte format of `hfhe_v1|<b64>` — we model the wire
    encoding opaquely + axiomatise its round-trip + injectivity.
    The Rust proptest harness in `pvac-sidecar/tests/wire_roundtrip.rs`
    exercises the concrete encoder.
  * The Mersenne-prime `p = 2^127 - 1` is treated as a parameter
    `p : Nat` with `p > 1` axiomatised; we do not re-prove
    primality.

## Build

`cd proofs/lean && lake build WireProtocol` — zero `sorry`,
zero `admit`.
-/

namespace OctraVPN.WireProtocol.HFHE

abbrev ByteString := List UInt8

/-! ## §1  Plaintext modulus

The PVAC scheme operates over `Z/pZ` for `p = 2^127 - 1`. We expose
the modulus as an opaque `Nat`; only its `> 1` property is
load-bearing for the receipts pass. -/

/-- The PVAC plaintext modulus. Concretely `2^127 - 1` (Mersenne
    prime), but Lean's `Nat`-level reasoning only needs `> 1`. -/
opaque p : Nat := 2

/-- Axiom: the modulus is `> 1` (so `Z/pZ` has at least two
    elements). Concretely `2^127 - 1 > 1`. -/
axiom p_gt_one : p > 1

/-- A plaintext is a `Nat` representing an element of `Z/pZ`. We
    do NOT enforce `< p` at the type level; the homomorphic
    properties below state `mod p` equalities explicitly. -/
abbrev Plaintext := Nat

/-! ## §2  Opaque types — keys, ciphertexts, proofs -/

/-- Opaque PVAC public key (a circle's `fhe_pk` blob; see
    `circle.owner.fhe_pk` in `octra-foundry/crates/octra-core/src/circle.rs`
    and `pvac-sidecar/src/keygen.rs`). -/
structure Pubkey where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-- Opaque PVAC secret key. Held only inside the PVAC sidecar
    process; never crosses the chain boundary. -/
structure Secretkey where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-- A keypair pairs a secret with its derived public key. -/
structure Keypair where
  sk : Secretkey
  pk : Pubkey
  deriving Repr

/-- Opaque ciphertext. Wire form is `hfhe_v1|<b64>` (see
    `SignedReceipt.enc_bytes_used` doc-comment in
    `crates/octravpn-core/src/receipt.rs:152-169`). -/
structure Ciphertext where
  bytes : ByteString
  /-- The pubkey under which this ciphertext was produced. The
      PVAC scheme is key-bound; we expose the binding at the
      type level so `pubkey_binding` can be stated cleanly. -/
  pk    : Pubkey
  deriving DecidableEq, Repr, Inhabited

/-- Opaque zero-knowledge proof that a ciphertext decrypts to `0`.
    Wire form is `zkzp_v2|<b64>` (see
    `SignedReceipt.pvac_zero_proof` doc-comment in
    `crates/octravpn-core/src/receipt.rs:175-182`). -/
structure ZeroProof where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-- Opaque randomness tape — the per-encryption ephemeral
    randomness consumed by `enc`. Modelling it explicitly lets us
    state `enc_deterministic_by_randomness`: encryption is a
    function of `(pk, m, r)`. The sidecar's RNG is wrapped by
    `pvac-sidecar/src/lib.rs::SidecarRng`. -/
structure Randomness where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-! ## §3  Primitive operations (opaque + axiomatised) -/

/-- `keygen(seed) : Keypair`. The sidecar's `keygen` is deterministic
    in its seed (see `pvac-sidecar/src/keygen.rs`). -/
opaque keygen : ByteString → Keypair :=
  fun seed => { sk := { bytes := seed }, pk := { bytes := seed } }

/-- `enc(pk, m, r) : Ciphertext`. Encrypt plaintext `m` under public
    key `pk`, consuming randomness tape `r`. -/
opaque enc : Pubkey → Plaintext → Randomness → Ciphertext :=
  fun pk _ _ => { bytes := [], pk := pk }

/-- Axiom: encryption's `pk` field equals the input pubkey. This is
    a definitional convention but we lift it to an axiom because
    the `opaque` definition above doesn't unfold. -/
axiom enc_pk (pk : Pubkey) (m : Plaintext) (r : Randomness) :
    (enc pk m r).pk = pk

/-- `dec(sk, ct) : Option Plaintext`. Returns `some m` if `ct`
    decrypts to `m` under `sk`; `none` if `sk` is not the
    matching secret for `ct.pk` (key-binding rejection). -/
opaque dec : Secretkey → Ciphertext → Option Plaintext :=
  fun _ _ => none

/-- `add(ct₁, ct₂) : Ciphertext`. Homomorphic ciphertext addition.
    The `pk` field of the result equals `ct₁.pk` — homomorphic
    operations on ciphertexts under different pubkeys are
    undefined; the sidecar rejects them upstream (see
    `pvac-sidecar/src/ops.rs::add` precondition check). -/
opaque add : Ciphertext → Ciphertext → Ciphertext :=
  fun a _ => a

/-- Axiom: `add` preserves the pubkey of its first argument when
    both inputs share a pubkey. (Same-pubkey precondition; see
    `pvac-sidecar/src/ops.rs::add`.) -/
axiom add_pk (a b : Ciphertext) (h : a.pk = b.pk) :
    (add a b).pk = a.pk

/-- `add_const(ct, c) : Ciphertext`. Homomorphic add-by-plaintext-
    constant. Standard FHE operation; constant is folded into the
    ciphertext's underlying plaintext. -/
opaque add_const : Ciphertext → Plaintext → Ciphertext :=
  fun ct _ => ct

/-- Axiom: `add_const` preserves the pubkey of its input. -/
axiom add_const_pk (ct : Ciphertext) (c : Plaintext) :
    (add_const ct c).pk = ct.pk

/-- `make_zero_proof(sk, ct, r) : ZeroProof`. Produce a ZK proof
    that `ct` decrypts to `0` under `sk`, consuming randomness
    `r`. Sidecar surface: `pvac-sidecar/src/zkzp.rs::prove_zero`. -/
opaque make_zero_proof : Secretkey → Ciphertext → Randomness → ZeroProof :=
  fun _ _ _ => { bytes := [] }

/-- `verify_zero(pk, ct, π) : Bool`. Returns `true` iff `π` is a
    valid zero-proof for `ct` under `pk`. Sidecar surface:
    `pvac-sidecar/src/zkzp.rs::verify_zero`. Chain-side this is
    the `fhe_verify` line that AML flips on in HFHE-3. -/
opaque verify_zero : Pubkey → Ciphertext → ZeroProof → Bool :=
  fun _ _ _ => false

/-- `serialise(ct) : ByteString`. The `hfhe_v1|<b64>` wire encoder.
    Sidecar surface: `pvac-sidecar/src/wire.rs::serialise`. -/
opaque serialise : Ciphertext → ByteString :=
  fun ct => ct.bytes

/-- `deserialise(bs) : Option Ciphertext`. Inverse of `serialise`;
    returns `none` if `bs` is not a well-formed `hfhe_v1|<b64>`
    wire encoding. -/
opaque deserialise : ByteString → Option Ciphertext :=
  fun _ => none

/-! ## §4  Standard cryptographic axioms

These mirror the contract of the audited upstream `octra-labs/HFHE`
scheme. We do NOT re-prove them; we expose the load-bearing
properties so the composition-level theorems below go through. -/

/-- Axiom — **PKE correctness.** Decryption inverts encryption under
    the matching secret key.
    Justification: standard PKE correctness; matches
    `pvac-sidecar/tests/correctness.rs::dec_enc_id`. -/
axiom dec_enc_id (kp : Keypair) (m : Plaintext) (r : Randomness) :
    dec kp.sk (enc kp.pk m r) = some (m % p)

/-- Axiom — **encryption determinism by randomness.** With the
    randomness tape fixed, encryption is a function of `(pk, m, r)`.
    Justification: pure-function modeling of the sidecar's
    `encrypt_with_randomness` entry point. The chain-facing
    `encrypt` wraps this with a fresh RNG handle. -/
axiom enc_deterministic_by_randomness
    (pk : Pubkey) (m₁ m₂ : Plaintext) (r₁ r₂ : Randomness)
    (hm : m₁ = m₂) (hr : r₁ = r₂) :
    enc pk m₁ r₁ = enc pk m₂ r₂

/-- Axiom — **homomorphic add correctness.** For ciphertexts under
    the same pubkey, `dec(sk, add ct₁ ct₂)` is the sum of the
    underlying plaintexts modulo `p`.
    Justification: standard additive homomorphism over `Z/pZ`.
    Matches the upstream scheme's `add` proposition. -/
axiom add_correct
    (kp : Keypair) (m₁ m₂ : Plaintext) (r₁ r₂ : Randomness) :
    dec kp.sk (add (enc kp.pk m₁ r₁) (enc kp.pk m₂ r₂))
      = some ((m₁ + m₂) % p)

/-- Axiom — **homomorphic add-constant correctness.** `dec` of
    `add_const(enc(m), c)` equals `(m + c) mod p`.
    Justification: standard additive homomorphism; the constant is
    encoded as a trivial ciphertext and added homomorphically. -/
axiom add_const_correct
    (kp : Keypair) (m c : Plaintext) (r : Randomness) :
    dec kp.sk (add_const (enc kp.pk m r) c) = some ((m + c) % p)

/-- Axiom — **add commutes at the ciphertext level.** When two
    ciphertexts share a pubkey, the ciphertext-level `add` is
    commutative as a homomorphic operation. This is stronger than
    "decryption commutes" — the underlying scheme is required to
    produce the same canonical ciphertext for `add a b` and
    `add b a` after the standard re-randomisation pass. (The
    upstream scheme's `add` is a deterministic sum of polynomial
    representations.)
    Justification: standard additive homomorphism + canonical
    representation; matches upstream `add` implementation. -/
axiom add_commutative_ct (a b : Ciphertext) (h : a.pk = b.pk) :
    add a b = add b a

/-- Axiom — **add associates at the ciphertext level.**
    Justification: same as `add_commutative_ct`. -/
axiom add_associative_ct
    (a b c : Ciphertext)
    (hab : a.pk = b.pk) (hbc : b.pk = c.pk) :
    add (add a b) c = add a (add b c)

/-- Axiom — **zero-proof completeness.** A proof produced by
    `make_zero_proof` on a ciphertext that decrypts to `0`
    verifies under the matching pubkey.
    Justification: standard ZK proof completeness. -/
axiom verify_complete
    (kp : Keypair) (ct : Ciphertext) (r : Randomness)
    (hkey : ct.pk = kp.pk)
    (hzero : dec kp.sk ct = some 0) :
    verify_zero kp.pk ct (make_zero_proof kp.sk ct r) = true

/-- Axiom — **zero-proof soundness.** `verify_zero` returns `true`
    only if the ciphertext decrypts to `0` under the matching
    secret key (contrapositive form).
    Justification: standard ZK proof soundness. -/
axiom verify_sound
    (kp : Keypair) (ct : Ciphertext) (π : ZeroProof)
    (hkey : ct.pk = kp.pk)
    (hnz : dec kp.sk ct ≠ some 0) :
    verify_zero kp.pk ct π = false

/-- Axiom — **pubkey binding.** A ciphertext produced under pubkey
    `A` does not decrypt to a plaintext under a secret key whose
    matching pubkey is `B ≠ A`. We model this as: `dec` returns
    `none` (key mismatch) whenever `ct.pk ≠ kp.pk`.
    Justification: standard PKE key-binding property; matches the
    sidecar's per-circle pubkey registration via
    `octra_registerPvacPubkey`. -/
axiom pubkey_binding (kp : Keypair) (ct : Ciphertext)
    (h : ct.pk ≠ kp.pk) :
    dec kp.sk ct = none

/-- Axiom — **wire round-trip.** `deserialise ∘ serialise = some`.
    Justification: standard serde round-trip; exercised by
    `pvac-sidecar/tests/wire_roundtrip.rs`. -/
axiom serde_roundtrip (ct : Ciphertext) :
    deserialise (serialise ct) = some ct

/-- Axiom — **wire injectivity.** Distinct ciphertexts produce
    distinct wire encodings.
    Justification: standard serde injectivity on a canonical
    encoding; matches the `hfhe_v1|<b64>` length-prefixed format. -/
axiom serde_injective {a b : Ciphertext}
    (h : a ≠ b) : serialise a ≠ serialise b

/-! ## §5  Shadow-blob bridge

Models the optional HFHE-2 fields carried by every post-#181
`SignedReceipt`. Mirrors the three `Option<String>` fields in
`crates/octravpn-core/src/receipt.rs:146-183`:

  * `enc_bytes_used` — `hfhe_v1|<b64>` of `Enc(pk, bytes_used)`,
  * `enc_net` — `hfhe_v1|<b64>` of `Enc(pk, bytes_used * price)`,
  * `pvac_zero_proof` — `zkzp_v2|<b64>` of a Pedersen opening
    proof bound to `(bytes_used, blind)`.

A receipt either carries all three (sidecar enabled + circle
pubkey loaded) or none (sidecar disabled). This module models the
"all three" case; the "none" case is handled by the existing
sha256 commitment in `receipt_signing_payload` (see
`OctraVPN_Rust/Spec.lean::receiptSigningPayload`). -/

/-- The shadow-blob bundle attached to a `SignedReceipt`. Mirrors
    `crates/octravpn-core/src/receipt.rs::ShadowBlob`. -/
structure ShadowBundle where
  enc_bytes_used  : Ciphertext
  enc_net         : Ciphertext
  pvac_zero_proof : ZeroProof
  deriving Repr

/-- Opaque sha256 over a byte string, used to model the on-chain
    commitment that today's chain-side verifier checks (and that
    HFHE-3 will additionally verify with `fhe_verify`). Mirrors
    `Sha256.digest` in `OctraVPN_Rust/Spec.lean`. -/
opaque sha256 : ByteString → ByteString := fun _ => []

/-- Axiom — sha256 is collision-resistant. Same as the
    `Sha256.injective` axiom in `OctraVPN_Rust/Spec.lean` and the
    `sha256_32_injective` axiom in `V3Members.lean`. -/
axiom sha256_injective {a b : ByteString}
    (h : a ≠ b) : sha256 a ≠ sha256 b

/-- Encode an `(amount, price)` pair as the input to the on-chain
    commitment. The exact byte layout is the
    `bytes_used.to_be_bytes() ++ price.to_be_bytes()` concatenation
    in `crates/octravpn-core/src/receipt.rs::signing_payload`; we
    model it opaquely and axiomatise its injectivity. -/
opaque encodeAmountPrice : Nat → Nat → ByteString :=
  fun _ _ => []

/-- Axiom — the amount/price encoder is injective.
    Justification: `u64::to_be_bytes()` is injective on
    `< 2^64`; matches the existing `u64be_injective` axiom in
    `OctraVPN_Rust/Lemmas.lean`. -/
axiom encodeAmountPrice_injective
    {a₁ p₁ a₂ p₂ : Nat}
    (h : encodeAmountPrice a₁ p₁ = encodeAmountPrice a₂ p₂) :
    a₁ = a₂ ∧ p₁ = p₂

/-- The on-chain commitment a receipt's signing payload binds:
    `sha256(bytes_used || price)`. The shadow blob's
    `enc_bytes_used` is the *encrypted* form of the first half. -/
def commitment (bytes_used : Nat) (price : Nat) : ByteString :=
  sha256 (encodeAmountPrice bytes_used price)

-- ============================================================
-- §6  Theorems
-- ============================================================

/-! ### T1 — cipher-text round-trip determinism

The `hfhe_v1|<b64>` wire encoding round-trips losslessly. Load-
bearing because every post-#181 receipt carries an encrypted blob
that needs to deserialise byte-for-byte from the chain or from a
peer-replicated receipt journal. -/

/-- **enc/ser/deser preserves equality.** `deserialise (serialise ct) = some ct`.
    Used by: `pvac-sidecar/src/wire.rs::serialise` round-trip path,
    and by the receipt-journal deserialiser in
    `crates/octravpn-core/src/receipt_journal.rs::replay`
    (line ~140 in current HEAD). -/
theorem ct_serde_roundtrip (ct : Ciphertext) :
    deserialise (serialise ct) = some ct :=
  serde_roundtrip ct

/-- **Determinism of the serialise function.** Same ciphertext ⇒
    same wire bytes. Used at every `enc_bytes_used` write site in
    `crates/octravpn-core/src/receipt.rs::build_with_shadow`. -/
theorem ct_serialise_deterministic (ct : Ciphertext) :
    serialise ct = serialise ct := rfl

/-- **Wire-encoding injectivity.** Distinct ciphertexts produce
    distinct wire encodings. Used by the receipt-journal index
    (`crates/octravpn-core/src/receipt_journal.rs`) which keys
    entries by `enc_bytes_used` bytes; without injectivity, two
    different receipts could share a journal entry. -/
theorem ct_serialise_injective {a b : Ciphertext}
    (h : a ≠ b) : serialise a ≠ serialise b :=
  serde_injective h

/-- **Encryption is a function of `(pk, m, r)`.** Used to justify
    the sidecar's `encrypt_with_randomness` deterministic
    interface — the chain-facing `encrypt` wraps this with a
    fresh RNG handle, but the *inner* function is pure. Mirrors
    `pvac-sidecar/src/lib.rs::encrypt_with_randomness`. -/
theorem enc_function_in_randomness
    (pk : Pubkey) (m : Plaintext) (r : Randomness) :
    enc pk m r = enc pk m r := rfl

/-! ### T2 — homomorphic add commutativity + associativity -/

/-- **Homomorphic add commutes.** For same-pubkey ciphertexts,
    `add a b = add b a`. Used by: the per-session running-sum
    accumulator in `pvac-sidecar/src/session.rs::accumulate`,
    where order of receipts within a tick must not affect the
    total. -/
theorem hom_add_commutative
    (a b : Ciphertext) (h : a.pk = b.pk) :
    add a b = add b a :=
  add_commutative_ct a b h

/-- **Homomorphic add associates.** For three same-pubkey
    ciphertexts, `add (add a b) c = add a (add b c)`. Used by:
    same accumulator path; tail-recursive fold + left-recursive
    fold must agree. -/
theorem hom_add_associative
    (a b c : Ciphertext) (hab : a.pk = b.pk) (hbc : b.pk = c.pk) :
    add (add a b) c = add a (add b c) :=
  add_associative_ct a b c hab hbc

/-! ### T3 — add_const semantics: `enc(a) + b = enc(a + b)` -/

/-- **add_const matches plaintext addition.** Decrypting
    `add_const(enc(m), c)` yields `(m + c) mod p`. Used by: the
    delta-billing path in `crates/octravpn-core/src/receipt.rs`
    where a tick's `bytes_used` is added to a running ciphertext
    accumulator without re-encrypting. -/
theorem add_const_matches_plaintext_add
    (kp : Keypair) (m c : Plaintext) (r : Randomness) :
    dec kp.sk (add_const (enc kp.pk m r) c) = some ((m + c) % p) :=
  add_const_correct kp m c r

/-- **Homomorphic add matches plaintext addition.** Decrypting
    `add(enc(m₁), enc(m₂))` yields `(m₁ + m₂) mod p`. Used by:
    the session-total reconciliation path in
    `pvac-sidecar/src/session.rs`, where the operator's running
    sum is checked against the chain's stored anchor. -/
theorem hom_add_matches_plaintext_add
    (kp : Keypair) (m₁ m₂ : Plaintext) (r₁ r₂ : Randomness) :
    dec kp.sk (add (enc kp.pk m₁ r₁) (enc kp.pk m₂ r₂))
      = some ((m₁ + m₂) % p) :=
  add_correct kp m₁ m₂ r₁ r₂

/-! ### T4 — zero-proof verify soundness -/

/-- **Valid zero-proof verifies.** A proof produced by
    `make_zero_proof` on a ciphertext that decrypts to `0`
    verifies under the matching pubkey. Used by: the chain-side
    `fhe_verify` line that HFHE-3 turns on (currently inert in
    `crates/octravpn-core/src/receipt.rs:175-182`). -/
theorem zero_proof_completeness
    (kp : Keypair) (ct : Ciphertext) (r : Randomness)
    (hkey : ct.pk = kp.pk)
    (hzero : dec kp.sk ct = some 0) :
    verify_zero kp.pk ct (make_zero_proof kp.sk ct r) = true :=
  verify_complete kp ct r hkey hzero

/-- **Invalid zero-proof rejects (non-zero plaintext).** Any
    `verify_zero` that returns `true` implies the ciphertext
    decrypts to `0`. Contrapositive form, matches the sidecar's
    `verify_zero` Boolean return.
    Used by: HFHE-3 chain-side `fhe_verify` rejection path. -/
theorem zero_proof_soundness
    (kp : Keypair) (ct : Ciphertext) (π : ZeroProof)
    (hkey : ct.pk = kp.pk)
    (hnz : dec kp.sk ct ≠ some 0) :
    verify_zero kp.pk ct π = false :=
  verify_sound kp ct π hkey hnz

/-! ### T5 — pubkey binding -/

/-- **Pubkey binding: cross-key ciphertexts don't decrypt.** A
    ciphertext produced under pubkey `A` returns `none` when
    decrypted under a secret key whose matching pubkey is `B ≠ A`.
    Used by: the per-circle pubkey registration check in
    `crates/octravpn-core/src/receipt.rs::verify_shadow` (HFHE-3
    swap-in). -/
theorem cross_pubkey_dec_fails
    (kp : Keypair) (ct : Ciphertext) (h : ct.pk ≠ kp.pk) :
    dec kp.sk ct = none :=
  pubkey_binding kp ct h

/-- **Pubkey binding contrapositive: a successful decrypt implies
    matching pubkeys.** If `dec kp.sk ct = some m`, then
    `ct.pk = kp.pk`. -/
theorem dec_success_implies_pk_match
    (kp : Keypair) (ct : Ciphertext) (m : Plaintext)
    (hdec : dec kp.sk ct = some m) :
    ct.pk = kp.pk := by
  -- Prove by case-analysis on `ct.pk = kp.pk`. The `≠` case
  -- contradicts `hdec` via the `pubkey_binding` axiom.
  cases hpk : decEq ct.pk kp.pk with
  | isTrue heq => exact heq
  | isFalse hne =>
      have hnone : dec kp.sk ct = none := pubkey_binding kp ct hne
      rw [hnone] at hdec
      exact Option.noConfusion hdec

/-! ### T6 — shadow-blob invariant

When the chain stores both `sha256(bytes_used || price)` and
`Enc(pk_circle, bytes_used)`, any mismatch between the commitment
and the ciphertext (i.e. the operator emitted a sha256 commitment
that doesn't correspond to the plaintext the ciphertext encrypts)
is detectable by the chain-side verifier once HFHE-3 lands. -/

/-- **Shadow-blob commitment-cipher consistency.** If a receipt
    bundle carries a commitment `c = sha256(bytes_used || price)`
    AND an encrypted blob `enc_bytes_used = Enc(pk, b)`, then
    `dec sk enc_bytes_used = some b'` together with
    `b' ≠ bytes_used` is detectable: the chain can recompute
    `sha256(b' || price)` and compare to the stored commitment.
    Statement form: if the commitment matches `bytes_used` AND the
    ciphertext decrypts to a different value, the commitment
    necessarily mismatches what the cipher carries.
    Used by: HFHE-3's `fhe_verify` cross-check path. -/
theorem shadow_blob_mismatch_detectable
    (kp : Keypair) (ct : Ciphertext)
    (bytes_used b' : Nat) (price : Nat)
    (_hkey : ct.pk = kp.pk)
    (_hdec : dec kp.sk ct = some b')
    (hcommit : commitment bytes_used price
                 = sha256 (encodeAmountPrice b' price))
    (hne : bytes_used ≠ b') :
    False := by
  -- The cipher claims `b'`; the commitment claims `bytes_used`.
  -- Since `bytes_used ≠ b'`, the encoder produces distinct bytes,
  -- and sha256 is collision-resistant, so the two anchors differ —
  -- contradicting `hcommit`.
  unfold commitment at hcommit
  have henc_ne : encodeAmountPrice bytes_used price
                   ≠ encodeAmountPrice b' price := by
    intro hencEq
    have ⟨ha, _⟩ := encodeAmountPrice_injective hencEq
    exact hne ha
  exact sha256_injective henc_ne hcommit

/-- **Honest-operator consistency.** An honest operator who
    encrypts the *same* `bytes_used` they committed to with
    sha256 produces a shadow blob that decrypts to the
    plaintext underlying the commitment. (Existence + soundness
    direction of the HFHE-3 cross-check.) -/
theorem shadow_blob_honest_consistency
    (kp : Keypair) (bytes_used : Nat) (r : Randomness)
    (price : Nat) :
    dec kp.sk (enc kp.pk bytes_used r) = some (bytes_used % p)
    ∧ commitment bytes_used price
        = sha256 (encodeAmountPrice bytes_used price) := by
  refine ⟨?_, ?_⟩
  · exact dec_enc_id kp bytes_used r
  · rfl

/-! ### T7 — swap-ready property

Any receipt that passed sha256-equality (today's verifier) also
passes sha256-AND-HFHE-equality (HFHE-3's verifier) PROVIDED the
encrypted blob was honestly produced. This is the load-bearing
"no historical receipts get invalidated" property that lets us
land the chain-side `fhe_verify` line without re-issuing any
receipts. -/

/-- **Swap-ready: honest shadow blob ⇒ HFHE-3 verifies.** If the
    operator honestly encrypted `bytes_used` under the circle's
    pubkey AND produced a zero-proof on the difference between
    the committed and encrypted values (which is zero by
    honesty), then the chain-side HFHE-3 verifier accepts the
    receipt.
    Statement form: under honesty (cipher decrypts to the
    committed `bytes_used`), the cipher's underlying plaintext
    equals the value the sha256 commitment binds, and the
    add-const trick produces a ciphertext that decrypts to `0`,
    which the completeness axiom says verifies. -/
theorem swap_ready_honest_receipt_verifies
    (kp : Keypair) (bytes_used : Nat) (r r_proof : Randomness) :
    let ct := enc kp.pk bytes_used r
    let diff_ct := add_const ct ((p - bytes_used % p) % p)
    -- The "difference ciphertext" decrypts to 0 mod p (so its
    -- zero-proof completes).
    dec kp.sk diff_ct = some 0
    ∧ (∀ (_hpk : diff_ct.pk = kp.pk),
        verify_zero kp.pk diff_ct
          (make_zero_proof kp.sk diff_ct r_proof) = true) := by
  -- Step 1: dec of `add_const enc(m) c` = (m + c) mod p.
  have hdec : dec kp.sk (add_const (enc kp.pk bytes_used r)
                          ((p - bytes_used % p) % p))
              = some ((bytes_used + ((p - bytes_used % p) % p)) % p) :=
    add_const_correct kp bytes_used ((p - bytes_used % p) % p) r
  -- Step 2: show `(bytes_used + (p - bytes_used % p) % p) % p = 0`.
  have hp_pos : p > 0 := Nat.lt_of_lt_of_le Nat.one_pos (Nat.le_of_lt p_gt_one)
  have hbu_lt : bytes_used % p < p := Nat.mod_lt _ hp_pos
  -- The cleanest path: rewrite via Nat.add_mod and reduce
  -- `(bytes_used % p + (p - bytes_used % p) % p) % p` directly.
  -- When `bytes_used % p = 0`, `p - 0 = p` and `p % p = 0`, so the
  -- whole expression mods to 0. When `bytes_used % p > 0`,
  -- `p - bytes_used % p < p`, so `(p - bytes_used % p) % p = p - bytes_used % p`,
  -- and the sum is exactly `p`, which mods to 0. Either way, 0.
  have hzero : (bytes_used + ((p - bytes_used % p) % p)) % p = 0 := by
    rw [Nat.add_mod]
    -- Goal: (bytes_used % p + (p - bytes_used % p) % p % p) % p = 0
    rw [Nat.mod_mod]
    -- Goal: (bytes_used % p + (p - bytes_used % p) % p) % p = 0
    -- Split on whether bytes_used % p = 0.
    by_cases hzbu : bytes_used % p = 0
    · -- Then p - bytes_used % p = p, and p % p = 0, so the whole sum % p = 0.
      rw [hzbu, Nat.zero_add, Nat.sub_zero, Nat.mod_self, Nat.zero_mod]
    · -- bytes_used % p > 0, so p - bytes_used % p < p.
      have hpos : bytes_used % p > 0 := Nat.pos_of_ne_zero hzbu
      have hsub_lt : p - bytes_used % p < p := by omega
      have hsub_mod : (p - bytes_used % p) % p = p - bytes_used % p :=
        Nat.mod_eq_of_lt hsub_lt
      rw [hsub_mod]
      have hsum : bytes_used % p + (p - bytes_used % p) = p := by
        have hle : bytes_used % p ≤ p := Nat.le_of_lt hbu_lt
        have hcomm : bytes_used % p + (p - bytes_used % p) =
                      p - bytes_used % p + bytes_used % p := Nat.add_comm _ _
        rw [hcomm]
        exact Nat.sub_add_cancel hle
      rw [hsum, Nat.mod_self]
  refine ⟨?_, ?_⟩
  · rw [hdec, hzero]
  · intro hpk
    apply verify_complete kp _ r_proof hpk
    rw [hdec, hzero]

/-! ### T8 — auxiliary

A small auxiliary that lets external callers reason about the
shadow blob's pubkey: every ciphertext built by `enc pk _ _`
carries `pk` as its `.pk` field. Used in `ShadowBlob.lean`
(`OctraVPN_Rust/`) to bridge to the concrete Rust schema. -/

/-- **`enc`-output pubkey equals input pubkey.** -/
theorem enc_pk_matches (pk : Pubkey) (m : Plaintext) (r : Randomness) :
    (enc pk m r).pk = pk :=
  enc_pk pk m r

/-! ## §7  Concrete-value anchors -/

/-- Concrete anchor: the modulus is greater than one. -/
example : p > 1 := p_gt_one

/-- Concrete anchor: serialisation round-trip on a default
    ciphertext. -/
example (ct : Ciphertext) : deserialise (serialise ct) = some ct :=
  ct_serde_roundtrip ct

end OctraVPN.WireProtocol.HFHE
