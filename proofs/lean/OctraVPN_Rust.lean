import OctraVPN_Rust.Spec
import OctraVPN_Rust.Lemmas
import OctraVPN_Rust.MachineRegistry
import OctraVPN_Rust.ACL

/-!
# OctraVPN — Rust security primitives, Lean 4 specification.

Sibling to `OctraVPN/` (v1.1 AML proofs) and `OctraVPN_V2/` (v2 AML
proofs). This module is the deductive companion to the 30+ Rust
proptest harnesses already protecting the security primitives in:

  * `octra-foundry/crates/octra-core/src/{circle,tx,sig,address,wallet_enc,util}.rs`
  * `crates/octravpn-core/src/{receipt,receipt_journal}.rs`
  * `crates/octravpn-mesh/src/{ip_alloc,acl,peer}.rs`

Proptests give random-input evidence (~32–4096 cases per property).
This module closes the gap with deductive proof against an opaque-
crypto axiomatic model.

## Theorem index

See `OctraVPN_Rust/Lemmas.lean` for the full list. Highlights:

Hash framing (h256_raw):
  - h256_framing_function
  - h256_split_neq_joined
  - h256_distinct_tags_neq

Circle IDs:
  - circle_id_function
  - circle_id_distinct_nonces
  - resource_key_collision_implies_h256_collision

Padded frame:
  - padded_frame_len_lower_bound
  - padded_frame_len_none
  - padded_frame_len_aligned

Sealed envelope (AEAD):
  - sealed_roundtrip
  - sealed_wrong_passphrase_rejected
  - sealed_wrong_circle_id_rejected
  - sealed_wrong_key_id_rejected
  - sealed_tamper_rejected

Ed25519:
  - sign_verify_roundtrip
  - sign_verify_rejects_tamper
  - sign_verify_rejects_wrong_pubkey
  - keypair_from_secret_function

Address:
  - address_from_pubkey_function
  - address_display_starts_oct
  - address_display_len_47

Wallet envelope:
  - wallet_roundtrip
  - wallet_wrong_passphrase_rejected

HKDF / subkey:
  - subkey_domain_separation
  - sealed_read_key_circle_distinct
  - sealed_read_key_key_id_distinct

Canonical tx bytes:
  - canonical_tx_function

Receipts:
  - receipt_signing_roundtrip
  - receipt_cross_program_rejected
  - receipt_cross_chain_rejected
  - receipt_cross_circle_rejected
  - receipt_payload_function

Receipt journal:
  - journal_fresh_floor_zero
  - journal_bump_records_floor
  - journal_bump_monotonic
  - journal_per_session_isolation
  - journal_restart_durability

IP allocation:
  - ip_alloc_deterministic
  - ip_alloc_in_cgnat
  - ip_alloc_router_in_prefix

ACL:
  - acl_canonical_function
  - acl_distinct_versions_distinct_bytes

Peer snapshot:
  - peer_canonical_function
  - peer_canonical_audit_todo (TODO: length-prefix audit)

## Axioms introduced

All cryptographic primitives are modeled opaquely. The axioms are:

  - Sha256.injective       — distinct inputs produce distinct digests
  - Address.displayOf_prefix / displayOf_len
  - verify_sign_roundtrip / verify_rejects_tampered_message /
    verify_rejects_wrong_pubkey  — Ed25519 EUF-CMA contract
  - aead_roundtrip / aead_wrong_key / aead_tamper_specific —
    AEAD authenticity + soundness
  - pbkdf2_salt_distinct / pbkdf2_passphrase_distinct
  - sealedReadKeySalt_injective  — salt prefix template is injective
  - hkdf_domain_distinct         — HKDF domain separation
  - circle_tags_distinct         — framing-tag uniqueness

These mirror the standard properties of SHA-256, Ed25519,
AES-GCM / ChaCha20-Poly1305, PBKDF2, and HKDF. We do NOT prove the
cryptographic primitives themselves; that is delegated to the audited
Rust crates and their respective FIPS / RFC references.

## Out of scope (follow-up pass)

The following Rust modules are NOT yet modeled:

  - `octra-foundry/crates/octra-core/src/coverage.rs` (instrumentation;
    no security property to prove).
  - `octra-foundry/crates/octra-core/src/verify.rs` (Kani harness shim).
  - Async runtime / control plane in `octravpn-node` — out of scope
    for deductive proof per the worktree brief.
  - boringtun / aes-gcm / chacha20poly1305 / ed25519-dalek internals
    — opaque assumptions only.
  - Full HFHE soundness (still a PROOF GAP shared with the AML modules).

## Build

`lake build` from `proofs/lean/` reaches zero `sorry`, zero `admit`.
-/
