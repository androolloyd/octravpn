# OctraVPN_Rust Theorem Index

Mechanically-checked Lean theorems for the Rust security
primitives. Companion to `WireProtocol/Theorems.md`.

Build: `cd proofs/lean && lake build OctraVPN_Rust` — must end with
"Build completed successfully." and zero `sorry` / `admit`.

The Lean code is intentionally non-Mathlib; only core `Lean 4` is
imported.

---

## 1. `OctraVPN_Rust.Spec` and `OctraVPN_Rust.Lemmas`

The original 54 security-primitive theorems from PR #181. See
`OctraVPN_Rust.lean`'s docstring for the full plain-English index.
Highlights:

- Hash framing (`h256_raw`):
  `h256_framing_function`, `h256_split_neq_joined`,
  `h256_distinct_tags_neq`.
- Circle IDs:
  `circle_id_function`, `circle_id_distinct_nonces`,
  `resource_key_collision_implies_h256_collision`.
- Padded frame:
  `padded_frame_len_lower_bound`, `padded_frame_len_none`,
  `padded_frame_len_aligned`.
- Sealed envelope (AEAD):
  `sealed_roundtrip`, `sealed_wrong_passphrase_rejected`,
  `sealed_wrong_circle_id_rejected`,
  `sealed_wrong_key_id_rejected`, `sealed_tamper_rejected`.
- Ed25519:
  `sign_verify_roundtrip`, `sign_verify_rejects_tamper`,
  `sign_verify_rejects_wrong_pubkey`,
  `keypair_from_secret_function`.
- Address:
  `address_from_pubkey_function`, `address_display_starts_oct`,
  `address_display_len_47`.
- Wallet envelope:
  `wallet_roundtrip`, `wallet_wrong_passphrase_rejected`.
- HKDF / subkey:
  `subkey_domain_separation`, `sealed_read_key_circle_distinct`,
  `sealed_read_key_key_id_distinct`.
- Canonical tx bytes:
  `canonical_tx_function`.
- Receipts:
  `receipt_signing_roundtrip`, `receipt_cross_program_rejected`,
  `receipt_cross_chain_rejected`, `receipt_cross_circle_rejected`,
  `receipt_payload_function`.
- Receipt journal:
  `journal_fresh_floor_zero`, `journal_bump_records_floor`,
  `journal_bump_monotonic`, `journal_per_session_isolation`,
  `journal_restart_durability`.
- IP allocation:
  `ip_alloc_deterministic`, `ip_alloc_in_cgnat`,
  `ip_alloc_router_in_prefix`.
- ACL (legacy):
  `acl_canonical_function`, `acl_distinct_versions_distinct_bytes`.
- Peer snapshot:
  `peer_canonical_function`, `peer_canonical_audit_todo`.

Theorem count: 5 in `Spec.lean` + 54 in `Lemmas.lean` = 59.

---

## 2. `OctraVPN_Rust.MachineRegistry`

Models the registry as a `Map Address MachineRecord`. Mirrors
`headscale-api::tailscale_wire::MachineRegistry` (re-exported by
`octravpn-mesh::lib.rs:38`). The registry is conceptually a
`HashMap<Address, MachineRecord>` guarded by an async lock; we
model the algebraic surface of `insert` / `remove` / `lookup` /
`toList` with the standard finite-map axioms.

Rust source: `octravpn-mesh::lib.rs` (re-export) +
`headscale-api::tailscale_wire::registry`.

| Theorem                                       | Plain-English statement                                                                                              |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `registry_insert_idempotent`                  | Inserting the same `(k, v)` pair twice equals inserting once.                                                        |
| `registry_lookup_after_insert`                | `lookup k (insert k v r) = some v`.                                                                                  |
| `registry_lookup_after_remove`                | `lookup k (remove k r) = none`.                                                                                      |
| `registry_all_no_clone_correct`               | The new no-clone `.all()` iterator (per #238) yields the same list as the old cloned `Vec<MachineRecord>` snapshot.  |
| `registry_concurrent_insert_well_typed`       | A race between two inserts to distinct keys leaves both reachable, regardless of serialisation order.                |
| `example` (lookup on empty)                   | `Map.lookup k Map.empty = none` (no entry in a fresh registry).                                                      |

Axioms introduced in `MachineRegistry.lean`:

- `Map.lookup_empty` — empty map looks up to `none`.
- `Map.lookup_insert_eq`, `Map.lookup_insert_ne` — standard
  insert-then-lookup laws.
- `Map.lookup_remove_eq`, `Map.lookup_remove_ne` — standard
  remove-then-lookup laws.
- `Map.insert_idempotent` — inserting the same `(k, v)` pair
  twice is the same as inserting once.
- `Map.toList_insert_no_clone` — the no-clone iterator view and
  the cloned-snapshot view agree as a list (the algebraic core
  of #238's `Vec<MachineRecord>` → `iter()` refactor).

All axioms mirror the contract of `std::collections::HashMap`;
Lean 4 core does not ship a packaged finite-map theory without
Mathlib, so we expose the load-bearing properties as axioms (same
strategy as `sortByKey` in `WireProtocol/V3Canonical.lean`).

Theorem count: 5 plus 1 example anchor.

---

## 3. `OctraVPN_Rust.ACL`

Models the ACL match function. Mirrors `AclDoc::match` in
`crates/octravpn-mesh/src/acl.rs`: walk the rules top-to-bottom,
first matching rule wins, no match means deny.

Rust source: `crates/octravpn-mesh/src/acl.rs`.

| Theorem                                       | Plain-English statement                                                                                              |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `acl_deny_all_rejects_everything`             | The empty policy denies every flow (matches the "no match ⇒ deny" rule in `acl.rs`).                                 |
| `acl_empty_policy_nothing_allowed`            | Corollary: nothing is `allowed` under the empty policy.                                                              |
| `acl_allow_all_admits_everything`             | A policy whose head rule is `acceptAll` accepts every flow.                                                          |
| `acl_wildcard_allows_all`                     | Corollary: every flow is `allowed` under the single-wildcard policy.                                                 |
| `acl_match_deterministic`                     | Same `(policy, flow)` ⇒ same decision (`eval` is a function).                                                        |
| `acl_match_monotone`                          | Prepending an `accept` rule never turns a previously-allowed flow into a denied one.                                 |
| `acl_match_short_circuit`                     | First-match-wins (positive case): if the head rule matches, its action is returned.                                  |
| `acl_match_fallthrough`                       | First-match-wins (negative case): if the head rule does not match, evaluation falls through to the tail.             |
| `example` (deny on empty)                     | The empty policy denies a default flow.                                                                              |
| `example` (accept under wildcard)             | The wildcard policy accepts a default flow.                                                                          |

No new axioms introduced. The evaluator is total over a finite
list of rules and the proofs go through purely structurally.

Theorem count: 8 plus 2 example anchors.

---

## 4. `OctraVPN_Rust.ShadowBlob`

Bridge from the abstract `WireProtocol.HFHE` module to the concrete
Rust `SignedReceipt` schema with the HFHE-2 shadow-blob fields.
Mirrors `crates/octravpn-core/src/receipt.rs:146-183` and the
`ShadowBlob { enc_bytes_used, enc_net, pvac_zero_proof }` triple
at lines 235-261. Closes the "what the chain stores looks like vs.
what the cipher claims" gap with seven theorems.

| Theorem                                | Plain-English statement                                                                                              |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `honest_dec_bytes_used`                | An honestly-emitted shadow blob's `enc_bytes_used` decrypts to the receipt's `bytes_used mod p`.                     |
| `honest_dec_net`                       | An honestly-emitted shadow blob's `enc_net` decrypts to `bytes_used * price mod p`.                                  |
| `honest_bytes_used_key_bound`          | An honestly-emitted `enc_bytes_used` is bound to the circle's PVAC pubkey.                                            |
| `swap_ready_indistinguishable`         | Two receipts with the same `(bytes_used, price)` produce the same sha256 commitment regardless of shadow blob.       |
| `forged_shadow_detectable`             | A forged shadow blob (cipher decrypts to b' ≠ committed `bytes_used`) is detectable by the HFHE-3 cross-check.       |
| `honest_emission_wire_stable`          | Honest emission survives wire round-trip — serialise + deserialise preserves the cipher.                              |
| `no_shadow_legacy_verifier`            | A receipt with no shadow blob (`Option::None` on every field) verifies under today's sha256-only verifier unchanged. |

No new axioms introduced — `ShadowBlob.lean` reuses
`WireProtocol.HFHE`'s axioms (`dec_enc_id`, `sha256_injective`,
`encodeAmountPrice_injective`, `pubkey_binding`).

Theorem count: 7.

---

## Theorem count

| Module                       | Theorems | Examples (anchors) |
| ---------------------------- | -------- | ------------------ |
| `Spec` (original)            | 5        | (various)          |
| `Lemmas` (original)          | 54       | (various)          |
| `MachineRegistry`            | 5        | 1                  |
| `ACL`                        | 8        | 2                  |
| `ShadowBlob`                 | 7        | 0                  |
| **Total (this module)**      | **79**   | 3+                 |

Combined with the 76 theorems in `WireProtocol/`, the deductive
proof surface now stands at **155 mechanically-checked theorems**
(79 Rust security primitives + 76 wire-protocol primitives).
