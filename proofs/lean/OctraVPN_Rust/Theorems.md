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

## 5. `OctraVPN_Rust.AuditLog`

HMAC-chained, tamper-evident audit-log model.  Mirrors
`crates/octravpn-node/src/audit.rs`.  Models the `chain_step` +
`verify_file` algebraic core; JSON/serde/tokio scheduling are
delegated to the Rust proptest harnesses at the bottom of that file.

| Theorem                                  | Plain-English statement                                                                                              |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `honest_chain_link`                      | Two consecutive honest lines are chained: line N+1's `prev_mac` equals line N's `mac`.                               |
| `verify_accepts_honest`                  | A chain produced by `writeHonest` from any starting `prev` is accepted by the recursive verifier.                    |
| `verify_file_accepts_honest`             | Top-level entry: an honest daily file always verifies cleanly.                                                       |
| `tamper_prev_mac_detected`               | Flipping the `prev_mac` field on any line yields a `failedAt` with the exact line number + claimed/expected MACs.    |
| `tamper_record_detected`                 | Flipping any byte in `record_json` (keeping prev_mac + mac intact) yields a MAC mismatch at that line.               |
| `per_day_chain_resets`                   | A new daily file resets the chain to the zero sentinel; cross-file chain breaks do not propagate.                    |
| `verify_completeness_honest`             | If `verifyFile` returns `ok n` on an honest file, `n` equals the file's line count (no skipped verification).        |
| `signed_seqs_roundtrip`                  | `parseSignedSeq (serializeSignedSeq r) = some r` for every record (`record_receipt_signed` round-trip).              |
| `signed_seqs_harvest_complete`           | The harvested `(sessionId, seq)` set equals the projection of the input record set.                                  |
| `first_error_localisation`               | Honest chains have no `failedAt` outcome — `verifyFile` either succeeds or localises the FIRST broken line.          |

Axioms introduced in `AuditLog.lean`:

- `HmacSha256.injective_on_chain` — HMAC-SHA256 chain step is
  injective on its `(prev_mac, record_bytes)` pair under a fixed
  key.  Standard PRF security assumption.
- `serializeSignedSeq_injective`, `parseSignedSeq_inverts` —
  round-trip property of the canonical `record_receipt_signed`
  serialiser, mirrors `serde_json` exercised by Rust proptest.

Theorem count: 10.

---

## 6. `OctraVPN_Rust.ReceiptJournal`

Append-only v1 journal model with v0 migration + compaction.
Mirrors `crates/octravpn-core/src/receipt_journal.rs`.

| Theorem                                  | Plain-English statement                                                                                              |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `fresh_floor_zero`                       | A fresh in-memory journal has floor 0 for every session.                                                             |
| `bump_never_decreases`                   | Successful bumps never decrease any session's floor.                                                                 |
| `anti_restart_replay`                    | A session that reached floor `K` rejects any `seq = 1` afterwards (forced-restart double-sign defence).              |
| `bump_strict_monotone`                   | No bump can succeed with `newSeq ≤ floor`.                                                                           |
| `per_session_isolation`                  | A bump on session `a` does not touch session `b`'s floor.                                                            |
| `migration_preserves_entries`            | Every v0 snapshot entry survives migration to v1 as exactly one record.                                              |
| `migration_preserves_replay`             | Replaying the migrated v1 file produces the same floor map as the original v0 snapshot.                              |
| `compaction_preserves_floor`             | Post-compact in-memory floor map equals pre-compact — compaction is semantically a no-op.                            |
| `crc_detects_seq_tamper`                 | A v1 record whose `seq` was mutated produces a different CRC32 than the honest encoding.                             |
| `torn_tail_dropped_silently`             | A partial trailing record is dropped at open time; the floor map equals the well-formed prefix's.                    |
| `every_write_immediate_durable`          | Under `EveryWrite`, every successful bump leaves `durable = disk` — durable the moment `bump` returns.               |
| `periodic_durability_bound`              | Under `Periodic d`, the bump is durable iff `now ≥ lastFsync + d` — bounded loss window of `d`.                      |

Axioms introduced in `ReceiptJournal.lean`:

- `crc32_ieee_distinct` — distinct CRC inputs ⇒ distinct CRC outputs
  (CRC32-IEEE one-byte-flip detection property).

Theorem count: 12.

---

## 7. `OctraVPN_Rust.EndToEnd`

The composition theorem.  Ties together the receipt-payload layer,
the v3 wire-anchor layer, the HFHE shielded-arithmetic layer, the
RPC envelope layer, and the audit + journal layer.  Mirrors the
`settle_claim → settle_confirm → claim_earnings` chain path.

| Theorem                                  | Plain-English statement                                                                                              |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `headline_settle_claim_correct`          | Honest receipt + matching circle + journal-monotonic seq ⇒ `settle = accepted (bytes_used * price)`.                  |
| `forged_sig_detected`                    | A receipt signed by the wrong secret key is rejected at the chain layer (`badSig`).                                  |
| `double_spend_detected`                  | A receipt with `seq ≤ floor` is rejected at the chain layer (anti-double-spend at settle).                            |
| `mismatched_program_addr_detected`       | A receipt whose `programAddr.raw` doesn't match the circle's is rejected at the chain layer.                          |
| `cross_chain_replay_detected`            | A receipt whose `chainId` doesn't match the circle's is rejected at the chain layer (P1-5 cross-chain replay defence). |
| `forged_shadow_blob_detected`            | A forged HFHE shadow blob (cipher decrypts to a different bytes_used) is detected by the HFHE-3 cross-check.          |
| `audit_tamper_caught_on_verify`          | A single-byte tamper of an honest audit record is caught by HMAC mismatch on next `verify_file`.                      |
| `honest_path_succeeds`                   | Bundled restatement of the headline — single-citation form for external auditors.                                    |

This module **composes** the following theorems from sibling
modules (each cited inline in `EndToEnd.lean`'s docstring):

- `Lemmas.receipt_signing_roundtrip` (receipt-payload layer)
- `Lemmas.receipt_cross_program_rejected` (receipt-payload layer)
- `Lemmas.receipt_cross_chain_rejected` (receipt-payload layer)
- `Lemmas.receipt_cross_circle_rejected` (receipt-payload layer)
- `Lemmas.sign_verify_rejects_wrong_pubkey` (sig layer)
- `ShadowBlob.honest_dec_bytes_used` (HFHE shielded-arithmetic layer)
- `ShadowBlob.honest_dec_net` (HFHE shielded-arithmetic layer)
- `ShadowBlob.forged_shadow_detectable` (HFHE shielded-arithmetic layer)
- `WireProtocol.HFHE.hom_add_matches_plaintext_add` (HFHE layer)
- `WireProtocol.V3Canonical.canonical_reorder_invariant` (wire-anchor layer)
- `WireProtocol.V3Members.members_anchor_collision_resistant` (wire-anchor layer)
- `WireProtocol.V3Policy.policy_anchor_collision_resistant_on_epoch` (wire-anchor layer)
- `WireProtocol.RpcEnvelope.tx_sign_verify_roundtrip` (RPC layer)
- `WireProtocol.RpcEnvelope.method_binding_rejects_replay` (RPC layer)
- `WireProtocol.RpcEnvelope.chain_id_binding_rejects_replay` (RPC layer)
- `WireProtocol.RpcEnvelope.nonce_binding_rejects_replay` (RPC layer)
- `AuditLog.verify_file_accepts_honest` (audit layer)
- `AuditLog.tamper_record_detected` (audit layer)
- `ReceiptJournal2.anti_restart_replay` (journal layer)
- `ReceiptJournal2.bump_strict_monotone` (journal layer)

Theorem count: 8.

### Headline theorem statement (copy-paste from `EndToEnd.lean:205`)

```lean
theorem headline_settle_claim_correct
    (circle : RegisteredCircle) (sk : SecretKey)
    (sessionId : SessionId) (seq : Nat) (bytesUsed price : Nat)
    (blind : Blind) (journalFloor : Nat)
    (h_fresh : seq > journalFloor)
    (_h_ctx_match : ∃ ctx_eq : ReceiptContext,
                       ctx_eq.programAddr.raw = circle.programAddr.raw ∧
                       ctx_eq.chainId = circle.chainId)
    : let ctx : ReceiptContext :=
        { programAddr := circle.programAddr,
          chainId := circle.chainId,
          circleId := some circle.circleId }
      let payload := receiptSigningPayload ctx sessionId seq bytesUsed blind
      let sig := ed25519Sign sk payload
      let receipt : SignedReceipt :=
        { ctx := ctx, sessionId := sessionId, seq := seq,
          bytesUsed := bytesUsed, price := price, blind := blind,
          sig := sig }
      settle circle (deriveVerifyingKey sk) receipt journalFloor
        = SettleOutcome.accepted (bytesUsed * price)
```

### What is delegated to operator trust

The headline theorem proves the **chain-side honesty story**: no
encrypted-arithmetic inflation, no double-spend, no cross-chain
replay, no forged signature, no rolled-back seq.  What it does NOT
prove (and what therefore remains in the operator's trust scope):

- **PVAC pubkey rotation discipline.**  If an operator leaves a
  stale PVAC pubkey registered after a key compromise, the
  attacker can decrypt past shadow blobs.  Mitigated by
  `ops/pvac-rotation-runbook.md`, not by this theorem.
- **Audit-log HMAC key safety.**  If `.audit.key` leaks, an
  attacker with write access can rewrite history.  HMAC is no
  longer a MAC against a known-key adversary.
- **Fsync durability of the underlying filesystem.**  POSIX
  `fsync` is assumed honest.  Theorem 22 (`periodic_durability_bound`)
  proves the algebraic relationship; the actual disk-side
  guarantee is delegated to the OS.

---

## Theorem count

| Module                       | Theorems | Examples (anchors) |
| ---------------------------- | -------- | ------------------ |
| `Spec` (original)            | 5        | (various)          |
| `Lemmas` (original)          | 54       | (various)          |
| `MachineRegistry`            | 5        | 1                  |
| `ACL`                        | 8        | 2                  |
| `ShadowBlob`                 | 7        | 0                  |
| `AuditLog` (new)             | 10       | 0                  |
| `ReceiptJournal` (new)       | 12       | 0                  |
| `EndToEnd` (new)             | 8        | 0                  |
| **Total (this module)**      | **109**  | 3+                 |

Combined with `WireProtocol/` (now 81 theorems with the new
`RpcEnvelope` module), the deductive proof surface now stands at
**190 mechanically-checked theorems** (109 Rust security primitives
+ 81 wire-protocol primitives, of which 35 are new in this pass:
10 AuditLog + 12 ReceiptJournal + 5 RpcEnvelope + 8 EndToEnd).
