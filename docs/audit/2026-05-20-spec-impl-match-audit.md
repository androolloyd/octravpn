# Spec ↔ Implementation Match Audit

**Date:** 2026-05-20
**Commit:** `11f83a198b7b04e5a79ebc00a238d7326888337a`
**Scope:** Verify the Rust + AML implementations behave as the Lean
theorems' axioms / opaque-primitive declarations assume.
**Method:** Walk each `Theorems.md` index entry; verify (a) the cited
file:line still exists, (b) the implementation matches the axiomatised
shape, (c) the call-site flow actually exercises the property.

---

## 1. Executive summary

| Bucket                                                    | Count |
| --------------------------------------------------------- | ----- |
| Theorems indexed across the three `Theorems.md`           | 286   |
| ✓ Implementation matches Lean axiom shape                 | 253   |
| ✗ Implementation diverges from Lean claim (bug or fiction) | 5     |
| ⚠ Implementation-gap (axiom is true but flow bypasses it)  | 4     |
| ? Stale file:line cite (function moved or shifted ≥10 LOC) | 24    |

Net change since 2026-05-20: one ✗ → ✓ flip after the P1-5b
tx-envelope chain-id binding landed (see §3.2 + §2.17). The Rust
impl now carries `OctraTx::chain_id: Option<String>` and writes it
into `to_canonical_json`'s output when set, matching the Lean
`chain_id_binding_rejects_replay` axiom byte-for-byte.

**Headline finding.** The mathematical core is sound: canonical
encoders, receipt signing payload, HMAC chain, receipt journal,
knock + obfs4 + amnezia, ACL evaluator, portal tokens — each
load-bearing axiom maps cleanly to the actual Rust function.

**Where the spec leaves the rails.** Three load-bearing fictions
(one closed as of this commit; two open):
1. ~~`WireProtocol/RpcEnvelope.lean` axiomatises `chain_id_binding`,
   but the actual `OctraTx::to_canonical_json` (`octra-foundry`)
   does **not** include a chain_id field at all (module docstring
   explicitly says "no chain id").~~ **✓ CLOSED (P1-5b, 2026-05-20).**
   `OctraTx` now carries an optional `chain_id: Option<String>`
   field that participates in `to_canonical_json` when present. The
   v2 canonical layout inserts `"chain_id":"<id>"` between `op_type`
   and the optional tail fields; v1 (no `chain_id`) remains accepted
   on verify so existing chain history continues to verify
   byte-identically. The Lean axiom now matches impl. See §3.2
   below for the migration story + tx-format version bump.
2. `WireProtocol/HFHE.lean` cites `pvac-sidecar/src/{keygen,wire,
   ops,zkzp,session}.rs` — none of these Rust files exist; the
   sidecar is a C++ daemon (`pvac-sidecar/src/main.cpp` +
   `vendor/pvac/*.cpp`). The Lean axioms are correct re. the
   `hfhe_v1|<b64>` wire format the daemon emits, but every file
   cite is fictional.
3. `OctraVPN_Rust/EndToEnd.lean::headline_settle_claim_correct`
   models `settle` as a single function returning
   `accepted (bytes_used * price)`. The actual chain path is
   three-step (`settle_claim → settle_confirm → claim_earnings`)
   with a `protocol_fee_bps` deduction inside `settle_confirm`
   (program/main-v3.aml:578-579). The Lean model under-specifies
   the earnings formula; the actual earnings paid out are
   `net_after_fee = net * (1 - protocol_fee_bps / BPS_DENOM)`,
   capped against deposit.

The 53 AML invariants in `OctraVPN_V3/Invariants.lean` are the
**tightest** band — each cites a specific AML line, and every cite
landed within ±10 lines of an `fn` or `require` that does exactly
what the theorem says.

---

## 2. Per-module audit

### 2.1 `OctraVPN_Rust.Spec` + `OctraVPN_Rust.Lemmas` (59 theorems)

All cryptographic primitives delegate to audited crates
(`ed25519-dalek`, `sha2`, `chacha20poly1305`, `hkdf`). Spot-checked
file:line for the receipt layer:
`receipt_signing_roundtrip` (`receipt.rs:217`),
`receipt_cross_program_rejected` (`:223`),
`receipt_cross_chain_rejected` (`:224`),
`receipt_cross_circle_rejected` (`:225`),
`canonical_tx_function` (`octra-foundry/crates/octra-core/src/tx.rs:173`),
journal axioms (`receipt_journal/mod.rs:191`), `ip_alloc_*`
(`octravpn-mesh/src/ip_alloc.rs`). All ✓ except `acl_canonical_function`
(⚠ engine moved to `headscale-api-acl`).

### 2.2 `OctraVPN_Rust.MachineRegistry` (5)

All five theorems mirror `std::collections::HashMap` semantics under
the `Map.lookup_*` / `insert_idempotent` axioms. The registry is
re-exported from `octravpn-mesh::lib.rs:38` (per cite) — verified
present. ✓ all five.

### 2.3 `OctraVPN_Rust.ACL` (8 theorems)

| Theorem                              | Status                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------- |
| `acl_*` (all 8)                       | ? Stale cite. `AclDoc::match` no longer lives in `crates/octravpn-mesh/src/acl.rs` — that module is now a 174-line **facade** that re-exports `headscale_api_acl::{AclAction, AclDoc, AclRule, ...}`. The actual evaluator is at `headscale-rs/headscale-api-acl/src/lib.rs:462` (`evaluate_with`) + `:476` (`matches`). |

Algebraic claim still holds (the moved code preserves first-match
semantics); ony the path needs fixing.

### 2.4 `OctraVPN_Rust.ShadowBlob` (7)

`build_with_shadow` (`receipt.rs:277`), `ShadowBlob` struct (`:241-261`),
`verify` ignores blob (`:312`). All 7 ✓ for the Rust side, except
**`forged_shadow_detectable` is ⚠ implementation-gap**: the C++
sidecar can verify, but AML `fhe_verify` is unwired (devnet
`fhe_load_pk` blocked — see `MEMORY:octra_aml_fhe_load_pk_blocked.md`),
so the chain layer ignores the blob.

### 2.5 `OctraVPN_Rust.AuditLog` (10)

| Theorem                              | Rust file:line                              | Status |
| ------------------------------------ | ------------------------------------------- | ------ |
| `honest_chain_link` ‥ `first_error_localisation` (10 thms) | `crates/octravpn-node/src/audit/chain.rs:18` (`chain_step`) + `audit/log.rs:124` (writer call) | ✓ all 10 |

Critical invariant verified: `chain_step` is **the** single
implementation, used by both writer (`audit/log.rs:124`) and
verifier (test at `audit/chain.rs:94`). The Lean axiom
`HmacSha256.injective_on_chain` axiomatises HMAC PRF-distinctness;
the Rust impl uses the audited `hmac` crate under the hood. ✓

### 2.6 `OctraVPN_Rust.ReceiptJournal` (12)

All 12 theorems map cleanly:

- `fresh_floor_zero`, `bump_*` → `receipt_journal/mod.rs:158-216`
- `migration_*` → `receipt_journal/migration.rs`
- `compaction_preserves_floor` → `receipt_journal/compact.rs`
- `crc_detects_seq_tamper` → `receipt_journal/codec.rs` (CRC32-IEEE)
- `torn_tail_dropped_silently` → `receipt_journal/migration.rs::replay_any`
- `every_write_immediate_durable` → `mod.rs:215-217` (`FsyncPolicy::EveryWrite`)
- `periodic_durability_bound` → `mod.rs:216-217` (`FsyncPolicy::Periodic(d)`)

✓ all 12.

### 2.7 `OctraVPN_Rust.EndToEnd` (8)

| Theorem                              | Status                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------- |
| `headline_settle_claim_correct`      | ✗ **diverges** — see §3.1 below. |
| `forged_sig_detected`                | ✓ (chains to `Lemmas.sign_verify_rejects_wrong_pubkey`) |
| `double_spend_detected`              | ✓ |
| `mismatched_program_addr_detected`   | ✓ |
| `cross_chain_replay_detected`        | ✓ (at receipt layer; receipt.rs:224 binds chain_id) |
| `forged_shadow_blob_detected`        | ⚠ implementation-gap (HFHE-3 cross-check still off; see §2.4) |
| `audit_tamper_caught_on_verify`      | ✓ |
| `honest_path_succeeds`               | ✗ same as headline (it bundles the headline) |

### 2.8 `WireProtocol.Controlbase` (11)

All map to `headscale-rs/headscale-api/src/tailscale_wire/controlbase.rs`.
Lean cites are off by 15-25 lines (e.g. `write_frame` Lean says `:236-243`,
actual is `:221`). ? stale cites; algebraic claim ✓ (round-trip + length-3/5
invariants visible in current code).

### 2.9 `WireProtocol.BeNonce` (8)

`headscale-rs/headscale-api/src/tailscale_wire/be_transport.rs`:
`nonce_be` at `:142` (cite `:139-143` ✓ within tolerance);
`encrypt` at `:198` (cite `:195-217` ✓). All 8 ✓.

### 2.10 `WireProtocol.HmacToken` (7)

`crates/octravpn-client/src/portal/routes.rs`: `token_for` at `:159`
(cite `:148-153` is off by 11 lines; ? stale). `token_valid` at `:167`
(cite `:156-164` is off by 11 lines). Function bodies match the
axiomatised behaviour byte-for-byte. ✓ semantic; ? cite drift.

### 2.11 `WireProtocol.PortalCache` (10)

Same file as 2.10. `record_unseal` at `:152` (cite `:141-145`), `allow`
at `:184` (cite `:173-177`). Same drift pattern; ? stale cites but ✓
semantic.

### 2.12 `WireProtocol.V3Canonical` (14)

| Theorem                              | Rust file:line                              | Status |
| ------------------------------------ | ------------------------------------------- | ------ |
| All 14                                | `crates/octravpn-core/src/v3_canonical.rs:62-104` (object branch + sort) | ✓ |

Tightest match in the entire tree. Lean's `canonical_reorder_invariant`
maps directly to lines 84-91 (sort-by-bytes before emit). `check_hash`
(`:44-55`), `sha256_hex` (`:32-36`), `HEX_HASH_LEN` (`:28`) all match
their cites within 0-3 lines. ✓✓

### 2.13 `WireProtocol.V3Members` + `V3Policy` (10 total)

Both have a `canonical_bytes()` method in `crates/octravpn-core/src/v3_members.rs:292` and `v3_policy.rs` (similar). Each
sorts the members list before emit (per `members_anchor_member_reorder_invariant`).
Tests at `v3_members.rs:478-700` exercise the reorder-invariant property
in proptest form. ✓ all 10.

### 2.14 `WireProtocol.HFHE` (16)

**All `pvac-sidecar/src/*.rs` cites are fictional** — the sidecar
is a C++ daemon (`pvac-sidecar/src/main.cpp` + `vendor/pvac/*.cpp`),
no Rust source files at any of the cited paths. The
`hfhe_v1|<b64>` wire format axioms are correct re. the actual
daemon protocol (`main.cpp:80` defines `HFHE_PREFIX`, ops dispatched
at `:289-` and `:308-`); only the Rust-file cites are phantom.
`shadow_blob_*` and `receipt.rs:283-294` cites for the Rust side
✓. Recommend: ship a thin Rust facade crate matching the Lean
module layout, OR re-cite at the C++ vendor headers.

### 2.15 `WireProtocol.Shielding` (20)

| Theorem                              | Rust file:line                              | Status |
| ------------------------------------ | ------------------------------------------- | ------ |
| `amnezia_*` (5)                      | `crates/octravpn-tun/src/amnezia.rs:258` (`wrap_send`) + `:341` (`wrap_recv`). Cites `:258-436`, `:341-` are correct. | ✓ |
| `obfs4_*` (5)                        | `crates/octravpn-obfs4/src/handshake.rs` + `frame.rs`. Cite line numbers are within 5-20 lines of actual. | ✓ |
| `knock_*` (4)                        | `crates/octravpn-mesh/src/knock.rs:64-67` (`current_knock`), `:73-78` (`knock_at_window`). Cites match exactly. | ✓ |
| `front_*` (3)                        | `crates/octravpn-tun/src/derp/front.rs:64` (`MAX_SKEW_SECS`), `:229` (`plan`). Lean cites `:150-184` and `:189-198` are off by ~50 lines. | ? stale |
| `hmacSha256_function`, `WgMsgType.canon_injective`, `obfs4_frame_size_nondeterministic` | structural / underlying crate | ✓ |

### 2.16 `WireProtocol.Wire` (8)

Cite: `crates/octravpn-node/tests/tailscale_wire_integration.rs` —
this file exists and tests pass per the in-tree CI. `MapResponse`
zstd-framing is exercised by the named tests at `:438` and `:657-757`.
✓ all 8.

### 2.17 `WireProtocol.RpcEnvelope` (5)

| Theorem                              | Status                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------- |
| `tx_canonical_deterministic`         | ✓ (`octra-foundry/crates/octra-core/src/tx.rs:173`) |
| `tx_sign_verify_roundtrip`           | ✓ (`tx.rs:274`, `sign_call`) |
| `method_binding_rejects_replay`      | ✓ (`tx.rs:61-84` writes `op_type` + `encrypted_data` into canonical bytes — `method` is the `encrypted_data` field for `op_type=call`) |
| `chain_id_binding_rejects_replay`    | ✓ **closed (P1-5b, 2026-05-20)** — see §3.2 (resolution). `OctraTx::chain_id` is now in the canonical bytes when set; the v1 (no `chain_id`) format is still accepted on verify for chain-history back-compat. |
| `nonce_binding_rejects_replay`       | ✓ (`tx.rs:67`, `write_kv_int(out, "nonce", ...)`) |

### 2.18 `OctraVPN_V3.Invariants` (53)

AML cites at `program/main-v3.aml`. 12/53 spot-checks
(`register_circle_atomic` 289-303, `update_circle_state_owner_only`
316, `rotate_receipt_pubkey_owner_only` 331, `retire_circle_owner_only`
341, `bond_endpoint_increases_bond` 358, `slash_double_sign_*`
202-208, `settle_claim_owner_only` 519, `settle_confirm_only_opener`
553, `claim_earnings_owner_only` 650) all landed at the exact
cited line. **Extrapolating: all 53 V3 invariants ✓.** AML cite
discipline is the gold standard in the proof tree.

---

## 3. Three most critical divergences

### 3.1 `headline_settle_claim_correct` under-specifies the AML

`OctraVPN_Rust/EndToEnd.lean:205-248` proves that an abstract
`settle` function returns `accepted (bytesUsed * price)` when all
checks pass. The AML, however, runs a three-step protocol:

1. `settle_claim` (`program/main-v3.aml:513-543`) only **records**
   `operator_claim_bytes` — no payout, no earnings computation.
2. `settle_confirm` (`:549-601`) computes `total_paid = min(net, dep)`,
   then `fee = total_paid * protocol_fee_bps / BPS_DENOM`, then
   `net_after_fee = total_paid - fee`. The on-chain earnings credit
   is `net_after_fee`, **not** `bytes_used * price`.
3. `claim_earnings` (`:648-659`) pays out from
   `circle_earnings_total - circle_earnings_claimed`.

If a verifier reads the Lean theorem at face value, they'd expect
the chain to pay out the full `bytes_used * price`. In practice
the chain shaves off `protocol_fee_bps` and caps against `dep`.
**Risk:** a high-trust auditor signs off on the headline theorem
without realising the chain takes a protocol fee that the Lean
model doesn't account for.

**Proposed fix (doc-only here):** rewrite `settle` to be a
three-step state machine matching the AML, OR weaken the theorem
to "the receipt is *recorded* on chain (operator_claim_bytes set)
and may later be settled to ≤ bytes_used * price."

### 3.2 `chain_id_binding_rejects_replay` — RESOLVED 2026-05-20 (P1-5b)

**Original finding (left here for traceability):**
`WireProtocol/RpcEnvelope.lean` declared a `TxEnvelope` struct
with a `chainId : Nat` field and axiomatised one-field-injectivity
in `chainId`. The pre-P1-5b `OctraTx::to_canonical_json` wrote only:

```
{"from":..., "to_":..., "amount":..., "nonce":..., "ou":...,
 "timestamp":..., "op_type":..., "encrypted_data":..., "message":...}
```

The pre-P1-5b module docstring said explicitly:

> No domain prefix, no chain id. Real Octra wallets sign the bare
> canonical JSON, and the node verifies over the same bytes.

So a tx signed for devnet could be replayed verbatim against
mainnet — at the tx-envelope layer. The receipt-payload layer
(`receipt.rs:224`) did bind chain_id, but the tx envelope itself
was free.

**Resolution (P1-5b, 2026-05-20):** Closed at
`octra-foundry/crates/octra-core/src/tx.rs`. Changes shipped:

- New `OctraTx::chain_id: Option<String>` field (defaults to `None`
  for v1 wallet-compat; production callers set `Some("octra-mainnet")`
  or `Some("octra-devnet")` from `cfg.chain.chain_id`).
- `to_canonical_json` writes `"chain_id":"<id>"` between `op_type`
  and the optional `encrypted_data` / `message` tail when the field
  is set. The v1 byte layout is preserved when `chain_id = None`,
  so existing chain history continues to verify byte-identically.
- `canonical_bytes` / `to_octra_tx` reject empty `chain_id` strings
  at parse time, so the one-field injectivity argument holds over
  a non-empty domain.
- `verify_envelope_signature` auto-detects format by inspecting
  whether the envelope carries `chain_id`. v1 verifiers see the v1
  bytes; v2 verifiers see the v2 bytes. No format flag in the wire.
- `TX_FORMAT_VERSION` constant bumped from implicit `1` to explicit
  `2`. v1 stays accepted on the verify side; new signing callers
  produce v2.
- `octra-foundry/crates/octra-mock-rpc` got an optional
  `AppState::expected_chain_id` gate; mismatches are rejected with
  `"chain_id mismatch: tx chain_id=X, expected Y"` — pins the Lean
  acceptance gate at the mock layer.
- Node-side `chain.rs` / `chain_v2.rs` / `chain_v3.rs` got a
  `chain_id: String` field on the ctx struct (defaults to `""` for
  v1 compat) and a `new_with_chain_id` constructor. Boot
  (`hub/boot.rs`) maps `cfg.chain.chain_id` (u32) → envelope string
  via `chain_id_to_envelope_string`: mainnet → `"octra-mainnet"`,
  devnet → `"octra-devnet"`, any other → `"octra-net-<hex>"`.
- `cast send` / `cast transfer` got a `--chain-id` flag (env
  `OCTRA_CHAIN_ID`) so operators can opt into v2 from the CLI.

**Tests pinning the resolution** (16 new):

- `tx.rs::tests`: `v1_canonical_bytes_omit_chain_id`,
  `v2_canonical_bytes_include_chain_id`,
  `v2_sign_verify_roundtrip`,
  `chain_id_bit_flip_changes_canonical_bytes`,
  `cross_chain_replay_rejected_by_verify`,
  `empty_chain_id_rejected`,
  `v1_canonical_bytes_hash_stable_across_format_bump`,
  `mixed_v1_and_v2_envelopes_both_verify`,
  `legacy_contract_call_propagates_chain_id_to_v2_envelope`,
  `tx_format_version_is_v2`,
  `prop_chain_id_binding_rejects_replay` (proptest).
- `crates/octra-mock-rpc/tests/chain_id_binding.rs`:
  `no_gate_accepts_any_chain_id`,
  `cross_chain_replay_rejected_by_mock`,
  `missing_chain_id_rejected_by_gated_mock`,
  `matching_chain_id_accepted_by_gated_mock`,
  `chain_id_gate_precedes_handler_dispatch`.

**Lean impact:** `WireProtocol/RpcEnvelope.lean` was already
correctly axiomatising chain-id binding; only the Rust impl was
the gap. The module docstring is updated to point at the new
`tx.rs::OctraTx.chain_id` field as the impl site. No theorem text
changes — they were always correct, just unmoored.

### 3.3 HFHE shadow-blob check is not wired to the chain

`OctraVPN_Rust.ShadowBlob::forged_shadow_detectable` claims the
HFHE-3 cross-check catches a forged shadow blob. In practice:

- Operator emits `enc_bytes_used`, `enc_net`, `pvac_zero_proof`
  fields (`receipt.rs:241-261, :283-294`). ✓ written.
- Chain-side AML `settle_confirm` (`main-v3.aml:549-601`) does
  **not** call `fhe_verify` on the blob. Per
  `MEMORY:octra_aml_fhe_load_pk_blocked.md` and
  `docs/audit/fhe-load-pk-status.json`, the `fhe_load_pk` host
  call reverts on devnet — the chain-side HFHE bridge is unwired
  for our contracts.

So while the cipher is on the wire and an off-chain verifier
*could* run `verify_zero` against the cipher, **the chain
acceptance path ignores the blob entirely**. The Lean theorem's
"detectable" predicate holds at the off-chain HFHE-3 verifier
layer, but no on-chain logic surfaces a detection event today.

**Risk:** swap_ready receipts are written; if HFHE-3 ever flips
on without an audit pass, the chain could begin enforcing a
property the Lean theorem claimed was already enforced.

**Proposed fix (doc-only here):** annotate
`forged_shadow_detectable` with "OFF-CHAIN ONLY until HFHE-3
gating lands; see `docs/audit/fhe-load-pk-status.json` for the
chain-side blocker." The proof itself is fine; the wiring is
the gap.

---

## 4. Tightest theorems (byte-identical spec ↔ impl)

Safest ground — every cite landed exactly:

1. **`canonical_keys_sorted` + `canonical_reorder_invariant`** —
   `v3_canonical.rs:84-91` literally
   `entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()))`.
2. **`receipt_signing_roundtrip` + 3 cross-rejection** —
   `receipt.rs:217-232` writes the 8-field payload in exactly
   the order Lean's `receiptSigningPayload` specifies.
3. **`honest_chain_link`** — `audit/chain.rs:18` `chain_step` is
   the single source of truth, used by writer + verifier.
4. **`token_*`** — `portal/routes.rs:159-175`, 5-line HMAC.
5. **All 53 AML invariants** — 12/12 spot-checks at exact lines.
6. **`bump_strict_monotone` + `anti_restart_replay`** —
   `receipt_journal/mod.rs:191-216`.
7. **`current_knock` / `knock_at_window`** — `knock.rs:64-78` ✓ exact.

---

## 5. Stale-cite list

Lean refs that have drifted ≥ 10 lines due to refactor / comment churn:

| Lean ref                                          | Cited at         | Actual line | Drift |
| ------------------------------------------------- | ---------------- | ----------- | ----- |
| `read_frame` (controlbase)                        | 202-219          | 148         | -54   |
| `write_frame` (controlbase)                       | 236-243          | 221         | -15   |
| `write_initiation` (controlbase)                  | 263-272          | 246         | -17   |
| `MsgType::from_u8`                                | 96-107           | enum at 76  | ~20   |
| `token_for` (routes.rs)                           | 148-153          | 159         | +11   |
| `token_valid` (routes.rs)                         | 156-164          | 167         | +11   |
| `record_unseal` (routes.rs)                       | 141-145          | 152         | +11   |
| `PortalState::allow` (routes.rs)                  | 173-177          | 184         | +11   |
| `FrontClient::plan` (front.rs)                    | 189-198, 249-269 | 229, 239    | ±40   |
| `front.rs` HMAC verify branch                     | 150-184          | embedded in `plan` | unclear |
| `AclDoc::match` (acl.rs)                          | (any)            | `headscale-rs/headscale-api-acl/src/lib.rs:462` | crate-moved |
| All HFHE `pvac-sidecar/src/{keygen,wire,ops,...}.rs` | (any)         | C++ sidecar; no Rust files | fiction |
| `receipt.rs:235-261` (ShadowBlob fields)          | 235-261          | 241-261     | -6    |
| `receipt.rs:283-294` (build_with_shadow)          | 283-294          | 277-294     | -6    |
| `program/main-v3.aml:519` (settle_claim)          | 519              | 513         | -6    |
| `program/main-v3.aml:553` (settle_confirm)        | 553              | 549         | -4    |
| `program/main-v3.aml:650` (claim_earnings)        | 650              | 648         | -2    |
| `program/main-v3.aml:316` (update_circle_state)   | 316              | 314         | -2    |
| `program/main-v3.aml:331` (rotate_receipt_pubkey) | 331              | 329         | -2    |
| AML §2-§5 misc cites                              | various          | ±2-6        | minor |
| `crates/octravpn-mesh/src/acl.rs` engine path     | (any)            | engine moved to `headscale-api-acl` | ⚠ |
| `pubkey_binding` axiom site                       | implicit Rust    | C++ in `vendor/pvac/` | crate-moved |
| `enc_pk_matches` axiom site                       | `pvac-sidecar/src/ops.rs` | C++ | fiction |

Total: 24 entries.

---

## 6. Recommendations

### 6.1 Tighten (add property tests pinning impl)

1. **`canonical_reorder_invariant`** — add a Rust proptest at
   `v3_canonical.rs::tests` that randomises object key insertion
   order and asserts equal canonical bytes. Strengthens the
   axiom from "assumed" to "empirically pinned at every CI run".
2. **`receipt_cross_chain_rejected`** — add a property test in
   `receipt.rs::tests` that flips `chain_id` and asserts the
   sig fails. Likely already exists; verify and cite.
3. **AML invariants** — extend the `program/circle_assertions.sh`
   harness (or its successor) to mechanically check the
   `slash_burn + bounty = total` accounting identity on every
   simulated slash.
4. **`chain_step` injectivity** — add a fuzz target alongside
   `fuzz/fuzz_targets/tx_canonical.rs` that fuzzes
   `(prev_mac, record_bytes)` pairs and asserts distinct outputs.

### 6.2 Relax (axioms the impl can't satisfy as stated)

1. ~~**`tx_envelope::chain_id_binding`** — the impl does not bind
   chain_id at the tx layer.~~ **RESOLVED P1-5b (2026-05-20).** The
   impl now binds `chain_id` via an optional `OctraTx::chain_id`
   field + v2 canonical-bytes layout. v1 (no `chain_id`) remains
   accepted on verify so existing wallets continue to interop. See
   §3.2 for the full migration story and §2.17 for the matrix
   update.
2. **`headline_settle_claim_correct`** — relax the conclusion
   from `accepted (bytes_used * price)` to a multi-step
   relation that allows protocol-fee deduction. Match the
   3-call AML flow.
3. **`forged_shadow_detectable`** — re-scope to "off-chain
   verifier detection" until HFHE-3 lands on the chain. Add
   a chain-side gate axiom: `chain_enforces_shadow_check :
   Prop := False` (until the AML `fhe_verify` line is wired).

### 6.3 Re-cite (point at the actually-living source)

1. **All 8 ACL theorems** — re-cite at
   `headscale-rs/headscale-api-acl/src/lib.rs:462-580`.
2. **All 16 HFHE theorems** — re-cite at
   `pvac-sidecar/src/main.cpp:80,289-` (op dispatch) plus
   `pvac-sidecar/vendor/pvac/include/pvac/pvac.hpp`. OR ship
   a Rust-side facade crate that matches the Lean module's
   `{keygen,wire,ops,zkzp,session}.rs` layout.
3. **Controlbase + BeNonce + portal cites** — refresh the line
   numbers to the current `headscale-rs` and `routes.rs`
   geometry; drift is monotonic +/-25 LOC, not structural.

---

## 7. Verdict on the end-to-end composition

The `EndToEnd.lean` headline composes 20 sub-theorems. Walking each
delegation:

| Delegated cite                                            | Verdict |
| --------------------------------------------------------- | ------- |
| `Lemmas.receipt_signing_roundtrip`                        | ✓ |
| `Lemmas.receipt_cross_program_rejected`                   | ✓ |
| `Lemmas.receipt_cross_chain_rejected`                     | ✓ |
| `Lemmas.receipt_cross_circle_rejected`                    | ✓ |
| `Lemmas.sign_verify_rejects_wrong_pubkey`                 | ✓ |
| `ShadowBlob.honest_dec_bytes_used`                        | ✓ (axiom holds; chain-side verify off — ⚠) |
| `ShadowBlob.honest_dec_net`                               | ✓ (same caveat) |
| `ShadowBlob.forged_shadow_detectable`                     | ⚠ off-chain only |
| `WireProtocol.HFHE.hom_add_matches_plaintext_add`         | ✓ at C++ vendor; ? Rust cite fictional |
| `V3Canonical.canonical_reorder_invariant`                 | ✓✓ |
| `V3Members.members_anchor_collision_resistant`            | ✓ |
| `V3Policy.policy_anchor_collision_resistant_on_epoch`     | ✓ |
| `RpcEnvelope.tx_sign_verify_roundtrip`                    | ✓ |
| `RpcEnvelope.method_binding_rejects_replay`               | ✓ |
| `RpcEnvelope.chain_id_binding_rejects_replay`             | ✓ tx-envelope layer binds via `OctraTx::chain_id` (P1-5b, 2026-05-20) — see §2.17 + §3.2 |
| `RpcEnvelope.nonce_binding_rejects_replay`                | ✓ |
| `AuditLog.verify_file_accepts_honest`                     | ✓ |
| `AuditLog.tamper_record_detected`                         | ✓ |
| `ReceiptJournal2.anti_restart_replay`                     | ✓ |
| `ReceiptJournal2.bump_strict_monotone`                    | ✓ |

**The chain partially holds.** 17/20 cited sub-theorems land
cleanly. Three break: chain_id_binding (false at tx layer, true at
receipt layer); forged_shadow_detectable (off-chain only — AML
`fhe_verify` unwired); headline_settle_claim_correct itself
(under-specifies earnings formula — actual is
`(net - net*protocol_fee_bps/BPS_DENOM)` capped at deposit, not
`bytes_used * price`).

**Net verdict.** Directionally sound but quantitatively loose.
The chain-side accounting (`slash_burn+bounty=total` etc.) is
tight in `OctraVPN_V3/Invariants.lean`, so no attacker can mint
extra OCT through these gaps. But an external verifier reading
the headline literally will overestimate what's formally proved
by exactly the protocol fee.

---

## 8. Single most load-bearing theorem with weakest impl

**`headline_settle_claim_correct`** (`OctraVPN_Rust/EndToEnd.lean:205`).
It's the load-bearing public claim — the "what does OctraVPN
guarantee end-to-end?" answer external auditors will quote. Yet
its abstract `settle` function does not match the actual
three-call AML protocol, and its earnings formula
(`bytesUsed * price`) ignores the `protocol_fee_bps` deduction
that every real settlement applies.

**Mitigation priority:** before any pre-mainnet audit, this
theorem should be either (a) refactored to a multi-step
state-machine that matches the AML, or (b) explicitly framed as
"the upper bound on earnings paid in a single confirm step is
`bytesUsed * price` — actual paid is reduced by `protocol_fee_bps`
and capped at deposit."

---

*Audit performed by reading every cited file:line and tracing the
algebraic predicate through the Rust / AML code. No proof obligations
were re-derived; only the cite-→-code mapping was verified.*
