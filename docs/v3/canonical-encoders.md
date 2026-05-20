# v3 canonical encoders

The chain stores 64-char hex SHA-256 anchors. The bytes hashed are
**canonical JSON** produced by Rust encoders in
[`crates/octravpn-core/src/`](../../crates/octravpn-core/src/):

- [`v3_canonical.rs`](../../crates/octravpn-core/src/v3_canonical.rs) — shared canonical-JSON walker + `sha256_hex` + `check_hash`.
- [`v3_state_root.rs`](../../crates/octravpn-core/src/v3_state_root.rs) — operator `state-root.json` schema + anchor.
- [`v3_policy.rs`](../../crates/octravpn-core/src/v3_policy.rs) — operator `policy.json` schema + anchor.
- [`v3_members.rs`](../../crates/octravpn-core/src/v3_members.rs) — tailnet `members.json` schema + anchor.

One byte of canonicalisation divergence between sender and verifier
= silent on-chain anchor desync. The encoders are the single source
of truth.

## The four rules

Locked in [`v3_canonical.rs:9-23`](../../crates/octravpn-core/src/v3_canonical.rs).

1. **Lexicographic key order.** JSON object keys are sorted by
   UTF-8 byte order before serialisation. `serde_json::Map`
   preserves insertion order; `canonical_write` re-sorts on every
   object. Verified by `canonical_keys_sorted`
   ([`proofs/lean/WireProtocol/V3Canonical.lean:218`](../../proofs/lean/WireProtocol/V3Canonical.lean)).
2. **No whitespace.** Tokens are concatenated directly; only `,`
   and `:` separate structural elements. No leading-zero numbers.
3. **Standard JSON escapes for strings.** `serde_json`'s default
   escape table; no implementation-defined deviations.
4. **64-char lowercase hex for all hash fields.** Enforced by
   `check_hash` at producer side. Lean references:
   `check_hash_length_required` (:279), `check_hash_rejects_non_hex` (:290),
   `check_hash_rejects_uppercase` (:299), `check_hash_accepts_canonical` (:304).

## Hex hash invariant

The chain stores `bytes` as JSON strings (memory:
`octra_aml_bytes_encoding.md`); `len()` is character count. So every
"32-byte SHA-256" anchor is actually 64 lowercase hex chars. The
canonical encoder NEVER emits uppercase, leading zeros stripped, or
short forms.

Lean theorems pinning the shape:

- `hex_hash_len_is_64` ([`V3Canonical.lean:275`](../../proofs/lean/WireProtocol/V3Canonical.lean)) — `HEX_HASH_LEN = 64`.
- `sha256_hex_length_is_64` (:317) — for any input, output is 64 chars.
- `sha256_hex_lowercase` (:321) — output is in `[0-9a-f]`.
- `sha256_hex_deterministic` (:325) — same input → same output.
- `anchor_distinct_inputs_distinct` (:333) — distinct inputs → distinct anchors (collision-resistance lifted to the schema layer).

AML-side: every entrypoint that takes a bytes argument enforces
`len(arg) == 64` before storing:
- `register_circle` ([`program/main-v3.aml:282`](../../program/main-v3.aml))
- `update_circle_state` ([`:319`](../../program/main-v3.aml))
- `create_tailnet` ([`:423`](../../program/main-v3.aml))
- `update_members_root` ([`:451`](../../program/main-v3.aml))

## State-root anchor

Source: [`crates/octravpn-core/src/v3_state_root.rs`](../../crates/octravpn-core/src/v3_state_root.rs).
Companion doc: [`../v3-state-root-schema.md`](../v3-state-root-schema.md).

```text
StateRoot {
  v:               u32   = 1                 // schema version
  circle_id:       String                    // oct… display, self-binding
  policy_hash:     String (hex64)            // sha256(canonical(policy.json))
  wg_pubkey_hash:  String (hex64)            // sha256(wg_pubkey_32B_raw)
  attestation_hash: Option<String> (hex64)   // omitted when None (NOT "field":null)
  region:          String                    // non-empty
  member_count:    u32
  epoch:           u64                       // monotonic per circle
  timestamp_secs:  u64                       // informational
  unknown:         BTreeMap<String, Value>   // forward-compat verbatim
}
```

Field-by-field semantics live at
[`v3_state_root.rs:80-160`](../../crates/octravpn-core/src/v3_state_root.rs). Key invariants:

- `circle_id` is **self-binding**: a verifier fetching
  `state-root.json` from circle X that reports `circle_id != X`
  MUST reject. Without it a malicious operator could host another's
  state-root.json under their own circle.
- `attestation_hash: None` is **omitted from canonical JSON**, NOT
  emitted as `"field":null`. Keeps the byte string stable as new
  nullable fields are added.
- `unknown` is `#[serde(flatten)]`-ed so a v2 anchor parsed by a v1
  verifier round-trips through `canonical_bytes()` unchanged. The
  anchor remains stable for upgraded peers.

The anchor itself is `sha256_hex(canonical_bytes(StateRoot))`,
stored in `circle_state_root[circle]` ([`program/main-v3.aml:88`](../../program/main-v3.aml)).

## Policy anchor

Source: [`v3_policy.rs`](../../crates/octravpn-core/src/v3_policy.rs).
Companion doc: [`../v3-policy-schema.md`](../v3-policy-schema.md).

The `policy.json` sealed at `oct://<circle>/policy.json` contains
the operator's endpoint URL ciphertext, WG pubkey ciphertext, region,
per-class tariffs, and ACL hash. It is NOT stored on chain; its
SHA-256 lives inside `state-root.json`'s `policy_hash` field. So
the chain anchors policy transitively via state-root.

Lean coverage (5 theorems, line refs in
[`proofs/lean/WireProtocol/V3Policy.lean`](../../proofs/lean/WireProtocol/V3Policy.lean)):

- `policy_anchor_deterministic` (:84)
- `policy_anchor_field_reorder_invariant` (:97)
- `policy_anchor_collision_resistant_on_epoch` (:111)
- `policy_anchor_includes_acl_hash` (:129)
- `policy_anchor_size` (:145)

## Members anchor

Source: [`v3_members.rs`](../../crates/octravpn-core/src/v3_members.rs).
Companion doc: [`../v3-members-schema.md`](../v3-members-schema.md).

`members.json` lists the tailnet's authorised members (sorted) +
`ip_salt` + version. Its canonical sha256 lives in
`tailnet_members_root[tid]` ([`program/main-v3.aml:103`](../../program/main-v3.aml)).

Lean coverage (5 theorems):

- `members_anchor_deterministic` ([`V3Members.lean:167`](../../proofs/lean/WireProtocol/V3Members.lean))
- `members_anchor_field_reorder_invariant` (:182)
- `members_anchor_member_reorder_invariant` (:199) — member-list
  ordering is canonicalised internally
- `members_anchor_collision_resistant` (:217)
- `members_anchor_size_bounded` (:235)

## Earnings hash chain

Not a JSON anchor — a SHA-256 hash chain over per-settle blindings.
Defined in AML at [`program/main-v3.aml:591-594`](../../program/main-v3.aml):

```text
bh        = sha256(settle_blinding)
new_head  = sha256(prev_head ‖ bh)
```

Genesis is `sha256(state_root)` at `register_circle`
([`program/main-v3.aml:303`](../../program/main-v3.aml)) — NOT the
AML default-zero string. Off-chain verification:
[`docker/devnet/v3-smoke.sh:87-98`](../../docker/devnet/v3-smoke.sh)
recomputes `head_1 = sha256(sha256(state_root_hex) ‖ sha256(blinding_hex))`
and asserts byte-for-byte match with `get_earnings_chain`.

The chain commit uses AML's string `+` to concatenate the two
64-char hex strings before hashing — so the bytes hashed are 128
hex chars, not 32 raw bytes. Off-chain replay MUST do the same
string-concat-then-hash, NOT raw-bytes-concat-then-hash.

## Property-test coverage

`v3_canonical.rs` carries 6 `proptest!` properties under a 256-case
budget ([`v3_canonical.rs`](../../crates/octravpn-core/src/v3_canonical.rs)).
The full v3 property surface across `v3_canonical.rs` + `v3_state_root.rs`
+ `v3_policy.rs` + `v3_members.rs` adds up to **23 proptest cases**
exercising:

- Idempotence of `canonical_write` on arbitrary `Value` trees.
- Object-key permutation invariance.
- Hash field length, case, and character-set invariants.
- Cross-schema collision avoidance (state-root vs policy vs members).
- Round-trip stability of unknown-field flattening (forward-compat).

Together with the **14 Lean theorems** in `V3Canonical.lean` + the
**5 + 5** in `V3Policy.lean` / `V3Members.lean`, the canonical layer
has 24 mechanised proofs and 23 proptest cases — the largest
formally-anchored surface in v3.

## What to check when adding a new anchor

1. Add the schema struct + `canonical_bytes()` impl alongside the
   existing modules.
2. Wire `check_hash` on every input hash field.
3. Add a Lean module proving deterministic + reorder-invariant +
   collision-resistant for the new schema.
4. Add proptest properties: idempotence, key-permutation invariance,
   bytes-stability across unknown-field expansion.
5. Bump the AML to take the new anchor (`bytes`, `len() == 64`).
6. Update [`call-flows.md`](call-flows.md) +
   [`data-model.md`](data-model.md) to register the new anchor map.
