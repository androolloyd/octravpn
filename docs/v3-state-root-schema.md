# OctraVPN v3 — `state-root.json` schema

Status: v1 frozen 2026-05-18. Encoder/decoder lives in
`crates/octravpn-core/src/v3_state_root.rs`. Companion doc:
`docs/v3-circle-resident-architecture.md` (§3.1 references this file).

## 1. What it is

Every operator circle holds a sealed asset at
`oct://<circle_id>/state-root.json`. This is the canonical, plaintext
JSON statement of the operator's current commitments (policy, WireGuard
identity, ACL, attestation, …). The chain stores a single 64-char
lowercase hex anchor:

```
circle_state_root[circle] = sha256_hex(canonical_bytes(state-root.json))
```

Verifiers fetch the JSON, recompute SHA-256, compare to the on-chain
anchor. The chain itself does NOT parse or interpret the JSON.

## 2. v1 fields

| Field             | Type             | Mandatory | Meaning                                                                                          |
| ----------------- | ---------------- | --------- | ------------------------------------------------------------------------------------------------ |
| `v`               | `u32`            | yes       | Schema version. v1 = `1`. Bump policy in §5.                                                     |
| `circle_id`       | `string`         | yes       | `oct…` display address. Self-binds the file to its hosting circle.                               |
| `policy_hash`     | hex64            | yes       | Lowercase hex SHA-256 of the sealed `oct://<circle_id>/policy.json`.                             |
| `wg_pubkey_hash`  | hex64            | yes       | Lowercase hex SHA-256 of the operator's WG public key (raw 32-byte form, NOT base64).            |
| `attestation_hash`| hex64 \| absent  | no        | Hex SHA-256 of `oct://<circle_id>/attestation.json`. **Omitted entirely when no attestation.**   |
| `region`          | `string`         | yes       | Freeform region tag (e.g. `"us-east-1"`). Non-empty. Display-only.                               |
| `member_count`    | `u32`            | yes       | Observability cache of tailnet member count. NOT authoritative.                                  |
| `epoch`           | `u64`            | yes       | Chain epoch at which this state was committed. Monotonic per circle.                             |
| `timestamp_secs`  | `u64`            | yes       | Wall-clock UNIX seconds at the operator. Informational; skew is expected.                        |

`hex64` = exactly 64 ASCII characters, all `[0-9a-f]` (lowercase only).
The AML runtime's `sha256()` builtin emits lowercase hex; mixing cases
would silently break the on-chain anchor comparison.

### Unknown fields

Any JSON keys not listed above are preserved verbatim under the
decoder's `unknown` bucket (`#[serde(flatten)] BTreeMap`) and re-emitted
during canonical encoding. This lets a v1 verifier compute a correct
anchor for a v2-produced file even if it doesn't know what the new
fields mean.

## 3. Canonicalization rules

The exact byte sequence committed on chain is produced by
`StateRoot::canonical_bytes()`. The rules:

1. **UTF-8** output, no BOM, no trailing newline.
2. **No whitespace** between tokens. The only structural separators are
   `,` between siblings, `:` between key and value, and the literal
   `{}` / `[]` brackets.
3. **Object keys** are emitted in lexicographic byte order on their UTF-8
   encoding. This applies to nested objects and to any `unknown` keys
   the v1 decoder preserved.
4. **Numbers** use serde_json's default `Display` form — bare decimal
   digits, no leading zeros, no `+`/`-` sign for non-negative values,
   no scientific notation, no fractional part for integer fields.
5. **Strings** use serde_json's default JSON-string escape rules. v1
   field values are ASCII; future fields containing non-ASCII strings
   MUST be NFC-normalized before encoding so distinct producers agree
   on byte form.
6. **Optional fields with `None`** are OMITTED from the output entirely.
   They do NOT appear as `"field":null`. This keeps the canonical bytes
   stable as we add new nullable fields over time.
7. **Booleans** (none in v1, but possible later) are `true` / `false`
   literals.

`serde_json::to_string` is NOT canonical out of the box (it preserves
insertion order). The encoder walks the parsed `Value` tree and
re-emits each object with sorted keys.

## 4. Anchor algorithm

```
let bytes  = StateRoot::canonical_bytes(&sr)?;      // §3
let digest = Sha256::digest(&bytes);                // sha2 crate
let anchor = hex::encode(digest);                   // lowercase 64 chars
```

That string is what flows into AML's `register_circle(circle,
state_root, …)` and `update_circle_state(circle, new_state_root)`. The
chain enforces `len(state_root) == 64` (see `main-v3.aml` lines 282,
319, 423) but does not validate hex-character set or recompute the hash.
All semantic integrity is off-chain.

## 5. Versioning policy

- **`v` is incremented** ONLY for breaking changes: field removal,
  field rename, semantics shift on an existing field.
- **Adding a new optional field** does NOT bump `v`. New encoders emit
  the field; old decoders flow it through `unknown` and round-trip the
  anchor correctly.
- **Adding a new mandatory field** DOES bump `v`, because old encoders
  would otherwise produce a JSON that fails strict decode at new
  verifiers.

### Decoder behaviour by version

| `StateRoot::decode`         | `v == 1`  | `v != 1`                              |
| --------------------------- | --------- | ------------------------------------- |
| Strict path                 | accepts   | `StateRootError::UnsupportedVersion`  |
| `decode_lenient`            | accepts   | accepts, preserves unknown fields     |

Verifiers that recompute the on-chain anchor and ONLY need the SHA to
match should use `decode_lenient`; they don't need to understand the
new fields to confirm the commitment is intact. Verifiers that act on
field semantics (e.g. "is this operator's policy still pointing at
expected hash X?") must use the strict path and refuse to act until
they're upgraded.

## 6. Worked example

Operator at circle `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`,
running an attested exit in `us-east-1`, with 42 tailnet members
committed at epoch 12345.

### Rust source

```rust
use octravpn_core::v3_state_root::StateRoot;

let sr = StateRoot::new_v1(
    "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    Some("3333333333333333333333333333333333333333333333333333333333333333".into()),
    "us-east-1",
    42,
    12345,
    1_705_000_000,
);
let anchor = sr.anchor_hex().unwrap();
```

### Canonical JSON bytes

```json
{"attestation_hash":"3333333333333333333333333333333333333333333333333333333333333333","circle_id":"oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3","epoch":12345,"member_count":42,"policy_hash":"1111111111111111111111111111111111111111111111111111111111111111","region":"us-east-1","timestamp_secs":1705000000,"v":1,"wg_pubkey_hash":"2222222222222222222222222222222222222222222222222222222222222222"}
```

Note: zero whitespace, keys sorted lexicographically
(`attestation_hash` < `circle_id` < `epoch` < `member_count` <
`policy_hash` < `region` < `timestamp_secs` < `v` < `wg_pubkey_hash`).
This is what the operator seals at `oct://<circle_id>/state-root.json`.

### Anchor

```
sha256_hex(canonical_bytes) =
  6dc60d262d2f232b3b90d260e789ee5a0b6b00f35637153665b61eadc64a2700
```

This is the value passed to AML:

```
update_circle_state(
  circle = oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3,
  new_state_root = "6dc60d262d2f232b3b90d260e789ee5a0b6b00f35637153665b61eadc64a2700"
)
```

### Variant: same operator, no attestation, smaller commitment

For an operator without remote attestation (most devnet operators
today), `attestation_hash` is omitted. Same `policy_hash` and
`wg_pubkey_hash` as above; region `"home-server"`, no members,
epoch 7:

```json
{"circle_id":"oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3","epoch":7,"member_count":0,"policy_hash":"1111111111111111111111111111111111111111111111111111111111111111","region":"home-server","timestamp_secs":1705000000,"v":1,"wg_pubkey_hash":"2222222222222222222222222222222222222222222222222222222222222222"}
```

Anchor:

```
6806061a09d4cf8586c8253823ad9c503cc25eaa437edab1d595eac3980d4d60
```

Note `attestation_hash` is absent from the JSON (not present as
`"attestation_hash":null`).

## 7. Verifier algorithm (reference)

```text
INPUT: circle_id, expected_anchor (from chain)
1. Fetch the sealed asset at oct://<circle_id>/state-root.json.
2. let sr = StateRoot::decode_lenient(json_bytes)
3. assert sr.circle_id == circle_id    // self-binding
4. let recomputed = sr.anchor_hex()
5. assert recomputed == expected_anchor // commitment intact
6. (optionally) StateRoot::decode strict — only if you act on fields
```

Step 2 vs step 6: lenient is sufficient for the anchor recompute;
strict is required only when consuming semantic fields.

## 8. Things explicitly out of scope for v1

- **Signatures on `state-root.json`.** The off-chain `state-root.json`
  is sealed inside the operator's circle. Authority is established by
  the chain's `update_circle_state` tx, which is already signed by the
  circle owner. No additional inner signature.
- **HFHE / encrypted-state commitments.** When the chain ships
  `fhe_*`, those commitments will be added as new optional fields
  without bumping `v` (per §5).
- **Per-member receipts or per-session data.** Those live in
  `oct://<circle_id>/receipts/{epoch}.json`, anchored separately.
- **ACL contents.** Member set lives in the tailnet-owner circle's
  `members.json`; this file commits only an observability count.

## 9. Implementation pointer

`crates/octravpn-core/src/v3_state_root.rs`. Tests cover:

- round-trip encode → decode equality
- determinism under repeated calls
- determinism under shuffled input key order
- canonical form (sorted keys, no whitespace)
- `None` optional fields are omitted
- hash length / lowercase-hex validation
- empty-`circle_id` rejection
- forward-compat: v(N+1) fields preserved by v(N) decoder
- worked-example anchor locked

The locked fixture in `worked_example_anchor_is_stable` will fail-loud
if the canonical encoder ever drifts from the rules above.
