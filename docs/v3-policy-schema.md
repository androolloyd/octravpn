# OctraVPN v3 — `policy.json` schema

Status: v1 frozen 2026-05-19. Encoder/decoder lives in
`crates/octravpn-core/src/v3_policy.rs`. Companion docs:
`docs/v3-state-root-schema.md` (consumes this file's hash via
`policy_hash`), `docs/v3-circle-resident-architecture.md` §3.1.

## 1. What it is

Every operator circle holds a sealed asset at
`oct://<circle_id>/policy.json`. This is the canonical, plaintext JSON
statement of how a client should dial the operator and what the
operator charges — endpoint URL, WireGuard public key, region tag,
price tiers, optional attestation pointer.

The chain does NOT anchor `policy.json` directly. Instead:

```
state_root.policy_hash    == sha256_hex(canonical_bytes(policy.json))
circle_state_root[circle] == sha256_hex(canonical_bytes(state-root.json))
```

So `policy.json` is committed transitively: its SHA-256 is one field
inside `state-root.json`, and `state-root.json`'s SHA-256 is the
on-chain `circle_state_root`. Verifiers fetch both files, recompute
both hashes, and check the chain anchor at the top.

## 2. v1 fields

| Field                   | Type            | Mandatory | Meaning                                                                                                |
| ----------------------- | --------------- | --------- | ------------------------------------------------------------------------------------------------------ |
| `v`                     | `u32`           | yes       | Schema version. v1 = `1`. Bump policy in §5.                                                           |
| `endpoint`              | `string`        | yes       | Dial target the client should use (e.g. `"wg://relay.example:51820"`). Non-empty. Plaintext in v1.     |
| `wg_pubkey_b64`         | base64-44       | yes       | Operator's WireGuard public key, base64 of 32 raw bytes (exactly 44 chars, one `=` pad).               |
| `region`                | `string`        | yes       | Freeform region tag (e.g. `"us-east-1"`, `"home-server"`). Non-empty. Display-only. NFC for unicode.   |
| `price_per_mb_shared`   | `u64`           | yes       | OU-per-MB charged to clients NOT on a tailnet shared with this operator.                               |
| `price_per_mb_internal` | `u64`           | yes       | OU-per-MB charged to clients on the same tailnet as this operator (typically lower, often zero).       |
| `effective_epoch`       | `u64`           | yes       | Chain epoch at which the operator began serving this policy. Monotonic per circle. Stale-detect knob.  |
| `timestamp_secs`        | `u64`           | yes       | Wall-clock UNIX seconds at the operator. Informational; skew is expected.                              |
| `attestation_url`       | `string` \| absent | no     | Pointer at a remote-attestation bundle. **Omitted entirely when no attestation.**                      |

### Why `wg_pubkey_b64` and not `wg_pubkey_hash`

Clients have to actually open a WireGuard tunnel with the operator,
which requires the real 32-byte public key — not a hash of it. The
hash is what `state-root.json` commits via its `wg_pubkey_hash`
field; the key itself lives here.

The textual form is standard base64 (the same form `wg` and
`boringtun` accept) so a client can pipe the value straight into its
WG config without an extra decode-and-re-encode step.

### Unknown fields

Any JSON keys not listed above are preserved verbatim under the
decoder's `unknown` bucket (`#[serde(flatten)] BTreeMap`) and
re-emitted during canonical encoding. A v1 verifier can therefore
compute a correct `policy_hash` for a v2-produced file even if it
doesn't understand the new fields.

## 3. Canonicalization rules

The exact byte sequence whose SHA-256 flows into `policy_hash` is
produced by `OperatorPolicy::canonical_bytes()`. The rules mirror
`v3_state_root.rs` exactly — both schemas MUST canonicalise the same
way:

1. **UTF-8** output, no BOM, no trailing newline.
2. **No whitespace** between tokens. The only structural separators
   are `,` between siblings, `:` between key and value, and the
   literal `{}` / `[]` brackets.
3. **Object keys** are emitted in lexicographic byte order on their
   UTF-8 encoding. This applies to nested objects and to any
   `unknown` keys the v1 decoder preserved.
4. **Numbers** use serde_json's default `Display` form — bare
   decimal digits, no leading zeros, no `+`/`-` sign for non-negative
   values, no scientific notation, no fractional part for integer
   fields.
5. **Strings** use serde_json's default JSON-string escape rules.
   ASCII fields (`endpoint`, `wg_pubkey_b64`) round-trip trivially.
   `region` admits non-ASCII text and MUST be NFC-normalised by the
   producer so distinct operators agree on byte form.
6. **Optional fields with `None`** are OMITTED from the output
   entirely. They do NOT appear as `"field":null`.
7. **Booleans** (none in v1, but possible later) are `true` / `false`
   literals.

`serde_json::to_string` is NOT canonical out of the box (it preserves
insertion order). The encoder walks the parsed `Value` tree and
re-emits each object with sorted keys.

## 4. Hash algorithm

```
let bytes  = OperatorPolicy::canonical_bytes(&p)?;   // §3
let digest = Sha256::digest(&bytes);                 // sha2 crate
let hash   = hex::encode(digest);                    // lowercase 64 chars
```

That string is the value placed into the `policy_hash` field of
`state-root.json`. The chain enforces `policy_hash` is a 64-char
string (transitively via the state-root anchor); it does not
recompute the hash.

## 5. Versioning policy

- **`v` is incremented** ONLY for breaking changes: field removal,
  field rename, semantics shift on an existing field.
- **Adding a new optional field** does NOT bump `v`. New encoders
  emit the field; old decoders flow it through `unknown` and
  round-trip the hash correctly.
- **Adding a new mandatory field** DOES bump `v`, because old
  encoders would otherwise produce a JSON that fails strict decode
  at new verifiers.

### Decoder behaviour by version

| `OperatorPolicy::decode` | `v == 1` | `v != 1`                            |
| ------------------------ | -------- | ----------------------------------- |
| Strict path              | accepts  | `V3PolicyError::UnsupportedVersion` |
| `decode_lenient`         | accepts  | accepts, preserves unknown fields   |

Verifiers that recompute `state-root.json`'s `policy_hash` and ONLY
need the SHA to match should use `decode_lenient`; they don't need
to understand new fields to confirm the commitment is intact.
Verifiers that act on field semantics (e.g. "is this operator still
charging at most X OU/MB?") must use the strict path and refuse to
act until they're upgraded.

## 6. Worked example

Operator at circle `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`,
running an attested exit in `us-east-1`, serving WG on
`relay.example:51820` for 1000 OU/MB shared / 0 OU/MB internal,
since chain epoch 12345.

### Fixed WG pubkey

To keep the worked example fully deterministic, we use a fixed key
of 32 bytes of `0x11`. Its base64 form:

```
ERERERERERERERERERERERERERERERERERERERERERE=
```

(That's exactly 44 chars including one `=` pad — the invariant
`OperatorPolicy::validate()` enforces.)

### Rust source

```rust
use octravpn_core::v3_policy::OperatorPolicy;

let p = OperatorPolicy::new_v1(
    "wg://relay.example:51820",
    "ERERERERERERERERERERERERERERERERERERERERERE=",
    "us-east-1",
    1000,
    0,
    12345,
    1_705_000_000,
    Some("https://op.example/attestation".into()),
);
let policy_hash = p.hash_hex().unwrap();
```

### Canonical JSON bytes

```json
{"attestation_url":"https://op.example/attestation","effective_epoch":12345,"endpoint":"wg://relay.example:51820","price_per_mb_internal":0,"price_per_mb_shared":1000,"region":"us-east-1","timestamp_secs":1705000000,"v":1,"wg_pubkey_b64":"ERERERERERERERERERERERERERERERERERERERERERE="}
```

Note: zero whitespace, keys sorted lexicographically
(`attestation_url` < `effective_epoch` < `endpoint` <
`price_per_mb_internal` < `price_per_mb_shared` < `region` <
`timestamp_secs` < `v` < `wg_pubkey_b64`). This is the byte sequence
the operator seals at `oct://<circle_id>/policy.json`.

### Policy hash

```
sha256_hex(canonical_bytes) =
  d24ee1b8b9fc41071ffa16fa747626b5e3827ef8a6921eb2108520e1af9ad04f
```

This is the value that flows into `state-root.json`'s `policy_hash`
field. See `docs/v3-state-root-schema.md` §6 for how `state-root.json`
then folds this hash into the chain anchor.

### Variant: same operator, no attestation, home-server region

For an operator without remote attestation (most devnet operators
today), `attestation_url` is omitted. Same `wg_pubkey_b64` and price
tiers as above; region `"home-server"`, `effective_epoch = 7`:

```json
{"effective_epoch":7,"endpoint":"wg://relay.example:51820","price_per_mb_internal":0,"price_per_mb_shared":1000,"region":"home-server","timestamp_secs":1705000000,"v":1,"wg_pubkey_b64":"ERERERERERERERERERERERERERERERERERERERERERE="}
```

Policy hash:

```
0bd6fe41741be1ca2205a8fa92f16fa34a7bd70f3d09ac394f1e0052529cb66c
```

Note `attestation_url` is absent from the JSON (not present as
`"attestation_url":null`).

## 7. Verifier algorithm (reference)

```text
INPUT: circle_id, expected_policy_hash (from state-root.json)
1. Fetch the sealed asset at oct://<circle_id>/policy.json.
2. let p = OperatorPolicy::decode_lenient(json_bytes)
3. let recomputed = p.hash_hex()
4. assert recomputed == expected_policy_hash
5. (optionally) OperatorPolicy::decode strict — only if you act on
   fields like price tiers or endpoint URL
```

Step 2 vs step 5: lenient is sufficient for the hash recompute;
strict is required only when consuming semantic fields.

## 8. Things explicitly out of scope for v1

- **Encrypted endpoint.** v1 `endpoint` is plaintext. Privacy of
  the endpoint URL is a future feature behind HFHE / hidden-exit v2,
  which will add an `endpoint_ct` optional field (encoder unchanged
  per §5).
- **Signatures on `policy.json`.** Authority is established by the
  chain's `update_circle_state` tx that anchors the enclosing
  `state-root.json`. No additional inner signature.
- **ACL / member set.** Lives in the tailnet-owner circle's
  `members.json`, anchored separately.
- **Per-session receipts or per-session prices.** Receipts live at
  `oct://<circle_id>/receipts/{epoch}.json`. The price tiers here
  are the rack-rate the operator advertises; per-session prices are
  signed off-chain at session open.

## 9. Implementation pointer

`crates/octravpn-core/src/v3_policy.rs`. Tests cover:

- round-trip encode → decode equality
- determinism under repeated calls
- determinism under shuffled input key order
- canonical form (sorted keys, no whitespace)
- `None` optional fields are omitted
- WG pubkey textual length / base64 / decoded-length validation
- empty-`endpoint` and empty-`region` rejection
- lowercase-hex helper enforcement (for future hash fields)
- forward-compat: v(N+1) fields preserved by v(N) decoder
- unicode `region` round-trips byte-identical
- worked-example hash locked

The locked fixture in `worked_example_hash_is_stable` will fail-loud
if the canonical encoder ever drifts from the rules above.
