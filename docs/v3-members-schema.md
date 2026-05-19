# OctraVPN v3 — `members.json` schema

Status: v1 frozen 2026-05-19. Encoder in
`crates/octravpn-core/src/v3_members.rs`. Companion docs:
`docs/v3-state-root-schema.md`, `docs/v3-policy-schema.md`,
`docs/v3-circle-resident-architecture.md` §3.2. Closes the long-pending
`ip_salt` ask tracked in task #183.

## 1. What it is

Every tailnet-owner circle holds a sealed asset at
`oct://<tailnet-owner-circle>/tailnet-{id}/members.json`. This is the
canonical, plaintext JSON statement of who is in the tailnet, their
WireGuard public keys, and the salt used to derive per-member tailnet
IPs without exposing the wallet → IP map.

The chain anchors `members.json` directly:

```
tailnet_members_root[tid] == sha256_hex(canonical_bytes(members.json))
```

The chain stores only the 64-char lowercase hex digest. Off-chain
verifiers fetch the file, recompute the SHA-256, and compare against
the on-chain anchor. The chain itself does NOT decode the JSON.

### Why this lives off-chain in v3

In v2 a `Tailnet` struct lived on chain and held an `ip_salt` plus a
small member list. That ran into AML's 4 KiB `map[address]string` cap
the moment tailnets grew past a handful of members. v3 moves the whole
record off chain into this file; the chain holds only the sha256
anchor. The schema is forward-compatible: future tailnets with
thousands of members do not require any chain change.

## 2. v1 fields

| Field             | Type                       | Mandatory | Meaning                                                                                                                  |
| ----------------- | -------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------ |
| `v`               | `u32`                      | yes       | Schema version. v1 = `1`. Bump policy in §5.                                                                             |
| `tailnet_id`      | `u64`                      | yes       | Chain-assigned tailnet identifier. Included so a `members.json` from tailnet A cannot be replayed against tailnet B.     |
| `ip_salt`         | hex-64                     | yes       | Exactly 64 lowercase hex chars (32 random bytes). See §6 for derivation semantics.                                       |
| `members`         | array of `Member`          | yes       | Member set. Canonicalised in sorted-by-`wallet` byte order. Duplicates rejected.                                         |
| `effective_epoch` | `u64`                      | yes       | Chain epoch at which the owner began serving this member set. Monotonic per tailnet (off-chain invariant).               |
| `timestamp_secs`  | `u64`                      | yes       | Wall-clock UNIX seconds at the owner. Informational; skew is expected.                                                   |

### `Member` sub-object

| Field           | Type      | Mandatory | Meaning                                                                                                  |
| --------------- | --------- | --------- | -------------------------------------------------------------------------------------------------------- |
| `wallet`        | `string`  | yes       | Member's Octra address (`oct…`). Non-empty. Prefix-checked here; full payload validation in `octra-core`.|
| `wg_pubkey_b64` | base64-44 | yes       | Member's WireGuard public key, base64 of 32 raw bytes (exactly 44 chars, one `=` pad).                   |
| `joined_epoch`  | `u64`     | yes       | Chain epoch at which this member joined the tailnet.                                                     |

### Unknown fields

Any JSON keys not listed above are preserved verbatim under the
decoder's `unknown` bucket (`#[serde(flatten)] BTreeMap`) and re-emitted
during canonical encoding. A v1 verifier can therefore compute a
correct `tailnet_members_root` for a v2-produced file even if it doesn't
understand the new fields.

## 3. Canonicalization rules

The exact byte sequence whose SHA-256 flows into the on-chain
`tailnet_members_root` is produced by
`TailnetMembers::canonical_bytes()`. The rules mirror `v3_state_root.rs`
and `v3_policy.rs` exactly — see `docs/v3-policy-schema.md` §3 for the
canonical formulation. In brief:

1. UTF-8, no BOM, no trailing newline, no whitespace anywhere.
2. Object keys emitted in lex (byte) order — top level, member
   sub-objects, and any `unknown` keys.
3. Integers as bare decimal digits (serde_json default `Display`).
4. Strings: serde_json's default escape rules. ASCII v1 fields
   round-trip trivially; unicode in future `unknown` fields MUST be
   NFC-normalised by the producer.
5. Optional `None` fields OMITTED entirely (no `"field":null`). v1
   has no optional fields, but the rule is preserved forward.

### 3.1 The member-sort rule (load-bearing)

`members` is sorted by `wallet` in lexicographic byte order on the
UTF-8 encoding BEFORE the array is serialised. This is a schema-level
invariant, not a convention:

- Two `TailnetMembers` values that differ only in the in-memory order
  of `members` MUST produce identical canonical bytes (and therefore
  the same SHA-256 hash).
- Duplicate `wallet` entries are rejected by `validate()`; the
  canonical form never contains two members with the same wallet.
- The sort is performed inside `canonical_bytes()` on a clone, so the
  caller's in-memory `Vec<Member>` is not mutated.

This rule lets clients build the members list in whatever order is
convenient (chronological by join, alphabetical, whatever) without
worrying about hash stability.

## 4. Hash algorithm

```
let bytes  = TailnetMembers::canonical_bytes(&m)?;   // §3
let digest = Sha256::digest(&bytes);                  // sha2 crate
let hash   = hex::encode(digest);                     // lowercase 64 chars
```

That string is the value placed into the chain's `tailnet_members_root`
map under the tailnet's id. The chain enforces `len(arg) == 64`
(transitively, via the AML hex-anchor convention from
`docs/v3-circle-resident-architecture.md`); it does not recompute the
hash.

## 5. Versioning policy

- **`v` is incremented** ONLY for breaking changes: field removal,
  field rename, semantics shift on an existing field, or a change to
  the canonicalisation algorithm.
- **Adding a new optional field** does NOT bump `v`. New encoders emit
  the field; old decoders flow it through `unknown` and round-trip the
  hash correctly.
- **Adding a new mandatory field** DOES bump `v`, because old encoders
  would otherwise produce a JSON that fails strict decode at new
  verifiers.
- **Changing the member-sort rule** DOES bump `v` (it changes the
  canonical bytes for every existing tailnet).

### Decoder behaviour by version

| `TailnetMembers::decode` | `v == 1` | `v != 1`                              |
| ------------------------ | -------- | ------------------------------------- |
| Strict path              | accepts  | `V3MembersError::UnsupportedVersion`  |
| `decode_lenient`         | accepts  | accepts, preserves unknown fields     |

Verifiers that recompute `tailnet_members_root` and ONLY need the SHA
to match should use `decode_lenient`; they don't need to understand
new fields to confirm the commitment is intact. Verifiers that act on
field semantics (e.g. "is this wallet in the tailnet right now?") must
use the strict path and refuse to act until they're upgraded.

## 6. `ip_salt` semantics

### 6.1 Size + format

`ip_salt` is exactly **64 lowercase hex characters** representing **32
random bytes**, drawn from a CSPRNG at tailnet-creation time. The
length is fixed by `IP_SALT_HEX_LEN = 64`; encoding is lowercase hex to
stay aligned with AML's `sha256()` output discipline (the chain
consumes 64-char lowercase hex everywhere — keeping schema fields in
the same shape means verifiers never have to case-fold).

Producers MUST NOT rotate `ip_salt`. Rotation requires re-issuing
every member's tailnet IP, which is a heavier operation than the
schema is designed for. If a salt rotation is genuinely needed, do it
by creating a fresh tailnet with a new `tailnet_id` and migrating
members across.

### 6.2 Per-member IP derivation

Clients derive per-member tailnet IPs as a deterministic function of
`(wallet, ip_salt)`:

```
let h = sha256(ip_salt_hex_bytes || wallet_utf8_bytes)
let ip_suffix = first_N_bits(h)               // N == CIDR host width
let member_ip = tailnet_cidr.network_addr() | ip_suffix
```

The tailnet's CIDR + prefix length live in the sibling
`tailnet-{id}/config.json` (out of scope; see §3.2 of the
circle-resident architecture doc). The exact mixing function is NOT
pinned by this schema — clients may evolve it provided the property
below holds and any change is captured by a `v` bump.

**Property:** an observer with only the on-chain `tailnet_members_root`
and wire-side per-packet IPs cannot link a tailnet IP back to a wallet
without the salt. The salt is held by tailnet owners + members (anyone
with access to the sealed `members.json`), but not by non-member chain
observers.

The concrete client-side `ip_alloc` impl is TBD — link the mesh
crate's module here once it lands.

## 7. Worked example

Tailnet `42` owned by a circle that holds three members — Alice, Bob,
Carol — added in that order at chain epochs 100, 105, 110. Effective
epoch `7`, wall-clock `1_705_000_000`.

### Fixed inputs (for deterministic fixture)

- `ip_salt = "a".repeat(64)` (32 bytes of `0x61` rendered as hex).
- Alice's WG pubkey: 32 bytes of `0x11` → base64
  `ERERERERERERERERERERERERERERERERERERERERERE=`.
- Bob's WG pubkey: 32 bytes of `0x22` → base64
  `IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=`.
- Carol's WG pubkey: 32 bytes of `0x33` → base64
  `MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=`.

### Rust source

```rust
use octravpn_core::v3_members::{Member, TailnetMembers};

// Members passed in REVERSE wallet order — canonical_bytes() sorts.
let m = TailnetMembers::new_v1(
    42,
    "a".repeat(64),
    vec![
        Member { wallet: "octcarol00000000000000000000000000000000000000".into(),
                 wg_pubkey_b64: "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=".into(),
                 joined_epoch: 110 },
        Member { wallet: "octbob0000000000000000000000000000000000000000".into(),
                 wg_pubkey_b64: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=".into(),
                 joined_epoch: 105 },
        Member { wallet: "octalice00000000000000000000000000000000000000".into(),
                 wg_pubkey_b64: "ERERERERERERERERERERERERERERERERERERERERERE=".into(),
                 joined_epoch: 100 },
    ],
    7,
    1_705_000_000,
);
let members_root = m.hash_hex().expect("hash");
```

### Canonical JSON bytes

```json
{"effective_epoch":7,"ip_salt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","members":[{"joined_epoch":100,"wallet":"octalice00000000000000000000000000000000000000","wg_pubkey_b64":"ERERERERERERERERERERERERERERERERERERERERERE="},{"joined_epoch":105,"wallet":"octbob0000000000000000000000000000000000000000","wg_pubkey_b64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="},{"joined_epoch":110,"wallet":"octcarol00000000000000000000000000000000000000","wg_pubkey_b64":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="}],"tailnet_id":42,"timestamp_secs":1705000000,"v":1}
```

Note: zero whitespace, top-level keys in lex order
(`effective_epoch` < `ip_salt` < `members` < `tailnet_id` <
`timestamp_secs` < `v`); each member's keys in lex order
(`joined_epoch` < `wallet` < `wg_pubkey_b64`); members sorted by wallet
(alice < bob < carol) regardless of input order. This is the byte
sequence the tailnet owner seals at
`oct://<tailnet-owner-circle>/tailnet-42/members.json`.

### Members root (locked anchor)

```
sha256_hex(canonical_bytes) =
  5a4cd4f99acf35e4fbafa2663710f476a4e5c52c71edf74c40a8d0375160cc15
```

This is the value that flows into the chain's `tailnet_members_root[42]`
via `update_members_root(42, "5a4cd4f9...0cc15")`. The locked-anchor
test `worked_example_hash_is_stable` in `v3_members.rs` asserts this
exact string; if the test trips, this doc fixture must be updated in
lockstep (never just the test).

## 8. Verifier algorithm (reference)

```text
INPUT: tailnet_id, expected_members_root (from chain)
1. Fetch the sealed asset at
   oct://<tailnet-owner-circle>/tailnet-{tailnet_id}/members.json.
2. let m = TailnetMembers::decode_lenient(json_bytes)
3. assert m.tailnet_id == tailnet_id   // replay defence
4. let recomputed = m.hash_hex()
5. assert recomputed == expected_members_root
6. (optionally) TailnetMembers::decode strict — only if you act on
   fields like wallet membership or per-member WG keys
```

Step 3 is required because the same `members.json` blob could
otherwise be sealed under a different resource key and pointed at by a
different tailnet's `tailnet_members_root`. Binding `tailnet_id` into
the canonical bytes makes that replay impossible.

## 9. Out of scope for v1

- **Per-member sealed keys** (`sealed-keys/{member}.bin`), **ACL Merkle
  root** (`acl-root`), **tailnet config** (`config.json`) — sibling
  assets with their own schemas.
- **Signatures on `members.json`.** Authority comes from the chain's
  `update_members_root` tx (gated on `tailnet_owner`); no inner sig.
- **HFHE-encrypted member set.** Future privacy feature; additive
  under §5's "optional new field" rule, no `v` bump.

## 10. Implementation pointer

`crates/octravpn-core/src/v3_members.rs`. Tests (20 total) cover:

- round-trip encode → decode equality
- determinism under repeated calls
- member-sort determinism (input order doesn't change hash)
- canonical form (sorted keys, no whitespace)
- `ip_salt` validation (wrong length, uppercase, non-hex)
- `wg_pubkey_b64` validation (length, base64, decoded-length)
- empty wallet rejection
- bad wallet prefix rejection
- duplicate wallet rejection
- forward-compat: v(N+1) fields preserved by v(N) decoder
- omits unknown by default unless flatten-decoded
- unicode in `unknown` fields round-trips byte-identical
- cross-check: hash matches independent `Sha256::digest`
- worked-example anchor locked at the value in §7

The locked fixture fails-loud if the canonical encoder drifts.
