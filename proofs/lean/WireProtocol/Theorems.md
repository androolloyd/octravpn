# Wire-Protocol Theorem Index

Mechanically-checked Lean theorems covering the wire-protocol
primitives that landed during the Tailscale interop work (Walls 1-5).
Companion to the 54 Rust security-primitive theorems in
`OctraVPN_Rust/` (PR #181).

Build: `cd proofs/lean && lake build WireProtocol` — must end with
"Build completed successfully." and zero `sorry` / `admit`.

The Lean code is intentionally non-Mathlib: only core `Lean 4` is
imported, matching `OctraVPN_Rust/Spec.lean`'s constraint.

---

## 1. `WireProtocol.Controlbase`

3-byte / 5-byte header round-trip and length invariants for the
Tailscale `controlbase` framing.

Rust source: `headscale-rs/headscale-api/src/tailscale_wire/controlbase.rs`.

| Theorem                                  | Plain-English statement                                                                                          | Rust function                                            |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `MsgType.fromByte_toByte`                | `fromByte ∘ toByte = some`; the four message-type bytes (1,2,3,4) round-trip.                                    | `MsgType::from_u8` (`controlbase.rs:96-107`)             |
| `MsgType.initiation_toByte_eq_one`       | The Initiation type byte equals 1 (literal from upstream `msgTypeInitiation`).                                   | `controlbase.rs:81`                                      |
| `MsgType.toByte_nonzero_for_regular`     | Any non-Initiation MsgType has a non-zero type byte (so the 3-byte regular path is unambiguous).                 | `controlbase.rs:202-219`                                 |
| `encode_regular_length`                  | A regular header encodes to exactly 3 bytes.                                                                     | `write_frame` (`controlbase.rs:236-243`)                 |
| `encode_initiation_length`               | An initiation header encodes to exactly 5 bytes.                                                                 | `write_initiation` (`controlbase.rs:263-272`)            |
| `header_length_correct`                  | A header always encodes to either 3 or 5 bytes.                                                                  | both encoders                                            |
| `initiation_distinguishable`             | An Initiation header is always 5 bytes on the wire (vs. regular's 3).                                            | `controlbase.rs:18-22`                                   |
| `u16be_destruct`                         | `u16be n` always evaluates to a 2-element list `[b0, b1]`.                                                       | (helper, mirrors `to_be_bytes`)                          |
| `regular_header_round_trip`              | `decode_header (encode_header (Regular mt len)) = some (Regular mt len)` for any non-Initiation `mt`.            | `read_frame` (`controlbase.rs:202-219`)                  |
| `initiation_header_round_trip`           | `decode_header (encode_header (Initiation ver len)) = some (Initiation ver len)` when `ver < 256`.               | `read_frame` (`controlbase.rs:173-200`)                  |
| `header_round_trip`                      | **Top-level round-trip.** For any well-formed header, `decode ∘ encode = some`.                                  | combines both above                                      |
| `example` (anchor)                       | `Initiation(39, 10)` round-trips (39 is the wire protocol version negotiated as of Wall-5).                      | concrete test value                                      |

Axioms introduced in `Controlbase.lean`:

- `u16be_length`, `u16be_injective` — `u16::to_be_bytes` is a length-2
  injection. Mirrors `OctraVPN_Rust/Lemmas.lean`'s `u32be_injective`.
- `u16be_lo_first_byte` — when `n < 256`, the high byte of `u16be n` is 0.
- `decodeU16BE_u16be` — `decodeU16BE` is the inverse of `u16be`.

---

## 2. `WireProtocol.BeNonce`

BE-nonce composition, monotonicity, and replay-window correctness for
the Tailscale-flavoured ChaCha20Poly1305 transport.

Rust source: `headscale-rs/headscale-api/src/tailscale_wire/be_transport.rs`.

| Theorem                                       | Plain-English statement                                                                                                | Rust function                                                |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `nonce_length`                                | `buildNonceBE c` is always 12 bytes.                                                                                   | `nonce_be` (`be_transport.rs:139-143`)                       |
| `nonce_first_four_bytes_zero`                 | `buildNonceBE c |>.take 4 = [0,0,0,0]`. The IETF nonce prefix is zero.                                                  | `let mut n = [0u8; 12]` (`be_transport.rs:140`)              |
| `nonce_byte_zero_at`                          | Index form of the above: byte `i < 4` is zero.                                                                          | (same)                                                       |
| `nonce_be_suffix_is_counter`                  | `nonce[4..12] = counter.to_be_bytes()`.                                                                                | `n[4..12].copy_from_slice(&counter.to_be_bytes())` (`:141`)  |
| `nonce_be_determines_counter`                 | A BE nonce uniquely determines the counter that produced it (within `< 2^64`).                                          | inverse of the construction                                  |
| `counter_monotonic_encrypts_distinct_nonces`  | **Distinct counters ⇒ distinct nonces.** Algebraic claim behind the strict-monotonic replay rule.                       | `BeTransport::encrypt` (`be_transport.rs:195-217`)           |
| `counter_advance_strictly_increases`          | `s.advance.counter = s.counter + 1`. Mirrors the `checked_add(1)` in encrypt/decrypt.                                   | `be_transport.rs:212-215`                                    |
| `replay_window_distinct_nonces`               | **Replay-window correctness.** For `i ≠ j`, the nonces at counter positions `start+i` and `start+j` are distinct.       | upstream "strict monotonic, no sliding window" semantic       |
| `example` (anchor: advance)                   | `({ counter := 0 }).advance.counter = 1` — concrete value witnessing monotonicity.                                      | concrete test value                                          |
| `example` (anchor: length)                    | `(buildNonceBE 0).length = 12` — concrete value witnessing the length invariant.                                        | concrete test value                                          |

Axioms introduced in `BeNonce.lean`:

- `u64be_length`, `u64be_injective` — `u64::to_be_bytes` is a length-8
  injection on `< 2^64`. Same style as the existing `u64be_injective`
  axiom in `OctraVPN_Rust/Lemmas.lean`.

---

## 3. `WireProtocol.HmacToken`

Per-circle HMAC-SHA256 approval token determinism + distinctness +
the functional spec of constant-time check semantics.

Rust source: `crates/octravpn-client/src/portal/routes.rs`, lines 148-164.

| Theorem                                | Plain-English statement                                                                                              | Rust function                                                |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `token_for_deterministic`              | `token_for secret c = token_for secret c` (the function is, well, a function — anchors the determinism claim).        | `PortalState::token_for` (`routes.rs:148-153`)                |
| `token_for_function`                   | Equal `(secret, c)` inputs produce equal tokens.                                                                     | `PortalState::token_for`                                     |
| `hmac_function`                        | HMAC is a function of `(key, message)`.                                                                              | underlying `hmac` crate                                      |
| `token_for_distinct_circles`           | **Distinct circles produce distinct tokens** (under the standard HMAC PRF / collision-resistance axiom).             | `PortalState::token_for`                                     |
| `token_valid_iff_match`                | **Functional spec of `token_valid`.** Returns `true` iff `hex_decode(supplied) = some(canonical_mac)`.                | `PortalState::token_valid` (`routes.rs:156-164`)              |
| `token_valid_self`                     | A token always validates against itself — `token_valid c (token_for c) = true`.                                       | composition of both                                          |
| `token_valid_cross_circle_rejected`    | The token for `c` does **not** validate against a different `c'`.                                                    | `confirm_post` rejection path (`routes.rs:357-378`)           |
| `example` (anchor)                     | A token round-trips through `tokenValid` (concrete instance of `token_valid_self`).                                  | concrete test value                                          |

Axioms introduced in `HmacToken.lean`:

- `hex_roundtrip`, `hexEncode_injective` — `hex::encode` is a bijection
  / its `hex::decode` is the left-inverse.
- `circleIdBytes_injective` — UTF-8 byte view of `String` is injective.
- `hmac_distinct_messages` — standard PRF-style collision-resistance
  for HMAC-SHA256. Same modeling strategy as `Sha256.injective` in
  `OctraVPN_Rust/Spec.lean`.

**Out of scope (assumed primitive):** HMAC-SHA256 cryptographic
strength (RFC 2104, NIST FIPS 198). That's a property of the audited
`hmac` + `sha2` crates; we do not re-prove it.

**Out of scope (runtime side-channel):** The Rust source uses
`subtle::ConstantTimeEq` for `verify_slice`. That's a side-channel
property — Lean proves the **functional** equivalence, which is the
plain `supplied == canonical` predicate.

---

## 4. `WireProtocol.PortalCache`

Approve+unseal cache lifecycle invariants for the portal's in-memory
state.

Rust source: `crates/octravpn-client/src/portal/routes.rs::PortalState`
(lines 88-178).

| Theorem                                | Plain-English statement                                                                                              | Rust function                                                |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `allow_set_monotonic`                  | **`allow` is monotonic.** Approving a circle never removes any other circle from the allow_set.                       | `PortalState::allow` (`routes.rs:173-177`)                    |
| `allow_adds_circle`                    | After `allow c`, `c ∈ allow_set`.                                                                                    | `PortalState::allow`                                          |
| `approve_monotonic`                    | **`approveWithToken` is monotonic** (gated `allow`).                                                                  | `confirm_post` (`routes.rs:357-378`)                          |
| `approve_invalid_token_no_change`      | An invalid token leaves the allow_set unchanged.                                                                     | `confirm_post`'s `if !token_valid { return … }` guard          |
| `unseal_does_not_add_to_allow_set`     | `record_unseal` only touches `unseal_cache`; the allow_set is unaffected.                                            | `PortalState::record_unseal` (`routes.rs:141-145`)            |
| `allow_set_implies_valid_approve`      | **Inductive invariant.** Starting from a state where `c ∉ allow_set`, an arbitrary trace of `approve`+`unseal` ops adds `c` to the allow_set ONLY through an `approve c sup` step whose `tokenValid c sup` was true. | combines all portal mutations            |
| `restart_clears_allow_set`             | Process restart wipes the allow_set.                                                                                 | `PortalState::new` re-allocates (`routes.rs:118-128`)         |
| `restart_clears_unseal_cache`          | Process restart wipes the unseal cache.                                                                              | `PortalState::new`                                            |
| `cache_does_not_outlive_process`       | Top-level statement: both maps are empty after restart.                                                              | (combined)                                                    |
| `post_restart_nothing_allowed`         | After restart, no circle is in the allow_set.                                                                        | (combined)                                                    |
| `example` (anchor)                     | A fresh state plus `approveWithToken c (token_for c)` puts `c` in the allow_set.                                     | concrete test value                                          |

No new axioms introduced; reuses `HmacToken.lean`'s axioms.

---

## 5. `WireProtocol.V3Canonical`

The v3 canonical-JSON encoder + hex-hash discipline. Mirrors
`crates/octravpn-core/src/v3_canonical.rs`, which is the single owner
of the on-chain anchor format for the three v3 schemas
(`v3_state_root`, `v3_policy`, `v3_members`). A one-byte deviation
between producer and verifier silently desyncs transparency, so the
encoder's algebraic properties are pinned here.

Rust source: `crates/octravpn-core/src/v3_canonical.rs`.

| Theorem                              | Plain-English statement                                                                                                  | Rust function / constant                          |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| `canonical_keys_sorted`              | `canonical` always emits an object's keys in sorted lex-byte order (it calls `sortByKey` before emitting).               | `canonical_write` object branch (`:76-101`)       |
| `canonical_reorder_invariant`        | **Two objects with the same multiset of (key, value) entries produce identical canonical bytes.** Load-bearing.          | `canonical_write` object branch                   |
| `canonical_determinism`              | `canonical` is a function — same input, same output.                                                                     | `canonical_write` (whole)                         |
| `canonical_idempotent`               | Canonicalising a pre-sorted entry list is a no-op for the encoder.                                                       | `canonical_write` + `sortByKey_idempotent`        |
| `canonical_string_injective`         | Two distinct JSON strings produce distinct canonical bytes.                                                              | `write_json_string` (`:105-109`)                  |
| `hex_hash_len_is_64`                 | `HEX_HASH_LEN = 64` by definition.                                                                                       | `HEX_HASH_LEN: usize = 64` (`:28`)                |
| `check_hash_length_required`         | A string whose length is not 64 is rejected by `checkHash`.                                                              | `check_hash` (`:44-52`)                           |
| `check_hash_rejects_non_hex`         | Any byte outside `[0-9a-f]` causes `checkHash` to return false.                                                          | `check_hash` (`:48`)                              |
| `check_hash_rejects_uppercase`       | **Specialisation: any uppercase A-F is rejected** (mixed-case anchors must never round-trip).                            | `check_hash` (same)                               |
| `check_hash_accepts_canonical`       | A 64-byte lowercase-hex string is accepted.                                                                              | `check_hash` (same)                               |
| `sha256_hex_length_is_64`            | `sha256_hex` always returns 64 bytes (matches the chain rule `len(arg) == HEX_HASH_LEN`).                                | `sha256_hex` (`:32-36`)                           |
| `sha256_hex_lowercase`               | `sha256_hex` always returns bytes in the lowercase-hex alphabet.                                                         | `sha256_hex` (same)                               |
| `sha256_hex_deterministic`           | `sha256_hex` is a deterministic function.                                                                                | `sha256_hex` (same)                               |
| `anchor_distinct_inputs_distinct`    | **Distinct canonical bytes ⇒ distinct on-chain anchors** (under SHA-256 collision-resistance). Verifiers can detect drift. | `sha256_hex ∘ canonical_write`                    |
| `example` (HEX_HASH_LEN anchor)      | `HEX_HASH_LEN = 64` literally.                                                                                           | concrete                                          |
| `example` (canonical null anchor)    | `canonical null = b"null"`.                                                                                              | concrete                                          |
| `example` (canonical bool anchor)    | `canonical (bool true) = b"true"`.                                                                                       | concrete                                          |

Axioms introduced in `V3Canonical.lean`:

- `canonicalString_injective` — distinct input strings produce
  distinct canonical-string bytes. Matches `serde_json::to_string` on
  `Value::String`.
- `sortByKey_isSorted`, `sortByKey_idempotent`, `sortByKey_sameKVs` —
  standard `List.mergeSort` properties (Lean 4 core does not ship a
  packaged `Sorted` proof at this level of generality without
  Mathlib).
- `sha256_hex_length`, `sha256_hex_lower`, `sha256_hex_injective` —
  SHA-256 standard cryptographic properties; same axiom style as
  `Sha256.injective` in `OctraVPN_Rust/Spec.lean`.

**Out of scope (assumed primitive):** RFC 8259 string-escape table
correctness. That's a property of the audited `serde_json` crate and
is exercised by the property-based test suite alongside the Lean
proofs (see `crates/octravpn-core/src/v3_canonical.rs::tests`'s
`canonical_write_is_idempotent` and `no_whitespace_outside_strings`).

**Out of scope (numerical formatting):** the v3 schemas use only
`u32` / `u64` integers; we model `JsonValue.number` as `Int` and
treat the decimal-formatting rule (`serde_json::Number::to_string`)
as an opaque primitive. The Rust proptest `prop_injectivity_on_distinct_epochs`
exercises this end-to-end.

---

## Theorem count

| Module                  | Theorems | Examples (anchors) |
| ----------------------- | -------- | ------------------ |
| `Controlbase`           | 11       | 1                  |
| `BeNonce`               | 8        | 2                  |
| `HmacToken`             | 7        | 1                  |
| `PortalCache`           | 10       | 1                  |
| `V3Canonical`           | 14       | 3                  |
| **Total (this module)** | **50**   | **8**              |

Combined with the 54 theorems in `OctraVPN_Rust/`, the deductive proof
surface now stands at **104 mechanically-checked theorems** (54 Rust
security primitives + 50 wire-protocol primitives).

---

## What is NOT proved here

- **Cryptographic security of HMAC-SHA256 or ChaCha20Poly1305.** Those
  are standard PRF / AEAD assumptions delegated to the audited crates.
  We prove the **composition layer**: that the framing, nonce
  construction, and token lifecycle preserve the security properties
  the primitives provide.
- **Real-world network behavior.** No I/O, no concurrency, no race
  conditions. Pure-function proofs only.
- **Side-channel / constant-time properties.** `token_valid` uses
  `subtle::ConstantTimeEq` in Rust; we prove the functional
  equivalence, not the timing behavior.
- **Headscale-side state machine.** The peer-side `MachineRegistry`
  + `MapResponse` long-poll machinery has its own Rust property tests
  in `crates/octravpn-mesh/src/tailscale_wire/`; pulling that into
  Lean is a future pass.
