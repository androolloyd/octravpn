# Security Properties

Numbered properties this codebase claims to enforce, with the code
that enforces each and the test or Lean proof that validates it.
Auditors: each property below is a falsifiable claim. If you can
exhibit a counter-example, that is a finding.

Notation: `path:line` references are valid at the commit recorded in
`manifest.json`. Later commits may shift line numbers; the symbolic
function/theorem names remain stable.

---

## P1. Receipt unforgeability (dual-signature integrity)

> A dual-signed receipt accepted by `Receipt::verify` was signed by
> both the named client session key and the named operator
> receipt-signing key over the *same* canonical payload.

- Enforces: `Receipt::verify` (`crates/octravpn-core/src/receipt.rs:218`)
  re-derives the canonical 32-byte payload (`signing_payload`,
  line 186) and verifies both signatures against the embedded
  pubkeys.
- Canonical payload definition: `crates/octravpn-core/src/receipt.rs:9–28`
  (domain tag `octravpn-receipt-v1` + `program_addr || chain_id ||
  circle_id || session_id || seq || bytes_used || blind`).
- Tests: `crates/octravpn-core/tests/prop_receipt.rs`
  `build_verify_round_trip` (line 22), `tampered_bytes_breaks_verify`
  (line 45).
- Lean: `OctraVPN_Rust/Lemmas.lean` `sign_verify_roundtrip` (line 257),
  `sign_verify_rejects_tamper` (line 270),
  `sign_verify_rejects_wrong_pubkey` (line 276).

## P2. Cross-deploy / cross-chain replay resistance (v1.2 domain binders)

> A receipt signed against program A on chain C with circle X is
> rejected when re-submitted against any other (A', C', X').

- Enforces: the v1.2 binders in `signing_payload` —
  `program_addr || chain_id_be || circle_id` are part of the AEAD'd
  payload, so any one of them changing invalidates both signatures
  (`crates/octravpn-core/src/receipt.rs:243` `canonical_payload`).
- Tests: `crates/octravpn-core/tests/prop_receipt.rs`
  `tampered_program_breaks_verify` (line 88),
  `tampered_chain_id_breaks_verify` (line 117), plus the cross-chain
  and cross-circle replay assertions in `receipt.rs` tests
  (`receipt.rs:371`, `receipt.rs:407`, `receipt.rs:437`).

## P3. Forced-restart double-sign protection

> After any crash or restart, the node will never sign a receipt at
> `(session_id, seq)` for a `seq ≤ floor(session_id)`, where `floor`
> is the persistent journal floor.

- Enforces: `ReceiptJournal` in
  `crates/octravpn-core/src/receipt_journal.rs:1–390` — every signing
  decision passes through `ReceiptJournal::reserve_next` which
  loads the persistent floor, computes `next = max(in_mem, prev)+1`,
  writes + fsyncs the new record per `FsyncPolicy`, **then** the
  caller signs.
- Tests: `crates/octravpn-core/src/receipt_journal.rs` `tests` module
  (search `mod tests` at end of file); the journal-after-restart
  scenarios cover P1-8/P1-9.
- Threat-model anchor: `docs/v2-threat-model.md` P1-8/P1-9.

## P4. Receipt monotonicity (no rewinds)

> For a fixed `session_id`, the operator's `last_seq` is monotone
> non-decreasing across all receipts it ever signs.

- Enforces: `Receipt::check_monotonic` (`crates/octravpn-core/src/receipt.rs:227`)
  rejects any submitted `(prev, current)` pair where `current.seq <=
  prev`. Combined with the journal floor, this is the operator side
  of the slash-evidence contract.
- Lean: `WireProtocol/BeNonce.lean` `counter_advance_strictly_increases`
  (line 172), `counter_monotonic_encrypts_distinct_nonces` (line 162),
  `replay_window_distinct_nonces` (line 182).

## P5. Equivocation is slashable

> Any two valid receipts for the same `(session_id, seq)` with
> different `bytes_used` (or any other payload byte) constitute
> evidence sufficient to call `slash_double_sign` and burn the
> operator's bond + pay the bounty.

- Enforces: `program/main-v3.aml` `slash_double_sign` entrypoint.
- Lean: `OctraVPN_V2/Lemmas.lean` (mirrors v2 program; v3 semantics
  match the v2 shape with v3 domain binders) —
  `slash_double_sign_slashes_stake` (line 203),
  `slash_double_sign_pays_bounty` (line 232),
  `slash_double_sign_distinct_payloads_required` (line 268).
- Drill: `docker/devnet/e2e-adversarial-v3.sh` category `S` includes
  one positive case (real keypair, real equivocation) that MUST
  succeed; surrounding cases MUST be rejected.

## P6. Operator boots only with a valid bond

> The operator daemon refuses to start unless the configured wallet
> address shows up in `is_octra_validator` AND has a non-zero
> registered bond on the in-scope program.

- Enforces: `crates/octravpn-node/src/v3_boot.rs` (boot gate) +
  `crates/octravpn-core/src/validator_oracle.rs` (oracle lookup).
- Tests: `crates/octravpn-node/tests/v3_boot_integration.rs`.

## P7. Audit-log tamper detection

> Any in-place modification, deletion, or reordering of an
> `audit-YYYY-MM-DD.jsonl` line is detected by `audit verify`,
> which reports the first chain-break line index.

- Enforces: HMAC chain in `crates/octravpn-node/src/audit.rs:266` —
  `mac_n = HMAC-SHA256(key, prev_mac || canonical_line_n)`.
- CLI: `crates/octravpn-node/src/audit_cli.rs` — `audit verify`.
- Tests: `crates/octravpn-node/tests/audit_cli_integration.rs`
  exercises tampered, truncated, and reordered files.
- Key custody: `<dir>/.audit.key` chmod 0600 (`audit.rs:19`).

## P8. Control-plane DoS resistance (token bucket)

> No single source IP can consume more than `capacity` +
> `refill_per_sec * elapsed` of the control-plane's request budget;
> excess is rejected with `429 Too Many Requests` and `Retry-After`.

- Enforces: `crates/octravpn-node/src/rate_limit.rs` — per-IP token
  bucket middleware (line 285 `rate_limit_layer`).
- Tests: `crates/octravpn-node/tests/stress.rs` exercises concurrent
  bursts.

## P9. Bounded per-peer memory

> An attacker spoofing UDP source addresses cannot grow the node's
> per-peer map without bound; entries age out at TTL and a hard cap
> evicts FIFO on insert.

- Enforces: `crates/octravpn-core/src/bounded.rs` `BoundedMap`,
  reused by `tunnel.rs` and `control.rs`.
- See module-doc at `bounded.rs:1`.

## P10. Default-deny ACL (and anchored ACL bytes)

> The tailnet ACL parser refuses unknown fields (so a typo never
> silently becomes "allow"), evaluation returns `Deny` on no-match,
> and the in-process document's SHA-256 matches the on-chain anchor.

- Enforces: `crates/octravpn-mesh/src/acl.rs` —
  `#[serde(deny_unknown_fields)]` (line 76),
  `decide` returns `AclAction::Deny` on no-match (line 235),
  canonical bytes → SHA-256 (line 144).
- Fuzz: `fuzz/fuzz_targets/fuzz_acl_parse.rs`.

## P11. Single-use preauth keys

> A preauth key minted as non-reusable, once redeemed, cannot be
> redeemed again (returns `RedeemError::Unknown`). Redemption is
> audit-logged.

- Enforces: `crates/octravpn-mesh/src/headscale_bridge.rs` —
  `PreauthMinter::redeem` (line 332) removes non-reusable keys after
  redemption; record stored in `redemptions` map (line 350).
- Tests: `single_use_redeem_consumes_key` (line 524).

## P12. Sealed asset (AES-GCM + PBKDF2) integrity

> Encrypted policy/members/state-root blobs at
> `circle_asset_put_encrypted` are AEAD-sealed and reject any single
> tampered byte, wrong passphrase, wrong circle_id, or wrong key_id.

- Enforces: AEAD envelope construction in `octra_core::wallet_enc`
  (sibling crate); also used for operator key sealing in
  `crates/octravpn-node/src/seal.rs`.
- Lean: `OctraVPN_Rust/Lemmas.lean` `sealed_roundtrip` (line 158),
  `sealed_wrong_passphrase_rejected` (line 166),
  `sealed_wrong_circle_id_rejected` (line 181),
  `sealed_wrong_key_id_rejected` (line 200),
  `sealed_tamper_rejected` (line 219),
  `wallet_roundtrip` (line 231),
  `wallet_wrong_passphrase_rejected` (line 239).

## P13. Canonical-JSON determinism for on-chain anchors

> Two producers emitting semantically identical v3 state-root, policy,
> or members JSON produce byte-identical bytes; on-chain
> `state_root[circle] = sha256_hex(bytes)` therefore matches what any
> verifier computes locally.

- Enforces: `crates/octravpn-core/src/v3_canonical.rs` — sorted keys,
  no whitespace, no leading zeros, lowercase-hex hashes.
- Lean: `WireProtocol/V3Canonical.lean` `canonical_determinism`
  (line 242), `canonical_idempotent` (line 249),
  `canonical_keys_sorted` (line 218),
  `canonical_reorder_invariant` (line 228).
- Hash-shape gate: `check_hash_length_required` (line 279),
  `check_hash_rejects_uppercase` (line 299),
  `sha256_hex_length_is_64` (line 317).
- Cross-input collision: `anchor_distinct_inputs_distinct` (line 333).

## P14. Wire frame round-trip + initiation distinguishability

> Every well-formed frame header round-trips through encode/decode;
> initiation frames are byte-distinguishable from regular data frames.

- Enforces: `WireProtocol/Controlbase.lean`
  `header_round_trip` (line 267), `initiation_distinguishable`
  (line 174), `MsgType.fromByte_toByte` (line 62).
- Code: control framing in `crates/octravpn-core/src/control.rs`.

## P15. Per-session nonce uniqueness (AEAD safety)

> No two AEAD seal operations on the same session key see the same
> nonce; the counter half of the BE-nonce is strictly monotone.

- Enforces: `Session::next_nonce` (sessions counter) —
  `crates/octravpn-core/src/session.rs`.
- Lean: `WireProtocol/BeNonce.lean` `nonce_length` (line 100),
  `nonce_be_determines_counter` (line 142),
  `counter_advance_strictly_increases` (line 172),
  `replay_window_distinct_nonces` (line 182).
- Tests: `crates/octravpn-core/tests/prop_session.rs`.

## P16. Portal HMAC token unforgeability

> A `token_for(c, k)` value verifies under `(c, k)` and only under
> `(c, k)`; cross-circle tokens are rejected.

- Lean: `WireProtocol/HmacToken.lean` `token_for_deterministic`
  (line 117), `token_for_function` (line 121),
  `token_for_distinct_circles` (line 156),
  `token_valid_iff_match` (line 178),
  `token_valid_cross_circle_rejected` (line 209).
- Code: portal token plumbing in
  `crates/octravpn-client/src/portal/routes.rs` and the chain
  helpers in `crates/octravpn-client/src/portal/chain.rs`.

## P17. Portal cache: restart clears allow-set

> The portal's in-process allow-set is process-local; a fresh start
> permits nothing until an explicit re-approval is observed.

- Lean: `WireProtocol/PortalCache.lean`
  `allow_set_monotonic` (line 121), `approve_monotonic` (line 140),
  `approve_invalid_token_no_change` (line 159),
  `restart_clears_allow_set` (line 261),
  `cache_does_not_outlive_process` (line 274),
  `post_restart_nothing_allowed` (line 279).

## P18. AML program invariants (slash, bond, owner-only, pause)

> The on-chain program enforces:
> (a) only the circle owner can `bond_endpoint`,
>     `update_circle`, `retire_circle`, `gov_slash_operator`;
> (b) `slash_double_sign` requires two distinct receipts;
> (c) pause halts user flows; governance bypasses pause.

- Enforces: `program/main-v3.aml` (each entrypoint guards `caller`
  against circle owner / governance addresses).
- Lean (v2 model; v3 mirrors the same shape):
  `OctraVPN_V2/Lemmas.lean`
  `register_circle_atomic_sets_owner_active_stake` (line 51),
  `bond_endpoint_requires_owner` (line 118),
  `update_circle_owner_only` (line 163),
  `retire_circle_owner_only` (line 174),
  `slash_double_sign_distinct_payloads_required` (line 268),
  `gov_slash_operator_requires_owner` (line 300),
  `unbond_locks_stake` (line 311),
  `finalize_unbond_clears_and_pays` (line 335),
  `update_acl_owner_only` (line 496).
- Drill: `docker/devnet/e2e-adversarial-v3.sh` categories R/B/S/F/P.

## P19. Pedersen commit binding (member commit)

> `verify_open(commit, opening)` accepts iff `opening` matches the
> address+blind that produced `commit`.

- Enforces: `crates/octravpn-core/src/commit.rs`.
- Tests: `crates/octravpn-core/tests/prop_commit.rs`.

## P20. Octra address bytes determinism

> `Address` rendering is a total function of the public key bytes;
> the display form always begins with `oct`.

- Lean: `OctraVPN_Rust/Lemmas.lean` `address_from_pubkey_function`
  (line 286), `address_display_starts_oct` (line 290),
  `circle_id_function` (line 96),
  `resource_key_collision_implies_h256_collision` (line 109).

## P21. Onion peel rejects tampered AEAD bytes

> A mutated onion ciphertext at any layer fails AEAD verification;
> no panic, no information leak via timing-distinguishable paths
> (constant-time tag comparison from `chacha20poly1305`).

- Enforces: `crates/octravpn-core/src/onion.rs` (per-hop
  `aead_seal` / `aead_open` using `chacha20poly1305`).
- Fuzz: `fuzz/fuzz_targets/onion_peel.rs` — must run libfuzzer
  without panics or AddressSanitizer hits.

## P22. Padded-frame length never below cleartext length

> Bell-curve / fixed-size padding classes always produce a frame
> length ≥ the cleartext payload length.

- Lean: `OctraVPN_Rust/Lemmas.lean`
  `padded_frame_len_lower_bound` (line 121),
  `padded_frame_len_aligned_or_bare` (line 140),
  `padded_frame_len_none` (line 132).

## P23. Stealth tag privacy (recipient holds view secret)

> An on-chain stealth tag emitted to a recipient's `view_pubkey`
> cannot be linked back to the recipient by an observer holding
> only the view pubkey.

- Enforces: `crates/octravpn-core/src/stealth.rs` — X25519 ECDH +
  HKDF-tagged outputs, view_secret stays off chain.
- Anti-property: an observer who controls the sender's ephemeral
  secret CAN link (sender must zeroize / never log eph_sk; see
  `bugreport.rs` redaction tests).

---

## Properties intentionally NOT claimed (residual risk)

These are not security properties of OctraVPN; an audit finding
that exhibits them is *not* a defect:

- **Pre-quantum cryptography only.** Curve25519 / ChaCha20 falling
  to a CRQC breaks confidentiality of recorded traffic
  retroactively. PQ overlay is not in this audit's scope.
- **`from→to_` chain linkage at deploy / registration time.** An
  operator that deploys a circle from a wallet with prior on-chain
  history accepts that the wallet → circle binding is permanent +
  public. Operator hygiene (`docs/v2-operator-key-hygiene.md`) is
  the mitigation.
- **Off-path observers + traffic analysis.** WG UDP envelopes
  expose 5-tuples + packet sizes + timings. Onion routing
  partially mitigates within the OctraVPN cloud; we do not claim
  resistance to a global passive adversary.
- **JSON-RPC operator (devnet.octrascan.io) as a trust root.**
  TLS pinning is optional and configurable; the default config
  trusts system roots. An operator running on devnet without
  pinning is accepting `OctraRPC` as a TLS-terminating observer.
