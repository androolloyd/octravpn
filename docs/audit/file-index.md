# In-Scope File Index

Each row: `path` → 1-line purpose → primary security property the
file enforces. Lean theorem references point at theorems we expect
the code to be a refinement of; the property tests pin the
correspondence in CI.

> Reproduce this list:
>
> ```sh
> find crates fuzz program proofs/lean docker/devnet -type f \
>   \( -name '*.rs' -o -name '*.aml' -o -name '*.lean' -o -name '*.sh' \) \
>   ! -path '*/target/*' ! -path '*/.claude/*' | sort
> ```
>
> Anything *not* in the table below is either out of scope (build
> glue, vendored test fixtures, generated artifacts) or is a
> re-export shim. If something looks load-bearing and isn't listed,
> that itself is an audit finding — please flag it.

---

## 1. Core crypto + wire primitives (`crates/octravpn-core/`)

| Path | Purpose | Security property |
|---|---|---|
| `src/receipt.rs` | Dual-signed session receipt (client+node), v1.2 domain binders | Receipt unforgeability + cross-deploy replay resistance. Lean: `OctraVPN_Rust/Lemmas.lean` `sign_verify_roundtrip`, `sign_verify_rejects_tamper`, `sign_verify_rejects_wrong_pubkey`. Tests: `tests/prop_receipt.rs`. |
| `src/receipt_journal.rs` | Persistent per-session seq floor with fsync gate before signing | Forced-restart double-sign protection (P1-8/9). |
| `src/control.rs` | Control-plane request/response types (`/session` POST/GET) | Wire-format contract between client + node. Lean: `WireProtocol/Controlbase.lean` `header_round_trip`. |
| `src/session.rs` | Session-id derivation + per-session counter state | Counter monotonicity for nonce reuse prevention. Lean: `WireProtocol/BeNonce.lean` `counter_advance_strictly_increases`, `replay_window_distinct_nonces`. |
| `src/onion.rs` | Per-hop X25519+HKDF+ChaCha20-Poly1305 layered AEAD | Per-hop traffic confidentiality + tamper rejection. Fuzz: `fuzz/fuzz_targets/onion_peel.rs`. |
| `src/rpc.rs` | rustls JSON-RPC client (system roots OR pinned roots) | TLS to chain RPC (no MITM under pinned-roots mode). |
| `src/v3_canonical.rs` | Single canonical-JSON encoder for v3 anchor schemas | Producer/verifier agree byte-for-byte. Lean: `WireProtocol/V3Canonical.lean` `canonical_determinism`, `canonical_idempotent`, `canonical_reorder_invariant`, `check_hash_*`. |
| `src/v3_state_root.rs` | Off-chain state-root.json schema + sha256 anchor | Tamper-evident state commitment. |
| `src/v3_policy.rs` | Off-chain policy.json schema + sha256 anchor | Tamper-evident policy commitment. |
| `src/v3_members.rs` | Off-chain members.json schema + sha256 anchor + ip_salt | Tailnet member-set integrity + ip-to-wallet unlinking. |
| `src/v3_calls.rs` | Single source of truth for v3 contract_call JSON envelopes | Caller-side method-name correctness (no stringly-typed drift). |
| `src/stealth.rs` | Octra-aligned X25519 stealth tag (sender↔recipient ECDH) | Recipient privacy on chain-emitted earnings (publishes view pubkey, not view secret). |
| `src/commit.rs` | Pedersen-style commit/open for member ACK | Hiding+binding for member commit. Tests: `tests/prop_commit.rs`. |
| `src/earnings.rs` | Curve25519 Pedersen point + sha256 hash-chain commitment | Per-circle earnings tamper-evidence while HFHE is blocked. |
| `src/bounded.rs` | TTL+capacity map for control-plane / tunnel per-peer state | Defends per-peer memory growth from UDP-source spoof. |
| `src/validator_oracle.rs` | Bulk-cache validator-set lookup with optional allowlist | Bonds register only against current validators. |
| `src/backend.rs` | Wallet+signing backend abstraction (env, file, sealed) | Key custody surface; gate to seal/unseal envelope. |
| `tests/prop_receipt.rs` | proptest: receipt round-trip + tamper-rejection (bytes, program, chain_id) | Pins receipt invariants. |
| `tests/prop_security.rs` | proptest: tx envelope sig verify, sealed payload AEAD | Pins tx + sealed AEAD invariants. |
| `tests/prop_canonicalization.rs` | proptest: canonical JSON determinism | Pins v3 anchor encoder. |
| `tests/prop_commit.rs` | proptest: commit/open binding | Pins Pedersen commit. |
| `tests/prop_session.rs` | proptest: per-session counter advance | Pins nonce monotonicity. |

---

## 2. Exit-node daemon (`crates/octravpn-node/`)

| Path | Purpose | Security property |
|---|---|---|
| `src/tunnel.rs` | WG tunnel session lifecycle (boringtun) | Inbound WG handshake validation, replay rejection at the AEAD layer. |
| `src/control.rs` | HTTP control plane `/session` POST/GET | Exit-only-signed proposal; client countersignature at settle. |
| `src/audit.rs` | HMAC-chained append-only JSON-Lines audit log | Tamper-evident operator history (chain-break detection). |
| `src/audit_cli.rs` | `audit verify` subcommand | Reproducible chain-walk in `octravpn-node audit verify`. |
| `src/seal.rs` | `seal-keys` / `unseal-keys` AEAD envelope (ChaCha20-Poly1305 + PBKDF2) | At-rest key custody for `wallet.key`/`wg.key`/`deployer.key`. Lean: `OctraVPN_Rust/Lemmas.lean` `sealed_roundtrip`, `sealed_wrong_passphrase_rejected`, `sealed_tamper_rejected`. |
| `src/chain_v3.rs` | v3 contract_call wrappers (open_session, settle, claim_earnings) | Operator-side chain RPC; signs via v3_calls. |
| `src/chain_v2.rs` | v2 contract_call wrappers (legacy program) | Same, prior program. |
| `src/chain.rs` | RPC-version-agnostic helpers | Shared retry/backoff. |
| `src/rate_limit.rs` | Per-source-IP token-bucket middleware (429 on empty) | Anti-DoS on the control plane. |
| `src/hub.rs` | UDP listener + WG packet demux | Per-source NAT pinning, per-peer state lookup. |
| `src/v3_boot.rs` | Boot-time validator-oracle + bond verification + key load | "Refuse to start without a registered bond" gate. |
| `src/v3_cli.rs` | v3-specific CLI verbs (`register-endpoint`, `bond`, etc.) | Operator-facing tx-construction surface. |
| `src/onion.rs` | Node-side onion peel (calls into `octravpn_core::onion`) | Egress correctness. |
| `src/events.rs` | Structured event stream (audit + analytics) | Observability for dispute resolution. |
| `src/main.rs` | argv + subcommand dispatch | Entry-point only; routes to the above. |
| `tests/audit_cli_integration.rs` | End-to-end `audit verify` flow | Tampered-line detection. |
| `tests/raw_tls_integration.rs` | TLS handshake against the headscale wire surface | TS2021 Noise handshake correctness. |
| `tests/tailscale_wire_integration.rs` | `/key` → `/ts2021` → `/machine/.../register` walk-through | Preauth-bridge correctness. |
| `tests/v3_boot_integration.rs` | Boot-gate refuses missing-bond cases | Defensive boot. |
| `tests/stress.rs` | Concurrent control-plane stress | Rate-limit + bounded-map under load. |

---

## 3. Client (`crates/octravpn-client/`)

| Path | Purpose | Security property |
|---|---|---|
| `src/runner.rs` | Top-level session-lifecycle driver | Coordinates discover → open_session → settle. |
| `src/v3_runner.rs` | v3 program lifecycle driver | Same, against `main-v3.aml`. |
| `src/v2_runner.rs` | v2 lifecycle driver | Legacy program path. |
| `src/v2_cache.rs` | Local cache for v2 discovery results | Stale-cache rejection. |
| `src/chain_v3.rs` | v3 contract_call client | Client-side tx construction, matches `octravpn_core::v3_calls`. |
| `src/tailnet.rs` | Tailnet open/join/leave flow | Anchored-members verification; ip_salt sanity. |
| `src/settler.rs` | Submits dual-signed receipts at session close | Receipt countersig + `settle_claim` tx. |
| `src/discover.rs` / `src/discover_v2.rs` | Validator + endpoint discovery from chain | Validator-oracle integration. |
| `src/operator_backend.rs` | v2 operator settlement (stub — see known-limitations) | NOT YET WIRED; tracked in known-limitations. |
| `src/portal/chain.rs` | Portal mode chain helpers + stub-RPC test harness | Portal binding sanity. |
| `src/portal/routes.rs` | Portal HTTP routes (axum) | Portal-side request validation. |
| `src/commands/open_url.rs` | `oct://` URL handler | URL-parse safety. |
| `src/commands/fetch.rs` | Manifest + circle-asset fetch | Off-chain asset fetch w/ on-chain sha256 verification. |
| `src/commands/bugreport.rs` | Redacted bug-report dumper | Redacts keys + bearer tokens before writing. |
| `tests/portal_integration.rs` | End-to-end portal flow against a stub RPC | Pins portal contract. |
| `tests/v3_client_integration.rs` | End-to-end v3 lifecycle | Pins client/program contract. |
| `tests/tailnet_cli.rs` | Tailnet CLI flow | Pins tailnet CLI semantics. |
| `tests/serve_cli.rs` | Subnet/serve CLI flow | Pins serve-advertise semantics. |
| `tests/v2_cli.rs` | v2 CLI flow | Pins legacy CLI contract. |
| `tests/bugreport.rs` | Bug-report redaction | Pins redaction. |

---

## 4. Mesh + control-plane glue (`crates/octravpn-mesh/`)

| Path | Purpose | Security property |
|---|---|---|
| `src/acl.rs` | Tailnet ACL parser + canonicaliser + default-deny matcher | ACL hash on-chain matches local document; misspelled fields fail loudly (`deny_unknown_fields`); no-match = deny. Fuzz: `fuzz/fuzz_targets/fuzz_acl_parse.rs`. |
| `src/headscale_bridge.rs` | Preauth-key minter + headscale-api `PreauthRedeemer`/`IpAllocator` bridge | Single-use preauth redemption (`single_use_redeem_consumes_key`); audit-record retention. |
| `src/peer.rs` | Peer registry + signed snapshot exchange | Snapshot signature verification (sig over canonical bytes). Fuzz: `fuzz/fuzz_targets/fuzz_peer_snapshot_decode.rs`. |
| `src/ip_alloc.rs` | Deterministic per-tailnet CGNAT allocator | Allocator collision freedom under tailnet sweep. Fuzz: `fuzz/fuzz_targets/fuzz_ip_alloc.rs`. Tests: `tests/prop_sweep.rs`. |
| `src/conn.rs` | Connection FSM (Probing → Direct/Relay → Upgraded) | State-machine soundness. |
| `src/magic_dns.rs` | Embedded UDP DNS resolver for peer names | DNS-poisoning resistance (only resolves snapshot-known peers). |
| `src/manager.rs` | Top-level mesh manager wiring stun/peer/dns/conn | Lifecycle correctness. |
| `src/subnet.rs` | Subnet-advertisement bookkeeping | Stale-advertise expiry. |
| `src/serve.rs` | Serve/funnel advertisement bookkeeping | Same as subnet. |
| `src/stun.rs` | RFC 5389 STUN client | Public-address discovery only — no auth. |
| `tests/integration_e2e.rs` | Mesh-level e2e | Pins mesh contract. |

---

## 5. AML on-chain program (`program/`)

| Path | Purpose | Security property |
|---|---|---|
| `main-v3.aml` | Current on-chain program: bonds, slash, sessions, tailnet treasury, sha256 anchors | `slash_double_sign` punishes equivocation; `pause` halts user flows; governance bypasses pause; `register_circle_atomic` is owner-only. Lean: `OctraVPN_V2/Lemmas.lean` — `slash_double_sign_*`, `gov_slash_operator_*`, `register_circle_atomic_*`, `pause_*`. Adversarial drill: `docker/devnet/e2e-adversarial-v3.sh`. |
| `main-v2.aml` | Previous on-chain program (legacy paths) | Same invariants, prior surface. Adversarial drill: `docker/devnet/e2e-adversarial-v2.sh`. |
| `operator-circle-v3.aml` | Per-operator circle program (v3) | Per-operator scoped slash + settlement. |

---

## 6. Lean proofs (`proofs/lean/`)

| Path | Subjects |
|---|---|
| `WireProtocol/BeNonce.lean` | `buildNonceBE`: length, counter-suffix, monotone-distinct, replay window. Theorems: `nonce_length`, `nonce_be_determines_counter`, `counter_monotonic_encrypts_distinct_nonces`, `counter_advance_strictly_increases`, `replay_window_distinct_nonces`. |
| `WireProtocol/Controlbase.lean` | Frame header encode/decode round-trip; initiation vs regular distinguishability. Theorems: `header_round_trip`, `initiation_distinguishable`, `MsgType.fromByte_toByte`. |
| `WireProtocol/HmacToken.lean` | Portal HMAC token: deterministic, functional, distinct circles → distinct tokens, valid iff match, no cross-circle accept. Theorems: `token_for_deterministic`, `token_for_function`, `token_for_distinct_circles`, `token_valid_iff_match`, `token_valid_cross_circle_rejected`. |
| `WireProtocol/PortalCache.lean` | Portal cache monotonicity; restart clears allow-set; allow ⇒ valid approve. Theorems: `allow_set_monotonic`, `approve_monotonic`, `approve_invalid_token_no_change`, `restart_clears_allow_set`, `cache_does_not_outlive_process`. |
| `WireProtocol/V3Canonical.lean` | Canonical-JSON determinism, key sort, hex-hash shape. Theorems: `canonical_determinism`, `canonical_idempotent`, `canonical_keys_sorted`, `canonical_reorder_invariant`, `check_hash_length_required`, `check_hash_rejects_uppercase`, `sha256_hex_length_is_64`, `anchor_distinct_inputs_distinct`. |
| `OctraVPN_Rust/Spec.lean` | u32/u64 big-endian encoding lengths; SHA-256 functional; PBKDF2 deterministic; canonical tx functional. Theorems: `u32be_length`, `u64be_length`, `Sha256.digest_function`, `pbkdf2_deterministic`, `canonical_tx_function`. |
| `OctraVPN_Rust/Lemmas.lean` | Circle-id/resource-key uniqueness; padded-frame lengths; sealed-asset roundtrip; wrong-passphrase/circle/key_id rejection; tamper rejection; ed25519 round-trip + tamper. Theorems: `circle_id_function`, `resource_key_collision_implies_h256_collision`, `padded_frame_len_aligned_or_bare`, `sealed_roundtrip`, `sealed_wrong_passphrase_rejected`, `sealed_wrong_circle_id_rejected`, `sealed_wrong_key_id_rejected`, `sealed_tamper_rejected`, `wallet_roundtrip`, `wallet_wrong_passphrase_rejected`, `sign_verify_roundtrip`, `sign_verify_rejects_tamper`, `sign_verify_rejects_wrong_pubkey`, `address_display_starts_oct`. |
| `OctraVPN_V2/Lemmas.lean` | AML semantic invariants: `register_circle_atomic_*`, `bond_endpoint_*`, `update_circle_*`, `retire_*`, `slash_double_sign_*`, `gov_slash_operator_*`, `unbond_locks_stake`, `finalize_unbond_clears_and_pays`, `create_tailnet_seeds_treasury`, `authorize_circle_*`, `revoke_circle_owner_only`, `add_member_grows_count`, `remove_member_drops`, `deposit_to_tailnet_grows_treasury`, `update_acl_owner_only`, `set_charge_internal_traffic_owner_only`. |

---

## 7. Fuzz targets (`fuzz/fuzz_targets/`)

| Path | Target |
|---|---|
| `receipt_decode.rs` | Untrusted receipt-bytes → verify. Property: never panic; tampered bytes reject. |
| `onion_peel.rs` | Untrusted onion blob → peel. Property: never panic; invalid AEAD rejects. |
| `tx_canonical.rs` | Canonical-JSON encoder on arbitrary `Value`. Property: idempotent + sorted. |
| `fuzz_acl_parse.rs` | ACL TOML parser. Property: parse failure ≠ permissive ACL. |
| `fuzz_peer_snapshot_decode.rs` | Peer-snapshot bytes → decode + verify sig. Property: bad sig rejects. |
| `fuzz_ip_alloc.rs` | Allocator under arbitrary insert/remove sequences. Property: no collisions, no leaks. |

---

## 8. Adversarial drills (`docker/devnet/`)

| Path | What it asserts |
|---|---|
| `e2e-adversarial-v3.sh` | Every category (R/B/S/T/E/C/F/P) must be rejected by `main-v3.aml`; positive slash case must fire. |
| `e2e-adversarial-v2.sh` | Same for `main-v2.aml`. |
| `e2e-adversarial.sh` | Same for `main.aml` (v1 reference). |
| `e2e.sh` / `e2e-full.sh` | Happy-path lifecycle. |
| `v3-smoke.sh` | v3 smoke. |
| `preflight.sh` | Devnet host gate. |

---

## 9. Out-of-scope shims worth noting

The following files appear in the tree but are intentionally NOT
part of the audit surface. They are listed here so an auditor can
confirm they are reading the right shim:

- `crates/octra-circle-sim/src/lib.rs` — in-memory chain simulator
  used by tests only. Not built into any production binary.
- `crates/octravpn-analytics/` — opt-in metrics emitter; turned off
  by default.
- `crates/octravpn-admin-ui/` — operator UI; not exposed to clients.
- `crates/octravpn-tun/src/lib.rs` — TUN adapter, OS-side I/O only.
- `pvac-sidecar/` — GPL-isolated daemon; communicates only via a
  documented Unix socket protocol. In scope only at that boundary.
