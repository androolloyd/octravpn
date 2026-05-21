# OctraVPN — Security Model

This is the load-bearing security overview. For the **live-substrate
crypto + dep-risk register** see `docs/v2-threat-model.md` (canonical,
current state). For **Rust crypto / log-leak audit** see
`docs/v2-rust-leak-audit.md`. For **operator-side hardening** see
`docs/v2-operator-key-hygiene.md`.

This doc is the entry point: it summarises the two deployed AML
substrates, the five verification layers we run against them, and
points to the deeper docs for fix queues and remediation plans.

## 1. What's deployed

Two AML programs ship side-by-side on devnet today. Both are
authenticated execution environments under the Octra runtime; both
share the same off-chain Rust crypto stack.

| Substrate | Address | Status | Notes |
| --- | --- | --- | --- |
| **v1.1 bulletproof** | `oct2YehVLezCi2RCcSkURc3nyyYtzxmspwGHHALm6pjkUvJ` | live | 49-case adversarial drill green (commit `4f1fc3c`); receipt-pubkey + deposit ledger; pause-gate carved out for governance (see §3.5 of `docs/whitepaper.md`). |
| **v2 slim registry + operator-circle** | `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7` | live | 45-case v2 drill green (commit `beae338`); circle-keyed registry; operator metadata moves into per-circle `operator-circle.aml` programs; PVAC sidecar past the chain-side AES-KAT gate on mainnet (commit `9e16868`). |

Both substrates accept ed25519 attestation via `ed25519_ok` (base64
pubkey + sig — the Octra runtime contract; see §2 of
`docs/octra-aml-wire-format.md`). The v2 substrate also runs an AES
known-answer-test on registered PVAC pubkeys: dummy / non-fork pubkeys
are rejected before signature verification, demonstrated on mainnet
under commit `9e16868`.

## 2. Five layers of verification

Every guarantee in `docs/v2-threat-model.md §1` is checked through at
least one of the following; the load-bearing properties are checked
through three or more.

| # | Layer | Where | Status |
| --- | --- | --- | --- |
| 1 | On-chain adversarial drill | `docker/devnet/e2e-adversarial.sh` (49 cases) + `e2e-adversarial-v2.sh` (45 cases) + `e2e-adversarial-v3.sh` (40 cases) | 49/49 + 45/45 + 40/40 green |
| 2 | Lean 4 theorems | `proofs/lean/{OctraVPN,OctraVPN_V2,OctraVPN_V3,OctraVPN_Rust,WireProtocol}/` | 373 theorems: 46 + 54 + 55 + 109 + 109; 0 sorry |
| 3 | TLA+ / TLC model-check | `proofs/tla/OctraVPN.tla` + v2 module | 17 invariants, 3.8M distinct states, 0 violations |
| 4 | Rust proptest harnesses | `crates/octravpn-core/tests/prop_*.rs`, `octra-foundry/crates/octra-core/tests/prop_*.rs` | 30 properties: crypto, tx canonicalisation, wallet_enc, receipt domain binders |
| 5 | Dep audit | `cargo audit` over both workspaces + `deny.toml` | clean for vulnerability advisories (RustSec db 1090); one informational unmaintained-crate warning (`paste 1.0.15`) |

`docs/v2-threat-model.md §4` is the dep-risk register. `docs/v2-rust-leak-audit.md`
is the log/Display/Debug audit. Both are owned by the v2 threat-model
subagent; do not edit them here.

## 3. Threat model

Dolev-Yao network adversary + selective key compromise. Octra
consensus failure (≥51% of stake) is a trust assumption inherited from
the chain and explicitly **out of scope** for this doc.

| Adversary capability | In scope |
| --- | --- |
| Network: read/inject/drop arbitrary packets | yes |
| Compromise of arbitrary client wallet keys | yes |
| Compromise of arbitrary client *session-ephemeral* keys | yes |
| Compromise of arbitrary node receipt / WG / view keys | yes |
| Compromise of operator FHE / Pedersen randomness | yes |
| Octra consensus failure | trust assumption |
| Side channels on operator hardware (timing / power) | out — operator hardening |

The detailed observer matrix (passive on-path, MITM, OctraRPC,
malicious operator, malicious tailnet member, malicious owner, quantum)
is in `docs/v2-threat-model.md §1`.

## 4. Cryptographic primitives

| Primitive | Library | Used for | Reduction |
| --- | --- | --- | --- |
| ed25519 | `ed25519-dalek 2.2.0` | tx, attestation, receipt sigs | EUF-CMA |
| X25519 (Noise IK) | `boringtun 0.7.1` + `x25519-dalek 2.0.1` | WG handshake, onion ECDH | DH on Curve25519 |
| ChaCha20-Poly1305 | `chacha20poly1305 0.10.1` | onion AEAD, sealed-key AEAD | IND-CCA |
| AES-256-GCM | `aes-gcm 0.10.3` | sealed `/policy.json` envelope | IND-CCA |
| PBKDF2-HMAC-SHA256 (120k) | `pbkdf2 0.12.2` | sealed-passphrase KDF | (P2-11: replace with Argon2id) |
| HKDF-SHA256 | `hkdf 0.12.4` | key separation (master → ed25519 / X25519 / view) | PRF |
| Pedersen on Ristretto | `curve25519-dalek 4.1.3` | route commitments + earnings ledger | DDH; binding by DLP |
| SHA-256 / SHA-512 | `sha2 0.10.9` | domain-separated transcript hashes | RO model |

Two Pedersen generators: `G` is the Ristretto basepoint; `H` is
`RistrettoPoint::from_uniform_bytes(SHA-512("octravpn-…-H-v1"))`, so
its discrete log w.r.t. `G` is unknown to anyone (no trusted setup,
no toxic waste).

Pinned versions are tracked in `docs/v2-threat-model.md §4`.

## 5. Per-component guarantees

### 5.1 Operator registration

- **Sybil cost = stake**: `register_circle` on v2 requires
  `bond ≥ 1_000_000_000 OU` plus `deploy_circle` (~200_000 OU). v1.1's
  `register_endpoint` requires `bond ≥ MIN_ENDPOINT_STAKE`. To create
  N fake operators the attacker locks N × bond.
- **On-chain attestation (v1.1 + v2)**: both substrates verify ed25519
  via the runtime `ed25519_ok` host call (base64 pubkey + sig). The
  v2 operator-circle additionally constrains `meter_bytes` to
  `caller == self.owner` (P0-3, commit `b9aedf7` — the dead
  `ed25519_ok(resource_key, …)` branch has been removed).
- **Cross-protocol key separation**: HKDF-Expand with three distinct
  domain tags: `octravpn-key-v1/{receipt-sign-ed25519, noise-x25519,
  stealth-view}`. Same scalar is never used for two protocols.

### 5.2 Liveness + slashing

- **Equivocation slash (in-AML)**: `settle_claim(sid, bytes_used)`
  conflicting with a prior claim slashes 90% to treasury, 10% to
  bounty pool; deposit refunds.
- **Cryptographic equivocation slash (off-chain receipts)**:
  `slash_double_sign(payload_a, sig_a, payload_b, sig_b)` on
  `main-v2.aml:382-418`. Anyone presenting two distinct receipt
  payloads under the same operator `receipt_pubkey` slashes the bond.
  Demonstrated twice on mainnet under the operator's attestation key
  (`ed25519_ok` accepts the **base64** encoding — see
  `docs/octra-aml-wire-format.md`).
- **Governance slash**: `gov_slash_operator(addr, evidence)` is
  owner-only and used when off-chain proof is presented.
- **Sweep + unbond**: `sweep_expired_session` is permissionless and
  pays 1% bounty; `finalize_unbond` clears stake after grace.

### 5.3 Receipt domain binding (P1-5 closed)

Receipt signing payload (`receipt.rs`) is:

```
sha256("octravpn-receipt-v1" || program_addr || chain_id_be ||
       circle_id_canonical || session_id || seq_be || bytes_be ||
       blind_32)
```

Binds:
- **program_addr** — v1.1 / v2 substrate-distinguishing.
- **chain_id** (u32 BE) — `CHAIN_ID_DEVNET = 0x6F637464` /
  `CHAIN_ID_MAINNET` / etc.
- **circle_id** (32 bytes; v1.1 encodes "None" as 32 zeros so hash
  domain is fixed-width across v1.1 / v2).

Cross-program, cross-chain, and cross-circle replay all fail signature
verification. Tests: `cross_program_receipt_rejection`,
`cross_chain_receipt_rejection`, `cross_circle_receipt_rejection`.
Property-based variants in `tests/prop_receipt.rs` and chain-side
parity in `tests/prop_canonicalization.rs`.

### 5.4 Receipt monotonicity across restart (P1-8 / P1-9 closed)

`crates/octravpn-core/src/receipt_journal.rs` persists
`(session_id → last_signed_seq)` to disk (default
`./state/receipts.bin`; fsync'd file + parent-dir on every bump). The
daemon shadows in-memory `ControlSession.last_seq` with
`max(in_mem, journal_floor)`. A forced restart (OOM / segfault /
signal) can no longer trick the daemon into signing two distinct
receipts at the same `(session_id, seq)`. Closes Tree F.2.a in
`docs/v2-threat-model.md §2`.

### 5.5 Session opening

- **Client identity is shielded** behind an ephemeral
  `client_session_pubkey` generated fresh per `connect`. The chain
  never sees the wallet pubkey alongside session activity.
- **Route is shielded** during the session: `route_commit[i]` is a
  Pedersen commitment to `(node_addr_i, blind_i)`; hiding is
  information-theoretic under uniform random `blind_i`.
- **Refund target is shielded**: client pre-commits a stealth output
  derived from their own view-pubkey + a fresh nonce.

### 5.6 Bandwidth metering

- **Off-chain dual-signed receipts** binder above (§5.3). Stored
  locally by both sides; not submitted to chain.
- **On-chain two-tx settle**: `settle_claim(sid, bytes_used)` + 
  `settle_confirm(sid, bytes_used)`. Mismatch → public `SettleDispute`
  event, session stays open; match → settle.
- **Idempotent on retry**: same-bytes re-submission is no-op;
  different-bytes is equivocation and slashes.
- **Integer-overflow safe**: AML bounded-int arithmetic reverts on
  overflow; Rust mirror uses `u64::checked_mul`.

### 5.7 Settlement

- **CEI ordering**: `settle_confirm` validates, snapshots, mutates,
  *then* updates the encrypted earnings ledger. Re-entrancy via the
  refund leg cannot observe partial state. The `nonreentrant`
  modifier is wired on `main-v2.aml:392` (`finalize_unbond`); v2
  drill case 46 for reentrancy attempts is still on the open list.
- **Replay protection**: canonical tx bytes per `octra-labs/webcli`
  format; per-account nonce disambiguates. Cross-chain replay is now
  bound by `chain_id` in the receipt hash (§5.3).

### 5.8 Earnings claim

- **Pedersen binding**: ledger entry `E_v = sum_i (a_i G + r_i H)`.
  To claim, validator reveals `(claimed_amount, claimed_blind_sum)`.
  A different opening reduces to DLP on Curve25519.
- **Stealth payout**: `emit_private_transfer(stealth_output, amount)`
  to a one-time output derived from the validator's view-pubkey + a
  fresh ephemeral nonce.

### 5.9 Sealed on-disk secrets (P1-6 closed)

`octravpn-node seal-keys` / `unseal-keys` subcommands wrap the
configured wallet + WG keys under the `OCTRA-WALLET-V1` envelope
(ChaCha20-Poly1305 + PBKDF2-HMAC-SHA256 120k; atomic write via
tempfile + fsync). Sealed-passphrase strings use `Zeroizing<String>`
(P1-10, commit `2d933fc`).

Strict mode (`[chain].require_sealed_keys = true`) refuses to boot
if any configured secret is still plaintext (`CoreError::PlaintextKeyOnDisk`).
Devnet keys remain plaintext for `e2e.sh` back-compat; v2 operators
opt in via TOML flag + `*.sealed` paths. See
`docs/v2-operator-key-hygiene.md §4`.

### 5.10 Control-plane authentication (P0-1 / P0-2 closed)

- **`/events` SSE**: now gated by `events_token` (commit `f4f5e65`).
  Previously plaintext + unauthenticated.
- **RPC cert pinning**: `[chain].pinned_root_paths` in node + client
  TOML (commit `2d933fc`). Pinning the devnet root denies any
  rogue / corporate / OS-installed CA from MITM'ing JSON-RPC. *Lib
  + config is wired; operator-side enablement is still on operators
  to switch on.*

## 6. Defense in depth

| Layer | Guarantee |
| --- | --- |
| Wallet | OS file permissions + sealed AEAD envelope (P1-6); HKDF subkeys rotate downstream |
| Tx submission | canonical bytes + chain-id + program-addr binding (P1-5); replay-impossible across forks |
| HTTP control plane | events_token gate (P0-1); cert-pinned RPC (P0-2); rate limit via `tower-http` (still open) |
| WireGuard data plane | peer pubkey allowlisted via control-plane announce; unsolicited UDP sources dropped |
| Onion peel | per-layer ChaCha20-Poly1305 with HKDF-derived keys from per-hop ECDH (P1-2 random-nonce hardening still open) |
| On-chain | bond-staked validator set; CEI ordering; integer-overflow-safe math; permissionless slash; receipt journal across restart |

## 7. What's *not* defended (hard limits)

- **Exit-node sees plaintext destination IP**: inherent to any VPN.
  Mitigations are protocol-external (TLS-only browsing, multi-hop
  with onion peel, Tor-over-OctraVPN).
- **Traffic-analysis from outside**: same-shape WG handshakes from
  client→entry are visible at the network level. Pluggable transports
  (obfs4-style) are a v2 milestone.
- **Operator OS compromise**: a fully malicious operator with root can
  extract `wg_secret`, `wallet_secret` from disk *unless* sealed-keys
  strict mode is on AND the passphrase comes from a keyring, not
  `OCTRAVPN_KEY_PASSPHRASE` shell env. HSM integration is a v2
  milestone.
- **Side channels**: timing, power, EM. Out of scope.
- **Quantum break of Curve25519** retroactively decrypts recorded WG
  + TLS. Out of scope until a credible PQ overlay exists; see
  `docs/security-roadmap.md §1.5`.

## 8. Crypto agility

Every primitive lives behind a single trait or single helper, so
rotating is a one-file change:

- **Key derivation**: `octravpn_core::util::derive_subkey`
- **Pedersen**: `octravpn_core::commit`, `octravpn_core::earnings`
- **Onion AEAD**: `octravpn_core::onion::derive_aead_key`
- **Tx canonical bytes**: `octravpn_core::tx::canonical_bytes`
- **Stealth derivation**: `octravpn_core::stealth::derive_output`
- **Sealed envelope**: `octra_core::wallet_enc`
- **Receipt domain**: `octravpn_core::receipt::ReceiptContext`

The `OctraBackend` trait is the swap-in point for runtime-specific
behavior (address codec, account-key signature verification, stealth
scheme).

## 9. Where to read next

- `docs/v2-threat-model.md` — observer matrix, attack trees, prioritized
  fix queue (the canonical live-state security artifact).
- `docs/v2-rust-leak-audit.md` — log / Display / Debug audit of the
  Rust crypto stack and node daemon.
- `docs/v2-operator-key-hygiene.md` — what operators need to do
  off-chain to avoid the chain-side wallet ↔ circle binding leak.
- `docs/threat-model.md` — v1 threat-model archive (kept for historical
  context; mostly subsumed by v2).
- `docs/security-roadmap.md` — closed P0/P1 items + remaining open work.
- `docs/attack-cost.md` — economic numbers per attack class.
- `docs/gap-analysis.md` — production-readiness inventory.
