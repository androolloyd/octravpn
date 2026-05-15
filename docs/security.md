# OctraVPN — Security Model

This is the load-bearing security document. Every guarantee below is
either (a) cryptographically reduced to a hardness assumption, or (b)
mechanically modeled in `proofs/`.

## 1. Threat model

| Adversary capability | In scope | Out of scope |
| --- | --- | --- |
| Network: read/inject/drop arbitrary packets (Dolev-Yao) | yes | — |
| Compromise of arbitrary client wallet keys | yes | — |
| Compromise of arbitrary client *session-ephemeral* keys | yes | — |
| Compromise of arbitrary node receipt/WG/view keys | yes | — |
| Compromise of arbitrary node FHE/Pedersen randomness | yes | — |
| Octra consensus failure / 51%-of-stake on the underlying chain | — | trust assumption |
| Side channels on operator hardware (timing/power) | — | operator hardening |

## 2. Cryptographic primitives

| Primitive | Library | Used for | Reduction |
| --- | --- | --- | --- |
| ed25519 | `ed25519-dalek` | tx, attestation, receipt sigs | EUF-CMA |
| X25519 (Noise IK) | `boringtun` + `x25519-dalek` | WG handshake, onion ECDH | DH on Curve25519 |
| ChaCha20-Poly1305 | `chacha20poly1305` | onion AEAD per layer | IND-CCA |
| HKDF-SHA256 | `hkdf` | key separation (master → ed25519/X25519/view) | PRF |
| Pedersen on Ristretto | `curve25519-dalek` | route commitments + earnings ledger | DDH; binding by DLP |
| SHA-256 / SHA-512 | `sha2` | domain-separated transcript hashes | Random oracle (in security argument) |

Two generators are used for Pedersen: `G` is the Ristretto basepoint;
`H` is `RistrettoPoint::from_uniform_bytes(SHA-512("octravpn-…-H-v1"))`,
so its discrete log w.r.t. `G` is unknown to anyone (no trusted setup,
no toxic-waste ceremony).

## 3. Per-component guarantees

### 3.1 Operator registration

- **Sybil cost = stake**: registration requires
  `bond_endpoint(amount ≥ MIN_ENDPOINT_STAKE)` of OU bonded into the
  program. No alternative path. To create N fake VPN identities an
  attacker bonds N × MIN_ENDPOINT_STAKE OU.
- **No on-chain attestation in v1**: the AML cannot call
  `verify_ed25519` at compile time, so cryptographic attestation
  (binding bond intent to a fresh signature over an epoch tag) is
  deferred to v1.1 (once Octra exposes the helper) or v2 Circles
  (which sidestep it by living inside an authenticated execution
  environment). The tx that submits `register_endpoint` is itself
  ed25519-verified at the tx layer by the Octra runtime; replay
  protection is the tx nonce.
- **Cross-protocol key separation**: the on-disk master secret is fed
  through HKDF-Expand with three distinct domain tags
  (`octravpn-key-v1/{receipt-sign-ed25519, noise-x25519, stealth-view}`)
  so the same scalar is never used for two protocols.

### 3.2 Liveness + slashing

- **Equivocation slash (in-AML)**: an operator submitting two
  `settle_claim(sid, bytes_used)` with different `bytes_used` for the
  same session is slashed atomically in the AML — no off-chain proof
  needed. 90% of stake burns to treasury; 10% bounty pool. The session
  deposit refunds to the tailnet treasury.
- **Governance slash**: `gov_slash_operator(addr, evidence)` is owner-
  only and used when off-chain proof of misbehavior is presented.
- **Cryptographic equivocation slash via off-chain dual-sig
  receipts (`slash_double_sign`)**: the receipt-signing protocol in
  `crates/octravpn-core/src/receipt.rs` makes the operator's
  `receipt_pubkey` (registered via `register_endpoint`, stored in
  `EndpointRecord`) a non-repudiation anchor. Anyone presenting two
  distinct signed payloads under that key can slash the operator
  on-chain — AML's `ed25519_ok` host call verifies both signatures
  in-program (confirmed by the Octra dev team 2026-05-14, mainnet
  reference `octBDvZSiTqdEBAyFSp79CHeoLMR9MzHugX9YkHtuQ57MRB`).
  Same 90 / 10 split as the in-AML equivocation slash, paid to the
  caller. This complements the `settle_claim`-internal slash by
  catching equivocations that never reach the chain (e.g. an
  operator who signs receipts off-chain but never submits
  `settle_claim`, or who signs two contradictory off-chain
  attestations for the same `(session_id, seq)`).
- **Unbond + sweep**: an operator can `unbond_endpoint` to start the
  grace period; the endpoint becomes inactive immediately. After
  `UNBOND_GRACE` epochs `finalize_unbond` returns the stake. If an
  operator goes silent mid-session, `sweep_expired_session` (callable
  by anyone) refunds the tailnet treasury and pays a 1% bounty to the
  sweeper.

### 3.3 Session opening

- **Client identity is shielded** behind an ephemeral `client_session_pubkey`
  generated fresh per `connect`. The chain never sees the wallet pubkey
  alongside session activity.
- **Route is shielded** during the session: `route_commit[i]` is a
  Pedersen commitment to `(node_addr_i, blind_i)`. Hiding holds under
  uniform random `blind_i` (information-theoretic).
- **Refund target is shielded**: the client pre-commits a stealth output
  derived from their own view-pubkey + a fresh nonce. Even at
  no-show / sweep refund time, observers cannot link the refund to the
  client's wallet (via `octra_privateTransfer`).

### 3.4 Bandwidth metering (off-chain receipts + on-chain two-tx settle)

- **Both parties consent off-chain**: the operator and client exchange
  dual-signed receipts (canonical signing payload:
  `H("octravpn-receipt-v1" || session_id || seq || bytes_used || blind)`)
  over the WireGuard control plane. These are stored locally by both
  sides as evidence for off-chain dispute resolution. The AML does
  NOT see these signatures — it cannot `verify_ed25519` at compile
  time today.
- **On-chain consent is the two-tx settle**: `settle_claim(sid, bytes_used)`
  from the operator records the operator's bytes count.
  `settle_confirm(sid, bytes_used)` from the session opener either
  matches (→ settle) or differs (→ public `SettleDispute` event,
  session stays open). Both txs are runtime ed25519-verified by Octra
  itself, so the AML can trust `caller`.
- **Equivocation is slashable in-AML**: a second `settle_claim` from
  the same operator on the same session with different `bytes_used`
  triggers a slash + deposit refund in a single tx. No off-chain
  evidence needed.
- **Forward unforgeability** (Tamarin `ReceiptUnforgeability`): the
  off-chain receipt protocol still holds — a settled session implies
  a real client signature was made earlier OR the client's session
  key was compromised. No middle path.

### 3.5 Settlement

- **CEI ordering**: `settle_confirm` does *all* validation, snapshots
  state, mutates state, and *only then* updates the encrypted earnings
  ledger. Re-entrancy via the refund leg cannot observe partial state.
- **Idempotent on retry**: re-submitting `settle_claim` with the same
  `bytes_used` is a no-op (covers network retries). A re-submit with
  *different* bytes is equivocation and slashes.
- **Integer-overflow safe**: settlement math uses
  `bytes_used * price_per_mb` with `checked_mul` in the Rust mock and
  the AML's bounded-int arithmetic; the AML reverts on overflow.
  Mirrored in Rust as `u64::checked_mul(...).ok_or(...)`.
- **Replay protection**: tx canonical bytes are exactly
  `canonical_json(tx).as_bytes()` (per `octra-labs/webcli`), so each
  account's per-tx `nonce` field disambiguates submissions. Cross-chain
  replay is currently moot because Octra has a single chain; when
  multi-chain ships, a chain id field will be added to the canonical
  layout.

### 3.6 Earnings claim

- **Pedersen binding**: the on-chain ledger entry is a Ristretto point
  `E_v = sum_i (a_i * G + r_i * H)`. To claim `claimed_amount`, the
  validator must reveal `(claimed_amount, claimed_blind_sum)` such that
  `E_v = claimed_amount * G + claimed_blind_sum * H`. Producing a
  different opening would require breaking DLP on Curve25519.
- **Stealth payout**: claimed OCT is sent via
  `emit_private_transfer(stealth_output, amount)` to a one-time output
  derived from the validator's view-pubkey + a fresh ephemeral nonce.

### 3.7 Stuck-channel sweep

- **Bounded escrow lockup**: a session that stays open past
  `K * session_grace_epochs` (default `K=10`) can be swept by anyone
  via `sweep_expired_session`. The sweeper receives 1% of the deposit
  as bounty; the rest refunds to the client's stealth output.
- **No client liveness requirement**: a malicious entry hop cannot
  hold the deposit forever by stalling.

## 4. Formal-verification correspondence

| Property | Tool | File | Status |
| --- | --- | --- | --- |
| Receipt unforgeability (1-hop) | Tamarin | `proofs/tamarin/octravpn.spthy::ReceiptUnforgeability` | mechanically checked |
| Receipt unforgeability (3-hop) | Tamarin | `…::ReceiptUnforgeability_3Hop` | mechanically checked |
| Double-sign slashable | Tamarin | `…::DoubleSignSlashable` | mechanically checked |
| Route hidden (1/2/3-hop) | Tamarin | `…::NoLinkBeforeSettle*` | mechanically checked |
| Conservation of funds | TLA+ | `proofs/tla/OctraVPN.tla::ConservationOfFunds` | TLC bounded model check |
| No double-settle | TLA+ | `…::NoDoubleSettle` | TLC |
| Slash amount ≤ bond | TLA+ | `…::SlashLeBond` | TLC |
| Monotonic seq | TLA+ | `…::MonotonicSeq` | TLC |
| Settle-or-refund liveness | TLA+ | `…::Liveness_SettleOrRefund` | TLC under fairness |
| `register; complete_unbond` returns full bond | Lean 4 | `proofs/lean/OctraVPN/Lemmas.lean::completeUnbond_returns_full_bond` | mechanically proven |
| Slash split conservation | Lean 4 | `…::slash_split_conservation` | mechanically proven |
| Settle advances seq | Lean 4 | `…::settle_advances_seq` | mechanically proven |
| Receipt/onion parsers no-panic | Kani + libfuzzer | `proofs/kani/`, `fuzz/fuzz_targets/` | bounded model check + continuous fuzz |

## 5. Defense in depth

| Layer | Guarantee |
| --- | --- |
| Wallet | OS file permissions on secret files; HKDF derives subkeys so a single rotation rotates everything downstream |
| Tx submission | canonical-bytes + chain-id + program-addr binding; replay-impossible across forks |
| HTTP control plane | bounded TTL session map + permissionless sweeper; rate limit via `tower-http` (planned) |
| WireGuard data plane | peer pubkey allowlisted via control-plane announce; unsolicited UDP sources dropped |
| Onion peel | per-layer ChaCha20-Poly1305 with HKDF-derived keys from per-hop ECDH |
| On-chain | bond-staked validator set; CEI ordering; integer-overflow-safe math; permissionless slash |

## 6. What's *not* defended (hard limits)

- **Exit-node sees plaintext destination IP**: inherent to any VPN.
  Mitigations are protocol-external (TLS-only browsing, multi-hop with
  onion peel, Tor-over-OctraVPN).
- **Traffic-analysis from outside**: same-shape WG handshakes from
  client→entry are visible at the network level. Pluggable transports
  (obfs4-style) are a v2 milestone.
- **Operator OS compromise**: a fully malicious operator can extract
  `wg_secret`, `wallet_secret` from disk. HSM integration is a v2
  milestone.
- **Side channels**: timing, power, EM. Out of scope.

## 7. Crypto agility

Every primitive lives behind a single trait or single helper, so
rotating a primitive is a one-file change:

- **Key derivation**: `octravpn_core::util::derive_subkey`
- **Pedersen** (commitments + earnings): `octravpn_core::commit`,
  `octravpn_core::earnings`
- **Onion AEAD**: `octravpn_core::onion::derive_aead_key`
- **Tx canonical bytes**: `octravpn_core::tx::canonical_bytes`
- **Stealth derivation**: `octravpn_core::stealth::derive_output` and
  `OctraBackend::derive_stealth_output`
- **Address codec**: `OctraBackend::address_from_display` /
  `address_to_display`

The `OctraBackend` trait is the swap-in point for
Octra-runtime-specific behavior (address codec, account-key signature
verification, real stealth scheme); the placeholder implementation is
semantically correct but byte-incompatible with mainnet Octra until
the real SDK is wired in.
