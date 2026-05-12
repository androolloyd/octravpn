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

### 3.1 Validator registration

- **Sybil cost = stake**: registration requires `bond ≥ min_bond` of OCT
  bonded into the program. No alternative path. To create N fake VPN
  identities an attacker bonds N × min_bond OCT.
- **Attestation binds to identity**: `register_validator` requires an
  ed25519 signature over `H(self_addr || "octravpn-validator-bond" ||
  epoch)` verified under the caller's account key by
  `verify_ed25519_acct`. A network attacker who replays an old
  registration sig fails because `epoch` advances.
- **Cross-protocol key separation**: the on-disk master secret is fed
  through HKDF-Expand with three distinct domain tags
  (`octravpn-key-v1/{receipt-sign-ed25519, noise-x25519, stealth-view}`)
  so the same scalar is never used for two protocols.

### 3.2 Liveness slashing

- **No silent disappearance**: validators must call
  `refresh_attestation` at most every `attest_grace_epochs`.
- **Permissionless slash**: `slash_offline` is callable by anyone; it
  pays the caller a 10% bounty out of the slashed amount, jails the
  validator, and reduces bond by 1%.

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

### 3.4 Bandwidth metering (dual-signed receipts)

- **Both parties consent**: the canonical signing payload is
  `H("octravpn-receipt-v1" || session_id || seq || bytes_used || blind)`,
  verified under *both* `client_session_pubkey` and
  `validator.receipt_pubkey` (separate from `wg_pubkey`, separate from
  the wallet key).
- **Equivocation is slashable**: `slash_double_sign` accepts two
  receipts with the same `(session_id, seq)` but different
  `(bytes_used, blind)` tuples — both signed by the same node — and
  zeroes the bond. Modeled in Tamarin as `DoubleSignSlashable`.
- **Forward unforgeability** (Tamarin `ReceiptUnforgeability`): a
  settlement implies a real client signature was made earlier OR the
  client's session key was compromised. No middle path.

### 3.5 Settlement

- **CEI ordering**: `settle_session` does *all* validation, snapshots
  validator state, mutates state, and *only then* calls
  `emit_private_transfer`. Re-entrancy via the refund leg cannot
  observe partial state.
- **TOCTOU-free**: hop validator records are snapshotted into a local
  list at the start of `settle_session`. A validator that becomes
  jailed mid-tx still receives credit for the work they signed for, and
  cannot be excluded by a slash that happens between check and credit.
- **Integer-overflow safe**: settlement math uses
  `mul_div_safe(a, b, divisor)` which checks for overflow on the
  intermediate `a * b` and reverts cleanly. Mirrored in Rust as
  `u64::checked_mul(...).ok_or(...)`.
- **Replay protection**: tx canonical bytes prepend a `chain_id` and
  the recursive tagged-binary serialization sorts object keys, so
  signatures from one program / chain cannot be replayed on another.

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
