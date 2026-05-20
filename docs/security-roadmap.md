# OctraVPN: Security and Identity Roadmap

This document lists security and identity provisions that are NOT in
the shipping protocol today, ordered by priority and grouped by
category. Each section gives: the property we want, the attack it
mitigates, the proposed mechanism, and the rough cost.

For what's already in the protocol see `docs/whitepaper.md §1`
(threat model), `docs/economics.md §10` (adversarial scenarios),
the formal proofs in `proofs/`, and **`docs/v2-threat-model.md §3`**
(canonical prioritized fix queue — the closed items in §-1 below all
link back into it).

Status legend: green = closed (this pass); planned = v1.1 / v2.1;
yellow = v1.x; red = research / v2+.

---

## -1. Closed since the v2 hardening pass

These items shipped between commits `374ba49` (v2 threat model doc)
and `dfc016e` (P1-6/P1-8/P1-9). They are listed here for traceability;
see `docs/v2-threat-model.md §3` for the full diagnostic and tests.

| Item | Commit | What landed |
| --- | --- | --- |
| **P0-1** plaintext `/events` SSE | `f4f5e65` | events_token gate on `/events`; per-session metadata no longer leaks to passive observers on the operator's HTTP control plane. |
| **P0-2** RPC cert pinning | `2d933fc` | `[chain].pinned_root_paths` config in both node + client TOML; rogue / corporate / OS-installed CAs can no longer MITM `devnet.octrascan.io`. **Operator-side enablement is still on operators** — the lib + config is wired, but operators must add the pinned root path to their config to activate it. |
| **P0-3** `meter_bytes` always-false `ed25519_ok` | `b9aedf7` | Removed the dead `ed25519_ok(resource_key, …)` branch in `operator-circle.aml`; auth is now `caller == self.owner` explicitly (no silent fall-through). |
| **P1-5** receipt cross-program / chain / circle replay | `060903d` | `ReceiptContext` field on `Receipt`; signing payload binds `(program_addr, chain_id, circle_id)`. Tests: `cross_program_receipt_rejection`, `cross_chain_receipt_rejection`, `cross_circle_receipt_rejection`, plus property-based variants. |
| **P1-6** sealed on-disk keys | `dfc016e` | `octravpn-node seal-keys` / `unseal-keys` subcommands; ChaCha20-Poly1305 + PBKDF2 envelope; atomic write + fsync; strict mode (`[chain].require_sealed_keys = true`) refuses to boot on plaintext keys. |
| **P1-8 / P1-9** restart resets `last_seq = 0` | `dfc016e` | Persistent fsync'd `receipt_journal.rs`; floor consulted before every signature; closes Tree F.2.a (restart-replay) in the v2 threat model. |
| **P1-10** sealed-passphrase not zeroized | `2d933fc` | `Zeroizing<String>` on the `discover_v2.rs` config path; core-dump / swap leak window closed. |
| **45/45 v2 adversarial drill** | `beae338` | All 45 cases hold under the v2 substrate. |
| **232 Lean theorems** (OctraVPN 46 + OctraVPN_V2 54 + OctraVPN_Rust 72 + WireProtocol 60) | — | TLC parity: 17 invariants, 3.8 M distinct states, 0 violations. |
| **30 Rust proptest harnesses** | — | Crypto, tx, wallet_enc, receipt-domain coverage. |
| **PVAC sidecar past the AES KAT gate on mainnet** | `9e16868` | GPL-isolated daemon; dummy / non-fork pubkeys reject before sig-verify; sidecar pubkeys accepted. |

---

## 0. Octra-team asks (highest priority, blocks v1.1)

Per `docs/aml-gap-analysis.md` our AML can only use confirmed Octra
host calls. The following AML extensions would unlock the
properties we currently can't enforce on-chain. Each item is a
discrete ask to the Octra core team.

### 0.1 (planned) `verify_ed25519(pubkey, msg, sig) -> bool` host call

**Status note:** the runtime contract is now `ed25519_ok` accepting
**base64-encoded** pubkey + sig (not hex — `docs/octra-aml-wire-format.md`
documents this). Both substrates already use it for receipt-pubkey
attestation and `slash_double_sign`. This ask is retained for
edge-case AML programs that want a verbose constant-time variant.

**Unlocks:**
- Dual-signed receipt verification in `settle_session` →
  cryptographic non-repudiation of `bytes_used`.
- `submit_equivocation(operator, evidence)` permissionless slashing
  (already wired for the operator-attestation key path; receipt-pubkey
  path still pending).
- `redeem_join_token` pre-auth tokens.
- Quorum-signed ACL updates (`§2.3`).

**Estimated cost:** ~1 week of Octra-team work.

### 0.2 (planned) Native `op_type="vpn_settle"` extension

**Unlocks:** Dual-signed bandwidth receipts verified by the native-tx
runtime BEFORE AML executes. AML sees pre-validated data.

**Mechanism:** Extend Octra's `op_type` set with `"vpn_settle"` that
carries `(session_id, bytes_used, blind, client_sig, node_sig)` in
`encrypted_data`. Runtime verifies both signatures + dual-sig
construction; rejected txs never reach AML.

**Rationale:** Mirrors the existing `op_type="stealth"` model where
range proofs + Pedersen commitments are runtime-verified.

**Estimated cost:** ~3 weeks of Octra-team work.

### 0.3 (v1.x) `verify_bulletproof(commit, proof) -> bool` host call

**Unlocks:**
- Encrypted bandwidth volumes in settle (`§6.2`).
- Range-proofed FHE-encrypted balances (prevent over-claim before
  the chain even runs `fhe_verify_zero`).

**Rationale:** Octra's stealth path uses bulletproof-shaped range
proofs at the native-tx layer (`pvac_make_range_proof`). Lifting to
AML lets programs adopt the same primitive.

**Estimated cost:** ~2-4 weeks (depends on the existing libpvac
bindings).

### 0.4 (v1.x) Linkable ring signature host call

**Unlocks:**
- Plausible-deniability join (`§6.1`).
- Multi-device unlinkability (a device proves it's "one of my
  registered devices" without revealing which).

**Estimated cost:** ~2 months including reference impl.

### 0.5 (v1.x) Schnorr DLEQ proof host call

**Unlocks:**
- Forward-secure receipt key rotation (`§2.1`).

**Estimated cost:** ~3 weeks.

### 0.6 (v1.x) General SNARK verifier (`verify_groth16` / `verify_plonk`)

**Unlocks:** Arbitrary zk statements about hidden witnesses. Range
proofs, ring sigs, DLEQ all subsume into a single verifier.

**Estimated cost:** ~3-6 months upstream + trusted setup ceremony.

### 0.7 (planned) `octra_isValidator(addr)` AML host call

**Unlocks:** Hybrid validator-as-operator model.

**Estimated cost:** ~1 week.

### 0.8 (RESOLVED 2026-05-18) **Devnet RPC body cap lifted**

The devnet nginx in front of `devnet.octrascan.io` previously returned
`413 Request Entity Too Large` on POST bodies above 1 MiB, which
blocked PVAC pubkey registration (~4 MiB lattice key). The upstream
team raised the cap on 2026-05-18 and `octra_registerPvacPubkey` now
confirms on devnet. The residual blocker for end-to-end HFHE settle is
AML-side: `fhe_load_pk` still reverts for our contracts even after a
successful pubkey registration (see `octra-dev-questions.md §1` and
`memory/octra_aml_fhe_load_pk_blocked.md`).

---

## 1. Identity & device attestation

### 1.1 (planned) Hardware-backed wallet keys

**Want.** Wallet private keys never exist in plaintext on disk; all
signing happens inside a hardware module.

**Now partially covered.** P1-6 (commit `dfc016e`) ships
passphrase-encrypted at-rest storage via `octravpn-node seal-keys`
(ChaCha20-Poly1305 + PBKDF2 envelope). HSM-backed signing (YubiKey /
Ledger / SE / TPM2) is the next step beyond passphrase wrap; see
table below.

**Mechanism.** Client + node daemons gain an `identity.backend`
option:

| Backend | Where the key lives | Sign latency |
| --- | --- | --- |
| `file` (today) | plaintext or sealed (P1-6); plaintext in RAM | < 1 ms |
| `yubikey-pgp` | YubiKey PIV / OpenPGP applet | ~50 ms |
| `ledger` | Ledger Nano via APDU | ~200 ms + UI |
| `secure-enclave` | Apple Secure Enclave (macOS / iOS) | < 5 ms |
| `tpm2` | TPM 2.0 (Linux / Windows) | ~10 ms |

The `KeyPair` trait in `crates/octravpn-core/src/sig.rs` is the
extension point; each backend implements `sign(&self, msg: &[u8]) ->
Signature`.

**Cost.** ~2 weeks per backend.

### 1.2 (planned) WebAuthn / passkeys for tailnet membership

**Want.** A user can be a tailnet member without managing a
long-lived wallet key on every device.

**Mechanism.** Two-key separation: a stable wallet identity (HSM-backed
per §1.1) signs the on-chain `register_device(passkey_pubkey)` once;
afterwards the passkey signs all session-level operations on that
device. Revocation is `revoke_device(passkey_pubkey)`.

**Cost.** ~3 weeks. WebAuthn verification via `webauthn-rs`.

### 1.3 (v1.x) DID anchoring (W3C did:octra)

**Mechanism.** A `did:octra:<chain>:<address>` method spec; DID
Document published in AML at `did_documents[address]`.

**Cost.** ~6 weeks.

### 1.4 (v1.x) Device attestation via TPM/SE measured-boot

**Mechanism.** `register_device` optionally accepts a
`MeasuredBootProof` (signed TPM 2.0 quote attesting PCR values).

**Cost.** ~4 weeks.

### 1.5 (v1.x) Per-session PSK for post-quantum hedge

**Want.** Resistance against an adversary with a future quantum
computer who recorded today's WireGuard handshakes (Tree A.5 / C.2.b
in `docs/v2-threat-model.md`).

**Mechanism.** Per-session pre-shared key derived via Kyber768 KEM
anchored to a per-member long-term Kyber public key on chain
(`kyber_pubkey: bytes`). Combined key: `BLAKE3(WG_classic || Kyber)`.

**Cost.** ~3 weeks. `pqcrypto-kyber` available; AML surface gains a
single bytes field per endpoint.

---

## 2. Operator security

### 2.1 (planned) Forward-secure receipt key rotation

**Want.** Compromise of an operator's receipt-signing key today does
not expose the validity of receipts they signed yesterday.

**Pair with** §1.5 (PQ PSK) and §1.1 (HSM destruction of old subkeys).

**Cost.** ~4 weeks.

### 2.2 (planned) Reputation-tiered rate limits

**Mechanism.** Node daemon's `control-plane` rate limit is
parameterized by `EndpointRecord.reputation`:

```
limit = base_rate × min(1 + log10(reputation + 1), TIER_MAX)
```

**Cost.** ~1 week.

### 2.3 (v1.x) Quorum-signed ACL updates

**Mechanism.** `Tailnet.owner` becomes a `MultiSigPolicy { signers:
Vec<Address>, threshold: u8 }`. Composes with §1.1.

**Cost.** ~2 weeks.

### 2.4 (v1.x) Per-hop attestation receipts (path verification)

**Cost.** ~4 weeks.

### 2.5 (research) Trusted-Execution-Environment receipts

**Cost.** ~3 months.

### 2.6 (v2.2 — NEW) Per-member encrypted wrap of sealed policy

**Want.** Replace the per-tailnet shared sealed-policy passphrase with
a per-member encrypted wrap. Today the passphrase is shared OOB to
every tailnet member; any member defection / phone-loss / coercion
hands the full plaintext `/policy.json` to the attacker, and the only
recovery is owner-driven re-key (rotate passphrase + re-upload + tell
everyone, on a side channel).

**Threatens.** **Defection fragility.** The current sealed-policy
scheme has no per-member revocation; one leaked passphrase is one
leaked tailnet.

**Mechanism.** Replace
`sealed = AES-GCM(PBKDF2(passphrase, circle_id||key_id), plaintext)`
with a hybrid scheme:

```
content_key  := random 32-byte ChaCha20-Poly1305 key
ciphertext   := XChaCha20-Poly1305(content_key, policy_json)
for each member m in tailnet:
    wraps[m]  := X25519-ECIES(m.recv_pubkey, content_key)
sealed       := { ciphertext, wraps: Vec<(member_addr, wrap)> }
```

Each member decrypts only their own wrap. Member revocation is a
re-wrap of `content_key` against the surviving member set (no
ciphertext re-encryption needed unless the revoked member is the
threat). The owner drives this via `circle_asset_put_encrypted` as
today; the wrap-table is on-chain alongside the ciphertext.

**Tradeoff.** Sealed-asset size grows ≈ 96 bytes per member. The
existing 4k / 16k / 32k / 128k padding classes still apply.

**Cost.** ~3 weeks. Pairs with §2.3 quorum-signed ACL.

### 2.7 (v2.3 — NEW) AES-GCM → XChaCha20-Poly1305 migration

**Want.** Replace AES-256-GCM with XChaCha20-Poly1305 for sealed
assets and any future sealed envelope. AES-GCM's 96-bit nonce is the
fragile path (see P2-11 / Tree B.4 in `docs/v2-threat-model.md`); a
random-nonce collision is 2^48 by birthday bound, far below the
sealed-asset lifetime if a tailnet accumulates many policy updates.
XChaCha20-Poly1305's 192-bit random nonce makes the collision
infeasible without needing a counter or KDF gymnastic.

**Cost.** ~2 weeks. RustCrypto `chacha20poly1305::XChaCha20Poly1305`
is available; envelope format gains a version byte for back-compat
with existing AES-GCM sealed blobs.

### 2.8 (v2.3 — NEW) PBKDF2-SHA256 → Argon2id migration

**Want.** Replace PBKDF2-SHA256-120k with Argon2id (memory-hard,
~5× higher GPU cost for the same operator-CPU budget). Tracks P2-11
in `docs/v2-threat-model.md §3`.

**Mechanism.** New envelope version byte; old PBKDF2-derived sealed
blobs continue to decrypt via the back-compat path. New seals use
Argon2id with parameters chosen to land at ≈ 250 ms on a typical
operator host (`m=64 MiB`, `t=3`, `p=4`).

**Cost.** ~2 weeks.

### 2.9 (planned — NEW) Operator daemon ↔ PVAC sidecar wire integration

**Want.** The PVAC sidecar (commit `9e16868`, GPL-isolated, AES-KAT
green on mainnet) is built and `cast register-pvac` works end-to-end.
What's not done: the operator daemon (`octravpn-node`) does not yet
spawn the sidecar as a subprocess and route HFHE encrypt / decrypt
through the defined JSON IPC contract. Today the sidecar is operated
manually via `octra cast`.

**Mechanism.** `octravpn-node` gains a `[pvac]` config block pointing
at the sidecar binary; on startup the daemon spawns it under its own
session, opens the JSON IPC socket, and routes `fhe_load_pk` /
`fhe_encrypt` / `fhe_decrypt` through. Crash semantics: if the sidecar
dies, the daemon restarts it with backoff and surfaces a metric.

**Cost.** ~2 weeks once the daemon + sidecar are on the same release
train.

---

## 3. Audit & forensics

### 3.1 (planned) Audit log shipping to write-once storage

**Cost.** ~2 weeks for the sidecar; ~1 week per sink.

### 3.2 (planned) Signed audit-log export with verification chain

**Cost.** ~1 week.

### 3.3 (v1.x) Receipt expiry epochs

**Mechanism.** `settle_session` gains
`require(now - session.opened_at_epoch <= SETTLE_EXPIRY_EPOCHS)`.

**Cost.** ~1 week.

---

## 4. Network layer hardening

### 4.1 (planned) Anti-MEV ordering at settlement

**Cost.** ~3 weeks.

### 4.2 (planned) Tor-routed control plane (operator option)

**Cost.** ~2 weeks.

### 4.3 (v1.x) STUN provider attestation

**Cost.** ~2 weeks.

### 4.4 (v1.x) Encrypted member metadata

**Cost.** ~3 weeks; pairs with §2.6 per-member wrap.

### 4.5 (v1.x — NEW) Onion AEAD random nonce hardening

**Tracks P1-2 in `docs/v2-threat-model.md §3`.** The onion AEAD
(`onion.rs:128`) uses a constant zero nonce. Safe today because
`wrap_layer` derives a fresh AEAD key per call, so it's the trivial
"fresh key per encryption" case — but any future caching of
`eph_secret` (retry-on-error, deterministic test mode) silently
downgrades to nonce-reuse and XOR's plaintexts. Use a random 12-byte
nonce included in the wire packet so the invariant is enforced in
code, not by convention.

**Cost.** ~3 days.

---

## 5. Operational

### 5.1 (planned) Signed releases via cosign + transparency log

**Cost.** ~1 week + ongoing CI maintenance.

### 5.2 (planned) Public bug bounty program

**Cost.** ~2 weeks to set up; ongoing payout budget.

### 5.3 (v1.x) Independent external audit

**Cost.** ~$150-300k.

### 5.4 (v1.x) Formal-verification expansion

**Status note:** the v2 Lean port (50 theorems) and TLC 17-invariant
expansion landed in the v2 hardening pass. Still open: Lean coverage
of the `nonreentrant` modifier paths in `main-v2.aml` (drill case 46
for re-entrancy attempts is the missing twin).

**Cost.** ~1 month residual.

### 5.5 (research) Side-channel resistance review

**Cost.** ~$50k audit + ~1 month engineering.

### 5.6 (planned — NEW) Wire `cargo audit` + `cargo deny` into CI

`deny.toml` exists; no GitHub Actions wiring on the workflows I see.
Most of the value of `docs/v2-threat-model.md §4` evaporates if a
future bump silently regresses.

**Cost.** ~2 days.

---

## 6. Privacy enhancements

### 6.1 (v1.x) Plausible-deniability join

**Cost.** ~3 weeks.

### 6.2 (v1.x — partially) Sealed bandwidth metadata

**Status note:** the v2 `operator-circle.aml` design has HFHE
byte-counter fields (`docs/v2-circles-design.md §4.4`), but the
deployed program still uses plaintext counters with a comment
admitting the gap (P3-17). HFHE settle is wired end-to-end on
mainnet (PVAC sidecar, AES-KAT green); devnet is blocked on the
RPC body-cap ask (§0.8).

**Cost.** ~2 weeks once §0.8 ships.

### 6.3 (research) Mix-network mode

**Cost.** ~3 months.

---

## 7. Anti-abuse

### 7.1 (planned) Per-tailnet capabilities & quota

**Cost.** ~2 weeks.

### 7.2 (planned) Reputation-weighted client penalty

**Cost.** ~1 week.

### 7.3 (v1.x) Slashed-operator denylist propagation

**Cost.** ~1 week.

---

## Roadmap milestones

**v2.1** — re-deploy with end-to-end hardening:
- §2.9 operator daemon ↔ PVAC sidecar wired (subprocess spawn + JSON IPC)
- §0.8 devnet RPC body cap lifted ✓ (resolved 2026-05-18); residual:
  chain-side AML `fhe_load_pk` bridge still reverts (see
  `memory/octra_aml_fhe_load_pk_blocked.md`)
- Owner-routed `fhe_load_pk` registration via `circle.owner` (already
  shipped per `memory/octra_hfhe_pubkey_per_wallet.md`)
- Drill case 46: re-entrancy attempt against `nonreentrant` paths

**v2.2** — defection-fragility fix:
- §2.6 per-member encrypted wrap of sealed policy
- §2.3 quorum-signed ACL (composes with the wrap-table)
- §4.4 encrypted member metadata (composes with §2.6)

**v2.3** — crypto-primitive uplift:
- §2.7 AES-GCM → XChaCha20-Poly1305 (with version byte for back-compat)
- §2.8 PBKDF2 → Argon2id (with version byte for back-compat)
- §4.5 onion AEAD random nonce hardening (P1-2)
- §1.5 per-session PQ PSK (Kyber768)

**v1.x parallel track** — operator hardening + audit baseline:
- §1.1 HSM-backed wallet keys (beyond P1-6's passphrase wrap)
- §1.2 WebAuthn / passkeys
- §3.1 / §3.2 audit log shipping + signed export
- §5.1 / §5.2 / §5.3 / §5.6 release engineering and external audit

**Research** — high-cost, high-uncertainty:
- §2.5 TEE receipts
- §5.5 side-channel resistance
- §6.3 mix-network mode

---

## How to contribute

Each item above is a discrete project. Tracking issues will be opened
under `androolloyd/octravpn` with the `roadmap` label. Funding for
priority items can come from the Tier 2 program treasury once
sufficient throughput exists (see `docs/economics.md §12.1`).
External contributors are welcome on every item that doesn't touch
crypto-critical surfaces; for crypto items we'll require a
co-signer from the core team plus an outside review.
