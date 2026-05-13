# OctraVPN: Security and Identity Roadmap

This document lists security and identity provisions that are NOT in
the shipping protocol today, ordered by priority and grouped by
category. Each section gives: the property we want, the attack it
mitigates, the proposed mechanism, and the rough cost.

For what's already in the protocol see `docs/whitepaper.md §1`
(threat model), `docs/economics.md §10` (adversarial scenarios),
and the formal proofs in `proofs/`.

Status legend: 🟢 = planned for v1.1, 🟡 = v1.x, 🔴 = research/v2.

---

## 0. Octra-team asks (highest priority, blocks v1.1)

Per `docs/aml-gap-analysis.md` our AML can only use confirmed Octra
host calls. The following AML extensions would unlock the
properties we currently can't enforce on-chain. Each item is a
discrete ask to the Octra core team.

### 0.1 🟢 `verify_ed25519(pubkey, msg, sig) -> bool` host call

**Unlocks:**
- Dual-signed receipt verification in `settle_session` →
  cryptographic non-repudiation of `bytes_used`.
- `submit_equivocation(operator, evidence)` permissionless slashing.
- `redeem_join_token` pre-auth tokens.
- Quorum-signed ACL updates (`§2.3`).

**Rationale:** Ed25519 is already in Octra's tx-signing pipeline
(`docs/octra-research.md §3`); the primitive exists at the chain
runtime. Exposing it to AML is a thin host-binding.

**Estimated cost:** ~1 week of Octra-team work.

### 0.2 🟢 Native `op_type="vpn_settle"` extension

**Unlocks:** Dual-signed bandwidth receipts verified by the native-tx
runtime BEFORE AML executes. AML sees pre-validated data.

**Mechanism:** Extend Octra's `op_type` set with `"vpn_settle"` that
carries `(session_id, bytes_used, blind, client_sig, node_sig)` in
`encrypted_data`. Runtime verifies both signatures + dual-sig
construction; rejected txs never reach AML.

**Rationale:** Mirrors the existing `op_type="stealth"` model where
range proofs + Pedersen commitments are runtime-verified.

**Estimated cost:** ~3 weeks of Octra-team work.

### 0.3 🟡 `verify_bulletproof(commit, proof) -> bool` host call

**Unlocks:**
- Encrypted bandwidth volumes in settle (`docs/security-roadmap.md
  §6.2`).
- Range-proofed FHE-encrypted balances (prevent over-claim before
  the chain even runs `fhe_verify_zero`).

**Rationale:** Octra's stealth path uses bulletproof-shaped range
proofs at the native-tx layer (`pvac_make_range_proof`). Lifting to
AML lets programs adopt the same primitive.

**Estimated cost:** ~2-4 weeks (depends on the existing libpvac
bindings).

### 0.4 🟡 Linkable ring signature host call

**Unlocks:**
- Plausible-deniability join (`§6.1`).
- Multi-device unlinkability (a device proves it's "one of my
  registered devices" without revealing which).

**Rationale:** No existing Octra primitive; net-new.

**Estimated cost:** ~2 months including reference impl.

### 0.5 🟡 Schnorr DLEQ proof host call

**Unlocks:**
- Forward-secure receipt key rotation (`§2.1`) — proves a new key
  is derived from the old key's secret without revealing the old
  secret.

**Estimated cost:** ~3 weeks.

### 0.6 🟡 General SNARK verifier (`verify_groth16` or `verify_plonk`)

**Unlocks:** Arbitrary zk statements about hidden witnesses. Range
proofs, ring sigs, DLEQ all subsume into a single verifier. Best
long-term answer to the "encrypted everything" privacy goal.

**Estimated cost:** ~3-6 months upstream + trusted setup ceremony.

### 0.7 🟢 `octra_isValidator(addr)` AML host call

**Unlocks:** OctraVPN can require operators to ALSO be Octra
validators (hybrid model from earlier design discussions). Currently
this is callable from RPC but not from AML.

**Mechanism:** Expose `is_octra_validator(addr) -> bool` as a host
call (the chain already knows; just lacks the AML binding).

**Estimated cost:** ~1 week.

---

## 1. Identity & device attestation

### 1.1 🟢 Hardware-backed wallet keys

**Want.** Wallet private keys never exist in plaintext on disk; all
signing happens inside a hardware module.

**Threatens.** Wallet exfiltration via filesystem read, memory dump,
or stolen backup tape.

**Mechanism.** Client + node daemons gain an `identity.backend`
option:

| Backend         | Where the key lives                  | Sign latency    |
| --------------- | ------------------------------------ | --------------- |
| `file` (today)  | Encrypted at rest, plaintext in RAM  | < 1 ms          |
| `yubikey-pgp`   | YubiKey PIV / OpenPGP applet         | ~50 ms          |
| `ledger`        | Ledger Nano via APDU                 | ~200 ms + UI    |
| `secure-enclave` | Apple Secure Enclave (macOS / iOS)  | < 5 ms          |
| `tpm2`          | TPM 2.0 (Linux / Windows)            | ~10 ms          |

The `KeyPair` trait in `crates/octravpn-core/src/sig.rs` becomes the
extension point; each backend implements `sign(&self, msg: &[u8]) ->
Signature`. The signed-envelope format is unchanged.

**Cost.** ~2 weeks per backend. Most of the work is making the
re-key flow ergonomic (the existing AML already supports key rotation
via `set_view_pubkey` + `set_receipt_pubkey`).

### 1.2 🟢 WebAuthn / passkeys for tailnet membership

**Want.** A user can be a tailnet member without managing a
long-lived wallet key on every device — passkey on phone + browser
+ laptop.

**Threatens.** Wallet-key sprawl, phishing of user wallets, the
"how do I get this key onto my Chromebook" friction.

**Mechanism.** Two-key separation:

- **Stable user identity**: a wallet key (could be hardware-backed
  per §1.1).
- **Per-device session key**: a WebAuthn credential created via the
  user's browser/OS passkey provider; bound on chain via
  `register_device(passkey_pubkey)`.

The wallet key signs the on-chain `register_device` once; afterwards
the passkey signs all session-level operations on that device.
Revocation is `revoke_device(passkey_pubkey)`.

**Cost.** ~3 weeks. WebAuthn assertion verification is supported via
`webauthn-rs`; the wire format for our signed-call envelope needs a
new `pubkey_kind: enum { Ed25519, WebAuthn }` field.

### 1.3 🟡 DID anchoring (W3C did:octra)

**Want.** Tailnet members + endpoints expose a portable, resolvable
identifier compatible with existing decentralized-identity
ecosystems.

**Threatens.** Vendor lock-in of identity to OctraVPN; inability to
prove tailnet membership outside the protocol (e.g., to an external
SSO).

**Mechanism.** A `did:octra` method spec:

```
did:octra:<chain>:<address>
  → DID Document published in AML at did_documents[address]
```

The document contains verification methods (wallet pubkey, current
passkey credentials), service endpoints (tailnet membership list,
preferred contact addresses), and a revocation index. Updates are
on-chain txs signed by the wallet.

**Cost.** ~6 weeks including the DID-resolver crate and a reference
verifier.

### 1.4 🟡 Device attestation via TPM/SE measured-boot

**Want.** When a member joins a tailnet from a device, the tailnet
can require evidence that the device booted a known-good OS image.

**Threatens.** Compromised devices joining via stolen passkeys; APT
persistence through bootkits.

**Mechanism.** `register_device` optionally accepts a
`MeasuredBootProof` — a signed TPM 2.0 quote attesting PCR values
matching a tailnet-configured allowlist. The ACL evaluator gains a
`require_attestation: bool` clause.

**Cost.** ~4 weeks. The hard part is keeping the PCR allowlist
maintainable across OS updates; we'll publish a public attestation-key
service that signs known-good PCR sets per `(os, version, kernel)`.

### 1.5 🟡 Per-session PSK for post-quantum hedge

**Want.** Resistance against an adversary with a future quantum
computer who recorded today's WireGuard handshakes.

**Threatens.** "Harvest now, decrypt later" attacks against
recorded session traffic.

**Mechanism.** WireGuard supports a per-session pre-shared key
(`PresharedKey`) added to the handshake. We derive the PSK via a
Kyber768 KEM exchange anchored to a per-member long-term Kyber
public key published on chain (`kyber_pubkey: bytes`). The combined
key is `BLAKE3(WG_classic_handshake || Kyber_secret)`.

**Cost.** ~3 weeks. Kyber implementation is available via
`pqcrypto-kyber`; the AML surface gains a single byte field per
endpoint.

---

## 2. Operator security

### 2.1 🟢 Forward-secure receipt key rotation

**Want.** Compromise of an operator's receipt-signing key today does
not expose the validity of receipts they signed yesterday.

**Threatens.** Operator key compromise leading to retroactive
equivocation evidence forgery (against an honest historical operator).

**Mechanism.** `receipt_pubkey` becomes a Merkle root of N
generation-specific subkeys. Each settled receipt batch advances the
generation. Old subkeys are *destroyed* (not merely rotated) at the
operator side after their epoch closes. Forging a receipt from
epoch K requires the subkey for epoch K — which physically no longer
exists.

A protocol-level slash-on-future-key-leak would require a
forward-secure construction the operator can attest to. Initial
version: rely on the operator's HSM (§1.1) for destruction.

**Cost.** ~4 weeks. Forward-secure signature schemes (Bellare-Miner
or similar) are available in `crates/octravpn-core` already; the AML
surface adds an `epoch` field to the equivocation-evidence reference.

### 2.2 🟢 Reputation-tiered rate limits

**Want.** Established operators get higher rate-limit ceilings; fresh
operators are throttled to limit damage from a stake-then-burn
attack.

**Threatens.** Operator-side flooding — a freshly-bonded operator
floods the control plane with malformed requests, gets slashed, but
extracts disruption value first.

**Mechanism.** The node daemon's `control-plane` rate limit is
parameterized by `EndpointRecord.reputation`:

```
limit = base_rate × min(1 + log10(reputation + 1), TIER_MAX)
```

Default: fresh operator gets 100 req/s, 1k-reputation operator gets
~400 req/s, 1M-reputation operator gets ~700 req/s.

**Cost.** ~1 week.

### 2.3 🟡 Quorum-signed ACL updates

**Want.** Tailnet ACL changes require N-of-M owner signatures, not
just a single wallet signature.

**Threatens.** Single-owner key compromise leading to silent ACL
relaxation; insider risk for shared tailnets.

**Mechanism.** `Tailnet.owner` becomes a `MultiSigPolicy { signers:
Vec<Address>, threshold: u8 }`. `update_acl` requires a
`SignedAclDoc` with ≥ `threshold` valid signatures from `signers`.
Membership changes (`add_member` / `remove_member`) gain the same
gate at the owner's option.

This composes with §1.1 — each signer can be hardware-key-backed.

**Cost.** ~2 weeks.

### 2.4 🟡 Per-hop attestation receipts (path verification)

**Want.** A client can prove their traffic actually traversed the
hops they paid for, not a shorter cheaper subset.

**Threatens.** Path-shortening — a multi-hop session where some
"hops" are colluding to skip real relay work and split the savings.

**Mechanism.** Each hop signs a per-batch path-attestation receipt
that includes:

- The hop's own pubkey
- The previous hop's pubkey (from the path commit)
- A hash of the encrypted onion layer they unwrapped

A client receiving the full set can verify the chain matches their
path commit; a mismatch is provable evidence to slash via
`submit_equivocation(domain: Path, ref: session_id||epoch)`.

**Cost.** ~4 weeks. Onion-routing receipt protocol extension.

### 2.5 🔴 Trusted-Execution-Environment receipts

**Want.** Receipts are signed inside an SGX / SEV enclave so the
operator's plaintext OS cannot fabricate receipts.

**Threatens.** OS-level operator compromise (root on the box) that
allows arbitrary receipt forgery without operator knowledge.

**Mechanism.** Receipt signing moves into a TEE enclave; the
enclave's attestation key signs all receipts; the chain verifies the
attestation key's certificate chain via Intel's / AMD's PKI.

**Cost.** ~3 months. TEE supply-chain risk is real (multiple
vulnerabilities per year); we'd ship this as an *option*, not a
requirement, and recommend it for high-value tailnets only.

---

## 3. Audit & forensics

### 3.1 🟢 Audit log shipping to write-once storage

**Want.** The HMAC-chained audit log is mirrored in real-time to
external storage that cannot be retroactively modified.

**Threatens.** Operator-side log tampering: an operator who
compromises root on the box could replace the audit log + key,
making post-hoc forensics impossible despite the chain.

**Mechanism.** A new `audit-shipper` sidecar reads the audit JSONL
stream and POSTs each line to one or more configured sinks:

| Sink                | Write-once?                                | Cost            |
| ------------------- | ------------------------------------------ | --------------- |
| S3 Object Lock      | Yes (compliance-mode retention)            | $$              |
| IPFS via Pinata     | Yes (content-addressed)                    | $               |
| Octra chain         | Hash-only (full body would bloat state)    | gas             |
| Signed-redis WORM   | Self-hosted append-only key-value          | self-host       |

**Cost.** ~2 weeks for the sidecar; ~1 week per sink integration.

### 3.2 🟢 Signed audit-log export with verification chain

**Want.** When operators ship the audit log to an external auditor,
the auditor can verify the chain without trusting the operator's
shipping process.

**Threatens.** Tampering in transit between operator and auditor.

**Mechanism.** Export bundles include `.audit.key`, the JSONL chain,
a root-MAC signed by the operator's wallet key, and a chain proof
referencing the most recent on-chain tx hash for cross-anchoring.
Auditor's verifier (`octravpn-node verify-audit-export`) checks all
three.

**Cost.** ~1 week.

### 3.3 🟡 Receipt expiry epochs

**Want.** A receipt held by a client for years cannot be settled
arbitrarily late; settlement must happen within a bounded window.

**Threatens.** Late-settle attacks where a client holds receipts and
settles them after the operator's reputation/stake context has
changed in a way that disadvantages the operator.

**Mechanism.** `settle_session` gains a check:

```
require(now - session.opened_at_epoch <= SETTLE_EXPIRY_EPOCHS)
```

Default: `SETTLE_EXPIRY_EPOCHS = 30 days`. Expired sessions can be
swept (refund-only, no operator pay) via `sweep_expired_session`.

**Cost.** ~1 week. Already partially implemented; needs param + test
coverage.

---

## 4. Network layer hardening

### 4.1 🟢 Anti-MEV ordering at settlement

**Want.** Settlement transactions cannot be reordered or
sandwich-attacked to drain treasuries.

**Threatens.** A block producer (or someone with mempool privilege)
who sees a settle tx coming and front-runs with an `update_endpoint`
or competing settle.

**Mechanism.** Two protocol changes:

1. `settle_session` includes a `commit_epoch` in its signing payload;
   the AML rejects settles whose `commit_epoch` is older than `now -
   N` (forces the client to commit to a recent state).
2. Critical entrypoints (`settle_session`, `submit_equivocation`)
   use commit-reveal — client posts `hash(call_payload)` in block N,
   reveals the payload in block N+1. Reorders are detectable.

**Cost.** ~3 weeks.

### 4.2 🟢 Tor-routed control plane (operator option)

**Want.** Operators can publish their control plane over a Tor hidden
service, hiding their public IP from rate-limiting / DDoS adversaries.

**Threatens.** IP-layer DDoS against operators that the on-chain
slashing model can't help with.

**Mechanism.** `EndpointRecord.endpoint` can be a `.onion` address;
clients with Tor support connect via SOCKS5. Onion service is
operator-side; clients reach via Tor.

Note: this hides the operator's IP, *not* the existence of the
service. Tor hidden services have well-known traffic patterns.

**Cost.** ~2 weeks.

### 4.3 🟡 STUN provider attestation

**Want.** The STUN servers used for public-address discovery are
themselves accountable, not arbitrary internet hosts.

**Threatens.** A malicious STUN server returns false public-IPs to
clients, breaking direct connectivity and forcing fallback to a
specific colluding operator.

**Mechanism.** STUN responses include a chain-epoch + signature from
an operator's `receipt_pubkey`. STUN service joins the unified
operator role (relay + directory + signaling + STUN). Slashable on
equivocation: two contradictory STUN responses for the same client
IP at the same epoch.

**Cost.** ~2 weeks; partially overlaps with signaling-fee work.

### 4.4 🟡 Encrypted member metadata

**Want.** A tailnet's member list is on chain but the human-readable
metadata (display names, device descriptions, contact info) is
encrypted.

**Threatens.** Tailnet membership doxxing — chain observers can
enumerate member addresses today; if they can also see `device_name`
fields, social-engineering becomes much cheaper.

**Mechanism.** Per-tailnet metadata stored as ChaCha20-Poly1305
ciphertext keyed by a tailnet-wide symmetric key distributed to
members via stealth outputs at join time. Owner can re-key on member
removal.

**Cost.** ~3 weeks including the key-rotation flow.

---

## 5. Operational

### 5.1 🟢 Signed releases via cosign + transparency log

**Want.** Every released binary is signed by a hardware-backed key,
the signature is logged in a public transparency log (Sigstore /
Rekor), and the verification process is documented for operators.

**Threatens.** Supply-chain attacks: a backdoored binary distributed
to operators.

**Mechanism.** CI signs releases via `cosign sign-blob` with a
keyless OIDC flow; verification command is in
`docs/deployment-runbook.md §2`. SBOMs (CycloneDX) attached to every
release. Reproducible build flags for the node binary.

**Cost.** ~1 week + ongoing CI maintenance.

### 5.2 🟢 Public bug bounty program

**Want.** External researchers have a clear path to report
vulnerabilities and get paid for impact.

**Mechanism.** Hosted via Immunefi or HackerOne, scoped to the
on-chain program + the node daemon. Funded from the Tier 2 program
treasury. Severity table tied to OWASP Top 10 + crypto-specific
classes (slashing-bypass, stealth-tag-correlation, key-recovery).

**Cost.** ~2 weeks to set up; ongoing payout budget.

### 5.3 🟡 Independent external audit

**Want.** A third-party security firm audits the AML program +
crypto-critical Rust crates before mainnet.

**Mechanism.** Engage Trail of Bits, Spearbit, or similar.
Deliverable: a published report with all findings + remediation
notes.

**Cost.** ~$150-300k via Tier 2 treasury or external grant.

### 5.4 🟡 Formal-verification expansion

**Want.** Coverage of the formal proofs in `proofs/` extends from
"safety properties of settle" to "safety properties of the entire
state machine, including bonding, slashing, and key rotation."

**Mechanism.** Continue Lean / TLA+ / Tamarin work; specifically:

- Lean: add slashing module with `slash_burns_stake`,
  `slash_pays_bounty`, `slash_terminal` lemmas.
- TLA+: extend spec with bonding/unbonding states; model-check
  `EquivocationDetected ⇒ <>StakeSlashed`.
- Tamarin: extend protocol model to cover directory + signaling
  equivocation alongside receipt equivocation.

**Cost.** ~2 months engineering + 1 month research-collaboration
budget.

### 5.5 🔴 Side-channel resistance review

**Want.** Constant-time guarantees on every crypto operation that
touches secret material; cache-timing audit of stealth-tag
computation.

**Threatens.** Co-location attacks where an attacker on the same
host reads secret-key bits via cache timing.

**Mechanism.** Audit by a crypto firm; convert any non-constant-time
operations (BIGNUM math, table lookups) to their constant-time
equivalents. Add fuzzing against `dudect`.

**Cost.** ~$50k audit + ~1 month engineering.

---

## 6. Privacy enhancements

### 6.1 🟡 Plausible-deniability join

**Want.** A device's join transaction is not publicly linkable to
the user's primary wallet identity.

**Threatens.** Join-time deanonymisation: someone watching the chain
sees `register_device(passkey)` from a wallet they can identify and
links the device to the human.

**Mechanism.** Two-stage join: (1) the owner creates a one-time
`JoinIntent` ticket; (2) the device claims the ticket from a fresh
wallet address funded via a stealth output. The chain sees a fresh
address join the tailnet, not the user's primary wallet.

**Cost.** ~3 weeks.

### 6.2 🟡 Sealed bandwidth metadata

**Want.** A tailnet's per-month bandwidth profile is not visible to
chain observers.

**Threatens.** Bandwidth-profile correlation: a 1 TB/month tailnet
in a region with one notable user is identifiable.

**Mechanism.** `settle_session` emits an event whose `bytes_used`
field is encrypted under the tailnet's symmetric metadata key.
On-chain aggregation still works (only the operator and the tailnet
members can decrypt; the program just sums Pedersen commitments).

**Cost.** ~2 weeks.

### 6.3 🔴 Mix-network mode

**Want.** Multi-hop relay sessions include cover-traffic + timing
obfuscation, providing actual anonymity against a global passive
adversary (not just confidentiality).

**Threatens.** Traffic-analysis deanonymisation against a global
passive adversary who observes both ingress + egress.

**Mechanism.** Per-hop fixed-rate batching with Poisson timing
(à la Loopix). Significant bandwidth overhead.

**Cost.** ~3 months. Likely deferred indefinitely unless a sponsor
needs it; the bandwidth-overhead cost makes it unattractive for the
target user.

---

## 7. Anti-abuse

### 7.1 🟢 Per-tailnet capabilities & quota

**Want.** A misconfigured or compromised member can't drain the
tailnet treasury via runaway sessions.

**Threatens.** Loose-cannon members (e.g., a child's phone) burning
through the family treasury.

**Mechanism.** ACL gains `capabilities: { max_session_deposit:
Option<u64>, max_daily_spend: Option<u64> }` per member. Enforced
at `open_session` by the on-chain ACL evaluator.

**Cost.** ~2 weeks.

### 7.2 🟢 Reputation-weighted client penalty

**Want.** A client who repeatedly opens-and-abandons sessions is
de-prioritised by operators.

**Threatens.** Operator-side resource exhaustion from no-show grief.

**Mechanism.** Operators publish a `min_client_reputation_for_open`
threshold; clients below the bar get rejected at handshake time.
Client reputation increments at every settled session.

**Cost.** ~1 week.

### 7.3 🟡 Slashed-operator denylist propagation

**Want.** A slashed operator can't immediately re-register under a
new wallet to keep operating.

**Threatens.** "Identity-rotation" attacks where a slashed operator
spins up a fresh address with fresh stake and keeps misbehaving.

**Mechanism.** Same as today: re-registering costs another full
`MIN_ENDPOINT_STAKE`, so the attack is at least linear in capital.
Plus: clients can opt-in to a community-curated denylist (off-chain
list of IPs / known-operator clusters) for additional friction. The
denylist is purely advisory — protocol enforcement is via the stake
floor.

**Cost.** ~1 week.

---

## Priority groupings

**v1.1 (next 3 months)** — operator hardening + audit baseline:
- §1.1 hardware-backed wallet keys
- §1.2 WebAuthn / passkeys
- §2.1 forward-secure receipt keys
- §2.2 reputation-tiered rate limits
- §3.1 audit log shipping
- §3.2 signed audit export
- §4.1 anti-MEV ordering
- §4.2 Tor control plane
- §5.1 signed releases (in progress)
- §5.2 bug bounty (kickoff)
- §7.1 per-tailnet quotas
- §7.2 client reputation

**v1.x (months 4-12)** — identity ecosystem + privacy:
- §1.3 DID anchoring
- §1.4 measured-boot attestation
- §1.5 post-quantum PSK
- §2.3 quorum-signed ACL
- §2.4 per-hop attestation receipts
- §3.3 receipt expiry epochs
- §4.3 STUN provider attestation
- §4.4 encrypted member metadata
- §5.3 external audit
- §5.4 formal-verification expansion
- §6.1 plausible-deniability join
- §6.2 sealed bandwidth metadata
- §7.3 slashed-operator friction

**v2 / research** — high-cost, high-uncertainty:
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
