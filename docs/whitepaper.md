# OctraVPN: Decentralized Private Mesh Networking on Octra

## Abstract

OctraVPN is a decentralized private mesh VPN. What Tailscale provides
through a central control plane, OctraVPN provides through the Octra
blockchain as the trust + economics layer and a bonded market of
operators as the off-chain control plane. Devices form **tailnets**:
on-chain groups whose membership, ACLs, and shared treasury live as
state in a single on-chain program. Members reach each other
peer-to-peer via WireGuard when network conditions allow, and fall
back to bonded operators when they don't. Internet egress through
**exit nodes** is the same mechanism applied to a tailnet whose
"destination" is the open internet.

For an audience-by-audience description of value, see
`docs/value.md`. For the economic model, see `docs/economics.md`.
For the security/identity provisions on the roadmap, see
`docs/security-roadmap.md`.

The system has three load-bearing pieces:

1. An **AML program** on Octra (`program/main.aml`) that owns
   tailnet objects, member sets, session deposits, operator stakes,
   slashable evidence, and encrypted operator earnings.
2. A **mesh layer** (`crates/octravpn-mesh`) that does STUN, peer
   registry, connection state machines, magic DNS, and ACL evaluation.
3. A **data plane** (`crates/octravpn-node`, `crates/octravpn-client`)
   running boringtun-based WireGuard with onion-routed receipts.

The novel contributions are:

- **In-program operator stake.** Operators stake OU in the AML
  program via `bond_endpoint`. The stake gates registration and is
  governance-slashable on off-chain equivocation evidence. (v1.1
  moves slashing fully on-chain once Octra exposes `verify_ed25519`
  in AML — see `docs/aml-gap-analysis.md`.)
- **HFHE-backed encrypted earnings.** Operator earnings accumulate as
  HFHE ciphertext under each operator's pubkey, using Octra's
  confirmed `fhe_add` / `fhe_add_const` / `fhe_verify_zero` host
  calls. Claims are a two-step: AML verifies the zero-proof and
  transfers plaintext OU; the operator's wallet wraps the funds in a
  native `op_type="stealth"` tx for unlinkable payout.
- **Three-tier fee structure.** Tier 1 (gas to Octra protocol
  validators) + Tier 2 (0.5 % of settlements funds the program
  treasury for audits + maintenance) + Tier 3 (per-byte pay to
  OctraVPN operators).
- **Tailnet treasuries.** Per-tailnet OU pools fund sessions;
  refunds return to the same pool. No per-user balances on chain.
- **Validator-only settlement with economic ceiling.** v1 is
  single-hop: the client deposits a `max_pay` ceiling from their
  tailnet treasury; the validator settles by reporting `bytes_used`;
  AML caps payment at the deposit. Receipt integrity is economic
  (the deposit), not cryptographic (v1.1 adds cryptographic dual-sig
  via Octra primitives).
- **Mesh-first connectivity.** Peer-to-peer WireGuard is the default;
  paid operators activate when direct probes fail. Upgrade is
  automatic.

## 1. Threat model

We assume:

- A globally-observable adversary that can read every chain
  transaction, every public-internet packet header, and any
  endpoint-operator traffic with that operator's cooperation.
- The adversary cannot compromise client or operator long-term keys
  without explicit modelling.
- The Octra chain remains live and correct in the consensus sense
  (transactions ordered, double-spend prevented, finality respected).

We protect (v1):

- **Confidentiality of operator earnings volume.** HFHE-encrypted
  earnings ledger; the chain operates on ciphertext via the
  confirmed `fhe_*` primitives. Decrypted only at the operator's own
  claim via the HFHE zero-proof.
- **Confidentiality of operator payout addresses.** Operators wrap
  the claim transfer in a native `op_type="stealth"` tx — the chain
  records a public claim then a stealth payment to a fresh address
  in the next block.
- **No stuck OU.** TLA+ and Lean models prove `<>(SessionSettled \/
  SessionRefunded)` and `treasury_monotone_on_no_show`.
- **Slashed operators cannot earn.** Lean lemma `slash_burns_stake`
  + TLA+ invariant `ActiveEndpointsAreBonded`.
- **Provable economic ceiling.** Lean lemma `settle_bounded_by_deposit`
  + AML `require(total_paid <= s.deposit)`. The client's max-pay
  deposit caps loss from any single dishonest operator.

We do not protect at v1 (deferred to v1.1 — see
`docs/security-roadmap.md §0`):

- **Cryptographic non-repudiation of receipts.** Requires
  `verify_ed25519` as an AML host call. Today receipt integrity is
  economic (the deposit ceiling).
- **Multi-hop route unlinkability.** Requires either
  `pedersen_verify_open` in AML or a native `op_type="vpn_route"`
  Octra extension. v1 is single-hop.
- **Cryptographic equivocation slashing.** Same dependency as
  receipt verification. v1 uses governance slash with off-chain
  evidence.
- **Tailnet membership.** Members are visible on chain (intentional
  for peer-to-peer authorisation). Privacy extensions in
  `docs/security-roadmap.md §6`.
- **Plaintext treasury balance.** Aggregate treasury is on-chain
  visible.
- **Disputable malice.** A dishonest operator can drop packets or
  be slow without producing cryptographic evidence. Reputation +
  market exit, not slashing. See `docs/economics.md §10`.

## 2. Architecture

### 2.1 Tailnet object

A tailnet is an on-chain record:

```text
Tailnet {
  owner: address              // governance (add/remove members, set ACL)
  treasury: int               // OU available for paid traffic
  members: map[address]       // who's in
  exits: map[address]         // operators authorised as exits/relays
  acl_policy: bytes           // sha256 of off-chain ACL doc
  created_at: epoch
}
```

The owner can mutate `members`, `exits`, and `acl_policy`; anyone can
deposit to `treasury`. Settlement and sessions reference the tailnet
they belong to.

### 2.2 Operator role (relay / directory / signaling)

OctraVPN operators provide three services from a single bonded
identity. The bonding flow:

```text
bond_endpoint(stake)
  require stake >= MIN_ENDPOINT_STAKE   // 1 000 OCT
  endpoint_stake[caller] += stake

register_endpoint(addrs, receipt_pubkey, view_pubkey, region,
                  price_per_mb, price_per_lookup, price_per_assist)
  require endpoint_stake[caller] >= MIN_ENDPOINT_STAKE
  endpoints[caller] = EndpointRecord { ... }
```

Operators publish three prices. The economic primitive is per-byte
for relay, per-event for directory and signaling. Discovery happens
by reading `list_active_endpoints` from the chain.

There is **no Octra-validator gate**. Any actor willing to bond
`MIN_ENDPOINT_STAKE` can be an operator. The stake is the Sybil
floor.

### 2.3 Governance slashing (v1) → cryptographic slashing (v1.1)

**v1 mechanism:** Off-chain evidence + governance slash.

```text
gov_slash_operator(operator_addr: address, reason: string) -> bool
  // owner-only; gates on require(caller == owner)
  // burns 90% of stake to program treasury, 10% to submitter (the owner here),
  // marks endpoint_slashed[op] = 1 permanently
```

The off-chain evidence is verified by `octravpn slash-evidence verify`
(in `crates/octravpn-client/src/commands/slash.rs`) — this performs
the cryptographic check on two contradictory signed receipts under
the operator's `receipt_pubkey`. The verified evidence is then
submitted as a governance proposal. The trust assumption is the
owner's honesty + the verifier's correctness.

**v1.1 target:** Once Octra exposes `verify_ed25519` in AML, this
becomes `submit_equivocation(evidence)` — permissionless and
cryptographically gated. The Tamarin model
(`proofs/tamarin/octravpn.spthy`) specifies the target guarantee.

### 2.4 Sessions (single-hop, v1)

A session opens against a tailnet's configured exit:

```text
session_id := sha256(self_addr || epoch || nonce || caller_addr)
sessions[session_id] := Session {
  tailnet_id,
  exit,                              // the chosen exit operator
  deposit = locked-from-tailnet-treasury,
  opened_at = epoch,
  status = open,
}
```

The client picks one exit at open time, deposits a `max_pay`
ceiling from the tailnet treasury. v1 is single-hop pending the
Octra primitives that make multi-hop route commitments verifiable
on-chain (`docs/security-roadmap.md §0`).

### 2.5 Settlement (validator-only)

`settle_session(session_id, bytes_used)` is callable only by the
exit operator:

```text
require caller == s.exit
require s.status == open
let total_paid = bytes_used * price_per_mb
require total_paid <= s.deposit                 // economic ceiling
let fee = total_paid * protocol_fee_bps / 10000
let net_pay = total_paid - fee
let refund = s.deposit - total_paid

// Effects (CEI ordering):
s.status := settled
enc_earnings[caller] := fhe_add(pk, enc_earnings[caller],
                                fhe_add_const(pk, op_zero_ct[caller], net_pay))
endpoints[caller].reputation += 1
program_treasury += fee
tailnet.treasury += refund
```

Integrity guarantee: **economic, not cryptographic**. The client's
deposit caps total operator extraction. Routine over-claiming
triggers off-chain reputation downgrade + market exit.

### 2.6 Encrypted earnings (HFHE)

Operator earnings accumulate as an HFHE ciphertext under each
operator's own pubkey, using the confirmed AML host calls:

- At `register_endpoint`, operator provides their HFHE pubkey and a
  pre-computed `enc_pk(0)` ciphertext.
- At each settle, `enc_earnings[op] = fhe_add(pk, cur,
  fhe_add_const(pk, op_zero_ct, net_pay))`.
- At `claim_earnings(amount, proof)`, AML reconstructs
  `enc(amount)` via `fhe_add_const`, subtracts, and verifies the
  zero-proof: `fhe_verify_zero(pk, cur - enc(amount), proof)`.

On a successful claim:
- AML resets `enc_earnings[op]` to the operator's `op_zero_ct`.
- AML calls `transfer(caller, amount)` — the operator's wallet
  receives plaintext OU.
- The operator's wallet immediately wraps it in a native
  `op_type="stealth"` tx (off-AML, at the Octra native-tx layer
  which has range proofs + Pedersen + zero-proofs built into the
  tx-validation pipeline per `docs/octra-research.md §5`).

The on-chain trail shows a plaintext claim followed by a stealth
output in the next block — the privacy story is intact.

### 2.7 Mesh data plane

The on-chain pieces above coordinate identity, money, and authority.
The mesh layer (`crates/octravpn-mesh`) makes peer-to-peer
connectivity work:

- **STUN client** (`stun.rs`): public-address discovery via RFC 5389
  Binding Requests.
- **Peer registry** (`peer.rs`): each member publishes their current
  candidate set (LAN, STUN, relay-via-operator).
- **Connection FSM** (`conn.rs`): per-peer state machine
  `Init → Probing → Direct | Relay`. Periodic upgrade probes from
  `Relay` back to `Direct` when direct reachability returns.
- **IP allocator** (`ip_alloc.rs`): deterministic CGNAT-range IP per
  (tailnet, member); every node computes every other node's address
  without coordination.
- **Magic DNS** (`magic_dns.rs`): in-process UDP resolver that maps
  `<peer>.<tailnet>.octra` → the allocated IP.
- **Subnet routing** (`subnet.rs`): a member can advertise a CIDR
  (corporate LAN, home network) to the rest of the tailnet.
- **ACL** (`acl.rs`): TOML ACL document, canonical hash matches the
  on-chain `acl_policy`. Runtime decisions through `AclDoc::decide`.

The mesh `MeshManager::tick(tailnet)` returns a list of `MeshAction`s
describing what the data plane should do — open a direct WG tunnel,
open via an operator-relay, or close an existing tunnel. The host
daemon translates those into `boringtun::Tunn` and kernel-routing
calls.

## 3. Formal claims

### 3.1 v1: AML state-machine safety + economic ceiling

| Property                                                    | Tool      | Artifact                                |
| ----------------------------------------------------------- | --------- | --------------------------------------- |
| Treasury non-negativity                                     | TLA+      | `proofs/tla/OctraVPN.tla`               |
| Session settles or refunds (no stuck OU)                    | TLA+      | `proofs/tla/OctraVPN.tla` (`Liveness_SettleOrRefund`) |
| Slashed operators have zero stake                           | TLA+      | `proofs/tla/OctraVPN.tla` (`SlashedHaveZeroStake`) |
| Active endpoints are bonded                                 | TLA+      | `proofs/tla/OctraVPN.tla` (`ActiveEndpointsAreBonded`) |
| Session exits are configured at open-time                   | TLA+      | `proofs/tla/OctraVPN.tla` (`SessionExitsAreConfigured`) |
| Settle requires caller is exit                              | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::settle_requires_caller_is_exit` |
| Settle bounded by deposit (economic ceiling)                | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::settle_bounded_by_deposit` |
| Settle returns refund to treasury                           | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::settle_returns_refund_to_treasury` |
| Settle finalises session                                    | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::settle_finalizes` |
| Register requires stake                                     | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::register_requires_stake` |
| Register not allowed after slash                            | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::register_not_slashed` |
| Bond increases stake                                        | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::bond_increases_stake` |
| Slash burns stake atomically                                | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::slash_burns_stake` |
| Slash is terminal (marks endpoint slashed)                  | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::slash_marks_terminal` |
| Slash requires owner                                        | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::slash_requires_owner` |
| Claim requires exact-match (FHE zero-proof soundness)       | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::claim_requires_exact_match` |
| Claim resets earnings ledger                                | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean::claim_resets_encEarn` |
| Crypto primitives correct shape                             | Kani      | `proofs/kani/Cargo.toml`                |

The Lean proofs go through without `sorry`; the TLA+ specification
is model-checked by TLC in CI (`.github/workflows/ci.yml::tla`).

### 3.2 v1.1 target (deferred pending Octra primitives)

These properties live at the cryptographic layer and require Octra
to expose `verify_ed25519` in AML (`docs/aml-gap-analysis.md §3`).
The Tamarin theory specifies the target guarantee:

| Property                                            | Tool      | Artifact                                |
| --------------------------------------------------- | --------- | --------------------------------------- |
| Receipt unforgeability                              | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Double-sign yields slash evidence                   | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Equivocation evidence cannot be fabricated          | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Route-commitment unlinkability                      | Tamarin   | `proofs/tamarin/octravpn.spthy`         |

### 3.3 Property-based tests

| Property                                                  | File                                      |
| --------------------------------------------------------- | ----------------------------------------- |
| Signed envelope always verifies (honest sign)             | `crates/octravpn-core/tests/prop_security.rs` |
| Field mutation breaks signed envelope                     | `crates/octravpn-core/tests/prop_security.rs` |
| Stealth tag unique per ephemeral                          | `crates/octravpn-core/tests/prop_security.rs` |
| Sealed-payload AEAD tamper detection                      | `crates/octravpn-core/tests/prop_security.rs` |
| Receiver/sender stealth tag agreement                     | `crates/octravpn-core/tests/prop_security.rs` |

### 3.4 Honest scope limits

Without Octra exposing additional host calls, the following move to
the native-tx-layer trust assumption (Octra's runtime is
closed-source and not yet formally verified):

- Cryptographic non-repudiation of bandwidth receipts
- Stealth payout unlinkability (depends on Octra's stealth
  implementation)
- Range-proof correctness on native stealth transfers

`docs/security-roadmap.md §0` is the up-to-date list of Octra-team
asks that close these gaps.

## 4. Economic design

Summarised in `docs/economics.md`. Key points:

- Single token (OU); no app-specific currency; no issuance.
- Three-tier fees: Tier 1 (Octra gas) + Tier 2 (0.5 % protocol fee
  funds program treasury) + Tier 3 (per-op operator pay).
- One bonded operator role. Stake `MIN_ENDPOINT_STAKE` = 1 000 OCT
  (1B OU). Slashable atomically on equivocation evidence (90 % burn
  / 10 % submitter bounty / permanent ineligibility).
- Payment flows: owner → tailnet treasury → session deposit →
  operator earnings → stealth payout. Refund completeness: every
  locked OU has a recovery path.
- No vesting on operator earnings; the encrypted-earnings ledger is
  the commitment device.
- Default parameters: `min_session_deposit = 10 OU`,
  `min_tailnet_deposit = 100 OU`, `session_grace_epochs = 100`,
  `sweep_bounty_bps = 100`, `protocol_fee_bps = 50`,
  `MIN_ENDPOINT_STAKE = 10⁹ OU`. Governance-mutable within
  constructor-enforced bounds.

## 5. Security & identity roadmap

The shipping protocol covers cryptographic accountability +
economic security. `docs/security-roadmap.md` enumerates additional
provisions planned by category:

- **Identity**: hardware-backed wallet keys (YubiKey, Ledger, Secure
  Enclave, TPM), WebAuthn / passkeys for per-device session keys,
  W3C `did:octra` anchoring, TPM measured-boot attestation,
  post-quantum PSK hedge.
- **Operator hardening**: forward-secure receipt key rotation,
  reputation-tiered rate limits, quorum-signed ACL updates,
  per-hop attestation receipts, optional TEE receipt signing.
- **Audit & forensics**: write-once log shipping, signed audit-log
  export with chain anchoring, receipt expiry epochs.
- **Network hardening**: anti-MEV settlement ordering, Tor-routed
  control plane, STUN provider attestation, encrypted member
  metadata.
- **Operational**: cosign-signed releases with Sigstore transparency
  log, public bug bounty, external audit, formal-verification
  expansion.
- **Privacy enhancements**: plausible-deniability join, sealed
  bandwidth metadata, mix-network mode (research).
- **Anti-abuse**: per-tailnet capabilities & quotas,
  reputation-weighted client penalty, slashed-operator denylist.

Prioritised by phase (v1.1, v1.x, v2/research) in the roadmap doc.

## 6. Implementation status

- AML program: v1 surface complete, built against confirmed Octra
  primitives only (see `docs/aml-gap-analysis.md`). Bond / unbond /
  finalize / governance-slash entrypoints present. Single-hop
  sessions with validator-only settle. HFHE earnings via
  `fhe_add`/`fhe_add_const`/`fhe_verify_zero`.
- Mock chain (`tests/mocks`): faithfully implements the v1 AML
  semantics. The HFHE earnings ledger is mock-cleartext but the
  state-machine transitions match.
- Mesh primitives: complete (`crates/octravpn-mesh`, 39 unit tests).
- Data plane: WireGuard via boringtun, onion routing, control plane,
  audit log, rate limiting all wired in.
- Equivocation tooling: `octravpn slash-evidence verify | build`
  for off-chain workflows; v1.1 will add `submit` once Octra exposes
  the necessary primitives.
- Property + integration tests: 54 test groups passing.
  `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Formal proofs: Lean + TLA+ updated for the v1 model; Tamarin
  theory retained as the v1.1+ target guarantee.

## 7. Where it stops being decentralised

We're honest about residual centralisation:

- **Off-chain ACL distribution.** The ACL document hash is on-chain
  but the document itself isn't. We assume tailnet owners serve it
  over HTTPS or pin it to IPFS; the failure mode is a stale ACL,
  which the recipient's mesh layer refuses to use until it can fetch
  the current hash. Future: ACL bodies served by bonded directory
  operators (in scope of the unified role); equivocation on the body
  is then slashable.
- **STUN servers.** Public-IP discovery talks to an off-chain STUN
  server. Today the set is configurable and bound to "wrong public
  IP discovered → fall back to relay." On the roadmap
  (`docs/security-roadmap.md §4.3`), STUN responses become signed
  claims under the operator's `receipt_pubkey` and equivocation on
  them is slashable like any other operator misbehaviour.
- **Initial bootstrap.** New devices need a way to find any node in
  the tailnet for the first time. Today this is a manual share of
  an endpoint URL; future work integrates a DHT.
- **Octra protocol layer.** OctraVPN inherits the liveness and
  ordering guarantees of Octra consensus. If Octra halts, OctraVPN
  halts. This is true of any L2 / application; we list it for
  completeness.

## 8. Comparison to Tailscale

| Aspect                    | Tailscale                | OctraVPN                                     |
| ------------------------- | ------------------------ | -------------------------------------------- |
| Control plane             | Centralised SaaS         | Octra blockchain (trust + economics) +       |
|                           |                          | bonded operator market (off-chain)           |
| Identity                  | OIDC / SSO               | Octra wallet + WebAuthn (roadmap)            |
| ACL store                 | Coordination server      | Hash on chain; doc served by directory ops   |
| Relays (DERP equivalent)  | Tailscale-operated DERPs | Bonded operators paid per byte               |
| Magic DNS                 | Yes                      | Yes (`<peer>.<tailnet>.octra`)               |
| Subnet routing            | Yes                      | Yes                                          |
| Exit nodes                | Tailnet member           | Bonded operators (subset configured as exits) |
| Pricing                   | Per-seat / month         | Per-byte through operators; ~zero baseline   |
| Open source               | Partially                | Fully                                        |
| Trust model               | Trust Tailscale          | Trust math (proofs) + economics (slashing)   |
| Operator accountability   | Tailscale TOS            | Cryptographic equivocation evidence + slash  |
| Single point of compliance | Tailscale Inc.          | None — protocol enforces, operators clear    |

## 9. References

| File                                              | Purpose                                              |
| ------------------------------------------------- | ---------------------------------------------------- |
| `program/main.aml`                                | On-chain program                                     |
| `program/interfaces/IOctraVPN.aml`                | Public surface                                       |
| `crates/octravpn-core/`                           | Shared types, RPC, crypto                            |
| `crates/octravpn-mesh/`                           | Mesh primitives (STUN, peers, conn, ACL)             |
| `crates/octravpn-node/`                           | Operator-side daemon                                 |
| `crates/octravpn-client/`                         | Client CLI                                           |
| (`octra-foundry/crates/octraforge/`)              | Foundry-style test harness (sibling repo)            |
| (`octra-foundry/crates/octra-cli/`)               | `octra forge\|cast\|anvil\|chisel` toolchain (sibling repo) |
| `proofs/{tla,tamarin,lean,kani}/`                 | Formal verification artifacts                        |
| `docs/value.md`                                   | What the system provides, by stakeholder             |
| `docs/economics.md`                               | Economic model (this whitepaper §4)                  |
| `docs/security-roadmap.md`                        | Additional security/identity provisions (this §5)    |
| `docs/tailnet-user-guide.md`                      | How to use a tailnet                                 |
| `docs/operator-guide.md`                          | How to run a paid endpoint                           |
| `docs/deployment-runbook.md`                      | Operator playbook for staging → mainnet → incidents  |
| `docs/validator-hardening.md`                     | Systemd / AppArmor / monitoring hardening profile    |
