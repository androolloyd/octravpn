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

- **In-program bond and slashing.** Operators stake OU in the AML
  program. Equivocation on any signed operational claim — receipt,
  directory response, signaling response — is verified on chain and
  slashes the stake atomically. We do not rely on Octra protocol-layer
  slashing; Octra protects Octra consensus, not OctraVPN receipts.
- **Unified operator role.** One bonded role, three revenue streams
  (relay / directory / signaling), one reputation, one slash surface.
- **Three-tier fee structure.** Tier 1 (gas to Octra protocol
  validators) + Tier 2 (0.5 % of settlements funds the program
  treasury for audits + maintenance) + Tier 3 (per-operation pay to
  OctraVPN operators).
- **Tailnet treasuries.** Per-tailnet OU pools fund sessions;
  refunds return to the same pool. No per-user balances on chain.
- **Shielded payments + traffic.** Operators receive
  Pedersen-committed earnings revealed only at claim; clients build
  routes as Pedersen commitments revealed only at settle.
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

We protect:

- **Confidentiality of who is talking to whom** within a tailnet.
  Pedersen commitments hide the route; only the exit (with the
  client's cooperation) learns its own role.
- **Confidentiality of payment volume per operator.** Encrypted
  earnings ledger; opening happens only at the operator's own claim.
- **Authenticity of receipts.** Dual-signed (client ephemeral session
  key + operator long-term key). Tamarin proof
  (`proofs/tamarin/octravpn.spthy`) shows unforgeability under
  Dolev-Yao with key-compromise.
- **Provable malice ⇒ atomic slash.** Equivocation on any signed
  operational claim is detected and acted on by the AML program in
  one transaction.

We do not protect (at v1):

- **Tailnet membership.** Members are visible on chain; that's how
  peer-to-peer authorisation works. The privacy goal is the contents
  and partner of each flow, not the existence of the tailnet. See
  `docs/security-roadmap.md` §6 for the privacy-extensions roadmap
  (encrypted member metadata, plausible-deniability join, sealed
  bandwidth).
- **Plaintext treasury balance.** Aggregate treasury is on-chain
  visible. Per-member contributions can be made private by
  depositing via stealth outputs once Octra exposes the necessary
  primitives.
- **Disputable malice.** A dishonest operator can drop packets,
  serve correct-but-stale data, or be slow without producing
  cryptographic evidence. We handle these via reputation + market
  exit, not slashing. See `docs/economics.md §10` for the full
  attack matrix and `docs/security-roadmap.md` §2 for planned
  hardenings.

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

### 2.3 Slashable evidence

The unified evidence type covers all three services:

```text
EquivocationEvidence {
  operator_addr        : Address
  receipt_pubkey       : [u8; 32]
  domain               : enum { Receipt, Directory, Signaling }
  ref                  : bytes              // session_id||seq | query_hash||epoch | ...
  claim_a              : bytes              // signed claim body
  claim_b              : bytes
  sig_a                : [u8; 64]
  sig_b                : [u8; 64]
}
```

`submit_equivocation(evidence)` is permissionless. AML verifies on
chain:

1. Both signatures validate under `receipt_pubkey` over the
   domain-separated message.
2. `Address::from_pubkey(receipt_pubkey) == operator_addr`.
3. The claim bodies hash to distinct values (real equivocation, not
   the same claim submitted twice).
4. `endpoint_stake[operator_addr] > 0`.

On success: 90 % of stake burned to program treasury, 10 % paid to
submitter, operator permanently marked slashed.

The full `(domain, ref)` table:

| Domain      | `ref`                              | Distinct means                  |
| ----------- | ---------------------------------- | ------------------------------- |
| `Receipt`   | `session_id ‖ seq`                 | Different `(bytes_used, blind)` |
| `Directory` | `query_hash ‖ epoch`               | Different response body hash    |
| `Signaling` | `session_handshake_id ‖ epoch`     | Different response body hash    |

### 2.4 Sessions

A session opens against a tailnet:

```text
session_id := sha256(self_addr || epoch || nonce || client_session_pubkey)
sessions[session_id] := Session {
  tailnet_id,
  client_session_pubkey,
  route_commit = [pedersen_commit(hop_i_addr, blind_i) for i in 1..hops],
  deposit = locked-from-tailnet-treasury,
  status = open,
}
```

The route is committed but not revealed; this hides which operators
the client picked until settlement. The deposit is locked from the
tailnet treasury.

### 2.5 Settlement

`settle_session` reveals the route, verifies the dual-signed final
receipt, and credits each hop's encrypted-earnings ledger:

```text
total_paid = sum_i (bytes_used * price_per_mb_i * split_bps_i / 10000)
require total_paid <= deposit
fee        = total_paid * protocol_fee_bps / 10000
to_hops    = total_paid - fee
for each hop i:
  enc_earnings[hop_i] += pedersen_commit(pay_i * G + blind * H)
program_treasury += fee
refund = deposit - total_paid
tailnet.treasury += refund
```

Directory and signaling have analogous batch settlements
(`settle_directory_batch`, `settle_signaling_batch`) that prove a
set of client-signed query/assist receipts and pay the operator
accordingly. CEI ordering throughout: checks first, then state
mutations, then external interactions.

### 2.6 Encrypted earnings

Each operator's earnings accumulate as a Ristretto point — a
Pedersen commitment to (amount, blind). The operator tracks their
own running `(amount_sum, blind_sum)` locally and submits both at
`claim_earnings`; the chain verifies the commitment opens correctly
and emits a stealth output for the claimed amount via X25519 ECDH
(see `docs/whitepaper-stealth.md` for the construction).

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

We make formal claims with corresponding proof artifacts:

| Property                                            | Tool      | Artifact                                |
| --------------------------------------------------- | --------- | --------------------------------------- |
| Receipt unforgeability                              | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Double-sign yields slash evidence                   | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Equivocation evidence cannot be fabricated          | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Route-commitment unlinkability                      | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Session settles or refunds                          | TLA+      | `proofs/tla/OctraVPN.tla`               |
| Treasury non-negativity                             | TLA+      | `proofs/tla/OctraVPN.tla`               |
| Slashed operators cannot earn                       | TLA+      | `proofs/tla/OctraVPN.tla`               |
| Stake unlock reachable for honest operator          | TLA+      | `proofs/tla/OctraVPN.tla`               |
| Settle advances receipt seq                         | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean`      |
| Settle finalises session status                     | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean`      |
| Settle returns refund to treasury                   | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean`      |
| Slash burns stake atomically                        | Lean 4    | `proofs/lean/OctraVPN/Slashing.lean`    |
| Slash is single-shot (no double-slash)              | Lean 4    | `proofs/lean/OctraVPN/Slashing.lean`    |
| Crypto primitives correct shape                     | Kani      | `proofs/kani/Cargo.toml`                |

The Lean proofs go through without `sorry`; the TLA+ specification
is model-checked by TLC in CI (`.github/workflows/ci.yml::tla`).
Tamarin lemmas are re-checked on each release.

Property-based tests cover the cryptographic surfaces that don't
admit symbolic-execution proof:

| Property                                                  | File                                      |
| --------------------------------------------------------- | ----------------------------------------- |
| Signed envelope always verifies (honest sign)             | `crates/octravpn-core/tests/prop_security.rs` |
| Field mutation breaks signed envelope                     | `crates/octravpn-core/tests/prop_security.rs` |
| Stealth tag unique per ephemeral                          | `crates/octravpn-core/tests/prop_security.rs` |
| Sealed-payload AEAD tamper detection                      | `crates/octravpn-core/tests/prop_security.rs` |
| Receiver/sender stealth tag agreement                     | `crates/octravpn-core/tests/prop_security.rs` |

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

- AML program: complete for v1 surface; bonding/slashing additions in
  progress. `crates/octraforge/tests/aml_fuzz.rs` runs 200+ random
  call sequences with all invariants asserted.
- Mesh primitives: complete (`crates/octravpn-mesh`, 39 unit tests).
- Data plane: WireGuard via boringtun, onion routing, control plane,
  audit log, rate limiting all wired in.
- Octra SDK integration: `OctraBackend` trait defined; `RpcBackend`
  wires real chain calls; `PlaceholderBackend` errors loudly when
  used in production (refuses to answer `is_octra_validator`).
- Equivocation tooling: `octravpn slash-evidence verify | build`
  for off-chain workflows; AML `submit_equivocation` for on-chain
  slashing.
- Property + integration tests: 294 tests pass. Docker e2e green.

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
| `crates/octraforge/`                              | Foundry-style test harness                           |
| `crates/octra-cli/`                               | `octra forge\|cast\|anvil\|chisel` toolchain         |
| `proofs/{tla,tamarin,lean,kani}/`                 | Formal verification artifacts                        |
| `docs/value.md`                                   | What the system provides, by stakeholder             |
| `docs/economics.md`                               | Economic model (this whitepaper §4)                  |
| `docs/security-roadmap.md`                        | Additional security/identity provisions (this §5)    |
| `docs/tailnet-user-guide.md`                      | How to use a tailnet                                 |
| `docs/operator-guide.md`                          | How to run a paid endpoint                           |
| `docs/deployment-runbook.md`                      | Operator playbook for staging → mainnet → incidents  |
| `docs/validator-hardening.md`                     | Systemd / AppArmor / monitoring hardening profile    |
