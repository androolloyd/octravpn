# OctraVPN: Decentralized Private Mesh Networking on Octra

## Abstract

OctraVPN is a decentralized private mesh VPN — what Tailscale provides
through a central control plane, OctraVPN provides through the Octra
blockchain. Devices form **tailnets**: on-chain groups whose
membership, ACLs, and shared treasury live as state in a single
on-chain program. Members reach each other peer-to-peer via WireGuard
when network conditions allow, and fall back to paid Octra
**validator-relays** when they don't. Internet egress through dedicated
**exit nodes** (always validators) is the same mechanism in disguise:
a tailnet whose only "destination" is the open internet.

The system has three load-bearing pieces:

1. An **AML program** on Octra (`program/main.aml`) that owns the
   tailnet objects, member sets, session deposits, and validator
   earnings.
2. A **mesh layer** (`crates/octravpn-mesh`) that does STUN, peer
   registry, connection state machines, magic DNS, and ACL evaluation.
3. A **data plane** (`crates/octravpn-node`, `crates/octravpn-client`)
   running boringtun-based WireGuard with onion-routing receipts.

The novel contributions are:

- **Validator-as-relay gate**: paid endpoints must already be Octra
  protocol validators. We do not duplicate bonding or slashing — the
  protocol layer's existing economic security is reused verbatim.
- **Tailnet treasuries**: per-tailnet OU pools fund sessions; refunds
  return to the same pool. No per-user balances on chain.
- **Shielded payments + traffic**: validators receive Pedersen-committed
  earnings revealed only at claim; clients build their routes as
  Pedersen commitments revealed only at settle.
- **Mesh-first connectivity**: peer-to-peer WireGuard is the default;
  paid relays activate when direct probes fail. Connection upgrade is
  automatic.

## 1. Threat model

We assume:

- A globally-observable adversary that can read every chain
  transaction, every public-internet packet header, and any
  endpoint-relay traffic (with that relay's cooperation).
- The adversary cannot compromise client or validator long-term keys
  without explicit modelling.
- The Octra protocol layer is correct in the sense that a slashed /
  jailed validator stops being reported as such by
  `octra_isValidator`.

We protect:

- **Confidentiality of who is talking to whom** within a tailnet.
  Pedersen commitments hide the route; only the exit (with the
  client's cooperation) learns its own role.
- **Confidentiality of payment volume per validator.** Encrypted
  earnings ledger; opening happens only at the validator's own claim.
- **Authenticity of receipts.** Dual-signed (client ephemeral session
  key + validator long-term key). Tamarin proof
  (`proofs/tamarin/octravpn.spthy`) shows unforgeability under
  Dolev-Yao with key-compromise.

We do not protect:

- **Tailnet membership.** Members are visible on chain; that's the
  point — tailnet membership is what makes peer-to-peer connectivity
  authorisable. The privacy goal is the contents and partner of each
  flow, not the existence of the tailnet.
- **Plaintext treasury balance.** Aggregate treasury is on-chain
  visible. Per-member contributions can be made private by depositing
  via stealth outputs once Octra exposes the necessary primitives.

## 2. Architecture

### 2.1 Tailnet object

A tailnet is an on-chain record:

```text
Tailnet {
  owner: address          // governance (add/remove members, set ACL)
  treasury: int           // OU available for paid traffic
  members: map[address]   // who's in
  exits: map[address]     // validators authorised as exits/relays
  acl_policy: bytes       // sha256 of off-chain ACL doc
  created_at: epoch
}
```

The owner can mutate `members`, `exits`, and `acl_policy`; anyone can
deposit to `treasury`. Settlement and sessions reference the tailnet
they belong to.

### 2.2 Validator endpoints

Validators register their endpoint via `register_endpoint`. The
program gates on `is_octra_validator(caller)` — a chain-level call
that returns true iff `caller` is currently a protocol-level Octra
validator. There is no in-program bond.

Each endpoint advertises (endpoint, wg_pubkey, receipt_pubkey,
view_pubkey, region, price_per_mb). Discovery happens by reading
`list_active_endpoints` from the chain.

### 2.3 Sessions

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

The route is committed but not revealed; this hides which validators
the client picked until settlement. The deposit is locked from the
tailnet treasury.

### 2.4 Settlement

`settle_session` reveals the route, verifies the dual-signed final
receipt, and credits each hop's encrypted-earnings ledger:

```text
total_paid = sum_i (bytes_used * price_per_mb_i * split_bps_i / 10000)
require total_paid <= deposit
for each hop i:
  enc_earnings[hop_i] += pedersen_commit(pay_i * G + blind * H)
refund = deposit - total_paid
tailnet.treasury += refund
```

CEI ordering throughout: checks first, then state mutations, then
external interactions.

### 2.5 Encrypted earnings

Each validator's earnings accumulate as a Ristretto point — a
Pedersen commitment to (amount, blind). The validator tracks their
own running (amount_sum, blind_sum) locally and submits both at
`claim_earnings`; the chain verifies the commitment opens correctly
and emits a stealth output for the claimed amount.

### 2.6 Mesh data plane

The on-chain pieces above coordinate identity, money, and authority.
The mesh layer (`crates/octravpn-mesh`) makes peer-to-peer
connectivity work:

- **STUN client** (`stun.rs`): public-address discovery via RFC 5389
  Binding Requests.
- **Peer registry** (`peer.rs`): each member publishes their current
  candidate set (LAN, STUN, relay-via-validator).
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
open via a validator-relay, or close an existing tunnel. The host
daemon translates those into `boringtun::Tunn` and kernel-routing
calls.

## 3. Formal claims

We make four formal claims with corresponding proof artifacts:

| Property                          | Tool      | Artifact                                |
| --------------------------------- | --------- | --------------------------------------- |
| Receipt unforgeability            | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Double-sign yields slash evidence | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Route-commitment unlinkability    | Tamarin   | `proofs/tamarin/octravpn.spthy`         |
| Session settles or refunds        | TLA+      | `proofs/tla/OctraVPN.tla`               |
| Treasury non-negativity           | TLA+      | `proofs/tla/OctraVPN.tla`               |
| Settle advances receipt seq       | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean`      |
| Settle finalises session status   | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean`      |
| Settle returns refund to treasury | Lean 4    | `proofs/lean/OctraVPN/Lemmas.lean`      |
| Crypto primitives correct shape   | Kani      | `proofs/kani/Cargo.toml`                |

The Lean proofs go through without `sorry`; the TLA+ specification is
model-checked by TLC in CI (`.github/workflows/ci.yml::tla`).

## 4. Economic design

Summarised in `docs/economics.md`. Key points:

- Single token (OU); no app-specific currency.
- Payment flows: owner → tailnet treasury → session deposit →
  validator earnings → stealth payout.
- No vesting on validator earnings; the encrypted-earnings ledger is
  the commitment device.
- Default parameters: `min_session_deposit = 10 OU`,
  `min_tailnet_deposit = 100 OU`, `session_grace_epochs = 100`,
  `sweep_bounty_bps = 100`. Governance-mutable up to hard caps in the
  constructor.

## 5. Implementation status

- AML program: complete and exhaustively tested
  (`crates/octraforge/tests/aml_fuzz.rs` runs 200+ random call
  sequences with all invariants asserted).
- Mesh primitives: complete (`crates/octravpn-mesh`, 39 unit tests).
- Data plane: WireGuard via boringtun, onion routing, control plane,
  audit log, rate limiting all wired in.
- Octra SDK integration: `OctraBackend` trait defined; `RpcBackend`
  wires real chain calls; `PlaceholderBackend` errors loudly when
  used in production (refuses to answer `is_octra_validator`).

## 6. Where it stops being decentralised

We're honest about residual centralisation:

- **Off-chain ACL distribution.** The ACL document hash is on-chain
  but the document itself isn't. We assume tailnet owners serve it
  over HTTPS or pin it to IPFS; the failure mode is a stale ACL,
  which the recipient's mesh layer refuses to use until it can fetch
  the current hash.
- **STUN servers.** Public-IP discovery talks to an off-chain STUN
  server. The set of acceptable servers is configurable; misbehaviour
  is bounded to "wrong public IP discovered" which causes peer-to-peer
  attempts to fail and the connection falls back to a paid relay.
- **Initial bootstrap.** New devices need a way to find any node in
  the tailnet for the first time. Today this is a manual share of an
  endpoint URL; future work integrates a DHT.

## 7. Comparison to Tailscale

| Aspect                    | Tailscale         | OctraVPN                                     |
| ------------------------- | ----------------- | -------------------------------------------- |
| Control plane             | Centralised SaaS  | Octra blockchain                              |
| Identity                  | OIDC / SSO        | Octra account address                         |
| ACL store                 | Coordination srv  | Hash on chain, doc off chain                  |
| Relays                    | Tailscale DERP    | Octra validators (paid in OU)                 |
| Magic DNS                 | Yes               | Yes (`<peer>.<tailnet>.octra`)                |
| Subnet routing            | Yes               | Yes                                           |
| Exit nodes                | Tailnet member    | Octra validator (subset of "exits")          |
| Pricing                   | Per-seat / month  | Per-byte through validators                   |
| Open source               | Partially         | Fully                                         |
| Trust model               | Trust Tailscale   | Trust the Octra protocol layer                |

## 8. References

| File                                              | Purpose                                    |
| ------------------------------------------------- | ------------------------------------------ |
| `program/main.aml`                                | On-chain program                           |
| `program/interfaces/IOctraVPN.aml`                | Public surface                             |
| `crates/octravpn-core/`                           | Shared types, RPC, crypto                  |
| `crates/octravpn-mesh/`                           | Mesh primitives (STUN, peers, conn, ACL)   |
| `crates/octravpn-node/`                           | Validator-side daemon                      |
| `crates/octravpn-client/`                         | Client CLI                                 |
| `crates/octraforge/`                              | Foundry-style test harness                 |
| `crates/octra-cli/`                               | `octra forge|cast|anvil|chisel` toolchain  |
| `proofs/{tla,tamarin,lean,kani}/`                 | Formal verification artifacts              |
| `docs/economics.md`                               | Token economics                            |
| `docs/tailnet-user-guide.md`                      | How to use a tailnet                       |
| `docs/operator-guide.md`                          | How to run a paid endpoint                 |
