# OctraVPN: Economic Design

This document specifies the economic model: who pays whom, in what
direction, at what price, with what incentives, and why we believe
the protocol is incentive-compatible against the threat model in
`docs/whitepaper.md §1` and `docs/security-roadmap.md`.

For the "what does this *do* for me" view, see `docs/value.md`. For
the additional security and identity provisions on the road map, see
`docs/security-roadmap.md`. This document is the economic backing.

---

## 1. Design foundations

Six non-negotiable choices shape every other decision below:

1. **Single token, no issuance.** Everything is denominated in OU,
   the Octra base unit (1 OCT = 1 000 000 OU). There is no OctraVPN
   token, no premine, no airdrop, no governance coin. Speculation is
   not the business model.
2. **In-program stake + in-program slashing.** Operators stake OU in
   the OctraVPN AML program. Equivocation on any signed operational
   claim — receipt, directory response, signaling response — is
   slashable atomically by the program. We do *not* rely on Octra
   protocol-layer slashing — Octra protects Octra consensus, not
   OctraVPN receipts.
3. **One bonded operator role.** A single staked role ("OctraVPN
   validator") provides three services: relay, directory, signaling.
   One stake, one reputation, one slash surface, three revenue
   streams.
4. **Capital efficiency.** No idle balance escrows beyond the
   per-session deposit, the tailnet treasury, and the operator
   stake. Each has explicit recovery paths.
5. **Privacy-preserving accounting.** Operator earnings are
   Pedersen-committed; payouts go through ECDH stealth outputs. The
   chain-visible aggregate is the operator's total revenue; the
   per-tailnet, per-service breakdown is private.
6. **Pay-as-you-go primitive, subscription as policy.** The protocol
   exposes per-operation settlement. Recurring billing, tiered plans,
   refund policies are operator-level features built on top.

---

## 2. Three-tier fee structure

The phrase "Octra as control plane for hire" cashes out as three
distinct payment tiers. Every OU spent in the system flows through
exactly one of them.

| Tier | Paid to                       | Mechanism                                       | What you're buying                                                       |
| ---- | ----------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------ |
| 1    | Octra protocol validators     | Per-tx gas fees                                 | Chain inclusion — global agreement on state changes                       |
| 2    | OctraVPN program treasury     | 0.5 % of settlements (governance-tunable ≤ 2 %) | Protocol maintenance, audits, bug bounties, dispute resolution            |
| 3    | OctraVPN operators            | Per-operation service fees                      | Off-chain work: relay bytes, directory lookups, signaling assists         |

Tier 1: you use the chain. Tier 2: you fund the protocol. Tier 3:
operators get paid for work.

---

## 3. Actors and value flow

```
                          ┌───── claim_earnings ────► [Stealth output]
                          │                              ▲
                          │                              │
                  ┌── pay ─► [Operator encrypted earnings]
                  │                                      
  [Owner / member wallets]                               
        │ create_tailnet / deposit_to_tailnet            
        ▼                                                
  [Tailnet treasury] ──── open_session(deposit) ──► [Session deposit]
        ▲                                                │
        │ refund (deposit − total_paid)                 │
        │ on settle / claim_no_show / sweep_expired      │
        └────────────────────────────────────────────────┘
                          │
                          ├── protocol fee (Tier 2) ──► [Program treasury]
                          │
                          └── operator pay (Tier 3) ──► [Operator earnings]


  [Operator wallet] ─ bond_endpoint(stake) ──► [endpoint_stake[addr]]
                                                    │
                       submit_equivocation(ev) ◄────┤
                                                    │
                                  90 % burned ◄─────┤
                                  10 % to submitter ┘
```

### 3.1 Tailnet owner

| Pays                                       | Receives                          | Authority                              |
| ------------------------------------------ | --------------------------------- | -------------------------------------- |
| Treasury seed at `create_tailnet`          | Nothing on chain                  | Add/remove members; set ACL; set exits |
| Optional top-ups via `deposit_to_tailnet`  | Utility of a functioning tailnet  | Issue pre-auth join tokens             |

The owner's incentive is the tailnet's existence. No protocol-level
profit motive — the tailnet is overhead they accept in exchange for
connectivity.

### 3.2 Tailnet member

| Pays                              | Receives                                                            |
| --------------------------------- | ------------------------------------------------------------------- |
| Their share of the treasury       | Authenticated mesh access to other members and configured exits     |
| Per-byte OU through paid exits    | Internet egress + NAT-blocked peer connectivity                     |
| Per-lookup OU for directory       | Resolution of `(member → current candidates)`, `(tailnet → ACL doc)` |
| Per-assist OU for signaling       | STUN response, handshake relay when both peers NAT'd                |

Peer-to-peer traffic between members is **free in OU terms**: the
mesh runs over the public internet, only paid hops cost.

### 3.3 OctraVPN operator (relay / directory / signaling)

| Pays                                                    | Receives                                                       |
| ------------------------------------------------------- | -------------------------------------------------------------- |
| `stake ≥ MIN_ENDPOINT_STAKE` in `bond_endpoint(stake)`  | OU per byte relayed × `price_per_mb × split_bps`               |
| `register_endpoint` / `claim_earnings` tx fees          | OU per directory lookup × `price_per_lookup`                   |
| Bandwidth + uptime + operator labor                     | OU per signaling assist × `price_per_assist`                   |
| Slashing if they equivocate on signed claims            | Pedersen-committed earnings; opened only at own claim          |
|                                                         | Reputation accrual (`EndpointRecord.reputation`)               |

Stake recovers via `unbond_endpoint` after `unbond_grace_epochs`
elapse (default 30 days of epochs).

### 3.4 Program treasury (Tier 2)

Funded by the 0.5 % protocol fee on settlements and by the 90 % burn
share of slashed stakes. Governance (the deployer's wallet) can
disburse for:

- Bug bounty payouts
- Formal-verification audit engagements
- Protocol upgrade development
- Dispute-resolution costs

This is the only mechanism keeping the protocol funded long-term.

---

## 4. Operator stake + slashing

### 4.1 Bonding

```
bond_endpoint(stake)
  require stake >= MIN_ENDPOINT_STAKE  // default 1 000 OCT = 1 000 000 000 OU
  endpoint_stake[caller] += stake
```

The stake is a deposit, not a payment. It sits in the program until
`unbond_endpoint` is called and `unbond_grace_epochs` elapse with no
intervening slash.

`register_endpoint(...)` requires `endpoint_stake[caller] >=
MIN_ENDPOINT_STAKE` — bonding is a prerequisite for advertising.

### 4.2 Unbonding

```
unbond_endpoint()
  require endpoint_unbonding[caller] is empty
  endpoint_unbonding[caller] = { stake: endpoint_stake[caller], unlock: now + UNBOND_GRACE }
  endpoint_stake[caller] = 0
  // operator no longer eligible to serve new sessions
```

The grace window (default 30 days of epochs) gives any client time
to surface pending equivocation evidence before the stake is
withdrawable. After unlock, the operator calls a finalising entrypoint
that pays out the locked amount.

### 4.3 Slashable event: equivocation on signed claims

There is exactly one third-party-provable form of operator malice:
**equivocation**. The operator signs two distinct claims with the
same `(domain, ref)` pair.

**v1 enforcement:** off-chain evidence verification +
governance-slash. The program owner submits a slash after running
`octravpn slash-evidence verify` on the two contradictory receipts.
Trust-the-owner gates the action; the owner is itself accountable
via the chain trail.

**v1.1 target:** cryptographic on-chain enforcement once Octra
exposes `verify_ed25519` in AML (see
`docs/security-roadmap.md §0.1`).

The slashable claim types (v1.1 target):

| Claim type           | `(domain, ref)`                          | Distinct means                           |
| -------------------- | ---------------------------------------- | ---------------------------------------- |
| `Receipt`            | `(session_id, seq)`                      | Different `(bytes_used, blind)`          |
| `DirectoryResponse`  | `(query_hash, epoch)`                    | Different response body hash             |
| `SignalingResponse`  | `(session_handshake_id, epoch)`          | Different response body hash             |

All claims share a common signing pattern:

```
sig = ed25519(operator.receipt_pubkey, domain_separator || ref || body_hash)
```

Equivocation evidence is the same shape regardless of claim type:

```
EquivocationEvidence {
  operator_addr        : Address
  receipt_pubkey       : [u8; 32]
  domain               : enum { Receipt, Directory, Signaling }
  ref                  : bytes                  // session_id||seq | query_hash||epoch | ...
  claim_a              : bytes                  // signed claim body
  claim_b              : bytes                  // signed claim body
  sig_a                : [u8; 64]
  sig_b                : [u8; 64]
}
```

`submit_equivocation(evidence)` verifies on-chain:

1. `sig_a` and `sig_b` both validate under `receipt_pubkey` over
   `domain_separator(domain) || ref || hash(claim_x)`.
2. `Address::from_pubkey(receipt_pubkey) == operator_addr`.
3. `hash(claim_a) != hash(claim_b)` — receipts are genuinely distinct.
4. `endpoint_stake[operator_addr] > 0`.

On success:

```
slash_amount  = endpoint_stake[operator_addr]
burn_share    = slash_amount × 90 / 100        // 90 % burned
bounty_share  = slash_amount × 10 / 100        // 10 % to submitter
program_treasury  += burn_share
balance[submitter] += bounty_share
endpoint_stake[operator_addr] = 0
endpoint_slashed[operator_addr] = true        // permanent: can't re-bond
```

Slashing is **single-shot terminal**. A slashed operator is
permanently barred from re-registering under the same address. They
can spin up a new identity but they lose all reputation and start
fresh.

### 4.4 Why this specific severity

- **100 % at-risk:** equivocation is necessarily deliberate. Two
  signatures over genuinely distinct claims at the same `(domain,
  ref)` cannot happen accidentally — the receipt-signer state machine
  monotonically increments `seq` (or `epoch`). So defection isn't
  forgivable.
- **90 % burn:** deflationary; removes the slashed amount from
  circulation; doesn't enrich any single party.
- **10 % bounty:** covers the submitter's gas (typically ~21 OU) plus
  a small profit. Avoids creating a windfall that could attract
  speculative watchers fishing for slashes. The cryptographic
  unforgeability of evidence means fabrication is impossible, so the
  bounty's risk is only "is anyone incentivized enough to bother
  submitting." 10 % of a 1 000 OCT stake = 100 OCT — comfortable.

---

## 5. Pricing per service

### 5.1 Relay (Tier 3a)

Per-byte to the exit operator. On `settle_confirm` (after the
matching `settle_claim`):

```
total    = bytes_used × endpoints[exit].price_per_mb
fee      = total × PROTOCOL_FEE_BPS / 10000
net_pay  = total − fee                              // → exit operator (HFHE)
refund   = deposit − total                          // → tailnet treasury
```

v1 is single-hop in the AML; the multi-hop onion data plane is
already implemented in `octravpn-core::onion` and lights up in v2
once the AML schema also records per-hop splits.

Defaults: `min_price_per_mb = 1 OU`, governance can raise but not
lower below the constructor floor.

### 5.2 Directory (Tier 3b)

Per signed lookup. Settled in batches via `settle_directory_batch`
where the operator submits N client-signed query receipts and
charges `N × price_per_lookup` against the requesting tailnet's
treasury.

Defaults: `min_price_per_lookup = 10 OU` (≈ 0.00001 OCT). Floor
exists because a zero-priced directory operator could serve
poisoned responses with no economic cost.

### 5.3 Signaling (Tier 3c)

Per assist (STUN response or handshake relay). Settled identically
to directory.

Defaults: `min_price_per_assist = 100 OU` (10× directory — assists
involve heavier work).

### 5.4 Open-time price snapshot

All three services snapshot price at the moment of session/batch
open. Mid-operation price updates via `update_endpoint` do not
affect in-flight settlement. Formal claim: Lean
`commitSettlement_sets_session` (settled sessions are commitments
to open-time state).

### 5.5 No transit-time overhead

Protocol fee is taken at *settle*, not per-operation. Operators see
no overhead during service — the bandwidth they pay for is the
bandwidth that hits the wire; the lookup they execute is the lookup
the client gets.

---

## 6. Market design

### 6.1 Supply side — operator entry

The operator population is permissionless. Entry costs:

1. `MIN_ENDPOINT_STAKE` lockup (default 1 000 OCT = 1B OU).
2. One tx for `bond_endpoint`, one for `register_endpoint`.
3. One UDP port reachable from the internet.
4. Bandwidth + uptime.

The stake is **not** a fee — it returns at `unbond_endpoint` if the
operator stays honest. Marginal cost to remain registered: zero
(after the initial bond). Marginal revenue: positive whenever
clients route through them.

Note: this dropped the Octra-validator gate that earlier drafts
proposed. Anyone willing to bond can operate. This expands the
operator pool beyond chain validators and removes the
"double-encumbrance" objection.

### 6.2 Demand side — client entry

| Action               | Cost                                            |
| -------------------- | ----------------------------------------------- |
| Create new tailnet   | `min_tailnet_deposit + tx_fee` (~121 OU)        |
| Open session         | `min_session_deposit + tx_fee` (~31 OU)         |
| Add member           | tx_fee only (~21 OU)                            |
| Update ACL           | tx_fee only                                     |
| Directory lookup     | `price_per_lookup` (~10 OU)                     |
| Signaling assist     | `price_per_assist` (~100 OU)                    |

Friction is low enough that demand experiments are essentially free.
1 OCT buys weeks of testing for a small tailnet.

### 6.3 Price discovery

There's no central market-maker. Operators set per-service prices
via `update_endpoint`. Clients discover via `list_active_endpoints`
and pick by some objective function (price, region, reputation,
latency-probe).

Equilibrium dynamics:

- **Undercutting** bounded below by per-service floors (§5) and by
  operator bandwidth cost.
- **Overcharging** punished by clients picking cheaper operators.
- **Price stickiness** from open-time snapshotting — operators
  can't time-discriminate within a session/batch.

Expected equilibrium: marginally above wholesale bandwidth cost for
relay; effectively-free for directory/signaling (10s of OU per
event) once enough operators are bonded.

### 6.4 Cross-tailnet aggregation

A single operator serving 1 000 tailnets has one
`enc_earnings[addr]` entry summing relay + directory + signaling.
Observers see aggregate revenue; per-customer, per-service breakdown
is private.

This matters for two reasons:

- **Privacy for operators**: revenue per customer is competitively
  sensitive.
- **Privacy for tailnets**: a tailnet's bandwidth/lookup profile
  leaks information about its members; aggregating across tailnets
  hides it.

---

## 7. Treasury mechanics

### 7.1 Single shared pool

The tailnet treasury is one OU balance per tailnet. Member-level
accounting is **off-chain**, by design. Why:

- A 100-person tailnet should not pay 100× the chain storage of a
  1-person tailnet.
- Subscription policies are operator decisions (price points, free
  tiers, refunds, churn).
- The aggregate is consensus-relevant; the breakdown is the
  operator's accounting problem.

Three reference patterns:

| Pattern             | Off-chain accounting                                       |
| ------------------- | ---------------------------------------------------------- |
| Family / friends    | Communal — nobody tracks                                   |
| Internal team       | Equal-split top-up cadence; HR pays                        |
| Customer-facing     | Per-customer subscription DB; auto-deposits proportionally |

### 7.2 Refund completeness

Every locked OU has a path home:

| Locked at        | Returns via                          | Conditions                                   |
| ---------------- | ------------------------------------ | -------------------------------------------- |
| `open_session`   | `settle_claim` + `settle_confirm`    | refund = deposit − total_paid                |
| `open_session`   | `claim_no_show`                      | No progress receipt, grace elapsed           |
| `open_session`   | `sweep_expired_session`              | `K × session_grace` elapsed; 1 % bounty paid |
| `bond_endpoint`  | `unbond_endpoint` → finalise         | `UNBOND_GRACE` elapsed with no slash         |

There is no on-chain state where OU is permanently stuck. Lean
lemma `settle_returns_refund_to_treasury` and TLA+
`StakeUnlockReachable` formalise this.

### 7.3 Treasury draining via fee

The protocol fee draws from each settled `total_paid`. At a generous
estimate of 500 GB/month/tailnet at 50 OU/MB:

```
month_spend  = 500 000 MB × 50 OU/MB        = 25 000 000 OU
fee_share    = 25 000 000 × 50 / 10 000     =     125 000 OU
                                             = 0.125 OCT
```

That's 0.5 % of throughput. Reasonable.

---

## 8. Operator earnings: encrypted ledger

### 8.1 Pedersen commitments

Per-operator, per-settle, each service-pay is added to
`enc_earnings[op_addr]` as a Ristretto-point commitment:

```
new_commit = old_commit + (pay · G + blind · H)
```

The operator tracks `(amount_sum, blind_sum)` locally; at
`claim_earnings`, they provide both; the chain verifies the
commitment opens correctly and emits a stealth output to a fresh
address.

### 8.2 No vesting

Operators can claim immediately. We considered vesting and rejected
it:

- Slashing is via equivocation evidence, which the program acts on
  atomically. There's no "waiting period" where vesting would catch
  retroactive bad behaviour.
- The encrypted ledger already binds the operator to the math.
- Latency-of-payout is real-world friction we don't bake in for no
  benefit.

### 8.3 Reputation as monotonic counter

`EndpointRecord.reputation` increments at every successful settle
(receipt-, directory-, or signaling-batch). It's monotonic, not a
ratio. This protects long-running operators from being undercut in
ordering by fresh Sybils — an operator with 1M settles can't be
displaced by a new actor with one fake settle.

`claim_no_show` and slashing do **not** retroactively decrement
reputation. The absence of new reputation gain is the market signal;
the on-chain `endpoint_slashed[addr]` flag is the absolute one.

---

## 9. Sybil resistance

The protocol enforces three Sybil floors:

| Role                      | Sybil cost                                                                  |
| ------------------------- | --------------------------------------------------------------------------- |
| Operator endpoint         | `MIN_ENDPOINT_STAKE` (1 000 OCT) locked indefinitely (returns on unbond)   |
| Tailnet creation          | `min_tailnet_deposit + tx_fee` (~121 OU) — linear in attacks                |
| Session opening           | `min_session_deposit + tx_fee` (~31 OU) — strictly money-losing if spammed  |
| Tailnet membership        | Owner-gated; owner is the trust boundary                                    |
| Device registration       | Owner-signed pre-auth tokens — bounded by owner key compromise              |

Operator Sybil at scale costs `N × 1 000 OCT` in locked capital. At
typical OCT prices that's prohibitive for any non-legitimate actor.

---

## 10. Adversarial scenarios

### 10.1 Operator equivocation (any service)

**Attack.** Operator signs two contradictory claims with same
`(domain, ref)`.

**v1 defense.** Off-chain evidence verification +
governance-slash. Anyone can run `octravpn slash-evidence verify` on
the two receipts; the program owner submits the slash tx based on
the verified bundle.

**v1.1 defense (target).** Permissionless `submit_equivocation(ev)`
once Octra exposes `verify_ed25519` in AML.

**Economics.** Marginal gain from a single fraudulent claim ≤ one
session deposit (≤ client's max-pay). Marginal cost = full stake
(1B OU at default). Ratio: 10⁷:1 against defection — holds whether
slashing is on-chain (v1.1) or owner-mediated (v1).

### 10.2 Treasury drain via owner-operator collusion

**Attack.** Tailnet owner secretly controls one of the configured
exit operators. Opens large sessions, settles with inflated
`bytes_used`, channels treasury → own earnings.

**Defense.** No protocol-layer prevention — owners pick any exits,
`bytes_used` is signed by both colluders. Observable on chain:
implied bytes-per-session is public; members compute and compare to
market. Off-chain: members revoke trust by stopping contributions.

Future: quorum-multisig owner key (see `docs/security-roadmap.md`
§3.7) makes single-owner collusion harder.

### 10.3 Operator price rug-pull

**Attack.** Operator advertises low price, attracts traffic, bumps
between session-open and settle.

**Defense.** Open-time price snapshot (§5.4). Update-endpoint
mid-session is a no-op for in-flight sessions.

### 10.4 Refund grief

**Attack.** Member opens many sessions, none settle, treasury locked
indefinitely.

**Defense.** `sweep_expired_session` is permissionless after
`K × session_grace_epochs`. 1 % sweep bounty. Attacker recovers
nothing; treasury recovers 99 %.

### 10.5 Operator no-show

**Attack.** Operator advertises, accepts sessions, doesn't serve.

**Defense.** No progress receipt → `claim_no_show` → deposit back.
No reputation gain; operator wastes opportunity cost.

### 10.6 Directory poisoning

**Attack.** Operator serves false directory responses to drive
clients to malicious peers.

**Defense.** Directory responses are signed with the same
`receipt_pubkey` and bound to the chain `epoch`. A client receiving
a response can cross-check with another operator; mismatch is
equivocation evidence and slashable.

In practice clients should query 2 operators per directory lookup
and trust only matching responses; any single operator who serves a
poisoned answer loses their stake the moment a second operator
publishes a contradicting (honest) one.

### 10.7 Receipt replay

**Attack.** Replay a settled receipt against the same session.

**Defense.** `require(seq > s.receipt_seq)` in AML. Tamarin
`ReceiptUnforgeability` formalises the property.

### 10.8 Stake withdrawal-then-misbehave

**Attack.** Operator submits `unbond_endpoint`, equivocates during
grace, withdraws stake before evidence surfaces.

**Defense.** `UNBOND_GRACE` is long enough (default 30 days of
epochs ≈ months) for any honest counterparty to find and submit
evidence. A `submit_equivocation` against an unbonding operator
slashes the unbonding balance directly.

---

## 11. Bootstrap dynamics

### 11.1 Operator side

- Marginal cost to register: `MIN_ENDPOINT_STAKE` (recoverable) +
  one UDP port + ongoing bandwidth.
- Marginal revenue at zero traffic: zero.
- Stake is at-risk only via equivocation — operationally trivial to
  avoid.

The bootstrap signal: at any reasonable OCT price, 1 000 OCT is
roughly the seed-capital of a small business. We expect early
operators to be the same people who'd run Tailscale-on-prem today
plus a class of Octra-aware operators who see this as a yield
opportunity.

### 11.2 Client side

- Brand-new tailnet works peer-to-peer over mesh **without any paid
  operator** — STUN + WireGuard direct-connect handles all
  device-to-device traffic.
- Paid operators are needed only for: NAT-blocked peers, internet
  egress, multi-hop privacy routing, directory at scale.
- Fresh tailnet with zero exits configured is immediately useful.

### 11.3 No operator subsidy

Explicitly no token issuance to early adopters. Subsidies attract
Sybil farming; we want real usage, not identity count.

---

## 12. Long-term sustainability

The Tier 2 protocol fee + 90 % burn share of slashes funds the
program treasury indefinitely.

### 12.1 Revenue at scale

| Scale                              | Daily bandwidth | Daily fee at 50 OU/MB | Annual fee  |
| ---------------------------------- | --------------- | --------------------- | ----------- |
| 1 tailnet, 5 users                 | 5 GB            | 1 250 OU              | 456k OU     |
| 100 tailnets, 5 users each         | 500 GB          | 125k OU               | 45.6M OU    |
| 1 000 tailnets, 50 users each      | 50 TB           | 12.5M OU              | 4.56B OU    |
| 10 000 tailnets, 100 users each    | 1 PB            | 250M OU               | 91B OU      |

At 1 PB/day throughput (a small ISP's worth), Tier 2 sustains a
multi-engineer team plus annual audits without external funding.
Breakeven for "covers one annual audit" (~$100k = ~100M OU at
$1/OCT) is ~10 TB/day total throughput.

### 12.2 Adjustment lever

`set_params` can raise `protocol_fee_bps` up to the 2 % cap. Cap is
constructor-enforced; no governance proposal can silently lift it.

---

## 13. Why a single-token, no-issuance model

| Alternative                                | Why rejected                                                                                            |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| OctraVPN governance token                  | Speculative dynamics misaligned with "private VPN that works." No clear protocol utility.               |
| Validator-staking token (≠ OCT)            | Duplicates Octra's existing capital lock. Pure overhead, capital fragmentation, double-encumbrance.     |
| Service-credit token (prepaid bandwidth)   | Another OU-equivalent with worse liquidity. Users just hold OU.                                         |
| Per-tx subsidies for early adopters        | Subsidy programs reliably attract Sybil farming. We optimize for real usage.                            |
| Issuance-funded operator rewards           | Inflation tax on holders to pay operators is a worse-properties Tier 2 fee. Hits passive holders.       |

A single-token, no-issuance design forces every economic flow to be
*real*: paid by someone, received by someone, balanced. If the math
doesn't work, it's visible immediately.

---

## 14. Parameter table (full)

Set in the `OctraVPN` constructor (`program/main.aml`). Governance
(via `set_params`) can adjust within constructor-enforced bounds.

| Parameter                  | Default       | Bound          | Rationale                                                                            |
| -------------------------- | ------------- | -------------- | ------------------------------------------------------------------------------------ |
| `MIN_ENDPOINT_STAKE`       | 1 000 000 000 OU | ≥ 10⁸ OU    | Bond floor: must exceed max plausible per-event extraction × 10³.                    |
| `UNBOND_GRACE_EPOCHS`      | ~30 days      | ≥ 7 days       | Long enough for honest counterparties to surface equivocation evidence.              |
| `SLASH_BURN_BPS`           | 9 000 (90 %)  | ≥ 5 000        | Slashed amount is mostly burned; small bounty avoids speculative-watcher economics.  |
| `SLASH_BOUNTY_BPS`         | 1 000 (10 %)  | ≤ 5 000        | Mirror of BURN_BPS; sum = 10 000.                                                    |
| `min_session_deposit`      | 10 OU         | > 0            | Dust floor; deters session spam.                                                     |
| `min_tailnet_deposit`      | 100 OU        | > 0            | Discourages spam tailnets; ~10× session deposit.                                     |
| `session_grace_epochs`     | 100           | > 0            | Long enough for real sessions; short enough that abandoned ones reclaim.             |
| `sweep_grace_multiplier`   | 10            | > 0            | Permissionless sweep at `K × session_grace`. K=10 → ~1000 epochs.                    |
| `sweep_bounty_bps`         | 100 (1 %)     | ≤ 1 000 (10 %) | Covers sweeper gas; uncapped would create grief incentive.                           |
| `min_price_per_mb`         | 1 OU          | > 0            | Floors relay pricing; zero is a Sybil vector.                                        |
| `min_price_per_lookup`     | 10 OU         | > 0            | Floors directory pricing.                                                            |
| `min_price_per_assist`     | 100 OU        | > 0            | Floors signaling pricing.                                                            |
| `protocol_fee_bps`         | 50 (0.5 %)    | ≤ 200 (2 %)    | Funds Tier 2.                                                                        |
| `max_hops`                 | 3             | ≥ 1, ≤ 5       | Privacy-routing depth; deeper costs more bandwidth without proportional gain.        |
| `receipt_seq_bits`         | 32            | ≥ 16           | Per-session receipt counter width; 32 bits ≈ 4B receipts per session is forever.     |

---

## 14.1 v2 / Circles parameters (since 2026-05-17)

The v2 slim-registry (`program/main-v2.aml`) adds the following
parameters on top of the v1 set. Defaults are constructor-set on the
devnet deployment at `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`.

| Parameter                  | Default       | Bound          | Rationale                                                                                  |
| -------------------------- | ------------- | -------------- | ------------------------------------------------------------------------------------------ |
| `min_circle_stake`         | 1 000 000 OU (1 OCT) | ≥ 100 000 OU (0.1 OCT) | Lower than `MIN_ENDPOINT_STAKE` because circles bond per-circle, not per-operator. Multiple circles per operator allowed; total at-risk is N × stake. |
| `sealing_fee_per_put`      | 5 000 OU      | > 0            | Per `circle_asset_put_encrypted` tx, on top of base gas. Pays for resource_key storage and AES KAT amortization on devnet/mainnet runtimes. |
| `price_per_mb_shared`      | per-circle     | ≥ `min_price_per_mb` | Class-0 (shared exit) price. Set by the operator inside the circle program. Snapshotted at session open.                  |
| `price_per_mb_internal`    | per-circle     | ≥ `min_price_per_mb` | Class-1 (intra-tailnet) price. Operators MAY set to 0 to grant free intra-tailnet routing; main-net registry permits this. |
| `class_count`              | 2             | ≤ 16           | Number of routing classes per circle. Class IDs are dense `int`.                                                          |

Per-class pricing replaces v1's single `price_per_mb` per endpoint.
A single circle can offer (shared-internet, 50 OU/MB) and (internal-
subnet, 0 OU/MB) simultaneously; clients pick a class at session
open.

Sealing fee economics: at 5 000 OU per put, an operator publishing a
new `/policy.json` once per epoch costs ≈ 5 000 OU × (3 600 / 10) ≈
1.8M OU/hour ≈ 1.8 OCT/hour. Operators in practice publish on policy
change, not per-epoch — typical real cost is 5 000 OU × handful of
updates per day = under 0.05 OCT/day.

## 15. Formal-verification anchor

The economic model rests on these properties; the properties are
verified mechanically:

| Property                                                  | Verified by                                                                  |
| --------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Treasury never goes negative                              | TLA+ `TreasuryNonNegative`                                                   |
| Settle returns refund to treasury                         | Lean `settle_returns_refund_to_treasury`                                     |
| Stake unlock reachable for honest operator                | TLA+ `StakeUnlockReachable`                                                  |
| Per-byte payment ≤ deposit                                | Lean `settle_advances_seq` + AML `require(total_paid <= s.deposit)`          |
| Session settles or refunds (no stuck OU)                  | TLA+ liveness `<>(SessionSettled \/ SessionRefunded)`                        |
| Stealth payments unlinkable without view secret           | Property test `observer_with_only_view_pubkey_cannot_recompute_tag`          |
| Receipts can't be replayed                                | Tamarin `ReceiptUnforgeability` + AML `seq > receipt_seq` check              |
| Equivocation (any service) yields slashable evidence      | Tamarin `DoubleSignSlashable` + `submit_equivocation` AML lemma              |
| Slash is atomic and single-shot                           | AML invariant: `endpoint_slashed[addr] ⇒ endpoint_stake[addr] = 0`           |
| Audit log is tamper-evident                               | HMAC chain + `AuditLog::verify_file` regression test                         |
| Any field mutation in signed envelope breaks verification | Property test `arbitrary_field_mutations_break_verification`                 |
| Sealed payload AEAD tamper detection                      | Property test `sealed_payload_tamper_byte_breaks_aead`                       |

The economic model holds **if and only if** these properties hold.
The properties hold in code. We re-verify on every PR.
