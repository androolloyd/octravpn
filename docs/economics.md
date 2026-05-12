# OctraVPN Token Economics

## Roles in the system

| Actor             | What they pay                                 | What they earn                                       |
| ----------------- | --------------------------------------------- | ---------------------------------------------------- |
| Tailnet owner     | Treasury seed at creation; ongoing top-ups    | —                                                    |
| Tailnet member    | Their share of treasury contributions         | —                                                    |
| Validator (relay) | Octra protocol-level bond + tx fees           | Pedersen-committed share of session payments         |
| Octra protocol    | —                                             | Slashed bond + burned share when validators misbehave |

There is no token issuance in OctraVPN itself. Everything is denominated
in OU (the Octra base unit; 1 OCT = 1 000 000 OU). The flows are:

```
  [Owner wallet]
        │ create_tailnet(deposit)
        ▼
  [Tailnet treasury]
        │ open_session(deposit)
        ▼
  [Session locked deposit]
        │
        ├── settle pays validators ───► [Validator encrypted earnings]
        │                                       │ claim_earnings
        │                                       ▼
        │                              [Stealth output]
        │
        └── refund (deposit − total_paid) ──► [Tailnet treasury]
```

The tailnet treasury is the only on-chain plaintext balance involved.
Per-session deposits are locked from the treasury at `open_session` and
either refunded (back to the treasury) or paid out to validators
(into their encrypted earnings ledger) at `settle_session`.

## Pricing model

### Per-byte traffic pricing

Each validator endpoint advertises a `price_per_mb` (raw OU per
megabyte) in its `EndpointRecord`. A session through that endpoint
incurs:

```
total_paid_to_endpoint = bytes_used × price_per_mb × split_bps / 10000
```

The split (`split_bps`) lets multi-hop sessions divide the payment
across hops. Single-hop sessions always use `split_bps = 10000` (100%).

A session opener picks the route, deposits an upper-bound budget, and
the actual settle records the bytes consumed. The unused portion
returns to the tailnet treasury — there is no per-session loss when
the deposit overshoots.

### Tailnet treasury

The treasury is shared and refilled by anyone (`deposit_to_tailnet`).
Per-member accounting is off-chain by design: a tailnet's social model
(subscription, employer-paid, donations) is its own concern, and only
the aggregate balance is consensus-relevant.

### No subscription primitive

There is intentionally no recurring "month of access" primitive in the
protocol. A subscription contract can be built on top by automating
`deposit_to_tailnet` calls. The protocol's job is to make pay-as-you-go
traffic safe and unforgeable; subscription/recurrence is application
policy.

## Default parameters

Set in the `OctraVPN` program constructor (see `program/main.aml:151`):

| Parameter                  | Default       | Rationale                                                                   |
| -------------------------- | ------------- | --------------------------------------------------------------------------- |
| `min_session_deposit`      | 10 OU         | A trivial 0.00001 OCT floor — keeps sessions out of dust territory.         |
| `min_tailnet_deposit`      | 100 OU        | Discourages spam-creating empty tailnets; ~10× minimum session deposit.     |
| `session_grace_epochs`     | 100           | Long enough for a real session; short enough that abandoned ones get swept. |
| `sweep_grace_multiplier`   | 10            | `K × session_grace` before a stranger can sweep on the owner's behalf.      |
| `sweep_bounty_bps`         | 100 (= 1 %)   | Pays a sweeper enough to cover gas; capped at 10 % by `set_params`.         |

These values are governance-mutable (`set_params`) — the owner of the
deployed `OctraVPN` program can raise them as the network matures or
external prices shift. Hard caps live in the constructor to prevent
governance from setting nonsensical values (e.g. `sweep_bounty_bps >
1000` is rejected).

## Validator earnings vesting

There is intentionally **no vesting**. A validator can `claim_earnings`
the moment the Pedersen commitment is opened correctly. Reasons:

- Vesting on top of the existing slash mechanism (Octra protocol-level)
  would double-encumber validators and create misaligned incentives.
- The encrypted-earnings ledger is already a strong commitment device;
  early-claim attacks are bounded by what's been accumulated.
- Cliff/vesting policies belong in the social layer (the tailnet ACL
  could enforce "validators in this tailnet must defer claim by N
  blocks" out-of-band).

## Griefing and dispute scenarios

### Treasury front-running

Risk: a tailnet owner who runs a malicious validator could open
sessions that drain the treasury into their own pocket.

Mitigation: members watching the chain can:
1. See every `SessionOpened` (deposit, hops) and `SessionSettled`
   (paid, refund) event.
2. Compute the implied price-per-MB and flag deviations from market.
3. Withdraw their off-chain trust by stopping deposits to the
   treasury and switching tailnets.

Because validators must be Octra protocol validators (gate in
`register_endpoint`), the malicious-validator vector also exposes the
attacker's protocol-level stake to slashing for documented
equivocation.

### Abandoned tailnet

Risk: a tailnet owner disappears with treasury still locked in
sessions.

Mitigation: `sweep_expired_session` is permissionless. After
`session_grace_epochs × sweep_grace_multiplier` (default 1000 epochs ≈
much longer than any real session), anyone can sweep the deposit back
to the treasury and collect the `sweep_bounty_bps` bounty.

### Spam tailnet creation

Risk: an attacker creates millions of tiny tailnets to bloat state.

Mitigation: `min_tailnet_deposit` (default 100 OU) makes creation
non-free. Combined with Octra's per-tx fee, the cost of state-bloat
attacks scales linearly with the harm.

### Validator pricing race

Risk: a validator advertises a low `price_per_mb`, attracts traffic,
then bumps the price mid-session before settle.

Mitigation: `settle_session` snapshots each hop's `price_per_mb` at
**session open time** (the on-chain `HopSnapshot`). Price changes via
`update_endpoint` between open and settle do not affect the
settlement.

## Why no in-program bond?

Earlier versions of this program kept a per-validator bond inside
`OctraVPN`. We removed it because:

1. **Double-encumbrance.** Octra validators already bond at the
   protocol level. Asking them to also bond inside an application is
   capital-inefficient.
2. **Slashing reuse.** Octra protocol slashing covers double-sign and
   liveness violations. The dVPN application can rely on those signals
   (jailed → no longer an Octra validator → `register_endpoint` gate
   rejects them).
3. **Operational complexity.** Two bond systems means two unbond
   timers, two slash distribution funnels, two governance surfaces.

The price we pay: equivocation slashing for receipt double-signs is
**out-of-band**. A client who collects two contradictory receipts from
the same endpoint key must publish them as evidence; resolution
happens at the Octra protocol layer. The Tamarin proof at
`proofs/tamarin/octravpn.spthy` shows that any double-sign produces
the necessary evidence (`Equivocated` predicate); the on-chain
response is a protocol-layer concern.

## Cap analysis for state-bloat

Worst-case `OctraVPN` state, per active tailnet:

| Map                  | Entry size              | Bound                                       |
| -------------------- | ----------------------- | ------------------------------------------- |
| `tailnets[id]`       | ~ 200 bytes             | Owner-paid creation deposit                 |
| `members[]`          | ~ 50 bytes / member     | Owner-controlled                            |
| `endpoints[addr]`    | ~ 200 bytes / endpoint  | Octra-validator gated (≤ chain validators)  |
| `sessions[id]`       | ~ 200 bytes             | Per-session deposit ≥ 10 OU                 |
| `enc_earnings[addr]` | 32 bytes (Ristretto)    | Per validator                               |

For 10 000 endpoints and 100 000 sessions: ~22 MB on chain. Negligible.
The dominating term in any realistic deployment is `members[]` (flat
member-set per tailnet); a 1000-member tailnet stores ~50 KB.

## Reference implementation

| Component                                    | File                                                        |
| -------------------------------------------- | ----------------------------------------------------------- |
| Parameter validation (constructor)           | `program/main.aml:151`                                      |
| Sweep + bounty calculation                   | `program/main.aml::sweep_expired_session`                   |
| Refund to treasury                           | `program/main.aml::settle_session` (CEI step 2)             |
| Mock chain enforcement                       | `tests/mocks/src/lib.rs::apply_*`                           |
| OU cost estimates                            | `ou-snapshot.txt` (committed)                               |
| Fuzz coverage                                | `crates/octraforge/tests/aml_fuzz.rs`                       |
