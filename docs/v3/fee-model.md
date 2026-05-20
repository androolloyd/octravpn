# v3 fee model

How OU flows through the v3 contract from session deposit to
operator wallet, and how slash + sweep + protocol fee divert pieces
along the way. All references are to
[`program/main-v3.aml`](../../program/main-v3.aml).

## Money locations (chain-side)

| Location                              | Source map / scalar                              | Held by                                                                 |
| ------------------------------------- | ------------------------------------------------ | ----------------------------------------------------------------------- |
| Operator bond                         | `circle_bond` ([`:93`](../../program/main-v3.aml)) | Slashable; finalize via `finalize_unbond`                              |
| Operator unbonding bond               | `circle_unbonding` ([`:94`](../../program/main-v3.aml)) | Still slashable; transfers out after grace                              |
| Tailnet treasury                      | `tailnet_treasury[tid]` ([`:101`](../../program/main-v3.aml)) | Funds opens; receives refunds                                          |
| Session escrow                        | `session_deposit[sid]` ([`:109`](../../program/main-v3.aml)) | Locked from open to settle/refund                                       |
| Operator earnings (claimable)         | `circle_earnings_total - circle_earnings_claimed` ([`:123,124`](../../program/main-v3.aml)) | Withdrawable via `claim_earnings`                  |
| Program treasury (protocol fees + burn) | `treasury` ([`:129`](../../program/main-v3.aml))  | Withdrawable via owner-only `withdraw_program_treasury`                  |
| Burn counter (audit-only)             | `burned` ([`:130`](../../program/main-v3.aml))    | Subset of `treasury`; never transferred out                              |

## Session deposit flow (happy path)

```text
Client opener wallet
        │
        │ (no value — escrow comes from tailnet)
        ▼
open_session(tid, circle, max_pay)
    tailnet_treasury[tid]  -= max_pay
    session_deposit[sid]   =  max_pay         ([main-v3.aml:497-503])
        │
        ▼
settle_claim(sid, bytes_used)           ([main-v3.aml:513])
        │
        ▼
settle_confirm(sid, bytes_used, net, settle_blinding)   ([main-v3.aml:549])
    total_paid = min(net, deposit)            ([:574-577])
    fee        = total_paid * protocol_fee_bps / 10000  ([:578])
    net_after_fee = total_paid - fee          ([:579])
    refund     = deposit - total_paid         ([:580])

    treasury              += fee              ([:583])
    tailnet_treasury[tid] += refund           ([:584-586])
    circle_earnings_total[circle] += net_after_fee  ([:589])
    circle_earnings_chain[circle] = sha256(prev_head || sha256(blinding))  ([:591-594])
        │
        ▼
claim_earnings(circle, amount)               ([main-v3.aml:648])
    require amount <= total - claimed         ([:653-654])
    circle_earnings_claimed[circle] += amount  ([:655])
    transfer(caller, amount)                  ([:656])
```

**Invariant**: `Δtailnet_treasury + Δsession_deposit + Δtreasury +
Δcircle_earnings_total == 0` on every settle. The deposit is conserved.

## Refund paths

Three ways a session ends in REFUNDED (returns deposit to tailnet,
minus optional bounty):

| Path                                                | Trigger                                             | Refund destination | Bounty               | Source              |
| --------------------------------------------------- | --------------------------------------------------- | ------------------ | -------------------- | ------------------- |
| Equivocating second `settle_claim`                  | Operator submits different `bytes_used`             | Tailnet            | None                 | [`:528-536`](../../program/main-v3.aml) |
| `claim_no_show` after `session_grace_epochs`        | Opener submits; operator never claimed              | Tailnet            | None                 | [`:611-614`](../../program/main-v3.aml) |
| `sweep_expired_session` after `10× session_grace`   | Anyone submits                                      | Tailnet (`deposit - bounty`) | `deposit * sweep_bounty_bps / 10000` (default 1%) | [`:626-636`](../../program/main-v3.aml) |

## Slash flow

`apply_slash` ([`:197-215`](../../program/main-v3.aml)) is the
single helper. Both `slash_double_sign` and `gov_slash_operator`
delegate to it.

```text
total    = circle_bond + circle_unbonding         ([:198-200])
burn     = total * slash_burn_bps / 10000         ([:202])
bounty   = total - burn                            ([:203])

circle_bond, circle_unbonding,
circle_unbond_unlock_epoch              = 0       ([:204-206])
circle_slashed, circle_active = 1, 0              ([:207-208])

treasury += burn                                   ([:209])
burned   += burn                                   ([:210])

if bounty > 0:
    transfer(caller, bounty)                       ([:211-213])
```

**Defaults at deploy** (constructor `100 1000 100_000_000 100 1000`
plus `set_params` later, devnet):

- `slash_burn_bps = 9000` — 90% burned (sits in `treasury`, never
  transferred out via `withdraw_program_treasury` because the burn
  counter is also bumped; runbook for governance withdraw should
  subtract `burned` from `treasury` before approving).
- `slash_bounty_bps = 1000` — 10% bounty to the slash submitter.
  This is what gives anyone an economic incentive to surface
  equivocation.

## Sweep economics

`sweep_expired_session` ([`:619-639`](../../program/main-v3.aml))
pays a small bounty for cleaning up dead sessions:

```text
sweep_grace = session_grace_epochs * sweep_grace_multiplier    ([:624])
bounty      = deposit * sweep_bounty_bps / 10000               ([:628])
refund      = deposit - bounty                                  ([:629])

transfer(caller, bounty)            ([:631])
tailnet_treasury[tid] += refund     ([:635])
```

Defaults: `sweep_grace_multiplier = 10`,
`sweep_bounty_bps = 100` (1%). So if `session_grace_epochs = 100`
(devnet), sweep is available at session_age = 1000 epochs, at 1% of
deposit to whoever calls.

## Governance parameter floors

Set in the constructor + enforced by `set_params`
([`:235-258`](../../program/main-v3.aml)):

| Parameter                  | Floor / Ceiling                           | Source                                                       |
| -------------------------- | ----------------------------------------- | ------------------------------------------------------------ |
| `min_session_deposit`      | `> 0`                                     | [`:237`](../../program/main-v3.aml)                          |
| `min_tailnet_deposit`      | `> 0`                                     | [`:238`](../../program/main-v3.aml)                          |
| `min_circle_stake`         | `>= 100_000_000` (1 OCT in atomic units)  | [`:242`](../../program/main-v3.aml)                          |
| `session_grace_epochs`     | `> 0`                                     | [`:239`](../../program/main-v3.aml)                          |
| `unbond_grace_epochs`      | `>= 1000`                                 | [`:243`](../../program/main-v3.aml)                          |
| `sweep_grace_multiplier`   | `> 0`                                     | [`:240`](../../program/main-v3.aml)                          |
| `sweep_bounty_bps`         | `<= 1000` (10%)                           | [`:241`](../../program/main-v3.aml)                          |
| `slash_burn_bps`           | `>= 5000` (50%)                           | [`:244`](../../program/main-v3.aml)                          |
| `slash_burn + slash_bounty` | `== 10000` (100%)                        | [`:245`](../../program/main-v3.aml)                          |
| `protocol_fee_bps`         | `<= 200` (2%)                             | [`:246`](../../program/main-v3.aml)                          |

Mainnet target values are listed in
[`ceremony/mainnet-params.toml.example`](../../ceremony/mainnet-params.toml.example);
ceremony walkthrough at [`../mainnet-ceremony.md`](../mainnet-ceremony.md).

## Cash flow for a 1 MB metered session (devnet defaults)

Numbers from the smoke test
([`docker/devnet/v3-smoke.sh`](../../docker/devnet/v3-smoke.sh))
with constructor `100 1000 100_000_000 100 1000`,
`protocol_fee_bps = 50`:

| Step                                              | tailnet_treasury | session_deposit | circle_earnings_total | treasury | wallet_caller |
| ------------------------------------------------- | ---------------- | --------------- | --------------------- | -------- | ------------- |
| `create_tailnet(value=10_000_000)`                | +10_000_000      |                 |                       |          | −10_000_000   |
| `open_session(max_pay=1500)`                      | −1500            | +1500           |                       |          |               |
| `settle_claim(bytes=1_048_576)`                   |                  |                 |                       |          |               |
| `settle_confirm(bytes=1_048_576, net=1000, …)`    | +500 (refund)    | −1500           | +995                  | +5       |               |
| `claim_earnings(amount=995)`                      |                  |                 | (claimed += 995)      |          | +995          |

Conservation: deposits in (10_000_000) = treasury (5) + tailnet
remaining (9_998_995 + 1000 + 0 = 9_999_500 + 500 = …) +
operator wallet (995) + protocol_fee_treasury (5).
The actual smoke verifies the earnings-chain head matches
byte-for-byte.

## What governance can withdraw

Only `treasury` ([`:260-269`](../../program/main-v3.aml)):

- Includes accumulated protocol fees.
- Includes slash burn share.
- Does NOT include `burned` independent of `treasury` — `burned` is
  a subset counter. The governance runbook is expected to leave
  `burned` worth of OU in `treasury` permanently (else slashing
  becomes a self-funding governance recapture mechanism, which
  defeats the burn).

Recommendation: governance multisig policy should require
`treasury_post_withdraw >= burned` for any
`withdraw_program_treasury` proposal.
