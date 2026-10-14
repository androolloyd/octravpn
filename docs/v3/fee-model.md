# v3 traffic payments

Traffic payments are denominated in OCT (1 OCT = 1,000,000 OU).
OctraVPN takes no protocol commission. Ordinary Octra transaction fees are
separate. See [the current AML](../../program/main-v3.aml).

## Settlement

```text
total_paid = min(agreed_net, session_deposit)
refund = session_deposit - total_paid
operator_earnings += total_paid
tailnet_treasury += refund
session_deposit = 0
```

The operator receives the full agreed charge. Settlement never credits the
program treasury. `protocol_fee_bps` remains in the ABI at zero; `set_params`
rejects nonzero values. A legacy nonzero state value cannot reduce earnings.

For a 1,500 OU deposit and a 1,000 OU charge, settlement credits 1,000 OU to
the operator and returns 500 OU to the tailnet. Claiming earnings transfers
those 1,000 OU; the caller pays the ordinary network transaction fee.

## Other balances

| Balance | Purpose and recovery |
| --- | --- |
| Operator stake | Slashable bond; unbond after retirement, session recovery and grace |
| Tailnet treasury | Funds sessions and receives refunds; authorized withdrawal |
| Session deposit | Escrow; settlement, no-show refund or expired-session sweep |
| Operator earnings | Full traffic payment; claimable by the operator |
| Program treasury | Retained slash share; no traffic commission |

Expired-session sweeps retain their explicit cleanup bounty. Slashing retains
its evidence-submitter bounty and treasury share. Neither is a commission on
successfully settled traffic.

The AML `burned` counter records retained slash amounts. It does not itself
remove OCT from supply or prevent treasury withdrawals. Treat the withdrawal
policy as a separate governance and security issue.

The native money regression checks full settlement/claim amounts, refunds,
relay settlement and unbond liabilities. Historical devnet reports describing
a 0.5% cut reflect earlier deployed bytecode, not the current source.
