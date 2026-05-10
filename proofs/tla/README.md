# TLA+ spec for OctraVPN

`OctraVPN.tla` models the on-chain state machine. Cryptography is abstracted
(signatures, FHE, commitments are assumed correct); what's checked is the
*structural* invariants the program is supposed to preserve regardless of
which actor calls it.

## Properties

- **ConservationOfFunds** — all monetary buckets stay non-negative, no OCT
  vanishes off-balance-sheet during transitions.
- **NoDoubleSettle** — a session never re-enters `open` after settling.
- **SlashLeBond** — bond is never driven negative by any slashing path.
- **MonotonicSeq** — receipt sequence numbers never go backward.
- **Liveness_SettleOrRefund** — every opened session eventually settles or
  refunds (under weak fairness on the corresponding action).

## Running

```
tlc OctraVPN.tla -config OctraVPN.cfg
```

Use `-workers auto -deadlock` for production runs.

A full TLAPS proof is a follow-up: TLC will exhaustively check up to the
configured constants (3 validators, 1 client, MaxSeq=3), giving us
high-confidence behavioral coverage. To make these properties machine-
checkable as theorems instead of bounded checks, write the proof in TLAPS
referencing the same operators here.
