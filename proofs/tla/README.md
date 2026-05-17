# TLA+ specs for OctraVPN

This directory holds two parallel TLA+ specs:

- `OctraVPN.tla` / `OctraVPN.cfg` — v1.1 (`program/main.aml`).
- `OctraVPN_V2.tla` / `OctraVPN_V2.cfg` — v2 slim-registry
  (`program/main-v2.aml`).

Cryptography is abstracted (signatures, FHE, commitments are assumed
correct); what's checked is the *structural* invariants the program is
supposed to preserve regardless of which actor calls it.

## v1.1 (carried over from the bulletproof v1.1 drill)

Properties: `ConservationOfFunds`, `NoDoubleSettle`, `TreasuryNonNegative`,
`ActiveEndpointsAreBonded`, `SlashedHaveZeroStake`, `Inv_DoubleSignSlashable`,
`Inv_SettlementOnlyOnConfirm`, `Inv_TreasuryConservation`, …

```
java -cp /tmp/tla2tools.jar tlc2.TLC \
  -workers auto -deadlock OctraVPN -config OctraVPN.cfg
```

Last run: 2,756,874 states / 223,118 distinct / depth 26 / 0 violations.

## v2 (circle-keyed, slim registry)

The v2 spec models the same state-machine *shape* with these deltas:

- Circle-keyed registry (`CircleId` opaque sort).
- `RegisterCircleAtomic` payable + atomic action: owner + active + bond
  in one transition. Inv `Inv_CircleAtomicRegisterBond` certifies the
  chicken-and-egg cannot recur.
- `AuthorizeCircle` replaces `ConfigureTailnetExit`. Inv
  `Inv_AuthorizedCircleIsActive` certifies only registered circles
  reach the authorization map.
- Per-class price stamped at open. Inv
  `Inv_StampedPriceImmutableInOpenSession` certifies live sessions
  retain their open-time price across `UpdateCircle` interleavings.
- `chargeInternalTraffic` toggle on tailnets.
- Slashes keyed on `CircleId`. v1.1's `Inv_DoubleSignSlashable` and
  `SlashedHaveZeroStake` carry over with the renamed key.

```
java -cp /tmp/tla2tools.jar tlc2.TLC \
  -workers auto -deadlock OctraVPN_V2 -config OctraVPN_V2.cfg
```

Last run: 52,676,571 states / 3,805,681 distinct / depth 31 /
0 violations in ~39s.

A full TLAPS proof is follow-up work: TLC exhaustively checks up to
the configured constants. The Lean 4 proofs (`proofs/lean/`) carry
the per-entrypoint state-transition contracts as theorems for both
v1.1 (45 theorems) and v2 (52 theorems).
