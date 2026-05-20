# OctraVPN v3 Design Docs

This directory is the canonical design-doc set for OctraVPN v3 — the
program currently deployed on Octra devnet at
`oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`, source at
[`program/main-v3.aml`](../../program/main-v3.aml) (712 lines).

v3 supersedes v2 as the live substrate. The top-level architecture
docs ([`../architecture.md`](../architecture.md),
[`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md))
remain valid for their narrower scopes; this set is the
auditor-grade reference.

## Canonical addresses

| Network  | Program address                                          | Source commit         |
| -------- | -------------------------------------------------------- | --------------------- |
| Devnet   | `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`         | deployed 2026-05-18   |
| Mainnet  | _TBD — gated on ceremony, see [`../mainnet-ceremony.md`](../mainnet-ceremony.md)_ | _TBD_ |

## Constructor signature

```text
constructor(
    min_session_deposit:   int,
    min_tailnet_deposit:   int,
    min_circle_stake:      int,   // floor: 100_000_000
    session_grace_epochs:  int,
    unbond_grace_epochs:   int    // floor: 1_000
)
```

Source: [`program/main-v3.aml:148-173`](../../program/main-v3.aml).
Devnet was deployed with `100 1000 100_000_000 100 1000`
(see [`docker/devnet/v3-smoke.sh:61`](../../docker/devnet/v3-smoke.sh)).

## The 19 entrypoints (excluding governance + views)

Defined in [`crates/octravpn-core/src/v3_calls.rs`](../../crates/octravpn-core/src/v3_calls.rs)'s
`method` module (lines 34-73). Walked end-to-end in
[`call-flows.md`](call-flows.md).

`register_circle`, `update_circle_state`, `rotate_receipt_pubkey`,
`retire_circle`, `bond_endpoint`, `unbond_endpoint`,
`finalize_unbond`, `slash_double_sign`, `create_tailnet`,
`update_members_root`, `retire_tailnet`, `deposit_to_tailnet`,
`withdraw_tailnet_treasury`, `open_session`, `settle_claim`,
`settle_confirm`, `claim_no_show`, `sweep_expired_session`,
`claim_earnings`.

(Owner-only governance entrypoints — `transfer_ownership`,
`set_paused`, `set_params`, `withdraw_program_treasury`,
`gov_slash_operator` — are documented in [`call-flows.md`](call-flows.md)
but are intentionally not in `v3_calls.rs` because the operator/client
crates never invoke them.)

## Documents in this set

| File                                              | Audience          | Summary                                                              |
| ------------------------------------------------- | ----------------- | -------------------------------------------------------------------- |
| [`overview.md`](overview.md)                       | everyone          | One-page narrative: what v3 is, what it adds over v2, what stayed.   |
| [`data-model.md`](data-model.md)                   | contributor       | Every on-chain map, field-by-field, with AML line refs.              |
| [`call-flows.md`](call-flows.md)                   | contributor       | End-to-end walk of every public entrypoint.                          |
| [`state-machine.md`](state-machine.md)             | auditor           | Formal FSM per stateful entity (Circle / Tailnet / Session).         |
| [`security-model.md`](security-model.md)           | auditor           | Trust assumptions, adversary capabilities, slash conditions.         |
| [`canonical-encoders.md`](canonical-encoders.md)   | auditor           | JSON canonical form for state-root / policy / members anchors.       |
| [`fee-model.md`](fee-model.md)                     | operator          | OU flow through session escrow, treasury, slash burn.                |
| [`v3-vs-v2.md`](v3-vs-v2.md)                       | operator          | Migration delta — same / renamed / new / removed, per entrypoint.    |
| [`deployment.md`](deployment.md)                   | operator          | Devnet status + chain-side blockers + link to mainnet ceremony.      |

## Reading order

- **New contributor** — [`overview.md`](overview.md) →
  [`data-model.md`](data-model.md) → [`call-flows.md`](call-flows.md) →
  [`state-machine.md`](state-machine.md).
- **External auditor** — [`security-model.md`](security-model.md) →
  [`state-machine.md`](state-machine.md) →
  [`canonical-encoders.md`](canonical-encoders.md) →
  [`../security/threat-model-v3.md`](../security/threat-model-v3.md).
- **Operator** — [`overview.md`](overview.md) →
  [`fee-model.md`](fee-model.md) → [`v3-vs-v2.md`](v3-vs-v2.md) →
  [`deployment.md`](deployment.md) →
  [`../mainnet-ceremony.md`](../mainnet-ceremony.md).
