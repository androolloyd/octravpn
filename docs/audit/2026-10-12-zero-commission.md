# Zero VPN commission

Traffic settlement credits the full agreed OCT charge to the operator. It
does not credit the program treasury. The legacy fee parameter is fixed at
zero and nonzero updates fail. Ordinary Octra transaction fees are separate.
Slashing and expired-session cleanup retain their explicit bounty rules.

Validated against the adopted lite_node baseline
`d3e834919bd586e81f947d0dae91becc6c43c756`:

- 41 AML tests, three negative controls and empty-selection rejection pass.
  Settlement fixtures seed a legacy 50 bps value and still credit all 20,000 OU.
- 129 native private-admin checks pass, including a valid proof attempting
  to enable commission, rollback, rotation, handoff and replay after restart.
- Native private-chain direct and relay settlement credit their full charges;
  earnings claims, refunds and unbond recovery verify actual balance deltas.
- 24 Rust lifecycle/simulator tests pass. Mock settlement uses zero commission.
- Lean builds with full operator-payment and unchanged-treasury settlement
  theorems. The bounded TLA+ run visits 223,118 distinct states without errors.
  These are abstract model checks, not AML/bytecode refinement proofs.
- Native Circle registry deployment, publish/retire, events, replay rejection,
  rollback and restart pass. App/ExEx/protocol tests and strict Clippy pass.

Local evidence is retained under `out/`:

| Evidence | Path |
| --- | --- |
| Native private admin | `private-admin-latest-no-fee-20261012/evidence.json` |
| Native money paths | `native-money-latest-no-fee-20261012/evidence.json` |
| Circle execution and restart | `circle-vpn-registry-node-reopen-20261012.json` |
| Registry package | `circle-vpn-registry-qualified-package-20261012/` |
| Unsigned canary | `mainnet-canary-no-fee-candidate-20261012/` |
| Official read-only compiler preflight | `mainnet-canary-no-fee-preflight-20261012/` |

The earlier fee-charging canary is superseded and rejected by the runner.
Compilation and local execution do not certify mainnet finality, production
setup or transport. Launch remains `NOT_READY`; nothing was broadcast.
The complete Rust node and live canonical ExEx adapter remain unfinished.
