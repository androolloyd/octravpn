# First-party Octra VPN

Baseline: lite_node `7f9be4489870645cfcc95439638cde40f5da9f50` (2026-10-13).
The Rust node port remains incomplete. [Source pin](rust-node/upstream.json)
and [source map](rust-node/source-map.json) retain the entire runtime scope.

Keep deterministic protocol logic in Circle apps. Embed the VPN service in
the node and expose it through the wallet. Users who only need the VPN do
not need to run a validator.

There is no VPN protocol commission. Agreed traffic charges are paid in OCT
to the serving operators. Ordinary chain transaction fees remain the network's
fee policy. The legacy fee argument is reserved at zero and cannot enable a cut.

| Component | Boundary |
| --- | --- |
| Discovery | WASM registry Circle app; operator-authored offers and revisions |
| Stake, escrow, sessions, receipts, settlement | Circle application state; native OCT transfers through existing host capabilities |
| Tailnet membership and policy | Circle application state; sealed assets where appropriate |
| Private administration | Proof checks in application methods; native Circle upgrade authority must also be bound to that policy |
| VPN engine | Local WireGuard/TUN, transport, metering and access enforcement |
| ExEx | Consume finalized Circle effects, update local indexes and admission; restart from durable history |
| Wallet | Discovery, funded session approval, connect/disconnect and recovery using the reusable VPN engine |
| Native browsing | `oct://<circle>/<path>` resolution from a committed snapshot; relative assets, cross-Circle navigation and separately approved app actions |

ExEx observes successful, durable execution. It cannot turn advertisements
into funded sessions or use packet timing as consensus input. Every tunnel
admission binds the wallet's session key and WG key to current eligibility.
Traffic stops when authorization expires; settlement and refunds remain
available after pause or retirement.

The fork may add a missing general Circle capability after specifying its
activation and replay behavior. No VPN-specific consensus operation is
implemented in this step. Public network activation requires the team's
release process; the local experimental branch does not activate anything.

The initial registry app is in `crates/octravpn-circle-registry`. It uses the
existing OCWR1/OCWS1 ABI, authenticated host caller, stable KV storage and
operator events. Offers require separate finalized stake and funding checks.
It is tested against a copy of the pinned upstream Rust WASM engine. Those
host ABI tests are complemented by native Circle deploy, update, event,
rollback and restart tests on an isolated private Single chain. Public network
finality and production upgrade authority are still unqualified.

The registry's `host` feature implements the durable ExEx index, including
code binding, batch rollback and replay checks. The Rust canonical store now
publishes Irmin-compatible objects, epoch history and the ExEx outbox in one
SQLite transaction. The live Rust validator actor now calls that boundary through
`octra-node::consensus::Canonical`; four-validator local tests compose public
Circle execution, browser state, VPN admission and ExEx. Production execution,
activation and the complete native driver still require qualification.

`octra-node-protocol` ports the epoch-index commitment and folded consensus
root. Its 134 differential cases use outputs from the real pinned OCaml
implementation. This validates that primitive, not the remaining runtime.

`octra-node-runtime` reuses the native Rust WASM engine through a safe API
with an explicit HFHE backend. Nine golden cases compare its complete
registry results with the unmodified engine. `octra-pvac` directly links
the latest native PVAC crypto; its owned handles avoid ordinary-operation
IPC. The full backend adapter and isolated verifier worker remain to be wired.

The requested backend target is now pure Rust after exact compatibility passes.
`octra-hfhe` ports the field, seeded RNG, keys, active/retained PRFs, ciphertext
formats, seeded encryption, arithmetic, commitments and decryption with native
oracle tests. Complete proofs, recryption and backend qualification remain;
[HFHE gates](rust-node/hfhe-parity.json) keep the remaining crypto scope explicit.

Build and qualify the app:

```sh
cargo build -p octravpn-circle-registry --release --target wasm32-unknown-unknown
python3 scripts/circle-apps/test-registry-native.py \
  --upstream /path/to/pinned/lite_node --out out/registry-native.json
python3 scripts/circle-apps/prepare-registry.py \
  --evidence out/registry-native.json --out out/registry-package
```

The embedded VPN library uses a mandatory local session-authority capability.
Real WireGuard admission, revocation, receipt replay floors, service cancellation
and restart have integration tests. Those tests use supplied funding fixtures;
the authority still needs the finalized settlement application's real state
adapter. They do not establish a production funded session.

Native browsing uses the same committed read snapshot for a page and its
resources. The HTTP bridge opens `oct://` URLs, isolates Circle views, and routes
application calls through scoped host capabilities. Local live-consensus tests
check view updates after a canonical commit and refusal while services are
suspended. System client launch and public-network qualification remain open.

Remaining work: complete the Rust runtime and consensus driver, bind the VPN
consumer to finalized app state, port the money protocol to Circle execution,
finish native browsing and authenticated client/relay transport, then qualify
combined node sync, restart, recovery and funded tunnel operation.
