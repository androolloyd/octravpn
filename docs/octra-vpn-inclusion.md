# First-party Octra VPN

Baseline: lite_node `7f9be4489870645cfcc95439638cde40f5da9f50` (2026-10-13).
The Rust node integrates VPN, ExEx and canonical Circle browsing, with a passing
[paid local checkpoint](rust-node/checkpoints/2026-10-15/native-vpn.json).
Full native parity and public deployment remain unqualified; [current status](rust-node/status.md)
separates those gates. [Source pin](rust-node/upstream.json) and
[source map](rust-node/source-map.json) retain the adopted runtime scope.

Keep deterministic protocol logic in Circle apps. Embed the VPN service in
the node and expose it through the wallet. Users who only need the VPN do
not need to run a validator.

There is no VPN protocol commission or protocol-set traffic rate. Operators
quote their own rates and peers pay them directly in OCT for carriage or exit.
Ordinary chain transaction fees remain the network's
fee policy. The legacy fee argument is reserved at zero and cannot enable a cut.
Creating a personal tailnet needs no treasury deposit, and self-carried traffic
has no operator toll. A third-party relay or exit requires a paid session for
the operator's committed tariff; tailnet membership is not a payment grant.

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

General Circle capabilities follow the adopted activation and replay rules.
The VPN adds no consensus operation. Public network activation requires the
team's release process. The paid qualification fixture has an explicit
application activation profile committed to a dedicated private genesis;
that fixture profile is refused for the public identity.

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
Circle execution, browser state, VPN admission and ExEx. The later paid fixture
adds actual escrow, signed metering, settlement and active traffic recovery.
Production activation and public-network interoperability require separate
qualification; neither fixture is a full native-parity claim.

`octra-node-protocol` ports the epoch-index commitment and folded consensus
root. Its 134 differential cases use outputs from the real pinned OCaml
implementation. This validates that primitive, not the remaining runtime.

`octra-node-runtime` reuses the native Rust WASM engine through a safe API
with an explicit HFHE backend. Nine golden cases compare its complete
registry results with the unmodified engine. `octra-pvac` directly links
the adopted native PVAC crypto as a separate bridge/oracle. The native Rust
launcher now wires `circle_hfhe::Backend`, using the Rust implementation through
bounded execution/proof workers. Every retained/active profile and operational
resource boundary still has its own qualification scope.

The requested backend target is now pure Rust after exact compatibility passes.
`octra-hfhe` ports the field, seeded RNG, keys, active/retained PRFs, ciphertext
formats, seeded encryption, arithmetic, commitments and decryption with native
oracle tests. The final Rust HFHE release suite passed 49 tests, including the
existing complete-proof and public-recryption fixtures. This is finite
compatibility evidence; [HFHE gates](rust-node/hfhe-parity.json) preserve the
remaining full-surface, side-channel and cross-architecture scope.

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
and restart have integration tests. The pinned Circle/Program adapter now binds
the actual finalized application's code, receipt domain/key, opening and escrow.
The paid checkpoint deployed the unchanged main-v5 application and exercised
real signed funding, receipts, settlement/refunds and operator restart through
that adapter. It establishes isolated local funded operation, not production
funding or public-chain readiness.

Native browsing uses the same committed read snapshot for a page and its
resources. The HTTP bridge opens `oct://` URLs, isolates Circle views, and routes
application calls through scoped host capabilities. Local live-consensus tests
check view updates after a canonical commit and refusal while services are
suspended. System client launch and public-network qualification remain open.

Remaining release gates include final broader runtime/Chromium results, actual
public snapshot import and P2P/HTTP catch-up/restart, external Tailscale/TLS and
additional-device navigation, production private-admin setup/upgrade authority,
and any unmapped native behavior in the source inventory. The protocol has no
commission and pays agreed traffic in OCT. Its two-step settlement still assumes
timely cooperation; local adversarial amount checks do not prove fair payment
when an operator or client refuses to complete settlement. Multi-hop selection
remains unsupported and is refused before funding.
