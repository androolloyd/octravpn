# Private payer scheduling and operator income

This is an experimental native service for the isolated BFT application
profile. It does not enable public-network shielded payments or complete the
[private route coordinator](private-route-coordination.md).

`payer::Service::resume` discovers existing encrypted funding and purchase
jobs. Its primary operator starts enabled. `add_operator(source, control)` adds
another independently accepted operator view of the same custody book, with
its purchases paused. The views share note reservations, proving capacity,
relayer nonces and the original finite fee policy. A different pool requires a
separate book and explicit relayer authority. Job discovery matches the complete
pool, directory, operator and chain target; a shared signing key does not merge
different directories.

An embedding host can drive `step()` and call
`set_operator_enabled(&target, true)` after that operator's paid carrier is
ready. Disabling it prevents subsequent purchase steps; kernel routing must
still prevent an in-flight request from falling back to a physical path.
`Status::paused` counts unfinished purchases held by this control. Additional
operators must be registered again after restart and always start paused.
The standalone `run()` adapter owns its scheduler until shutdown; a route
controller instead retains the service and drives `step()` itself.

Operator registration and enablement do not create jobs, enlarge byte caps,
change prices, increase fee consent or authorize replenishment. Every purchase
still needs native execution and canonical credit before transport admission.
Route-owned consent is held by its ordered controller. The standalone scheduler
reports such jobs as blocked, even if their operator is enabled. Ownership is
embedded in the encrypted job as well as its marker; removing a marker does not
turn it into standalone consent.
`PrivateControl::new_pinned` accepts a socket address without DNS and retains
the original hostname, CA and SPKI checks. The native payer configuration can
set `control_pin`; a coordinated route must require complete accepted pins.

`Service::with_income(wallet)` explicitly attaches an unlocked operator wallet
from the same node and custody source. On each pass, the service imports
canonically earned notes through the existing durable, exclusive assignment
mechanism. Already assigned, spent or reserved notes retain their state. Income
creates no new purchase consent and incurs no protocol commission.

For a combined experimental node, set `spend_operator_income: true` in its
private payer configuration. Startup requires its private operator wallet and
shares that existing unlocked handle with the payer, rather than opening a
second writer. The option defaults to false; a missing or different-custody
wallet is an error. This assigns earnings to the configured payer book, whose
recovery files and original operator credential must remain available.

The [host checkpoint](checkpoints/2026-10-20/private-payer-routing.json) records
69 release payment tests, 376 client tests and strict checks for the client and
experimental/default node. It covers a real grouped native purchase, paused
requests, income conservation and cold recovery requiring both original wallets.
The source-frozen single-hop Linux kernel/ExEx regression also passed both exact
tests on the same executable, with clean exits and verified removal of its two
containers and temporary volumes. It covers canonical native purchase, real
tunnel traffic, client/operator restart and reopening canonical history and
ExEx. The complete route phase journal, ordered private funding/admission,
authenticated chain access during activation, and combined private multihop
kernel recovery remain unfinished.

Run the native payment gate with the established release profile:

```sh
cargo test --locked --release -p octra-node \
  --features private-payments-experimental --lib vpn::payments
```

The large canonical scenario overflows the default debug test stack in both
the pre-change frozen baseline and this candidate. Stack settings were not
increased; the comparison is retained in
`out/private-payer-routing-20261020/debug-comparison.json`. This remains a debug
scenario limitation, rather than a passing debug gate. Linux tunnel and ExEx
validation uses the separate [private kernel runner](private-kernel.md).
