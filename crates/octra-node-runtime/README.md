# Octra Rust runtime

Reuses the pinned native Rust WASM Circle engine through a safe byte-slice API.
The engine keeps its interpreter, metering, effects and memory ownership. The
Rust host supplies an explicit HFHE capability; no OCaml callback is required.

The nine registry golden cases compare complete native-engine outputs,
including storage, events, effort, response bytes and refusals. Build the
registry WASM before running `cargo test -p octra-node-runtime`.

`CanonicalApplications` serves public `program.info` and `program.view` from
the same committed snapshot as `CanonicalAssets`. It checks the stored program
hash, loads native stable storage and declared public reads, and runs the actual
WASM engine with the native anonymous caller. The node supplies the epoch's
activation profile. Views cannot publish effects. Private/HFHE reads and OCTB
execution refuse until their authorization and execution hosts are available.

The adopted counter's 30 complete native-host outcomes and 307 Circle state
cases qualify this read path. Restart tests cover retained/new snapshots and
the corresponding durable ExEx cursor. Chromium uses this host for program
reads and reviewed native wallet submissions on a local development chain.

`circle_call` executes standard WASM updates from a captured state and a host-owned
context. Native storage guards preserve both active sorted validation and legacy
table traversal. Stable writes are speculative, checked against the original
snapshot, and rolled back on refusal. Native fixtures cover 6,247 guard cases,
823 storage/cost/root cases and 104 counter update cases. The canonical restart
test admits five genuinely signed counter transactions, checks the native staging
fee rule, persists account balances/nonces and VM receipts, and publishes state
and ExEx together through a QC signed by local fixture validators. ExEx resumes its
checkpoint after restart without redelivering that epoch.

`finality::Publisher` verifies native persisted QCs against trusted local validator
history, executed transaction/outcome commitments and the computed state root.
Consensus receipts, state, history and ExEx commit atomically. Opening the publisher
reauthenticates retained certificates and receipts; missing authority or evidence
refuses. The raw canonical API remains a trusted import/storage-test boundary.
Native outcome reconstruction and envelope gates match 1,705 oracle cases.

`circle_transaction` now supplies the ordinary Circle-call transaction host:
fee debits, nonce progression, value journals, exact auxiliary VM receipts and
rollback match 160 complete native sender-loop cases. Operational failures roll
back the entire attempt. Inputs still need the epoch's admission/rule checks.

`browser_wallet::Wallet` signs reviewed intents using host-owned signer and node
capabilities. It binds chain/genesis/Circle, limits value and OU, checks available
funds, serializes signing, verifies the returned signature and submits the exact
transaction. `tx.wait` is bound to the wallet and Circle by the node. Chromium
qualifies the upstream site's real signed update, canonical counter/fee change,
committed status and durable ExEx record. Fixture validator keys and funded wallet
are public development keys; the fixture applies native epoch rewards but does not
run peer consensus. A production node implementation of the wallet capability remains
required alongside durable pending transaction management.

`epoch_footer` applies the native emission schedule, weighted validator rewards,
account key attribution and supply metadata with atomic rollback. It matches 388
full native footer cases; 961 additional oracle cases cover reward plans, weighted
rounding and emission binding. Signed browser/restart tests now distribute fees and
reload the complete account tree, preserving public supply and reward recipients.
The node must still supply authenticated activation and reward attribution.
 HFHE, nested calls, spawn/asset effects and native session
transport remain unavailable in this update host. Full AML execution and the
networking/consensus driver, validator activation history and preverification
receipt policy also remain node-port work. Malformed outcome JSON diagnostic
parity remains unavailable. This crate is not a complete node and does not certify
public-chain finality.
