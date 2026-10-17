# Octranet payment application review

The source-pinned results below describe the earlier postpaid candidate. The
[new prepaid revision](octranet-prepaid-2026-10-17.md) removes operator credit and
requires its own validation record; these historical results do not qualify it.

This record covers the staged `program/octranet-payments.aml` and its
deployment-only factory. Existing v5 contracts and their qualification are
separate. No public transaction was broadcast for this candidate.
The [machine-readable checkpoint](octranet-payments-status.json) records the
source hashes and observed local check results with deployment gates closed.

## Rules

- Payer exit requests stop paid admission and open exactly 86,400,000 canonical
  milliseconds for receipt settlement. Successful claims reduce the refundable
  remainder. At the deadline, claims stop and withdrawal becomes available.
- Operator unstake requests stop paid admission and open a separate fixed
  604,800,000-millisecond hold. Claims against that stopped provider generation
  expire after 24 hours; unused reservations become releasable. Retrying the
  request cannot extend the hold. Rebonding cannot revive an old offer or plan.
- Immutable offers support distinct class prices, including zero. Cumulative
  per-class charges round up to raw OU once, avoiding packet-splitting discounts.
  All collected traffic payment becomes operator earnings; no commission exists.
- The cap bounds accounted liabilities, including stake. Unsolicited native
  transfers can increase the actual ledger balance beyond this funding cap.
  Such donations do not create a right to withdraw another user's funds.

## Adversarial source review

An independent read-only agent reviewed accounting, receipt replay, clocks,
provider generations, failed transfers and native upgrade authority.

The review found a payment-avoidance attack in the original draft: a payer could
race a high-sequence tiny receipt ahead of an operator's larger authorization,
invalidating the earned receipt. Redemption now follows increasing cumulative
usage. Sequence is authenticated metadata, and cannot veto a larger authorized
amount. Duplicate cumulative usage cannot pay twice. The regression covers both
lower sequences and a reused sequence with greater usage.

Other review findings resulted in persisted provider-generation cutoffs, a
deployment-only factory, strict offer/class queries, and negative tests. Native
metadata ownership alone is insufficient evidence: production admission must
also bind transaction sender to its public key. A forged factory sender is
refused by that envelope check even if its wallet signature verifies.

A subsequent review covered the shared tariff, native reader, durable meter and
portal boundary. Two concrete findings were corrected. Dropping an unresolved
send ticket now preserves nonbillable uncertain capacity through later writes
and restart. Native plan admission now requires a revocable, bounded current
publication lease; resuming the same retained head cannot renew its freshness
deadline. Callers cannot replace the plan facts bound to that lease. The
reviewer found no further concrete defect in those applied fixes. The connected
path guards the actual nonblocking packet handoff; its isolated kernel
qualification is recorded below.

The connected candidate adds explicit bounded postpaid credit, durable signed
connection watermarks, native publication guards at nonblocking packet handoff,
and a separate payer journal. Further adversarial review corrected canceled key
rotation, publication-gap pruning, retired-route retention, receipt-only restart
recovery, and opaque WireGuard rekey queues. A separate control worker keeps
traffic and signed-status freshness checks running while settlement waits.
An immutable persisted fee budget bounds operator relayer spending across
retries and restart. Already covered rounding intervals and zero-rate traffic
do not create redundant zero-increment transactions.

Escrow cannot force a payer to sign its final usage receipt. Operators explicitly
choose the maximum unacknowledged bytes and OU they accept; reconnects and
uncertain sends cannot reset either limit. This is bounded postpaid risk, not a
claim of cryptographically fair exchange or proof of packet delivery. Operator
status signatures authenticate their signer, not independent chain finality.

The recovery review also closed two debt/accounting gaps. The operator persists
the authenticated tariff before admitting traffic, so a removed or expired
Circle asset cannot erase the preimage needed to redeem existing receipts.
Recovery still checks current custody, code, keys, rates and deadlines, and its
claim-only result grants no forwarding capability. The client now reserves
exposure durably before an actual packet handoff; interrupted sends retain
nonbillable uncertainty against the original budget. Publication pauses also
retain valid return paths instead of pruning them under table pressure.

A separate read-only review of Legacy execution found no confirmed custody or
admission exploit. U256 range guards are embedded in emitted OCTB, and the
native signature verifier rejects small-order receipt keys. Legacy numeric
coercions can still let a caller create unusable terms; native plan admission
rejects noncanonical state. Application regressions exercise negatives,
values above U256, malformed scalar/account inputs and unsafe receipt keys.
This is a bounded source review with finite regressions, not a proof of the VM.

## Compilation boundary

The adopted typed Program profile excludes Ed25519 verification, while the
`epoch_time` source expression is restricted to Program declarations. Full
`compileAml` Program admission therefore rejects this application. The explicit
local `octra-node compile-legacy` tool uses the unchanged native source emitter,
verifies ordinary raw OCTB binary admission and emits a v1 source-build
certificate. The existing factory deploys that exact binary. Source syntax
does not grant typed Program authority, and the certificate is not a compiler
attestation. No compiler, VM or consensus rule was changed.

Execution under this Legacy path lacks typed ABI/storage enforcement. Embedded
integer guards, signature checks and independent canonical state validation
remain in force. The local build and the exact factory image are tested
together; no unpublished application source needs a public compiler endpoint.

## Local qualification

Run from the repository root, with the pinned toolchain and workspace siblings:

```sh
cargo test --locked --release -p octra-node-runtime --test octranet_payments
cargo clippy --locked --release -p octra-node-runtime --test octranet_payments -- -D warnings
(cd proofs/lean && lake build)
```

The final combined release run across browser, canonical node, runtime, client,
VPN and TUN targets passed **1,558 tests, zero failures and three designated
ignored helpers across 12 targets**. The frozen inputs remained unchanged.
Strict Clippy, formatting and the full Lean build passed. Fourteen application
tests include exact seven-day operator and 24-hour payer boundaries, malformed
inputs, signature safety and custody rollback. The node process tests bind the
recovered clock to actual authenticated finality and refuse substituted heads.

The final isolated Docker gate also passed. Four native validators execute
ordinary signed deployment, stake, funding, offer and claim transactions. The
actual payer client carries TCP, UDP and ICMP through two endpoint kernels with
no external network. Held receipts exhaust the configured 32,768-byte credit;
SIGKILL of client and operator cannot reset that exposure. After receipt release,
canonical charges restore credit. Another restart preserves the same plan,
address and original budget. A canonical exit blocks traffic from a still-live
WireGuard client, early withdrawals fail, and retrying operator unstake retains
its original seven-day deadline. Five successful canonical claims agree across
all four ExEx sinks, including zero charge for the operator's free class.

These process kills occur while idle at bounded-credit/restart checkpoints;
they are not send/fsync fault injection. Component regressions cover interrupted
handoff accounting. Mature 24-hour refunds and seven-day unstake are separate
finite canonical-clock boundary tests, not elapsed wall-clock tests. The gate
does not qualify throughput, seamless client reconnection, stock Tailscale,
portal onboarding, public DNS/TLS or Mainnet. Exact source, executable, image and
log hashes are in the machine-readable checkpoint. No Mainnet transaction was
sent. The existing public observer was separately observed serving canonical
state, with paid settlement unconfigured.

The production Program transaction adapter compiles the actual application and
factory and executes signed transactions, staged storage and real ledger
transfers. The suite covers time boundaries, request retries, payer remainder,
class tariffs, budgets, replay, rebond/rejoin, invalid constructor inputs, zero
clock, key possession, cross-program/domain signatures, sender binding,
unauthorized upgrades, and rollback of all three failed withdrawal types. Fees
and nonce consumption remain subject to native rules on a refused transaction.

`proofs/lean/OctranetPayments.lean` contains 19 abstract theorems about accounting,
fixed deadlines, seven-day stake protection, stopped-generation admission and
cumulative redemption. They do not establish AML/compiler/VM refinement,
signature security, traffic classification, tariff rounding correctness or
packet delivery. Native application tests are finite checks of the actual code.

## Mainnet alpha gates still open

The explicit native `payments` configuration selects the new application;
legacy v5 mode keeps its own adapter. The new implementation connects canonical
admission, durable class metering, payer authorization and claim publication.
The isolated kernel/client/chain path is qualified in the scope above. Stock
Tailscale paid exits, funding/onboarding, MagicDNS and the bounded unpaid Circle
portal still require qualification together before accepting user funds.

The native reader and meter have their scope described
in the [architecture](../architecture/octranet-payment-tier.md). The reader's
positive grant is now tested through actual post-genesis factory/application
deployment, signed validator QCs, authenticated epoch history and canonical
Circle resolution. Separate tests cover publication suspension and a guarded
handoff, payer exit, operator unstake and Circle expiry. These finite checks
cover the reader's publication boundary. The connected gate covers the local
kernel/client/claim path; neither proves AML/compiler/VM refinement.

Public network identity, sustained synchronization/recovery, the public control/TLS
deployment and stateful public end-to-end qualification remain required. A
provider needs its configured stake (minimum 100 OCT), payer funds and network
fees; the earlier one-OCT zero-escrow canary is insufficient for an active
provider. Local tests and source review do not qualify a Mainnet launch.
