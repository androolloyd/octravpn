# Octranet payment application review

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
path now guards the actual nonblocking packet handoff; combined kernel
qualification remains required.

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

## Local qualification

Run from the repository root, with the pinned toolchain and workspace siblings:

```sh
cargo test --locked --release -p octra-node-runtime --test octranet_payments
cargo clippy --locked --release -p octra-node-runtime --test octranet_payments -- -D warnings
(cd proofs/lean && lake build)
```

The combined local run across browser, canonical node, runtime and VPN targets
passed 1,120 tests, with three explicitly ignored qualification/helper cases.
The node process test also checked the recovered epoch clock against its actual
authenticated finality header and refused a substituted captured head. Strict
Clippy and the full Lean build passed. These results qualify their stated local
scope, not the pending public or new paid-packet integration.

The subsequent final run includes the client and TUN crates: **1,541 passed,
zero failed, three ignored helpers across 12 targets**. Strict Clippy, formatting
and the full Lean build passed on the recorded source snapshot. This run also
includes the positive native publication, durable credit/fee budgets, signed
control protocol, stopped-plan receipt recovery and separate client settlement
worker. The observer remained connected to public devnet but was not serving;
its current status is recorded separately. No Mainnet transaction was sent.

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
Those boundaries still require a combined kernel/client/chain qualification
with the bounded unpaid Circle portal before accepting user funds.

The staged native reader and meter are components, with their scope described
in the [architecture](../architecture/octranet-payment-tier.md). The reader's
positive grant is now tested through actual post-genesis factory/application
deployment, signed validator QCs, authenticated epoch history and canonical
Circle resolution. Separate tests cover publication suspension and a guarded
handoff, payer exit, operator unstake and Circle expiry. These finite checks
close the reader's previous positive-grant gap; they do not qualify the full
kernel/client/claim path or prove AML/compiler/VM refinement.

Public network identity, synchronized canonical state, the public control/TLS
deployment and stateful public end-to-end qualification remain required. A
provider needs its configured stake (minimum 100 OCT), payer funds and network
fees; the earlier one-OCT zero-escrow canary is insufficient for an active
provider. Local tests and source review do not qualify a Mainnet launch.
