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
reviewer found no further concrete defect in those applied fixes. Atomic
publication checks at actual packet queueing remain an integration requirement.

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

This new application is not connected to the existing v5 native VPN adapter or
client settlement path. The `can_forward` view specifies admission; exposing it
does not enforce it on packets. Paid per-class metering, stopped-generation
revocation, durable receipt delivery and the bounded unpaid Circle portal must
be wired and tested together before accepting user funds.

The staged native reader and meter are components, with their scope described
in the [architecture](../architecture/octranet-payment-tier.md). The reader's
positive projection of actual compiled application state is tested separately
from its negative canonical-clock check and publication-lease checks. A positive
grant through post-genesis deployment, authenticated epoch history and canonical
Circle resolution is still required. Local component checks do not close that
gap or qualify the new application for forwarding.

Public network identity, synchronized canonical state, the public control/TLS
deployment and stateful public end-to-end qualification remain required. A
provider needs its configured stake (minimum 100 OCT), payer funds and network
fees; the earlier one-OCT zero-escrow canary is insufficient for an active
provider. Local tests and source review do not qualify a Mainnet launch.
