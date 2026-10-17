# Native stalled-validator recovery

The Rust health supervisor could probe catch-up and quarantine a bad root, but
it did not apply the adopted stalled-validator fallback to an existing driver.
Reconstructing a driver at round zero would discard different state and is not
the native operation.

The fallback now samples current engine and host state inside the owning actor.
Its queued trigger carries no old snapshot or reset decision. It applies the
adopted state/height clocks, the actual current step timeout plus 30 seconds,
and every observer, voting, catch-up, quarantine, attestation, proposal-work and
pending-finalization guard. Health ages use native wall time; proposal grace and
actor timers remain monotonic. Production captures the stall setting from the
release configuration once, with native default/minimum 150 seconds and maximum
3,600 seconds. An absent captured value uses the default rather than shell state.

A permitted reset advances the same engine's round. It explicitly aborts stale
work, clears pending local votes, pacing and retry state, retains only relevant
future round work, advances the relay generation and drains new engine outputs.
Existing generation checks reject old workers, fetches and timers. Locks, valid
values, POLCs, round evidence, pending durable precommits, journals and signing
floors remain intact. Canonical history and ExEx are not rewound or rewritten.
The supervisor queues polls for live connected generations after health checks,
and avoids requesting them while an authenticated catch-up target is pending.

The [checkpoint](native-liveness.json) records **320 passing tests across 24
composed targets**, four standalone ignores, strict lint, formatting and source
manifests. Repeated targets and nested controlled helpers are counted once.
The unchanged compiled payment application
passes all 14 tests, and its 19-theorem abstract Lean model builds. Operator
unstake remains seven days from the first request, payer exit remains 24 hours
and commission remains zero. Those payment proofs are not a liveness or
whole-node refinement proof.

The pinned OCaml module supplies **1,012 native reference vectors**, including
all 256 blocker combinations, threshold boundaries, proposal-clock refresh,
height versus step age, arbitrary-byte keys, floating-point bit patterns,
counter wrap and 198 actual consensus timeout projections. Rust requires the
complete input vector's fixed canonical digest and exact group counts before
comparing every result. The entire adopted source inventory is restored and
verified in the immutable offline builder. The policy body and real consensus
dependency are unchanged; the restrictive public interface is verified but
omitted to observe internal state. No driver or timeout stubs are used.

Real driver tests use signed loopback peers and exercise three boundaries:

- A restored round-four lock survives a same-height reset, a conflicting proposal
  receives a nil prevote, the durable precommit and floor survive, and replay
  retains the lock after the actor stops cleanly.
- A real pending finalization blocks reset while publication fails. Eight polls
  queued behind a held publication are processed after commit without applying
  an old-height reset to the next height.
- A wall-clock jump cannot bypass current proposal grace. Advancing the test's
  monotonic clock past that grace permits recovery from blocked verification;
  new work starts and the old generation's timeout cannot change the new round.

Those tests invoke the actual driver through its public handle with a controlled
host. The supervisor trigger and actual Node host projection were reviewed in
source, and broader existing Service tests run with the wiring present. A forced
positive automatic fallback under that production host is a separate remaining
qualification step. This checkpoint does not claim complete native health-loop
or public-network equivalence.

Before testing, independent review found and corrected an initial process-env
capture that could ignore the release's stall setting. Initial strict checks
also caught an incorrect Option adapter and a direct floating-point test
comparison; the final source uses the actual Option and exact bit comparison.
The initial checks and every source stage remain in the checkpoint.
The initial combined run also found two four-validator test fixtures supplied
only one peer, below the native startup gate. Adding a third authenticated node
fixed their topology; all eight driver tests then passed. Production code was
unchanged. The final driver run uses ordinary runtime features, while the
combined suite and strict lint include the node's existing test helpers.

The public observer remains on the prior `f69473b` image. This candidate has not
been installed there or qualified for Mainnet. A read-only sample at 10:06:02 UTC
saw that unchanged process at epoch 1,707,929 with three peers, suspended while
catching up and with payments unconfigured. Actual legacy unjournaled
IrminPack repair, staged crash recovery, public resource/sync and Circle asset
qualification, stock Tailscale paid binding, bounded portal onboarding, DNS/TLS
and the macOS paid route guard remain open.

The [Service follow-up](service-liveness.md) now covers the forced positive
automatic fallback through the actual Node host locally, including a normal-
feature run and service revocation. It retains separate public qualification.
