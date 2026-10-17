# Peer diagnostics and retained-state recovery

The local operator peer endpoint now separates transport, handshake, admission
and session outcomes. Labels are fixed and storage is bounded; remote payloads,
identities and error strings are excluded from the new snapshot. Counters reset
per run, stale-generation completions are ignored, and queued session cancellation
records once. Native peer RPC, authentication, retry and consensus behavior retain
their existing rules. The [API notes](../../peer-diagnostics.md) describe the field.

Checkpoint reopening still authenticates both the imported floor and a later
canonical head. It now releases the floor's independent tree before restoring a
different current head. The regression imports a signed epoch-65 floor, publishes
a real QC-backed epoch-66 suffix, checks ExEx parent continuity, then independently
corrupts objects unique to each tree and verifies startup refusal. This removes
avoidable overlapping allocations; it does not establish a production memory bound.

The final composed validation passes **305 tests across 25 targets**, with four
intentional helper ignores. It includes actual four-process devnet execution,
Single execution, connected recovery, canonical publication, ExEx, network parity
and all 14 compiled payment-application tests. Strict Clippy, formatting and the
19-theorem abstract Lean model pass. The payment AML remains fixed at seven days
from the first operator unstake request, with immutable retry deadlines and
separate 24-hour payer/stopped-operator settlement windows. The economics document
now explicitly distinguishes this application from its historical v1 table.

The first combined run failed the new refused-TCP fixture. A socket bound without
listening did not complete the connection before its five-second test deadline
on this Mac. A subsequent held alternate-loopback fixture also timed out. The
final fixture releases a reserved localhost listener immediately before dialing
the closed port; both actual connection refusal and graceful early closure pass
their distinct assertions. Only this test file changed after the combined run.
The affected ten-test target and strict lint pass on the final source snapshot;
the other 24 targets retain identical sources. All initial failures and source
stages are recorded in the [machine-readable checkpoint](peer-recovery-diagnostics.json).

Separately, the previously qualified `f69473b` public observer was adopted on its
retained database and identity through the existing relay. Read-only consistency
checks bound 63 post-restart epochs and 525 transactions to canonical commits,
the ExEx outbox, archive files and durable extension checkpoint. This script does
not independently reexecute or reverify signatures. A later bounded sample at
08:15:50 UTC saw epoch 1,707,599, 20 peers and serving admission enabled. The old
Circle address requested through both loopback and tailnet HTTPS returned the
same HTTP 404 response. That demonstrates neither published asset availability
nor a stable public paid service. Payments remain unconfigured, no funds were
spent, and this batch's diagnostics and allocation change are not installed in
that running image.

Positive legacy nonjournaled fork repair, complete native orchestration parity,
stock-client onboarding, public paid routing and Mainnet alpha qualification
remain open. These local tests and abstract proofs do not establish AML/compiler/VM
refinement or seven elapsed days of deployed operation.
