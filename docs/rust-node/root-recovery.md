# Peer-root quarantine and immutable finality

The recovery supervisor checks signed current-head root responses before its
connected-driver and serving-observer fast paths. Previously those paths could
skip the probe, and forward-target selection discarded conflicting roots.
Matching-root filtering remains useful for choosing a forward catch-up target;
it cannot decide whether the current head is safe to serve.

The health query captures the exact canonical head, its next-epoch active and
historical stake authorities, and a quarantine token. It retries one moving-head sample.
`EpochRoots` verifies validator signatures and deduplicates responders at its
receive boundary. The health classifier also refuses duplicate, unknown,
zero-weight and malformed internal records. Native health admission requires
`min(n - 1, max(active_f + 1, OCTRA_STATE_ATTEST_MIN_PEERS))` distinct peers,
independently of the weighted source-agreement and consensus-proof rules.
The most common root wins, with adopted seed-zero OCaml table traversal deciding
count ties. Weighted consensus evidence is recorded separately and cannot
replace the required peer count. This choice has no finality or rollback authority.

A fresh conflict suspends services under the canonical publication lease.
Existing VPN permits, browser application snapshots and retained gateway URLs
are revoked. Publication can still advance authenticated canonical history,
but neither it nor an ordinary resume can clear the root gate. The supervisor
joins the stopped driver generation and reconciles already committed pending
work before another generation can run.

Native ahead grace, drift tolerance, quarantine streak and soft-lag policy
control admission separately. Authenticated rootless responses still contribute
head observations; the native fault-tolerant target uses the active set's `f`,
so one exaggerated head cannot establish a catch-up obligation. A matching
one-epoch soft lag can admit an initially suspended node before successor data
arrives. Larger lag must complete authenticated recovery before admission.

Public startup holds services and signing until this policy admits the retained
head. Peer hello heights cannot establish mandatory startup catch-up targets.
HTTP recovery probes the consecutive range even when its advertised head is
stale or unavailable. Only its first locally QC-verified successor becomes a
persistent target; an unverified suffix cannot stall a healthy driver.

Clearing a quarantine checks both the exact head and the token captured before
the query. A newer conflict invalidates an older sample even at the same head.
The original cause also controls which evidence may clear it. The adopted
runtime permits ordinary peer-root, ahead and lag causes to recover through
their corresponding root evidence. An originating `catchup_failed:` or
`catchup_apply_failed:` cause requires an in-sync sample with weighted consensus
proof; the distinct-peer admission count alone is insufficient. Hard local
causes survive both kinds of root evidence and later recoverable observations.
The first cause remains until recovery, except that a hard cause may replace a
recoverable one. Every new quarantine observation still invalidates old tokens.

Failed catch-up clears the queued target and records its failure cause. Complete
forward catch-up can clear a recoverable cause only with a fresh token, an exact
current head and an actual canonical successor of the retained starting head.
An already-reached target with no new committed epoch supplies no such evidence.
Neither this path nor root attestation removes a hard local cause.
Successful verified forward recovery supplies the native self-attestation for
that head, so it does not wait for another peer-root poll. The configured
connection gate and the final `resume_at` head/token checks still apply; clearing
an active quarantine also resets the controller's ahead streak.

Clear leaves services suspended; `resume_at` checks the admitted head again
while holding the publication lease and audits canonical history.
Resuming the same head preserves its original paid-admission age.
`GET /operator/status` reports the suspension reason. As in the adopted
runtime, the quarantine gate is process-local, not a durable ledger marker.
The public host methods trust their caller to authenticate peer evidence;
they are not exposed as untrusted RPC operations.

## Why an empty epoch cannot simply be removed

The adopted source is lite_node
`7f9be4489870645cfcc95439638cde40f5da9f50`. Its preliminary
`Catchup.decide_fork_repair` predicate is followed by stronger storage guards.
`lib/core/fork_head_repair.ml` refuses repair across any commit-journal Prepare
or Commit above the target. `test/test_apply_fork.ml` deliberately creates an
otherwise repairable empty tail, adds the journal entries and verifies that
stage, store resume and chain resume all refuse without changing evidence.
Modern native publication writes Prepare before durable epoch effects.

The Rust canonical suffix is QC-authenticated, atomically published with its
state/history/ExEx outbox and protected by durable signing floors. A zero
transaction count does not imply unchanged state: rejected outcomes, rewards
and epoch metadata still matter. Root quarantine therefore leaves canonical
records, certificates, ExEx sequences/checkpoints and signing history intact.

The [offline legacy repair command](legacy-repair.md) now resumes locally staged
native-format repair through a pinned native physical backend. Native codec,
finality and physical crash-order checks have separate evidence. Automatic
repair selection and a Rust physical backend remain open; modern canonical
SQLite history is never rewound by this compatibility command.
The [stalled-voter fallback](checkpoints/2026-10-17/native-liveness.md) now observes
step and height age inside the existing driver actor, applies native
timeout/proposal/finality guards, and advances its round while preserving locks
and durable signing history. Its policy has an independent unchanged-OCaml
reference corpus and real driver regressions. The supervisor trigger and actual
Node flag projection are covered by the later
[Service checkpoint](checkpoints/2026-10-17/service-liveness.md), including a
forced positive fallback under the production host. Public recovery and full
native health-loop parity remain separate qualification boundaries.
