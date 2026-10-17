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

Legacy nonjournaled empty-fork repair, its durable staged recovery and native
crash-order parity remain separate implementation and qualification work.
This quarantine change does not qualify that positive repair path, full native
health-loop parity or public-network recovery.
