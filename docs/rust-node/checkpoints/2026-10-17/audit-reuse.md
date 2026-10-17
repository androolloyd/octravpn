# Retained finality audit reuse

The publisher can reuse successful transaction/QC verification for the same
complete authenticated inputs within one process. It still scans the entire
retained prefix, rereads each record and resolves historical validator authority
before every lookup. Startup begins with an empty cache. This changes no
consensus rules, peer admission, publication or exported-record authentication.

The SHA256 transcript includes chain origin, both complete heads, the complete
outbox epoch and transactions, raw certificate, consensus receipts, retained
proposal, reward source, receipt policy and all resolved validator/relief fields.
In particular, derived validator thresholds and ordered weights are included;
the validator wire encoding alone omits some of these fields. Exhaustive Rust
patterns require added input fields to be considered explicitly.

Only completed successful authentication enters the cache. It retains at most
32,768 sequence/digest entries, preferring the lowest sequences so repeated full
scans above capacity retain useful work. A poisoned lock disables reuse. No
records, state snapshots, sequence watermarks or cache files grant authority.

Regression cases cover warm-cache mutation of old QCs, receipts, proposals,
rewards and outbox transactions without a head change; selected authority object
bodies, required edges, child kinds and missing relief evidence; mutable receipt
policy and authority failures; full transcript field mutations and encoding
boundaries; capacity, replacement and cold restart. Public export still requires
independent fresh verification. The existing complete Node resume regression
remains part of the composed validation.

This optimization still reads and hashes the whole retained prefix. It is not
ledger reexecution, an audit of every state object, or evidence of public service
availability. Local performance measurements describe only their fixture.

The same batch repairs demo infrastructure: native Rust DERP replaces references
to a deleted Go sidecar; the external Headscale package is tested without an
unsupported workspace feature override; the operator demo image includes `ps`.
Recording jobs stage successful fresh GIF/MP4 outputs separately, bind manifests
to their run/commit and file hashes, and reject incomplete or overlapping groups
before publishing. Tracked VTT files remain narration sources. Actual remote VHS,
public RPC and stock-Tailscale runs have their own qualification boundary.

Qualification preserves the initial failed attempts. The first run lacked local
socket permissions; two new fixture assumptions were then corrected to match
native quorum-weight and legacy reward binding. An overlapping build/test run
also exposed four preexisting two-second helper-greeting timeouts. The harness
now gives successful startup 30 seconds and normal EOF the production two-second
close budget; deliberately stalled helpers retain explicit 100 ms deadlines and
owned-child reaping checks. Production timeouts are unchanged. The complete final
combined run uses four test workers rather than overlapping unbounded test loads.

The bounded follow-up caught a shutdown race in the recovery supervisor: its
driver and outer shutdown future can both become ready on the same stop signal,
allowing an ordinary stop to return an unexpected-driver-exit error. The release
corrects that boundary with six deterministic positive/negative controls; the
failed composed run is retained rather than treated as qualified.

The [frozen-source checkpoint](audit-reuse.json) records **1,744 passing tests**
across 23 targets with four intentional helper ignores, strict lint, formatting,
39 unchanged bounded Lean payment-model theorems and the normal-feature Service
regression. Nine recording artifact regressions, shell/workflow/Compose checks
pass. The separate pinned Headscale API component has 786 passing tests and one
intentional ignore under its own committed lockfile; it does not substitute for
Octra integration tests.

The 128-epoch signed-transaction fixture measured a 50.161 ms cold audit and
28.751125 ms warm audit. The second scan reused all 128 successes while resolving
authority 128 more times. This is one local diagnostic measurement, not a public
throughput or availability qualification.

The frozen normal image from `7b2522636ceedeccb059415cadbca9a8a36ff829` is now
[adopted by the existing public observer](audit-reuse-public-adoption.json),
preserving epoch 1,708,425 after a clean exit of the previous process. Startup
continuity matches the canonical/outbox/archive prefix and ExEx checkpoint.
Cold startup is under observation; public serving and paid service remain
unqualified. No funds were spent and no state, key, relay or configuration was
reset. The separate [media-only follow-up](demo-integrity.json) preserves all
compiled node inputs while adding current narration and exact negative controls.
