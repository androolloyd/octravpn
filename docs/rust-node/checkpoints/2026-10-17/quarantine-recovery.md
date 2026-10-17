# Cause-sensitive quarantine recovery

The recovery controller previously treated every root quarantine as recoverable
through a fresh matching peer count. It also left failed catch-up targets queued.
The adopted native runtime distinguishes ordinary root observations, failed
catch-up and hard local failures; its verified forward completion can attest the
new head without another root poll.

The Rust controller now carries explicit native root-evidence labels. An
originating `catchup_failed:` or `catchup_apply_failed:` cause requires in-sync
weighted consensus evidence, rather than the independent distinct-peer count.
Hard causes survive all root attestations and later lag observations. The first
cause remains unless a hard cause replaces a recoverable one; every observation
still invalidates older query tickets. Catch-up failure records its cause before
reconciliation and removes the obsolete queued target.

Complete forward catch-up supplies admission evidence only after an actual new
canonical commit, with the exact retained starting head, exact current head and
fresh quarantine token. Zero progress cannot supply this evidence. Hard causes
remain closed. Successful completion avoids a redundant peer-root query while
retaining the configured connection gate and final `resume_at` checks. Clearing
an active quarantine resets the controller's ahead streak. Canonical history,
certificates, signing floors, ExEx and consensus rules are not rewound or changed.

The [machine-readable checkpoint](quarantine-recovery.json) records **311 passing
tests across 26 composed targets**, four intentional helper ignores, strict
Clippy and formatting. The unchanged compiled payment application passes all
14 tests, and its 19-theorem abstract Lean model builds. Operator unstake remains
seven days from the first request, payer exit remains 24 hours and commission
remains zero.

Real signed TCP peers exercise a failed soft-lag catch-up, refusal of two-of-four
matching roots, recovery with three-of-four consensus evidence, obsolete-target
removal and hard-cause persistence through lag-seven and in-sync probes. Browser
HTTP, VPN admission, stopped signing and immutable history are checked. Another
actual Service run imports a genuine native-executed successor with a three-vote
QC while every successor-root reply is withheld; canonical record, browser, VPN
admission and durable ExEx cursor agree. A separate real-QC Node regression
refuses zero progress, stale heads/tickets and a forged retained start.

The initial combined run caught a test timing error: the extension callback had
run before its durable checkpoint advanced. Both new positive tests now wait for
the exact SQLite checkpoint independently of their callback assertions. Only two
test files changed. The final Node library passes all 100 tests; the other 25
unchanged targets pass 211. The initial failure and every source stage remain in
the checkpoint.

The Rust policy matches **37,302 cases** executed by unchanged adopted
`consensus_runtime_state.ml` on OCaml 4.14.2. The pinned public interface is
verified but omitted to observe internal predicates; implementation bodies have
no prefixes, adapters or edits. Arbitrary-byte prefix mutations and actual native
entry/clear transitions are covered. This host run and the local integration
tests do not prove whole-node refinement or complete native orchestration parity.

The public observer was not restarted or changed. At 08:36:43 UTC its prior
`f69473b` image was alive at epoch 1,707,647 with 22 peers, suspended for `lag_7`,
with payments unconfigured. This batch is not installed there. Native stalled
voter realignment, the actual legacy repair backend, persistence CPU scaling,
stock-client onboarding and public deployment qualification remain open.
