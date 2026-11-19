# Suggested changes for lite_node, from implementing release 8f785a93

These come from implementing the `8f785a93` devnet release (sequence 42,
`consensus_recovery`) in an independent node, checked case by case against
lite_node's own code. None of them is a consensus bug. Each makes releases
harder to follow, reproduce or reimplement. The three most important are
listed first.

## 1. Publish release notes for consensus-visible changes

**What happened.** The release was mandatory, but its main commit
("weighted quorum, execution time slices and store gc", 379 files)
combined the new quorum rule with storage GC and execution timing work.
Nothing said which rules changed, from which epoch, or why.

**Suggestion.** Ship a short changelog with each required release, either
as a file in the repo or in the signed release marker. For each change,
give:
- the rule id and its activation (chain, anchor epoch and root, first
  epoch);
- one line on what it changes;
- the error strings that become consensus outcomes.

Keep consensus changes in their own commits, apart from storage and
performance work.

## 2. Change the compatibility labels when consensus rules change

**What happened.** The release marker's `consensus_profile` number and
`consensus_rules_id` stayed the same across releases that changed quorum
and execution rules. A watcher can't use them to tell that a release
changes consensus.

**Suggestion.** Either bump `consensus_rules_id` whenever a release adds
or changes a rule (the rule graph's root would work), or put the set of
scheduled rule ids and activation epochs in the signed marker. Nodes could
then refuse paid work ahead of a rule they don't implement, instead of
finding out when blocks stop verifying.

## 3. Keep the environment out of the execution profile

**What happened.** From seatless activation on, every epoch writes
`meta/execution_profile` = `Consensus_profile.hash`, and later epochs and
restored states are checked against it. That hash reads environment
variables (`Sys.getenv_opt`), so a node configured differently could
compute a different marker and stop accepting a correct state.

**Suggestion.** Compute the execution profile only from the chain id, the
epoch and compiled-in constants, or say exactly which variables it may
read and fix their values per chain.

## 4. Make the release buildable from its lockfile

**What happened.** `controls/lib/gc_build.py` downloads and patches irmin
at build time. `store_irmin.ml` calls functions that exist only in that
patched build (`Store.Gc.cleanup_debt`,
`Irmin_pack_unix.Async.Unix.mask_for_exit`). A plain `opam install` from
`octra_node.opam.locked` therefore can't build `lib/core`. A full build
also needs `make -C mcl ...` and cargo, outside the dune graph.

**Suggestion.**
- Pin the patched irmin as an opam package (a pinned git or tarball
  source with a hash) in the lockfile.
- Bring the `mcl` and Rust library builds into dune rules, or document
  them in one script.
- Have CI build from a clean container, so the release can be rebuilt
  without network access beyond the lockfile.

## 5. Use stable error codes instead of message text

**What happened.** Rejection reasons such as `validator change increases
blocking weight` or `program input effort exceeds limit` end up in
recorded outcomes. Rewording a message therefore changes what nodes must
agree on, and every implementation has to copy the text byte for byte.

**Suggestion.** Record a short stable code (for example
`validator_weight_blocking`) as the consensus value and keep the readable
message off-consensus. If that's too large a change, publish the exact
strings per rule as part of the release notes (see 1).

## 6. Make failures behave the same way inside a check

**What happened.**
- In `Epoch_exec.check_registry_change`, most failures return `Error`, so
  only the transaction is rejected. But `snapshot_parameters` uses
  `failwith "validator seat limit is missing"` inside the same chain,
  which escapes and fails the whole epoch.
- The result of `check_weight_change ~before:(select …) ~after:(select …)`
  depends on OCaml evaluating arguments right to left.

**Suggestion.**
- Return `Error` from `snapshot_parameters` (or decide that it really
  should fail the epoch, and say so in a comment).
- Bind the two `select` calls to names before the call, so the order is
  explicit.

## 7. Check the activation anchor wherever a rule is switched on

**What happened.** The rule graph authenticates each activation against an
anchor epoch and state root. But the new rules are actually switched on
by `Rule_graph.seatless_at`, `scalar_work_at`, `program_result_at` and
`source_create_at`, which look only at the chain id and the epoch. So
there are two ways a rule is on, and only one of them checks the anchor.

**Suggestion.** Route these `*_at` helpers through the authenticated rule
graph, or document that the anchor is checked once at fold time and that
`*_at` is only a lookup afterwards.

## 8. Write the one-time penalty record from data that is always present

**What happened.** The first seatless epoch that runs
`prepare_validator_penalties` turns every applied slash into
`validator_penalty:<address>` and writes `validator_penalty_epoch`. A
state written only at that moment is easy to get wrong for nodes that
start later or from a snapshot.

**Suggestion.** Derive penalties from the registry each epoch, or record
this migration explicitly (rule id, epoch, expected keys) so checkpoints
and new implementations can verify it.

## Minor

- `lib/core/epoch_exec.ml` has no `.mli`, so everything in it is public
  and the stable API is unclear. An interface file would help both
  maintainers and ports.
- `Validator_admission` was renamed to `Validator_entry` with no
  compatibility alias, which breaks external tools and test harnesses
  built on the old name.
