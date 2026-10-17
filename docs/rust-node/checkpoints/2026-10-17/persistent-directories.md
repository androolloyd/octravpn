# Persistent native directories

Warm state updates previously rebuilt wide directory commitments and traversed
unchanged children when preparing persisted objects. Native physical inode pages
bounded disk growth, but those in-memory walks still scaled with directory width.

The protocol now keeps immutable native directory tries with cached commitments,
name routes and page values. An edit copies its changed path. The runtime retains
dirty child names, uses persistent-map differences and streams changed pages in
child-first order. It preserves no-op node identity and does not retain old ledger
values through a cache history. Cold construction and restore still read the
authenticated directory once.

Physical page reuse still requires the canonical SQL writer's authenticated
persisted-root grant. A legacy flat image or an unrelated store does not supply
that grant. Commitments, native page encodings, SQL atomicity and consensus rules
are unchanged. Tests cover thresholds, deletion collapse, kind changes, arbitrary
byte keys, savepoint rollback, restored caches, foreign grafts and old-leaf release.
An independent adversarial review found no remaining concrete cache invalidation,
reuse-grant or retention defect.

The [checkpoint](persistent-directories.json) records **522 passing tests across
123 composed outer Cargo targets**, seven standalone ignores, strict Clippy and
formatting. Those ignores include external native-peer, public-certificate and
browser qualification as well as controlled crash helpers. The initial full run
passed 518 tests and exposed four stale or missing reference failures. After
repairing the reference inputs, the final affected run passed all 228 tests across
eight targets. Repeated targets and nested helper summaries are counted once.
Strict lint then required small argument-signature corrections: copy the
eight-byte route and borrow a page while encoding it. The accepted lint,
formatting and repeated affected release run share one final source snapshot.

The cached tree implementation replays 7,464 operations from 92 adopted native
storage cases. The runtime inode corpus adds 3,100 operations, for **10,564 native
tree operations across two corpora**. All use the adopted reference
`7f9be4489870645cfcc95439638cde40f5da9f50`.

Deterministic hot-edit regressions at 512, 4,096 and 32,768 children observed 38
runtime child visits and four, five and six encoded objects respectively across
eight epochs. An authenticated restored 8,192-child directory observed 38 visits
and five objects. Protocol set/remove checks at 4,096 and 131,072 names each hash
one name and encode three or four native pages. These are bounded operation
counts; public throughput, peak RSS and whole-epoch cost have not been qualified.

Fresh native references also close the four initial fixture failures. The native
compiler/VM executed 33 private-admin calls and all 42 settlement security methods,
including 24 expected refusals. The pristine native Circle engine executed nine
cases against the current locked registry WASM. Its exact artifact and reference
were explicitly selected together for the final Rust parity run. Full source
inventories, immutable builder identity, artifact hashes and unchanged-source
checks are recorded in the checkpoint; expected results were regenerated from
the adopted implementation.

Reproduction of Circle parity requires the current WASM and its native fixture
together. Generate both with `scripts/circle-apps/test-registry-native.py` and
`--runtime-fixture`, then select them with `OCTRA_CIRCLE_REGISTRY_WASM` and
`OCTRA_CIRCLE_REGISTRY_FIXTURE`. The historical tracked Circle fixture is retained;
it does not describe the current workspace lockfile.

Appending every security test to the current production AML initially collided
with the adopted compiler's fixed function/control label namespace. The harness
now compiles each test separately with every production method and shared helper.
The compiler and VM are unchanged. Rust requires the exact declared method set,
no duplicate cases and every source-declared refusal reason, then compares complete
bytecode, state, effort, events and transfer transcripts with the native output.
The failed native attempt and initial combined results are retained.

All 14 compiled payment AML tests pass, including refusal one millisecond before
operator unlock and successful withdrawal at exactly seven days. The deadline
starts at the first request; retries cannot reset it. New paid admission stops
immediately. Payer exit remains 24 hours and protocol commission remains zero.
The unchanged 19-theorem Lean payment model builds; it is an abstract state model,
without a compiler or VM refinement proof.

The public observer was not restarted or changed and still uses the prior
`f69473b` image. This candidate is not installed there or qualified for Mainnet.
Native stalled-voter realignment, actual legacy IrminPack repair, sustained public
sync and Circle delivery, stock Tailscale payment binding, bounded portal
onboarding, DNS/TLS and the macOS paid route guard remain separate gates.
