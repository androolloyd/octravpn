# Core parity implementation review — 2026-10-17

This reviews the active implementation batch against lite_node
`7f9be4489870645cfcc95439638cde40f5da9f50`. The workspace base is
`4d6b57acbc8168c50b03f0815b5a9cd2309fa35e`. The
[qualification record](core-parity.json) binds results to source and dependency
snapshots rather than attributing them to that older base commit. This is local
qualification, with no mainnet readiness claim.

The [31-entry census](core-parity-census.json)
keeps the historical partial labels and unchanged native source hashes. Its
current descriptions were checked against production callers, and its current
Rust and evidence paths exist. A mapping or an existing test file is not proof
of parity. Both full-parity flags remain false. The historical missing
`consensus_host.rs` and `network_sessions.rs` planned names are not current
evidence; the cited tests use their actual paths.

## Implemented boundaries

| Boundary | Concrete implementation | Regression entry points |
| --- | --- | --- |
| Consensus driver | Generation-scoped frame identity; native past-round window/cursor; jump cleanup and retry; authenticated signer versus transport-sender blame; unknown-member handling; vote-evidence age and bounded signing-slot retention | [Driver policy](../../../../crates/octra-node-protocol/tests/driver_round_recovery_parity.rs), [signed TCP recovery](../../../../crates/octra-node-runtime/tests/live_consensus/round_recovery.rs) |
| Proposal acquisition | Explicit retained raw-bundle `local()` lookup before remote-only `query()`; complete Pending transaction lookup; local receipt capture; remote fallback after local failure. Reuse still checks candidate freshness, expected transaction hashes/order, proofs, receipts, state root and txid | [Stateful local bundles](../../../../crates/octra-node/tests/services/local_bundles.rs), [bundle queries](../../../../crates/octra-node-runtime/tests/bundle_queries.rs) |
| Per-item proof reuse | Root, purpose, epoch and transaction key plus complete immutable proof-policy binding; FIFO/count and 32MiB limits; Ready/Invalid retention; coalescing; owner-ticket cancellation; old-root work cannot repopulate a replacement scope | [Cache lifecycle](../../../../crates/octra-node-runtime/src/consensus_preverify_cache/tests.rs), [native cache fixture comparison](../../../../crates/octra-node-runtime/src/consensus_preverify_cache/tests/parity.rs) |
| Public transaction reuse | Separate 1024-entry/32MiB verified transaction cache; only complete locally admitted proposal transactions are shared. Gossip reads Pending first, then shared bytes, without cloning unrelated pending transactions; lookup failures discard reply effects | [Shared cache](../../../../crates/octra-node-runtime/src/consensus_preverify_cache/shared.rs), [gossip](../../../../crates/octra-node/src/rpc/gossip_tests.rs) |
| Raw proposal retention | Captured native `OCTRA_BUNDLE_CACHE_CAP`: default 4096, accepted startup range 64–65536. First insertion determines FIFO age; lookup and exact retry do not refresh it. Empty bundles count; epoch pruning removes queue records before reinsertion | [Raw-cache stateful regressions](../../../../crates/octra-node/src/peers/raw_cache.rs) |
| Private and VM cryptography | Immutable key/cipher images in the parent; decode, serialization, arithmetic and proof work in the shared owned child-process service. Deterministic rejection remains distinct from cancellation, timeout, RSS/protocol failure and unavailability | [Packaged private vectors](../../../../crates/octra-node-runtime/tests/private_isolation.rs), [process failure cases](../../../../crates/octra-node-runtime/tests/crypto_process.rs) |
| Crypto admission | Independent native lanes use the same process runner: FHE actor with one active task; PVAC capacity 1/2, Required queue 128, Speculative queue 6, required burst 4. BFT proofs queue Required; prepared Circle and synchronous OCTB proofs try Speculative; asynchronous OCTB uses the FHE actor. Single speculative range verification uses the same proof channel | [Native scheduler traces](../../../../crates/octra-node-runtime/tests/compute_parity.rs), [real contention](../../../../crates/octra-node-runtime/tests/private_admission.rs) |
| Legacy fork staging | `stage_if_proven` owns the stopped native-store lease, captures authority/origin/source facts, acquires fresh signed peer roots, applies native current-root refusal and ahead/target rules, then asks the pinned backend to recheck the source token, journal, suffix, tags, boundaries and finality before staging | [Signed-peer staging](../../../../crates/octra-node/tests/legacy_stage.rs), [physical qualification driver](../../../../scripts/node-port/legacy-repair-qualify.py) |
| Account summaries | A bounded validated aggregate is reused only for the exact account-subtree commitment and kind; no retained complete ledger or decoded cipher objects. Changed roots require a full validated cold load | [Summary cache](../../../../crates/octra-node-runtime/src/account_summary.rs), [targeted account reads](../../../../crates/octra-node/src/rpc/account_tests.rs) |
| Epoch metadata | Atomic canonical epoch tags, real native Irmin labels, startup reconciliation and bounded pruning; SQLite reports its own storage capabilities | [Epoch tags](../../../../crates/octra-node-runtime/src/canonical/epoch_tags.rs), [native reference](../../../../scripts/node-port/epoch-tags-fixtures.py) |
| Mesh relay admission | The pinned Headscale DERP service checks current membership before every frame and keepalive, and pair ACL before each relayed packet. Canonical suspension or revocation removes permission immediately | [Native DERP](../../../../crates/octravpn-node/src/native_derp.rs), [canonical admission](../../../../crates/octra-node/src/mesh.rs) |

Cache hits return reusable work or public bytes. Fresh preparation and output
gates remain outside the cache: a retained transaction is not queue admission,
a retained proof result is not a current proposal, and a raw bundle is not
authenticated execution. Invalid proof outcomes may be retained under the exact
binding; operational failures are forgotten. A cancelled waiter does not cancel
the protected shared computation, and a stale owner cannot erase or complete a
new ticket.

The new native generators compile the unchanged adopted implementations rather
than reproducing their verdicts in Python:
[driver](../../../../scripts/node-port/driver-round-recovery-fixtures.py),
[cache](../../../../scripts/node-port/consensus-preverify-cache-fixtures.py), and
[PVAC admission](../../../../scripts/node-port/pvac-admission-fixtures.py).
Their comparison tests bind the source pin, source hashes, oracle/runner bytes,
canonical input vectors and pinned builder
`sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95`.
The cache oracle supplies proof outcomes to exercise cache policy; it does not
qualify cryptography by itself. Generator availability and fixture presence
alone are not a candidate test result. The final record includes the actual
comparisons and generated-source bindings.

## Host and storage adaptations

Modern canonical persistence uses authenticated SQL history, object storage and
an atomic ExEx outbox. It preserves native commitments and verifies retained
finality; it does not reproduce Irmin pack files or OCaml heap layout. The real
legacy Irmin adapter remains a separately pinned native executable. The new
staging command applies peer-selection policy to a stopped native-format store;
it stages a plan and requires restart. Ordered finishing remains a separate
operation. Neither operation permits the modern service to rewind authenticated
canonical history or rewrite signing records.

Rust owns immutable transaction strings and key/cipher images through normal
ownership. It does not emulate weak-string GC identity, exact OCaml heap-byte
estimates or collection timing. The raw cache has the native entry limit and
no invented byte cap; native raw-byte accounting is diagnostic. It also keeps
the host's pre-existing rejection of conflicting contents under one proposal ID
and its release of obsolete raw epochs. Native permits raw replacement and
prunes a separate frozen table. Those are explicit host retention differences,
not claims of identical cache statistics.

Production launch requires an explicitly configured crypto worker. The normal
CLI supplies the trusted executable and captured resource limits, and the
executor installs invocation scopes around proof work, transaction execution,
Circle views and migration-status decoding. A configured scoped call fails
closed when the worker is unavailable; it does not retry cryptography locally.
Deadline, RSS, cancellation and child reaping belong to the shared service.
Circle parameter/key failures precede the verifier mutex; decoding remains
inside it, and only a prepared proof reaches speculative admission. OCTB async
verification releases its verifier lane before suspension.

Low-level local cryptographic APIs and a runtime constructed without a worker
remain useful component/embedding APIs. Their direct execution does not prove
that an application configured process isolation. Embedders must construct the
isolated runtime and retain scopes; the production launcher rejects an
unconfigured runtime. Tests of local primitives and tests of the actual
packaged-worker path therefore establish different boundaries.

## Qualification and corrections

The broad release workspace run completed with 2,563 passes, four failures and
12 intentional controlled-fixture/stress ignores. Its four failures were test
inputs: an obsolete assertion that counted even the new local lookup as a
remote request, a two-Circle transaction fixture exceeding the unchanged native
one-Circle compute budget, and the registry golden fixture's stale root lock
binding. The corrected complete Service and Circle targets pass all 33 tests.
The registry reference was freshly replayed in the pristine pinned native WASM
host before promotion; its source hashes were not edited to simulate a replay.
The unchanged HFHE component's 49 passes remain applicable under a separately
reverified 413-input source manifest. The resulting union is 2,616 passing
nonignored tests across 237 targets, not the sum of overlapping reruns.

The record also preserves the earlier actual authority bug found by the broad
run: proposal-bound rules deliberately have no finalized authority certificate.
Execution now uses the independently authenticated context authority while
retaining proposal root/policy binding. Finality authority checks remain intact.
Tests invalidate cached proof results when validator keys, order, weights or
proof policies change. Native startup raw-cache capacity now comes from captured
release settings, including the distinction between absence and a later process
environment change.

The Linux gate executes real canonical paid TCP/UDP/ICMP traffic through two
kernel endpoints and four validators. Separate actual Chrome tests cover signed
Circle applications, wallet review and publication-pinned gateway assets. Stock
Tailscale checks cover registration persistence, direct traffic, forced TLS DERP,
encrypted TSMP/ICMP and live ACL denial/restoration. They use a standalone
self-hosted mesh fixture; they do not qualify paid stock-client onboarding,
system DNS, public `octra.to` TLS or portal funding. The gateway renderer uses
controlled HTTPS-origin CDP transport, not a public TLS deployment.

The source-applicability audit verifies no production Rust, Cargo or local
dependency changes after the broad workspace and Linux runs. Later differences
are enumerated CI, test-reference, test-fixture and interop-harness changes, and
the affected tests are rerun. Failed/interrupted runs remain failed in evidence.
The strict lint gate uses the optimized production profile; no native deadlines
were relaxed to accommodate debug or coverage instrumentation. Instrumented
coverage itself was not qualified by this batch.

The public observer was not modified or restarted by this qualification batch;
its prior retained history cannot qualify these new paths. Public sustained
catch-up, current release adoption and restart at production state size remain
separate operational gates.

Finite fixtures and controlled signed TCP/process tests do not establish every
asynchronous crash/cancellation schedule, arbitrary public catch-up behavior,
every retained/active VM and HFHE profile combination, cross-architecture
equality, performance at production load, or secret side-channel resistance.
These require their own evidence; source mappings do not close them.

The [active HFHE census](hfhe-active-census.json)
also separates active node behavior from whole-library experimental APIs. Full
hidden carriers, native reset certificates and reusable hidden evaluation are
still absent Rust library entry points. The inspected C/OCaml interfaces and
lite-node callers do not reach those exact APIs, and released Recrypt
transactions are disabled by the adopted native policy. This review does not
claim full HFHE library parity or enable a native-disabled transaction.
