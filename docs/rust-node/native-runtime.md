# Native execution adoption

The node port adopts lite_node `7f9be4489870645cfcc95439638cde40f5da9f50`.
Full node parity remains incomplete. This revision changes installer/upgrade
tooling only; all 1,158 inventoried runtime sources match the previous adopted
revision. Older fixtures retain their original generating commit; the source
inventory checks equivalence against both revisions.

`octra-node-runtime` uses the existing Rust Circle WASM engine through a safe
slice API and explicit HFHE backend. Reply ownership retains the engine's
memory lease. The engine's default native regression suite passes all 256
tests; nine full-output registry cases match through the Rust API. That checks
the execution boundary, not canonical state commits or finality.

`octra-pvac` directly links the adopted PVAC cryptographic implementation.
Rust owns thread-confined key/cipher handles; the bridge catches C++ exceptions
and uses the native allocator for returned buffers. Imports, arithmetic and
commitments pass functional checks. Proof verification and the node's isolated
worker policy remain separate integration work.

The cached ciphertext-add benchmark alternates nine C++ and Rust samples of
2,000 calls each, including allocation/release. On this machine the medians
are 6.094 µs in C++ and 6.086 µs through Rust (ratio 0.9988). The distributions
overlap; this does not establish a speedup. It shows no measurable call-boundary
penalty for this workload. Key loading, serialization, proofs, worker IPC and
full node throughput are not covered. Evidence:
`out/native-pvac-boundary-benchmark-20261012.json`.

Adopted source hashes and the small host API patch are checked by:

```sh
python3 scripts/node-port/check-native-sources.py --upstream /path/to/lite_node
```

The latest BSD PVAC tree is separate from the older GPL sidecar. No source or
license from that sidecar was replaced in this step. Cryptographic algorithms,
transaction formats and consensus activation were not changed.

The Circle host port now decodes native method frames, method descriptors,
HFHE transcript commitments and complete execution results. `execute_effects`
returns typed storage, events, spawns, public/encrypted assets and compute trace
fields, preserving operational unavailability. Native null-storage replies retain
the pre-call state. The runtime also enforces the native 16 MiB non-session input
limit before parsing. These are execution boundaries; authenticating context,
building native inputs and authorizing/applying effects still belong to the host.

The adopted OCaml helpers match 1,343 codec, manifest, transcript and result cases.
The same oracle additionally qualifies 11,045 default Base64 inputs against the
installed OCaml base64 3.5.2 implementation, including exhaustive short padding
patterns and all byte values in representative positions. This found and fixed a
Rust port mismatch: native accepts some full excess-padding groups that the previous
Rust helper rejected. Error precedence and trailing-bit behavior now match too;
the shared transaction/state decoder uses the corrected implementation. Native
source and dependency hashes accompany `out/circle-call-native-20261013-v3.json`.

`octra-hfhe` is the gated pure Rust replacement. Its field, RNG, keys,
compression, retained/active PRFs, ciphertext wire formats, seeded encryption,
linear/product arithmetic, commitments and decryption policies match 8,857
native fixture cases. Four pipelines compare complete bytes through encryption,
arithmetic, UBK permutation and decryption. The standard full-size public key
matches hashes over every raw and compressed byte; small key fixtures and
ciphertexts compare complete bytes directly. Readers preserve v1–v5 defaults
and native refusal precedence. Secret-key output reserves its final allocation
and wipes on drop; derived AES keys borrow secret inputs and use protected
buffers.

Noise-budget qualification records compiler flags and target-specific results.
Of 326 boundary inputs, 27 yield different budgets between the native ARM and
translated x86 macOS builds. Rust matches the corresponding build's floating
contraction behavior; host-generated CI fixtures cover the runner's own libm.
This does not establish public-chain reachability or cross-platform consensus
equivalence for those nonstandard parameters.

Proof foundations include native Prior/Wide scalar arithmetic, transcripts,
generators, inner-product proofs, R1CS, and the native proof gadgets. Zero and
bound proof qualification includes 11 complete proofs, including an 84,833-gate
key-bound case; four aggregate range proofs also match. The deterministic entropy
stream compares complete proof bytes, draw consumption and post-call transcripts.
Standalone zero proofs preserve the raw OCaml FFI encoding and its trailing-byte
acceptance; zero/range envelopes have separate native-qualified decoders.

Randomized and scoped encryption match 90 native cases. Legacy rebalancing/reset
matches 130 cases; reset resource profiles and hidden coefficient/chosen-statement
policy match 488 more. Composable commitments match 234 cases, and reusable
key generation matches 90 complete encrypted-key and admission cases. Eight public
recryption equality proofs and seeded bundles match both circuit profiles, including
complete bytes, entropy consumption, acceptance and mutation checks. The pinned
native aggregate range verifier always returns
false. Ordinary legacy range construction exceeds the native zero-proof base-layer
limit at its final linear-combination proof; the embedded bound-range path is
separately qualified. These native limitations are preserved.

Complete reset certificates, hidden-carrier arithmetic and reusable recryption,
backend profile/resource policy, isolated verification, side-channel review,
cross-architecture qualification and end-to-end performance remain open. Native
PVAC stays the oracle and available integration path; no backend switch or public
activation has occurred. Evidence: `out/pure-rust-hfhe-cipher-parity-20261013.json`
and `out/pure-rust-hfhe-proof-parity-20261013.json`.

The protocol port additionally has native transaction identity/signing bytes,
envelope checks and loaded-account ledger transitions with nested journals.
The authenticated transport covers OCE1 frames, handshake/profile signatures,
message limits and connection lifecycle tests. These are tested components;
complete transaction admission, state storage, consensus and sync are still
being implemented.

ExEx now has a native retained-history recovery adapter. Real Irmin/chaindata
fixtures prove export after durable HEAD but before journal completion, atomic
Rust import and consumer restart. Concurrent native writers, unrecovered
auxiliary receipts and pruned anchors refuse. This is a trusted local recovery
boundary; it does not authenticate network finality.

The new Rust canonical store retains native Irmin commitments while using
SQLite as its local object/history container. Its 152 native oracle cases
include 7,556 tree-root comparisons, flat-node and commit preimages, 32-way
inodes, the 256-child stable-hash boundary, deep hash buckets and raw-byte
paths. Evidence records all 1,158 node source hashes and 293 dependency source
hashes (Irmin/Irmin-pack 3.11.0 and Repr 0.7.0).

Applied state and ExEx events publish in one FULL-synchronous WAL transaction.
Recovery tests kill a child process before and after commit, reject competing
stale writers and corrupt objects/outbox bindings, and resume an extension
without a commit notification. These establish storage atomicity and recovery.
The complete authenticated consensus/execution driver, native snapshot-file
interop, settlement-state VPN authority and combined node/tunnel sync tests
remain open; this is not a Mainnet qualification result.

The 2026-10-13 integration checkpoint consolidates the parallel work under one
owner. Protocol tests (including process-exclusive validator journals), runtime
tests, ExEx tests and strict Clippy pass together after reconciling the activation
parser API and regenerating the native Circle fixture for the current lockfile.
Validator-set relief, root-query cancellation and finality-query retry policies
now match 1,532 native recovery cases, including authenticated relief proofs,
stale query leases and integer boundaries. The asynchronous driver integration
remains open. Public recryption's full-proof
oracle and Rust test now pass all eight complete native cases.

`CanonicalAssets::capture` now supplies the HTTP browser directly from a verified
published Rust store snapshot. It binds the chain identity, genesis root, epoch,
folded root, Irmin ledger root and commit, and refuses a mismatched stored epoch.
Existing readers retain their original snapshot through speculative preparation,
commit and store restart. Public serving checks native publication/visibility
policy, encoding, body size and SHA-256 binding; sealed resources are refused.
The native oracle covers 965 raw-path, metadata, policy and Irmin lookup cases.
The snapshot tests cover old/new head isolation, percent decoding exactly once,
policy overrides, malformed content and resource limits.

The HTTP viewer resolves relative resources, directory index pages, query strings,
fragments and cross-Circle links within the same snapshot. Real Chromium testing
checks stylesheets/images, user-activated cross-Circle clicks, fragment forwarding,
script isolation and switching between retained snapshots. Evidence records the
browser version and tested source hashes in `out/circle-browser-chromium-20261013.json`.
Run it with `node scripts/node-port/test-circle-browser.mjs <report.json>`; the
runner uses a temporary browser profile and loopback fixture, then stops both.
`Browser::with_application` now enables the `OctraCircle.request` API used by the
pinned counter example: `wallet.info`, `wallet.balance`, `program.info`,
`program.view`, `program.call` and `tx.wait`. The default viewer remains passive. Executable
documents run in an opaque sandbox with no direct network, same-origin access,
forms, nested frames or top navigation. A MessageChannel connects only the intended
frame to the trusted shell; user-activated links stay within the captured snapshot.

The shell holds a random session credential outside the app. Server-side sessions
bind its loopback origin, Circle and snapshot. Calls create immutable intents and
require an explicit trusted dialog decision; the server consumes each review before
awaiting the host. Replay, concurrent approval, tampered context, oversized bodies,
expired reviews, closed sessions and failed submissions have refusal tests. Session
and request counts, host concurrency and timeouts are bounded. Reloading the app
revokes its session; late wallet read replies are refused after revocation.

The Chromium runner also accepts a pristine upstream checkout as its third argument:

```sh
node scripts/node-port/test-circle-browser.mjs out/circle-sdk-chromium.json /path/to/lite_node
```

It reads the counter site's exact Git blobs from the adopted commit and publishes
them in a temporary canonical store. `CanonicalApplications` now implements
`program.info` and public `program.view` against that exact immutable snapshot.
It binds code to the stored hash, decodes native stable records, loads declared
cross-Circle reads with native visibility and effort rules, and invokes the real
WASM engine. Epoch and anonymous caller come from the host. The node supplies the
epoch's activation profile; apps cannot choose it. Four execution workers remain
bounded even if an HTTP request is cancelled. Views never publish VM effects.

The native OCaml oracle qualifies 307 Circle state/public-read cases and 30 complete
counter view outcomes, including Active/Prior modes, bad input, write-in-view
refusal and declared/undeclared asset reads. Native source inventories, counter/SDK
source hashes and the exact WASM are recorded in `out/circle-state-native-20261013.json`
and `out/circle-view-native-20261013.json`. Restart tests preserve old/new code and
storage snapshots, reject mismatched context and check the committed ExEx cursor.

Standard WASM update execution now has a snapshot-bound Rust host. It reproduces
native storage loading, read/write effort, returned values, event costs and
speculative stable-root writes for 104 native counter cases. Execution and
storage-commit activation are independent host choices, matching upstream.
Applying an old call to a changed batch refuses without changing state. The
restart test now executes five real counter updates before publishing the epoch
and ExEx cursor through a QC signed by local fixture validators. This exercises
the publication boundary, not a live network consensus driver.

`finality::Publisher` authenticates native persisted QCs using independently
supplied local validator history. It binds the actual state and transaction index,
parsed transaction hashes, outcome partition, receipt root, previous root and
transaction high-water mark. Consensus receipts persist in the same SQLite
transaction as state, retained finality and ExEx. Restart audits every retained
certificate against local authority and stored commitments, refusing missing or
modified evidence. Tests cover forged/foreign/duplicate/insufficient signatures,
commitment mismatches, stale publication, dropped preparations, receipt storage
failure and restart reauthentication. Validator activation history, live proposal
policy and the asynchronous driver are still required.

Outcome encoding, normalization, confirmed/rejected reconstruction, charged
outcomes and rule-selected envelope checks match 1,705 unmodified native cases in
`out/transaction-outcome-native-20261013.json`. The finality boundary now uses the
outcome decoder; activation-specific envelope and preverification receipt policy
remain execution-host work. Malformed JSON diagnostic strings are not yet native
qualified and return operational unavailability rather than fabricated refusals.

Native qualification additionally covers 6,247 storage authorization/hash-table
cases and 823 storage loading, limit, cost and Irmin root cases. The complete
WASM receipt decoder now retains storage traversal order; its expanded native
fixture covers 12,388 cases. Historical uncharged storage reads preserve decode
failure precedence over blob rejection, and charged reads preserve native Irmin
contents-root behavior. Reports are `out/circle-storage-native-20261013.json`,
`out/circle-stable-native-20261013-v2.json`,
`out/circle-call-native-20261013-v3.json` and
`out/circle-update-native-20261013-v2.json`.

The ordinary Circle transaction host now matches 160 complete native sender-loop
cases: fees, nonces, positive value transfer, receipt bytes, failure retention and
storage/value rollback. The native report is
`out/circle-transaction-native-20261013.json`. Unsupported operations and unqualified
JSON diagnostic paths abort the entire execution attempt. The canonical integration
test admits five real signed calls, applies native staging fee rules, flushes account
state, commits their exact archives/receipts through an authenticated local QC, and
checks ExEx delivery and checkpoint recovery after restart.

`browser_wallet::Wallet` replaces the synthetic browser signing path with explicit
node and signer capabilities. Local policy binds the chain/genesis/Circle and caps
value/OU; preparation checks spendable balance and native parameter/fee constraints.
It serializes signing, verifies the native signature and requires the node to recheck
admission and the reviewed snapshot atomically. Keys never enter the app frame.
`tx.wait` exposes status only through the host's wallet/Circle-bound capability.

Chromium now exercises the upstream site's approved native signed transaction,
actual WASM counter increment, fee debit, quorum-signed canonical publication,
durable ExEx transaction/receipt and committed status. It also checks approval/
decline, forged approval refusal, isolation, reload revocation, retained snapshot
reads and cross-Circle navigation. Evidence:
`out/signed-circle-footer-chromium-20261013-v2.json`. This uses public development
keys and a local funded genesis fixture; native fee distribution runs, but a peer
consensus driver does not. The production node still needs to implement the wallet's
admission, pending nonce and status capability.

HFHE contexts, nested calls, spawn/asset effects, large-input session transport,
private views/assets and OCTB execution remain unavailable where their hosts are
missing. Full epoch activation/preverification handling, node/client portal
wiring and a combined authenticated consensus network with funded VPN traffic,
browser execution, sync and restart remain unfinished. These local checks do not
establish full node parity or Mainnet readiness.

The epoch footer now matches native reward/emission application, including weighted
rounding, reward-account key precedence, zero-reward behavior, emission guard and
activation metadata. Both account and tree journals roll back on failure; state
roots before and after account flush match 388 native cases. Reward planning and
security-curve binding match 961 additional cases. Reports:
`out/epoch-footer-native-20261013.json` and `out/epoch-rewards-native-20261013.json`.
The signed browser path now applies the footer, preserving total public supply
when distributing fees under its explicitly inactive emission profile. Full policy
activation and reward-source selection still require authenticated node history.

The peer transport now includes full-duplex connection ownership and a managed
swarm: signed discovery, validator/observer limits, deterministic duplicate
selection, temporary bans, profile offers/switches, reconnects and shutdown.
Native policy comparisons cover 761 peer-record/guard cases and 832 upgrade/swarm
cases. Three-node TCP tests exercise discovery, delivery, observer limits, ban
retention, simultaneous dialing and restart. A live unmodified OCaml swarm also
completes HELLO/ACK/FINISH, signed discovery/profile exchange, ping/pong and
transaction inventory/request framing with Rust. Evidence:
`out/swarm-native-interop-20261013-v3.json`. This is a localhost development-key
transport qualification, not public-network sync or consensus execution.

Transaction gossip codecs and request planning match 1,238 native cases. The
bounded retry cache and per-peer quotas match 158 traces, including backwards
and nonfinite clocks; timestamps are compared by their exact floating-point
bits. The receiver matches 219 native signed-transaction traces through envelope
normalization, admission, duplicate suppression, legacy framing and queue effects.
Reports: `out/tx-gossip-native-20261013.json`,
`out/gossip-guard-native-20261013-v2.json`, and
`out/p2p-transaction-native-20261013.json`. Its queue is an explicit host boundary:
the native staging backend is qualified below, while the full consensus/resource message dispatcher still needs integration.

The native pending queue is now implemented in `staging/`: ordered indexes,
exact fee-rate replacement, capacity eviction and dependent nonce removal,
pending balance/nonce accounting, epoch selection, preview refusals/holds,
expiry and drop records. It matches 209 native traces (7,878 steps). Native
resource lanes match 851 cases across every operation, including declared versus
execution OU and exact serialized byte limits. The shared RPC/peer intake matches
178 native traces (1,351 steps), including normalization, profile/activation
checks, preverification refusal and replacement side effects. A Rust worker-panic
regression checks cleanup without restoring previously evicted transactions.
Reports: `out/staging-native-20261013.json`,
`out/resource-lanes-native-20261013.json`, and
`out/staging-intake-native-20261013.json`.

The staging and intake oracles inject only their wall clocks into ephemeral
container copies after checking all pinned runtime sources. Reports include the
original, injected prefix and compiled source hashes. Expiry output is compared
by hash because native hash-table iteration is not canonical. Equal-time eviction
from the bounded diagnostic drop cache uses Rust hash ordering and is not claimed
to reproduce OCaml hash-table iteration. Consensus transaction selection retains
native fee, sender, nonce and hash ordering.

`p2p_transaction::Staging` connects authenticated gossip to this same queue and
canonical account view; effects target the originating connection and broadcasts
exclude it. `peer_staging` runs two authenticated TCP swarms through inventory,
request, signed transaction delivery, nonce-gap selection, replacement, signature
refusal and pending-balance refusal. It stops at block selection. The browser
qualification host now uses the same native intake and selection before WASM
execution and quorum-certified canonical publication. These hosts still use
explicit development fixtures; they do not supply the missing live consensus
scheduler, proof workers, persistent pending recovery or funded VPN authority.

A native off-chain admission bug was reproduced while testing head changes:
start with balance 5000, stage two transactions costing 1001 each, commit the
first with canonical balance 3999, and remove it from staging. The native cache
refunds that reservation and accepts another transaction costing 3999, even though
the remaining transaction still reserves 1001. This reproduces queue over-admission;
it does not demonstrate a consensus execution or fund-transfer bypass. Evidence:
`out/staging-rebase-native-20261013.json`.

Live Rust intake now refreshes the sender's remaining reservations against the
canonical balance before adding a transaction. The low-level queue still retains
the pinned transition for differential comparison. The matching upstream fix is
reviewable in `scripts/node-port/staging-reservations.patch` and its guarded
applicator, `staging-reservations.py`. An offline build of the exact native patch
rejects the reproducer with `insufficient balance (including pending)`:
`out/staging-rebase-fixed-native-20261013.json`. Rust regression checks cover both
canonical debits and credits. Transaction execution, wire formats, consensus and
fee schedules are unchanged by this correction. The pristine oracle checkout is
unchanged; the upstream patch has not been published or deployed.

The completed staging integration checkpoint is
`out/staging-integration-checkpoint-20261013.json`: 123 tests across 58 suites,
zero failures and three explicitly ignored integrations. Source hashes were
unchanged throughout that combined run. The current staged Chromium report is
`out/staged-circle-chromium-20261013-v2.json`; its source hashes were also checked
before and after the run. Live peer propagation passed separately after the
reservation correction. Shared preverification workers and the full consensus
driver remain the next integration boundaries.

The shared preverification pool now follows the native scheduler across 202
controlled traces (10,965 steps), including deduplication, cancellation,
required-work displacement, stale-source retries, rejection rebinding and
concurrent batch collection after cache eviction. The shared compute pool follows
164 native traces (51,236 steps) covering bounded queues, required-work bursts,
speculative fairness and failure/cancellation accounting. Additional Rust tests
cover concurrent callers, shutdown during binding, worker teardown and shared
capacity across async and blocking workers. A cancelled caller cannot release a
running CPU job's permit before the job stops. These tests use controlled workers;
the private-ledger/PVAC/HFHE adapters remain unimplemented integration work.
Evidence: `out/preverify-native-20261013.json` and
`out/compute-native-20261013.json`. Neither oracle changes native source.

Native proof receipt parsing, validation, canonical bytes and commitment hashes
match 1,610 cases in `out/preverify-receipt-native-20261013.json`. Epoch receipt
admission matches 544 cases in `out/preverify-commit-native-20261013-v2.json`,
including duplicate/orphan receipts, wrong transaction bindings, lane budgets,
crypto activation and native error bytes. Canonical publication and restart audit
now require receipt rules from trusted historical authority and check the native
receipt gate after outcome partitioning. Positive QC fixtures now carry real
native rejection records instead of opaque placeholder receipts. A separate
publication regression verifies that even a correctly signed QC cannot bypass
missing receipts, bad commitments, cost mismatches or missing rule history, and
that refusal leaves canonical state and ExEx unchanged. This gate does not itself
execute cryptographic proofs or bind their source to the live private ledger.
The 2026-10-13 preverification integration checkpoint passed 134 tests across 62
suites (three ignored), with unchanged source hashes. The receipt-gated real
Chromium Circle flow also passed all 16 application checks. Evidence is in
`out/preverification-integration-checkpoint-20261013-v3.json` and
`out/preverified-circle-chromium-20261013.json`. These are local boundary and
browser qualifications; the consensus driver and funded VPN flow remain open.


`octra-node` now coordinates the canonical writer, Circle browser, embedded VPN
and ExEx manager. Startup audits retained finality but keeps admission suspended
until the execution/sync host explicitly resumes it. Publication revokes the old
snapshot before committing, then wakes ExEx and creates the new browser scope.
A failed view refresh leaves an already committed epoch successful and services
suspended. Newer catch-up requests cannot be undone by an older resume. Late
private wallet reads are withheld after revocation; wallet submission still
requires atomic state checks in the transaction host.

Local integration uses actual native counter WASM, development-signed quorum
certificates, HTTP, WireGuard, durable ExEx checkpoints and restart. The VPN
settlement reader in that test is explicitly synthetic. The production adapter
must authenticate the pinned application's real code, escrow, operator and
opening transaction at the supplied committed tree. This crate is a service
coordinator library, not yet a complete validator executable. The full consensus
driver, private-ledger/proof-worker integration, executed money application,
Internet return traffic and multi-hop VPN transport remain unqualified.

The coordinator checkpoint (`out/node-services-integration-checkpoint-20261013.json`)
passed 138 tests across 64 suites, with three ignored. Its 1,437 source hashes
include the used sibling checkouts and remained unchanged during the run. Strict
Clippy passed for the five node/browser/ExEx crates. The registry's nine native
host outputs also remain unchanged after the dependency graph refresh.

Consensus scheduling now includes the native output actor, serialized proposal
gate, worker slot, round-sync history and asynchronous proposal relay. The relay
uses the authenticated swarm, bounds pending broadcasts, enforces native expiry
and deduplication, and cancels stale work on generation changes or shutdown.
Worker tasks do not keep their owner alive; dropping the last relay handle
cancels pending I/O. Stale completions cannot change a replacement queue.

`out/driver-work-native-20261013-v3.json` qualifies 754 native traces and 37,458
transitions, including 82 proposal-gate traces and 98 asynchronous relay traces.
The oracle injects only the round-pool wall clock; every upstream runtime file
is checked against the adopted source map. A three-peer authenticated TCP test
also covers exact relay payloads, origin exclusion, deduplication, generation
advance and close/open. That test deliberately treats proposal payloads as
opaque; it does not execute consensus. The full consensus driver remains open.

The combined relay checkpoint (`out/relay-integration-checkpoint-20261013.json`)
passed 144 tests across 68 suites, with three ignored and no source changes
during the run. Strict Clippy passed for the changed node crates. Run
`scripts/node-port/qualification-checkpoint.py` with fresh `--out` and `--log`
paths to repeat the combined local qualification; it also detects newly added
or deleted source files while the tests run.

The relief journal now preserves native record bytes, atomic plan publication,
conflict handling, retention and restart semantics. Its 198 unmodified-native
traces cover 4,101 operations (`out/relief-log-native-20261013-v2.json`). Only OS
and malformed JSON parser diagnostic text is normalized in that comparison.
`JournalOwner` retains the relief journal under the same exclusive ownership as
votes and round-sync witnesses. Additional tests cover conflicting writers,
reopening and reauthentication of stored witness signatures. The journal itself
stores decisions; the consensus host must run `relief::Plan` checks before
keeping a mark and before restoring its validator set.

The local vote guard follows `C_driver` startup-floor checks, authenticated vote
restoration, round advancement, readiness diagnostics and precommit persistence
ordering. It checks conflicts before invoking the host persistence callback,
then fsyncs the local vote before publishing it to the authenticated swarm.
164 unmodified-native driver traces cover 2,658 operations in
`out/driver-votes-native-20261013.json`. Separate tests exercise cancellation
during the callback, restart and actual TCP broadcast ordering. Failed
persistence and conflicting votes produce no peer message.

The host callback now validates cached transaction/receipt bundles and proposal
bindings, synchronizes a changed bundle through the execution host, and fsyncs
the native pending-precommit WAL before the vote guard persists or broadcasts.
Pending records share the exclusive validator journal owner; new files are mode
0600 and staged symlinks are refused. The native serializer rejects non-finite
write timestamps. 219 unmodified-native WAL cases cover byte encodings, legacy
inputs, conflicting writes, malformed files, size limits, deletion and restart
(`out/pending-log-native-20261013.json`).

Authenticated recovery verifies both signatures against the supplied historical
validator set and rechecks bundle commitments, receipt bindings and envelope
rules. 381 unmodified-native cases qualify recovery, finalized-bundle admission
and host callback ordering (`out/pending-recovery-native-20261013.json`). The
startup coordinator also matches 438 native traces for unreadable stores,
non-contiguous records, latest-round lock restoration, legacy peer agreement,
catch-up with no head advance, and deletion only after canonical progress
(`out/pending-reconciliation-native-20261013.json`). Parser diagnostic text is
normalized separately from acceptance. Native source hashes remain unmodified.

The authenticated TCP test now uses the real pending WAL callback, then the vote
journal, then peer publication. Restart tests reopen the files, authenticate the
bundle, restore the engine lock and advance beyond the saved vote's round. They
also exercise a crash boundary after pending fsync but before the vote write.
Execution synchronization and peer catch-up are controlled host callbacks in
these tests; this is not a complete validator or full-chain recovery test.
Historical rule/set selection, the complete driver loop and the remaining
execution adapters still need integration. Speculative recovery data never
enters canonical state or ExEx.

The pending recovery checkpoint
(`out/pending-recovery-integration-checkpoint-20261013.json`) passed 156 tests
across 73 suites, with three ignored and no source changes during the run.
This covers the combined local node, browser, VPN admission, ExEx and protocol
boundaries; full-node and funded-VPN end-to-end qualification remain false.

The signed epoch-root query service now uses the authenticated swarm and native
0x34/0x35 messages. It admits replies only from the active validator set with
valid signatures, records one reply per validator, and keeps concurrent readers
independent when one is cancelled. Source agreement and consensus quorum use
the native historical weight rules; 720 unmodified-driver cases qualify those
decisions (`out/epoch-roots-native-20261013.json`).

Four-peer TCP tests cover concurrent queries, cancellation, deduplication,
missing roots, forged signatures and the request for missing finality. They also
reopen a legacy pending journal and run startup recovery through real network
queries. The journal stays intact when the catch-up callback makes no progress,
and is removed only after that callback advances the head. The callback itself
is controlled: authenticated live-chain catch-up and finality acquisition are
still responsibilities of the incomplete driver.

The focused live recovery checkpoint
(`out/live-recovery-checkpoint-20261013.json`) passed seven tests across four
suites with unchanged source hashes. Strict Clippy also passed for runtime and
node targets. This newer checkpoint covers the signed query service added after
the 156-test combined checkpoint; it does not replace the full-node gates.

Signed bundle fetching now uses native 0x36/0x37 frames, validator-first peer
rotation and 2/4/rest query waves. 192 native plans qualify ordering and rotation;
549 additional native cases qualify proposal admission, including error order
and the distinction between response hashes and authenticated proposal hashes.
Validated bundles normalize binary wire hashes to the hexadecimal cache/journal
representation. Four-peer TCP tests cover forgery, invalid bodies, duplicate
responders, fallback, missing bundles, cancellation and recovered journal data.

The upstream query lifecycle has two reproducible bugs: cancellation/validation
exceptions retain a reply slot, and overlapping same-proposal readers overwrite
or erase each other's slot. Rust owns each slot with a cancellation guard and
serializes readers of the same proposal. An isolated OCaml candidate matches
that ownership behavior without changing wire messages or consensus rules:

- Baseline: `out/bundle-query-lifecycle-native-20261013-v2.json`.
- Candidate: `out/bundle-query-lifecycle-fixed-20261013.json`.
- Reviewable patch: `scripts/node-port/bundle-query-ownership.patch`.

The pristine upstream checkout is unchanged. The candidate report records its
source replacements separately. Rust additionally tests panic cleanup and
cancelled waiters; unrelated proposal IDs remain independent.

`Node::import_finalized` connects certificate authentication, bundle fetching,
staged execution and canonical publication. It verifies the historical quorum
certificate and consecutive parent before querying peers. The execution host
selects historical rules and returns staged effects; the publisher checks their
roots, transaction identities and receipts before exposing them. Missing data,
cancellation while fetching, unavailable execution and mismatched execution roots leave
the previous state and service capabilities intact. Empty bundles bypass peer
queries; a signed certificate for the wrong parent is refused.

Public WASM execution now captures and consumes Circle preverification receipts.
The binding includes snapshot identity, Circle/code/stable roots, public reads,
execution context and the HFHE transcript. 104 cases from the unmodified OCaml
Circle host qualify capture bindings and execution results. Rust replay tests
alter each binding field and prove complete ledger/state rollback on refusal.
Private capability contexts, full preview/rule-fold orchestration and shared
cryptographic worker integration remain separate work.

The local node integration test now imports its Circle updates through signed
TCP bundle queries, reexecutes them against the canonical parent, verifies their
captured receipts, publishes atomically, advances scoped oct:// browser reads,
revokes old VPN permissions and resumes ExEx from durable checkpoints after
restart. The test still uses development-signed certificates and synthetic VPN
escrow. It does not qualify a live validator driver, general private execution,
funded VPN settlement, multihop/return traffic or public-chain synchronization.
Evidence: `out/query-peers-native-20261013.json`,
`out/proposal-bundles-native-20261013.json`, and
`out/circle-bindings-native-20261013.json`.

The combined peer-import checkpoint
(`out/peer-import-integration-checkpoint-20261013.json`) passed 166 tests across
76 suites, with three ignored and no source changes during the run. It includes
node, protocol, runtime, ExEx and browser targets; full-node and funded-VPN
qualification remain false. Runtime/node strict Clippy passed. This checkpoint
precedes the subsequent finality-query service work.

The finality-query service now serves native v1/v2 catch-up replies and acquires
certificates through authenticated peers. Missing-finality and explicit-proof
windows remain independent. Peer selection and request IDs match 320 native
cases, including raw-byte addresses; retries preserve upstream's three-attempt
and rest policy. Signature, chain, membership and request-window checks precede
delivery. Legacy complete proofs can deliver a certificate without treating
unsigned status/continuation fields as authenticated peer state. Obsolete or
closed windows cannot deliver late certificates.

Delivery queues a certificate for the driver's ordinary finality admission;
it never commits state from the response handler. The combined services test
now obtains both certificates and bundles over real signed TCP messages. A
peer-supplied certificate with an invalid quorum signature is refused before
bundle fetching. Valid certificates continue through receipt-checked WASM
execution, canonical publication, browser/VPN scope changes and ExEx recovery.
Root hints, validator history and certificates originate from development
fixtures; complete catch-up range agreement and the live driver remain open.
Evidence: `out/finality-query-native-20261013.json`.

The finality-import checkpoint (`out/finality-import-checkpoint-20261013.json`)
passed all node/runtime targets: 79 tests in 34 suites, two ignored and no
source changes during the run. Log SHA-256:
`3461894a6c63ce36640fe2db0dafb8947958df857c8190ededfadf1038a1f4bd`.
This checkpoint precedes the consecutive recovery coordinator.

Consecutive proof recovery is now assembled in `octra-node/src/sync.rs`:
signed epoch-root discovery selects peers, historical QC and parent checks filter
proof candidates, signed bundle fetching supplies receipt-checked execution, and
publication advances one consecutive epoch at a time. Invalid certificates do
not mask later valid answers. Missing data returns the last committed head.
The driver selects the target and explicitly resumes browser/VPN admission after
catch-up; advertised peer heights never authorize a commit or resume.

Awaited proofs have bounded delivery, independent ownership and cancellation
cleanup. Cancelling or timing out a queued reader cannot erase the active
reader's window; an explicit driver proof survives cancellation even if its
native request ID collides with the old reader. The node serializes resume
against recovery, so an overlapping resume cannot expose an intermediate tree.

`out/consecutive-recovery-checkpoint-20261013-v2.json` passed 10 tests in three
suites with no ignored tests and unchanged captured sources. Strict node/runtime
Clippy passed. The tests cover three peer-imported Circle epochs, a missing
second bundle, restart from the first commit, cancelled recovery, refusal of a
wrong execution root, checkpointed ExEx delivery of only the remaining epochs,
the final HTTP Circle view, and unchanged admission when the target is already
reached. Root hints are now obtained through signed
network queries. Source history, historical validator/rule configuration and
certificates remain development fixtures; VPN escrow remains synthetic. This
qualifies individual-proof recovery, not native bulk range agreement, a full
validator driver, general private execution or funded VPN operation.

Canonical history now retains the execution footer's reward attribution in the
same SQLite transaction as the state, receipts, finality and ExEx outbox. A
proposal index supports direct bundle lookup. Export and restart validation
check the retained proposal binding, canonical reward encoding and native reward
attribution rules, in addition to the existing QC, state and receipt checks.
The upstream historical Prior behavior is preserved; stronger parent-participant
binding is applied only where the native rules require it.

Reward source conversion, standard activation, full-set attribution, weighted
parent participants, protocol resolution and finality binding match 720 cases
from unmodified native code. Evidence:
`out/reward-attribution-native-20261013-v3.json`. Historical epoch-log fallback
for records lacking reward metadata remains unported. Existing experimental
Rust databases without the new reward evidence fail closed; the implementation
does not guess missing attribution.

The node exposes read-only history for asynchronous peer root, range and bundle
queries. Ranges capture a committed prefix and use native 16-epoch and 4 MB
planning limits. The consecutive recovery integration now reopens the source
database and serves its retained records over the authenticated swarm, with the
fixture record and bundle maps empty. Both the source and recovering node are
restarted. Nine focused node/publication tests pass, including refusal of wrong
legacy reward attribution, injected persistence failure, dropped preparations,
missing or malformed reward evidence, altered proposal indexes, range boundaries,
ExEx checkpoint recovery and the final HTTP Circle view. Validator/rule
configuration, certificate production and VPN escrow remain test fixtures.

The combined canonical-history checkpoint
(`out/canonical-history-checkpoint-20261013.json`) passed all node, protocol,
runtime, ExEx and browser targets: 174 tests across 78 suites, three ignored,
no failures and unchanged captured sources. The log SHA-256 is
`ee8c7af045de08502f0fb086eb279506611467e839a5c4680ab3f854dc335651`.
Strict Clippy passed for node/runtime/protocol. This checkpoint precedes the
small executor-interface change to pass the complete authenticated finality
certificate, including its parent participants, instead of only its header.

The final execution-context interface is covered by
`out/canonical-history-context-checkpoint-20261013.json`: all five node tests
pass with unchanged captured sources, and node strict Clippy passes. Only
`octra-node/src/import.rs` and its service test changed after the broader
174-test checkpoint. The production executor can now inspect the authenticated
parent certificate; implementing the remaining operation hosts and validator
driver is still required.

### Native bulk ranges and canonical recovery (2026-10-13)

The Rust range selector matches 384 cases executed through the unmodified
native `C_driver.query_catchup_range` at the adopted `7f9be448` baseline.
`out/catchup-agreement-native-20261013.json` records all pinned source hashes,
the oracle and runner hashes, and an empty instrumentation map. The corpus
covers weighted/count-capped sets, historical count floors, conflicting full
ranges and shared prefixes, native hash-table tie order, rejected-source
memoization, scheduled activation limits and peer waves. Responses are injected
directly into the native response collection, bypassing authentication, so this
evidence qualifies selection separately from transport and certificate admission.

The existing seed-zero OCaml string table was extracted into `native_table::Table`
and reused by Circle storage and range selection. Storage traversal parity still
passes. Native selection chooses the strongest full group and longest prefix
before testing agreement; that ordering is preserved, including cases in which
a longer prefix prevents selection of a shorter agreed prefix.

`Finality::query_range` shares the signed v1/v2 catch-up handler with individual
proof queries while retaining independent ownership and responder deduplication.
It uses native validator-first rotation, range waves and activation caps.
Cancellation, timeout, queued-reader timeout and callback errors release only
the owning range. Legacy complete replies require their actual authenticated
source peer, and unsigned status/continuation fields are normalized. Single-proof
requests remain live when a range reader is cancelled. Native wire and consensus
rules are unchanged; query timeout also bounds queued Rust callers and host I/O.

`Node::catch_up_range` checks peer payload commitments and continuity, then
imports each record against the actual committed parent. Historical validator-set
hash, QC, transaction high-water mark, header metadata, reward binding and bundle
admission precede execution. Execution receives authenticated historical reward
attribution and must return the same canonical source. State, finality, receipts,
rewards and ExEx are published through the existing atomic boundary. Browser/VPN
admission stays suspended until explicit resume, including after failure or
cancellation. Complete records supply their own bundles without a second fetch.

The combined recovery test serves real database history from two authenticated
peers, stops at the available prefix, restarts both database-backed nodes, rejects
forged records before execution, refuses a corrupt execution result, cancels an
in-flight recovery, and finishes with only the remaining ExEx deliveries and the
expected HTTP Circle state. It also checks VPN permit revocation and exclusion
of browser views during recovery. Authority configuration, public-WASM execution
and VPN settlement are still fixtures. Full validator driving, the remaining
catch-up shell (target selection, HTTP fallback, snapshots and fork recovery),
private/AML operation hosts and funded bidirectional VPN operation remain open.

The combined checkpoint (`out/bulk-recovery-checkpoint-20261013.json`) passed
178 tests across 79 suites, with three ignored and no failures; captured sources
were unchanged. Log SHA-256:
`0c73e65d62640cc0c531fc9f34a468d15c6ea7e29151b79d34e213abae294b5e`.
It precedes the final allocation optimization in the range selector and query
reader, which shares immutable response payloads and borrows prefix records.

The final three-file allocation optimization passes the focused checkpoint
`out/bulk-recovery-borrowed-checkpoint-20261013.json`: 12 tests across the native
selector, authenticated finality/range transport and combined node services,
with no failures or ignored tests and unchanged captured sources. It includes
all 384 native selection comparisons. Log SHA-256:
`be0dda7ac5edadcf09f55450fbef3994239873931b6a8d555c04d97392f879f5`.
Strict Clippy passed for protocol/runtime/node after this optimization.

### Live validator driver and canonical publication (2026-10-13)

`octra-node-runtime::consensus_driver` now owns a live engine, authenticated peer
inbox, proposal worker, timers, vote guard and exclusive recovery journals.
Peer readers enqueue consensus messages without awaiting execution, allowing
bundle replies to arrive on the connection that supplied a proposal. The actor
checks signatures, membership, proposal envelopes and parent binding; handles
current/future votes, vote conflicts, finality, round sync and round-fetch
responses; and keeps speculative execution separate from canonical publication.
The default native startup wait, proposal-work grace, retry delays, local
round-sync persistence and epoch pacing are retained. Engine transition and
quorum algorithms are unchanged.

Outputs preserve the durability barriers: pending proposal/bundle data precedes
non-nil precommit persistence and broadcast; canonical publication precedes
finality acknowledgement, vote-floor advancement and next-height activation.
Failed publication leaves the certificate pending for an idempotent retry.
Generation changes cancel obsolete work. Shutdown cancels owned work and
suspends application services. Startup retains restored locks instead of
reinitializing the height.

`octra-node::consensus::Canonical` binds the publication interface to the
existing authenticated bundle importer, executor and canonical SQL transaction.
The transaction includes state, receipts, finality, reward attribution and ExEx.
A retry after an interrupted return verifies the certificate against retained
parent history and compares its proposal with the committed record, avoiding
re-execution and duplicate ExEx publication. Conflicting retries fail and
suspend serving. A failed local view refresh cannot turn a durable commit into
a failed canonical publication.

`tests/live_consensus.rs` exercises four authenticated Rust validators forming a
real engine QC, a transient builder failure, repeated publication failures with
an unchanged vote floor, fsynced precommit recovery before broadcast, a blocked
verifier with a responsive peer reader, cancellation, restored-lock startup,
and failed precommit durability. `octra-node/tests/services/live.rs` composes
four live engines with peer bundle fetching, executed public Circle WASM,
canonical databases, `oct://` opening through the HTTP bridge, VPN permit
revocation and ExEx. It checks unchanged state and ExEx on idempotent retries,
conflicting retry rejection, stop-time revocation, and retained state after
reopening the database. Development keys, activation authority and genesis
escrow are explicit fixtures.

This is a working local integration boundary, not full native driver parity or
mainnet readiness. Whole-driver native differential/interoperability runs,
production boot and proposal execution, live relief/resource activation,
autonomous catch-up and past-round/finality recovery, the remaining private/AML
operation hosts, funded bidirectional VPN traffic and the system client launch
flow still need implementation or qualification. Native pure-boundary corpora
and Rust loopback tests do not close those acceptance gates.

The broad checkpoint `out/live-driver-checkpoint-20261013.json` passed **183**
tests across 80 result groups, with three ignored and no failures; all captured
sources were unchanged. Its log SHA-256 is
`e0863dea171b4448c68ad1946a5dcad1cda48eefa44fb941d7f9f4f22ada8bb9`.
The ignored cases remain the dedicated native-peer interop launcher, browser
fixture launcher and child crash worker; their parent/specialized harnesses are
separate evidence, not silently counted as covered here.

Review then found and reproduced a busy loop: a pending proposal's expired
verification retry repeatedly woke the actor while failed canonical publication
was backing off. The publication deadline now takes precedence over work that
cannot be serviced until publication succeeds. Proposal-relay keys also include
epoch and round, matching native identity when a header is reproposed.
Only `consensus_driver/work.rs` and its live integration test changed after the
broad checkpoint. The final focused checkpoint
`out/live-driver-backoff-checkpoint-20261013.json` passed all **10** live-driver
and node-service tests with unchanged captured sources, no failures and no
ignored tests. Its log SHA-256 is
`c3a319e986d1086e88ec45f338e4ac83f700bd6593b4bb815481db36ab406131`.
Strict Clippy passes for protocol, runtime and node across all targets after
this correction. These checks do not change the outstanding acceptance gates
listed above.

## Validator stake execution and recovery (2026-10-13)

`octra-node-protocol::validator` now implements native bonded admission,
registry persistence, bond proof verification, readiness and exit records,
withdrawal eligibility, verified equivocation slashing, snapshot selection,
weighted/count quorum, weighted leader selection and admission policy.
Serialization preserves native field order, decimal strings, base64 and
first-key JSON lookup. Snapshot selection preserves incumbents before sorting
by bond, address and public key. Errors retain the native validation order.
Policy accepts explicit boot configuration; resolved exit rules are supplied
by the trusted epoch context. No upstream consensus rule is changed.

`octra-node-runtime::validator_transaction` applies bond, exit, withdrawal and
evidence transactions inside the existing coupled ledger/tree savepoints.
It charges native OU, moves principal through the native validator escrow,
burns slashed principal and updates the supply/retirement envelope. Manual
validator updates retain the native rejection. Missing rule context aborts
the whole execution attempt, while transaction refusals restore their own
savepoints without consuming the nonce. There is no added protocol fee.

The new evidence uses `native-oracle.py`, which checks all 1,158 adopted source
hashes and runs the unmodified modules offline in the existing builder:

- `validator-lifecycle.json`: **503 cases**, comprising 115 lifecycle traces
  with **3,995 operations**, 200 snapshot/quorum/leader cases, 104 registry
  decoding cases and 84 policy cases. Rust independently constructs the signed
  bond and vote proofs. Cases include top-ups, wrong proof bindings, exit and
  withdrawal boundaries, rebond/replay protection, corrupt records, duplicate
  fields, arbitrary byte strings and epoch overflow.
- `validator-transactions.json`: **91 sequences**, **367 execution rounds** and
  **2,441 transaction inputs** through real native `Epoch_exec`, sender ordering,
  ledger and Irmin savepoints. Rust compares completion, fees, complete account
  JSON, registry bytes, retired supply, spent nonces and exact Irmin roots.
  Native-generated proof-bearing transactions are execution inputs; outer
  signatures are fixture labels. Trusted fold results are injected on both sides.
- `bonded_stake_and_exex_survive_canonical_restart` publishes bond and exit state
  through the canonical storage API, checks no ExEx visibility before commit,
  drops an uncommitted preparation, reopens after each commit and checks exact
  history and accounts. Persisted nonces reject replay after restart. A withdrawal
  from recovered state is kept speculative and disappears on another reopen.
  This storage test does not substitute for finality authentication; it publishes
  consecutive bond/exit epochs and does not skip epochs to publish withdrawal.

This stake checkpoint did **not** complete production validator activation.
It left `Set_fold`, readiness reference/duty execution, the trusted rule graph,
production boot and proposal host open. The next checkpoint below implements
the duty/readiness boundary; production activation remains open.
The existing local consensus/VPN/browser tests and these native execution
comparisons remain distinct from a complete node or funded VPN acceptance run.

The broad checkpoint `out/validator-stake-checkpoint-20261013.json` passed
**186 tests in 82 result groups**, with three ignored harness cases and no
failures. Captured sources were unchanged; log SHA-256:
`fc4a7478db899251e15e0d82ebcfdc4b8e3d92f0180dc35e2b0beea91598b5f0`.
The same dedicated native-peer, browser and child-crash harness cases remain
ignored in this general invocation.

The final fixture explicitly observes a successful bond before a later sender's
fold failure and then verifies restoration of the whole attempt. Its native and
Rust observers agree on the completed transaction index. The prior inputs are
retained under `out/validator-stake-before-witness-20261013`; changes after the
broad checkpoint are limited to this stronger test/oracle/fixture, an exhaustive
test match for strict lint, and the execution module's attribution header.
Production logic is unchanged. Final focused evidence is
`out/validator-stake-final-checkpoint-20261013.json`: **3 tests passed**, no
failures or ignored tests, unchanged captured sources. Log SHA-256:
`269e12cb43062c27791808da94bf6511d19c6ebb8922a0fb2f70253695f59287`.
Strict Clippy passes for protocol and runtime across all targets. None of these
results closes the production activation or funded VPN gates above.

## Finalized duty and readiness execution (2026-10-13)

`validator::set_fold` implements native live/shadow membership, participation
windows, readiness pulses, proof challenges, seat locks, member pruning,
missed-epoch delays, finality references and exact persisted JSON. Sparse epoch
marks preserve defined native bitset results without allocating empty spans.
Duty proofs bind votes to the recorded finalized proposal and validator-set
hash. Parent certificates undergo signature and quorum checks; the caller still
owns canonical parent selection. Held advancement retains the same partial
state as native execution; repeated advancement does not apply duty twice.

`validator_transaction` now executes bonded and legacy readiness through the
existing sender loop and coupled ledger/tree savepoints. It checks current or
historical roots, finalized proposal delivery, chain/config claims, proof owner,
consensus key and participation before saving readiness. Native delayed pulse
credits and the 64-epoch rejoin rule are preserved. Both standard profiles first
mark the fixture candidate ready at epoch 66 after its first pulse at epoch 2.
Legacy metadata preserves native field order. Native OU remains the only fee.
`validator::update` supplies weighted pending-set construction and serialization
for subsequent activation integration.

The new offline corpora use unmodified adopted source and verify all 1,158
source hashes before running:

- `set-fold.json`: **433 native-result cases**: 155 state traces with **5,169
  operations**, 160 persisted-state decoder cases, 46 configurations and 72
  readiness claims. Rust independently signs parent commits and duty votes.
  Cap-boundary cases begin from explicit persisted state to avoid storing
  hundreds of redundant large intermediate states.
- One additional native exception reproducer queries participation at
  `2^63 - 1`: converting the bit index to OCaml's signed 63-bit integer causes
  `Invalid_argument("Z.testbit")`. This is outside the native epoch host's integer
  range. Rust's sparse helper returns a finite result there; this synthetic
  boundary is recorded separately and is **not** counted as parity coverage.
- `validator-ready.json`: **69 sequences**, **260 execution rounds** and **271
  transaction inputs**. Comparisons cover fees, nonce progression, account and
  registry bytes, duty persistence, legacy readiness metadata and exact Irmin
  roots. The native and Rust observers both witness a successful bond before a
  later readiness anchor failure restores the whole attempt. Transactions,
  parent wire and initial metadata produced by the oracle are execution inputs;
  rule context is supplied explicitly on both sides.
- `duty_readiness_and_exex_survive_canonical_restart` extends the canonical
  storage test with an authenticated duty-proof readiness transaction, no ExEx
  visibility before commit, dropped preparation, reopened duty state and nonce
  replay rejection. The finalized reference is seeded fixture input and outer
  transaction signatures are labels; this is storage/execution qualification,
  separate from the live consensus finality tests.

The anchored rule and snapshot scheduling/promotion implementation below
supersedes those gaps in this checkpoint. A production activation source and
composition with proposal execution and swarm membership remain open.
Complete private/AML hosts, autonomous recovery,
native interoperability, funded bidirectional VPN traffic and system browser
launch acceptance remain open. These results do not establish full lite-node
parity or mainnet readiness.

The combined checkpoint `out/validator-duty-checkpoint-20261013.json` passed
**189 tests in 83 result groups**, with **zero failures** and the same **three
ignored dedicated harness cases**. Protocol, runtime, node, browser and ExEx
were tested together across all targets; captured sources were unchanged.
This includes the new duty/readiness/restart tests and existing live consensus,
VPN admission and `oct://` service integration. Log SHA-256:
`3fd31b37fb9bbd7c03e46d87523bf8c3cf032d26edc8b5206556b48afee0c4cd`.
Strict Clippy passes for protocol and runtime across all targets. The checkpoint
preserves the outstanding full-node and funded-VPN gates listed above.

## Anchored rules and validator epoch advancement (2026-10-13)

`rules::Graph` preserves all 28 adopted native rule profiles, their historical
anchors, activation epochs, consensus identity, trusted-floor fallback and
program-source overlap window. An activation requires its matching historical
root; missing, mismatched and unreadable anchors fail. Epoch-only profile
predicates remain separate. `validator_epoch::BoundFold` binds the context once
for one epoch, verifies the supplied parent certificate when required, and
shares it with transaction execution through `Arc`. Canonical root lookup and
parent selection remain the production host's responsibility.

`validator_epoch::advance` applies finalized duty, locks seats, promotes due
weighted membership and schedules eligible replacements in native order. It
preserves original pending bytes during promotion, retains held duty state,
honors the participating profile and scheduling-slot rules, and skips snapshots
with insufficient eligible members. Its tree savepoint restores all advancement
writes on failure; the enclosing epoch journal must also restore preceding
transactions. The host still needs to bind durable membership into consensus
and peer admission.

`compute_roots` retains the native 65-slot committed Circle input history.
Projection reads published HEAD, checks its epoch against the parent, excludes
non-Circle state and preserves native metadata bytes and Irmin subtree hashes.
`StateBatch::graft` shares immutable subtrees, including native empty-tree removal
semantics. Speculative Circle writes cannot enter retained input roots. This
implements committed-root retention, not the remaining compute prepare/pin host.

Two unmodified-source OCaml oracles check all 1,158 adopted source hashes:

- `rule-activation.json`: **450 cases**, including activation boundaries,
  mainnet/local fallbacks, missing and conflicting anchors, exact fault bytes,
  native fault priority, signed parent rejection and bound-epoch mismatch.
- `validator-epoch.json`: **86 sequences / 1,635 transitions**, including
  scheduling, promotion, seat limits, participation, repeated/skipped epochs,
  byte-preserving promotion, corrupt metadata, committed Circle projection and
  replacement of old roots with an empty tree. All state bytes and roots match.
  The **21 operational failures** restore the same state. Three malformed JSON
  cases compare operation tag and syntax-error category: Yojson and Rust parser
  diagnostic prose differs. Other error text compares exactly.
- `scheduled_membership_and_circle_roots_survive_canonical_restart` commits
  **66 epochs**, reopens before and after activation, verifies pending/active
  state and retained roots, rejects an expired root, and checks that failed or
  dropped preparations publish no ExEx event. Raw trusted publication isolates
  storage recovery here; existing live driver tests qualify finality separately.

Strict Clippy passes for protocol and runtime across all targets. These results
preserve the adopted consensus rules. Durable validator configuration, production
proposal/execution/activation composition, resource committee effects, complete
private/AML hosts, autonomous recovery, native peer interoperability, funded VPN
traffic and system `oct://` launch acceptance remain open.

The combined checkpoint `out/validator-epoch-checkpoint-20261013.json` passed
**192 test executions in 85 result groups**, with **zero failures** and **three
ignored dedicated harness entries**. Protocol, runtime, node, browser and ExEx
were tested across all targets with unchanged captured sources. Live quorum
publication, VPN admission, `oct://` HTTP services, canonical recovery and the
new rule/epoch tests all passed. Native-peer and physical browser harnesses are
separate; the ignored crash worker is invoked by its parent recovery tests.
Log SHA-256:
`71ea83a26ee12463c9db7b01db46c419bbd21b9f2e3e206216b30ec567a1f7e0`.


## Validator configuration and canonical membership (2026-10-13)

`validator::config` now ports native validator entry parsing, identity errors,
static schedules, durable active/pending binding, count-weight caps, consensus
configuration hashes and startup admission. Native fault priority and byte
messages are preserved. Expired pending updates without a durable active marker,
manual legacy updates and conflicting schedules fail. The anchor's fallback
activation parsing remains separate from `Validators` parsing because the
adopted implementation gives them different behavior.

`validator::config::anchor` selects trusted stake and effective membership and
validates durable relief proofs. Pending-lock recovery can supply a round to
preserve the old set through the relief round; native finalized-history callers
use the epoch-only selector. No validator set is accepted from peer metadata.

`canonical::Reader` exposes retained heads and hash-checked immutable trees
without exposing the canonical writer. `CanonicalValidators` resolves membership
from exactly that retained tree and captured startup configuration. A forged head
is rejected, speculative metadata cannot affect the result, and later activation
does not overwrite historical membership.

The unmodified-source oracle checks all 1,158 adopted source hashes. Its
`validator-config.json` corpus contains **347 configuration cases**, including
**1,735 anchor query rows** and **8,675 expected-set comparisons** across
epoch-only selection and explicit rounds.
It covers startup permission, unsafe-quorum handling, weighted activation,
configuration hashes, malformed entries, pending metadata, environment fallback
and signed relief recovery/refusal. Native-generated raw metadata and proof wires
are explicit fixture inputs; Rust independently computes the resulting decisions.

The existing 66-epoch canonical restart test now also resolves membership before
and after activation, reopens storage, reads genesis membership after later
updates, rejects a forged historical head and ignores corrupt speculative
pending metadata. This test uses trusted raw publication to isolate storage;
the separate live driver tests validate signed quorum publication.

Strict Clippy passes for protocol and runtime across all targets. Finality and
production driver composition with canonical membership remain the next step.
Historical finality must retain authenticated relief evidence alongside canonical
history before the live journal is pruned; reading only the live relief journal
is insufficient for later audits. The asynchronous storage reader must also be
bound into finality verification and catch-up proof acquisition.
The complete private/AML hosts, resource committee effects, autonomous recovery,
native interoperability, funded bidirectional VPN traffic and system `oct://`
launch acceptance remain open. These results do not establish full-node or
mainnet readiness.


The combined checkpoint `out/validator-config-checkpoint-20261013.json` passed
**193 test executions in 86 result groups**, with **zero failures** and **three
ignored dedicated harness entries**. Node, protocol, runtime, ExEx and browser
were tested across all targets with unchanged captured sources. The live quorum,
canonical recovery, VPN admission and `oct://` HTTP service tests passed alongside
the new configuration and historical membership checks. Log SHA-256:
`dd3d706cf1867368f9f944a940266a3754674da1fb5642b36ca0b50599c0f6a6`.


The dedicated Chromium harness also passed against the adopted upstream counter
site (`out/validator-config-chromium-20261013.json`). It verifies real rendering,
cross-Circle navigation, immutable reads, frame isolation, explicit wallet review,
rejection of synthetic approval, one signed native transaction, WASM execution,
fee debit, quorum-authenticated publication and durable ExEx output. This uses
public development keys and fixture finality, with no peer consensus driver or
funded VPN traffic. System `oct://` handler registration/launch remains separate.


The isolated OCaml swarm harness passed as well
(`out/validator-config-native-peer-20261013.json`), after verifying all adopted
source hashes. It covers Rust-to-OCaml HELLO/ACK/FINISH, bidirectional native
frames, signed discovery records and profile offers, inventory/request exchange
and shutdown. This qualifies swarm interoperability; cross-language consensus
execution and autonomous full-node synchronization remain open.


## Canonical finality authority and relief archive (2026-10-13)

`validator_history::Authority` now supplies finality membership from a verified
retained tree, captured validator configuration and native relief selection.
Receipt activation, crypto profile and stealth minimum are captured startup
values using the qualified native parsers. `ValidatorHistory::resolve` is async;
certificate checks, catch-up record checks, publication, historical audits and
node import/retry paths await the authority. Peer proof acquisition also awaits
historical verification without blocking connection readers.

Every authenticated publication now stores its selected relief proof, or an
explicit absence, in `node_epoch_relief` in the same SQLite transaction as state,
history, receipts, rewards and ExEx. These are local recovery records; ledger
roots, consensus frames and native selection rules do not change. The archive
uses the native relief encoding and record-size limit. A historical epoch with
missing or corrupt evidence fails; it cannot consult the mutable live journal.
Raw older imports therefore require explicit evidence requalification. Relevant
archived proofs are revalidated against the original parent membership.

The new tests cover:

- **66 signed epochs** using the actual canonical authority, with an unweighted
  four-member set changing to a different weighted four-member set at epoch 64.
  Old signers are refused after activation. Dropped preparations emit no ExEx
  commit; restart audits reconstruct old and new membership. A corrupt live
  journal cannot alter committed absence, and deleting an archive row blocks
  historical audit. State transitions are explicit execution fixtures.
- Atomic storage of a signed native-height relief proof, rollback, exact encoded
  bytes, live-journal pruning, reopened evidence, witness-signature rejection and
  oversized/corrupt archive refusal. The short raw storage prefix isolates the
  archive; it is not a full consensus replay at the native relief height.
- Revocation while asynchronous proof verification is pending, followed by a new
  successful request. Ownership is rechecked after the await so a revoked request
  cannot return a certificate or erase a later request's window.

Strict Clippy passes for protocol, runtime and node across all targets. Full
production proposal execution, driver activation/peer membership, private/AML
hosts, resource committee effects, autonomous full-node recovery, cross-language
consensus execution, funded VPN and system `oct://` launch remain open.

This checkpoint identified a Circle RPC clock mismatch: native views and
resource policies use the captured epoch plus one. The subsequent correction
and its independent native oracle are described below.

The finality authority checkpoint passed 196 test executions across 87 result groups, with three explicit harness-only ignores and no failures. `out/canonical-authority-checkpoint-20261013.json` records unchanged captured inputs and log SHA-256 `ac40298cf36d544c39d4a722fdc3bfe2fb873b3024ca7d55fad8a914eec4dd61`. Strict Clippy passed for protocol, runtime and node across all targets. This checkpoint precedes the Circle RPC clock correction below.


## Circle RPC clocks and authenticated view profiles (2026-10-13)

`circle_view` implements the native snapshot clock, OCaml integer ceiling and
`Contract_rpc.view_profile` fault order: Standard, Math, ObjectCost, FheWork,
ProofExecution, WasmFloat. `CanonicalApplications` passes that next epoch to both
public reads and the WASM engine; `CanonicalAssets` applies it to resource
visibility. Browser provenance still identifies the captured committed epoch.

Node serving now derives its view profile from authenticated canonical history.
It reads each required anchor once, refuses missing/mismatched/unreadable roots
in native order, and never reads anchors beyond the captured snapshot. `Host`
retains only an optional availability check for views. The concrete canonical
validator authority can now be supplied directly to `Node`.

The unmodified native RPC oracle verifies all 1,158 pinned source hashes and
records **267 cases**: 13 snapshot-clock/overflow cases, 237 activation-profile
cases, 16 actual upstream-counter resource activation/expiry combinations and a
small SDK guest reading the VM epoch directly. `circle-rpc.json` binds the oracle,
generator, runner, upstream guest sources and guest WASM bytes. The direct epoch
guest reports `1` from a snapshot at epoch `0`.

Before the adapter correction, the new differential test failed at native case
252: Rust returned resource bytes that upstream hid at the expiry boundary.
`/private/tmp/octra-circle-rpc-before-fix-20261013.log` preserves that expected
failure. The authority unit test checks raw-root decoding, one read per anchor,
fault priority and snapshot bounds. Strict Clippy passes for runtime and node
across all targets. Validation of the corrected combined services follows below.

The corrected checkpoint (`out/circle-rpc-checkpoint-20261013.json`) passed
**13 test executions across four result groups**, with one browser harness test
explicitly ignored for separate execution. The dedicated authority unit test
also passed. Captured inputs stayed unchanged. The test log SHA-256 is
`b09d38cfa5d47c860b9e2f3c31d7c32117d10e14dd7e9e712aefa9d2105402a1`.

The dedicated Chromium harness then passed on those same sources:
`out/circle-rpc-chromium-20261013.json`. It exercises actual upstream app code,
CSS/images, cross-Circle links, SDK views, explicit review, synthetic approval
refusal, one signed update, fee debit, canonical commit, durable ExEx receipt,
retained snapshot reads and reload revocation. Its development-chain publication
uses fixture validators; the separate six node-service tests include the live
quorum driver, WireGuard admission, catch-up and restart. The prior native peer
interoperability report still matches every captured Rust input; no network
implementation changed in this correction.

Full production transaction/proposal composition, private/AML hosts, committee
effects, autonomous cross-language consensus recovery, funded VPN operation and
system-level `oct://` launch still need qualification. These results close the
canonical-authority and public browsing boundaries, not the complete node goal.

## BFT epoch execution and committed receipt bindings (2026-10-13)

`epoch_execution` composes transaction effects, validator advancement, rewards,
account packing and the final Irmin root under one rollback boundary. It uses
native `(sender, nonce, transaction hash)` order, preserves charged failures,
registers carried sender keys only after confirmation and clears spent nonces at
the native boundaries. Rejected candidates retain their canonical positions;
the charged outcome flag follows the activated compute-operation rule.

`preverify_state` checks the static receipt gate first, then checks private
cipher/key bindings or Circle snapshot bindings against the committed ledger.
The root is the full Irmin HEAD hash. The consensus root, which may also commit
the transaction index, is a different input used by the validator environment.
The node-service fixture previously used that consensus root for receipts; it
now uses the committed ledger root.

`circle_transaction::Calls` supplies the existing WASM transition to either
execution path, keeping auxiliary receipts local until publication. The node
service and browser-wallet qualification hosts now use the BFT runner instead
of separately invoking the legacy sender loop, reward footer and account flush.
Their proposal policy, funding and validator identities remain fixtures.

Three offline differential fixtures verify all 1,158 upstream source hashes at
`7f9be4489870645cfcc95439638cde40f5da9f50`, without source instrumentation:

| Fixture | Cases | Native boundary |
| --- | ---: | --- |
| `epoch-execution.json` | 89 | `Epoch_exec.run_core`, real standard/validator transitions, committed roots, key activation, rewards and rollback |
| `preverify-state.json` | 318 | `Preverify_commit.check_bound`, committed HEAD with speculative writes, source/key checks and refusal order |
| `epoch-circle.json` | 160 | Production `Consensus_vm_transition.process_tx` inside `run_core`, actual upstream counter WASM, fees, VM receipts and complete state roots |

The epoch fault cases inject declared operation failures to test savepoints;
they do not stand in for compute execution. The Circle cases cover prior Circle
policy and compute-manifest modes, with explicit VM proof/inspection settings.
Receipt-binding fixtures construct receipts to exercise admission and do not
prove cryptographic work. The lower-level epoch fixture includes direct negative
money inputs which both network decoders reject; the BFT transition follows the
native debit/credit ordering for those probes as well.

This closes the qualified BFT epoch core and its public Circle composition.
Production proposal/transaction host assembly, activated Circle policy and code
mutation paths, private/AML operation hosts, resource committee effects,
autonomous cross-language consensus recovery, funded VPN and system `oct://`
launch still require implementation or qualification.

The focused integration checkpoint, `out/bft-epoch-checkpoint-20261013.json`,
passed **15 test executions across five groups**, with the Chromium harness
explicitly ignored for separate execution. Inputs remained unchanged. Its log
SHA-256 is `a9b7daa77c0b8347cacb321e1649dd3bf49b9635643ee5a1c748dc2fcbb66647`.
The six node-service tests include live Rust quorum publication, receipt replay,
ExEx delivery, browser reads, authenticated WireGuard admission, missing-bundle
recovery and restart. Strict Clippy passes for runtime and node across all targets.

The dedicated Chromium run also passed on the unchanged checkpoint sources:
`out/bft-epoch-chromium-20261013.json`, SHA-256
`30d312902adc329d51cec7909e48c05005652a8e1ba8385d3276e64d09f19fab`.
Its 16 application checks include actual upstream site/SDK code, explicit call
review, signed BFT Circle execution, fee debit, committed receipts, durable ExEx,
retained snapshots and cross-Circle navigation. The browser host still uses
fixture validators without its own peer driver; live quorum is covered by the
separate node-service tests. Existing native peer-wire evidence matches all 20
captured Rust inputs and was not rerun. None of these results substitutes for
upstream/Rust consensus replay or an executed, funded VPN settlement application.

## Finalized rejection replay (2026-10-13)

The native proposal path uses two different execution partitions. Its first
preview proves outcomes for every candidate. Its final preview and application
execute confirmed transactions plus charged compute failures. Ordinary refusals
remain in the receipt history, but their speculative fees and state effects do
not enter finalized state. In particular, a failed Circle call can pay a preview
fee without being a charged finalized outcome.

`epoch_partition::Partition` implements both selections and the native outcome
comparison. Finalized selection checks the full candidate envelope and charged
operation rules, then rebuilds charged rejection positions after removing
ordinary refusals. Comparison uses confirmed hashes in order and canonical
rejection encodings. The epoch runner checks the result inside its savepoint,
after validator advancement, rewards and account flush; disagreement restores
all of those effects. Operational failure and panic also restore the caller's
ledger journal and speculative tree.

Both finalized peer import and catch-up now pass a prepared
`consensus_bundle::Replay` to the executor. It retains the complete historical
bundle separately from its executable partition. The combined node-service
test executes a real failing WASM call in a disposable preview, imports its
rejection alongside a successful call, verifies retained outcome history before
and after restart, and successfully reuses the excluded call's nonce in the next
epoch. Existing live quorum, ExEx, browser and authenticated VPN-admission checks
continue to pass. The live proposal fixture explicitly refuses rejection
proposals until it has an independent full-candidate preview.

The unmodified native `Consensus_proposal.verify_preview_partition`,
`Tx_outcome` and `Tx_envelope` match **2,380 differential cases**. The oracle
verifies all 1,158 pinned sources, with no instrumentation. Cases use recorded
epoch artifacts and controlled mutations; this qualifies selection and outcome
verification, not a new compute implementation. The separate atomicity test
injects declared compute effects to prove fee/state rollback. Fixture:
`crates/octra-node-runtime/tests/fixtures/epoch-partition.json`, SHA-256
`5a6aea5d17c321609228ed571161c5f6a365ea81d786098bd1319e789f0449c3`.

Final checkpoint `out/partition-checkpoint-20261013-final.json` passes **20 tests
across seven groups**, with unchanged inputs and one explicitly ignored browser
harness. Its log SHA-256 is
`18c27e3a111a3c30612cd28bd93b2cee393cfd574fb1d9dcc9e8f318042bf4e3`.
Strict Clippy passes for node, runtime and protocol across all targets. An earlier
checkpoint was deliberately interrupted for test-only lint cleanup and is not
qualification evidence.

The separate current-source Chromium run passes all 16 application checks:
`out/partition-chromium-20261013.json`, SHA-256
`5cb121a1d58e285bd09019855cae5881036a6ccfeef59d41377943fe66ecb3eb`.
The approval screenshot was visually checked. All 20 inputs captured by the
existing native peer-wire evidence still match; that boundary was not rerun.

Production execution/proposal assembly with authenticated historical rules,
activated Circle and code mutation paths, private/AML and compute operation
hosts, cross-language consensus recovery, funded VPN settlement and system
`oct://` launching remain open. The new replay boundary does not complete those
features or qualify public-chain deployment.

## Canonical execution rules (2026-10-14)

Finalized import and catch-up now bind one execution context to the authenticated
parent and retained chain history. Circle, compute-manifest, object-cost,
migration, private-payload and validator-fold selection follow the native
preview backend's fault priority. Anchor failures remain failures throughout
that attempt. The validator membership used for execution is the same captured
authority that checked the certificate; publication still reauthenticates it.

The unmodified native preview backend matches **978 rule contexts**, including
conflicting anchor faults and signed parent membership. A deliberately wrong
snapshot root stops these oracle cases before transaction execution. Separate
Rust tests verify canonical parent binding, single-read anchor failures and an
authority that becomes unavailable after authenticating the certificate.

Circle calls now select native Compute/Manifest loading and update policy from
that context. Ordinary updates still execute under Standard. Native BFT tests
cover **640 complete counter epochs** across both policy/loading modes and **16
additional policy-sensitive epochs** using an unused nonpersistent WASM import.
The latter exposed a one-effort divergence: Rust charged the outer receipt
budget before VmBytes activation. Budget creation now follows that rule, as
upstream does. Both complete state roots and auxiliary receipt bytes are checked.
All three native oracles verify the 1,158-source pin without instrumentation.

This closes historical rule binding for the existing import execution boundary;
it does not finish production operation/proposal assembly. Circle code mutations,
private/AML and compute hosts, cross-language consensus recovery, executed funded
VPN settlement and system `oct://` launching remain open. Earlier checkpoints
above are historical snapshots; their source hashes predate these changes.

Checkpoint `out/execution-rules-checkpoint-20261014.json` passes **39 tests in
12 groups**, with unchanged source inputs. The two ignored entries are the
separately launched browser fixture and the crash worker exercised by its parent
test. The log SHA-256 is
`6a4e8e1f434f0304e45ffe4d65945feb2529ef51cd6972fa9dcf1310db78d05e`.
Strict Clippy passes for node, runtime and protocol across all targets. Existing
native peer-wire evidence still matches all 20 captured Rust inputs and was not
rerun; it does not qualify cross-language epoch execution.

The unchanged-source Chromium run passes all **16 application checks**:
`out/execution-rules-chromium-20261014.json`, SHA-256
`2fc34d4636feee51dfe32d5e159bf54d438b28de53c1defefdd3d349fd40de1d`.
The approval screenshot was visually reviewed. An initial attempt timed out
during fixture compilation, before browser checks began; the separate fixture
build and subsequent browser run succeeded. This uses real upstream site/SDK
code and signed canonical Circle execution with fixture validators, without a
peer driver in the browser fixture or funded VPN settlement.

## Circle deployment and code updates (2026-10-14)

The transaction host now routes Circle deployment and program replacement through
`circle_code`. `circle_program` preserves the native payload field priority,
Int64 exception precedence, canonical JSON and deployment address derivation.
Deployments write the native metadata/code/usage fields and proof-activation call
marker. Updates enforce ownership, code limits, admission profiles, wrapping
version increments and marker preservation. Both operations debit only the OU
fee; a transaction amount is not a deployment deposit.

The new native oracle invokes the unmodified `Consensus_vm_transition.process_tx`
inside `Epoch_exec.run_core`. Its **238 epochs** compare complete Irmin state roots,
account bytes, fee/nonce results, refusal bytes, auxiliary receipts, canonical
payloads and derived addresses. The cases include deploy → call → update → call
under all eight proof/inspection/manifest combinations, metadata-only OCTB
deployments, malformed fields and Int64 inputs, invalid WASM/base64, ownership,
limits, insufficient fees, duplicate and partial metadata, version overflow and
retry after a refusal. Every oracle input is checked against the adopted 1,158
source hashes; there is no native instrumentation. A separate rollback test
checks that an operational failure after a valid deployment restores the earlier
code writes, accounts, supply and nonce journal.

Proof-active deployments require the native resumable interpreter. The safe Rust
API now owns that upstream session directly, restores the HFHE capability around
each step, retains the native input bound and releases suspended state when its
owner is dropped. At this checkpoint ordinary updates could finish through this
path, while value/balance/transfer and nested program requests were unavailable.
The shared journal implementation below extends that boundary.

This checkpoint qualified WASM code installation/replacement and ordinary
execution. OCTB code admission/execution, authenticated HFHE context, spawn/asset effects, private/compute
transitions, production proposal/node assembly, cross-language recovery, funded
VPN settlement and OS `oct://` launching remain open. Large-input admission,
JSON syntax exception text and non-UTF-8 refusal transport also remain
unsupported at this host boundary.
The original snapshot/app tests and the new native lifecycle tests are separate
from a public-chain deployment qualification.

Checkpoint `out/circle-code-checkpoint-20261014.json` passes **41 tests in 13
groups**, with unchanged source inputs and log SHA-256
`525e9a349bc8185f51555b697e7d5e477313ecb1b8c780e2acb1ac41d1f3cffc`.
The two ignored helpers are the browser fixture launched separately and the
crash worker exercised by its parent. The safe session API test also passes
(suspend/resume, closed-session reuse, invalid input and abandonment). Strict
Clippy passes for node, runtime and protocol across all targets after fixing one
test-helper style lint; the earlier queued checkpoint was stopped before tests
and replaced by this unchanged-source run.

The corresponding Chromium report, `out/circle-code-chromium-20261014.json`, passes all
**16 application checks**, including approval, signed execution, ExEx and
cross-Circle navigation. Its SHA-256 is
`b253e5ba03de5d2986b30749f6ccd15de51d6c0d83bbe1a3273460133475b38c`;
all 71 recorded source hashes were rechecked and the approval screen was visually
reviewed. The six node-service tests separately cover authenticated peer import,
live quorum publication, WireGuard admission, ExEx, cancellation and recovery.
They continue to use fixture validators and settlement. None of these results
qualifies funded VPN execution or full-node/mainnet deployment.

### Shared Circle value and call journals (2026-10-14)

`circle_journal` supplies the native resumable interpreter with `call_value`,
effective balances, transfers and nested WASM calls. One invocation tree owns
the value deltas and staged storage. Child calls see earlier writes and balance
changes, including self-transfers and re-entry. A failed child restores its
value/program/state snapshots; a failed top-level call restores all application
effects while retaining the native fee outcome. An operationally unavailable
host aborts the enclosing execution attempt. Shared receipt budgets retain their
native consumption across rollback.

Nested event receipts preserve the emitting Circle and call depth, interleaved
at the parent's suspension point. Snapshot, storage, transfer, output and event
effort follow the pinned native routines. Depth checks and the call-code marker
are enforced before entering another Circle. Unsupported OCTB execution remains
an operational error.

The unmodified native epoch oracle produced **682 reference epochs** in
`tests/fixtures/circle-journal.json`, using a purpose-built guest and the pinned
upstream SDK. Cases cover transaction value, balance, transfer failure and
self-transfer, repeated/nested/reentrant calls, depth exhaustion, reserved
writes, child/parent failure, failed calls followed by later transactions, and
full account/state-root/fee/nonce/receipt comparisons. The generator verifies
that shared-budget cases reach the intended boundary: 258 total events succeed
under prior inspection rules and fail under active rules; 254 succeed under
both. Separate cases exceed the per-interpreter event cap. Debug sections are
stripped from the test guest to avoid repeatedly hashing 1.5 MB of debug data.

All **682 Rust epoch comparisons pass**. The separate operational-error test
confirms that an unavailable nested OCTB call restores an earlier successful
child's storage/transfers, fees, balances, supply and nonce journal. The first
checkpoint failed that test's diagnostic assertion because it expected plain
text instead of the API's byte-vector diagnostic; the assertion was corrected
without changing execution behavior.

Checkpoint `out/circle-journal-checkpoint-20261014-v2.json` passes **43 tests in 13
groups**, with all **1,962 source hashes unchanged**. The two ignored helpers are
the separately launched browser fixture and the crash worker exercised by its
parent. The test log SHA-256 is
`35bf79f70b3dee24261b5de2ce9ab6cb68eebca88b7aa13c065061bb7a3ed490`.
Strict Clippy passes for node/runtime/protocol across all targets; formatting
checks pass for the changed Rust files.

The Chromium run `out/circle-journal-chromium-20261014.json` passes all **16
application checks**; all 72 recorded source hashes were verified and the
approval screenshot was reviewed. Its SHA-256 is
`49d91befbe237bf54ef20fbb086f0e24d574318d8a4ea9f825a7610357fc68c9`.
This uses a development chain with fixture validators and settlement. Full node
execution, OCTB/AML, authenticated HFHE, private/compute transitions,
cross-language recovery, funded VPN settlement and OS protocol launching remain
open. Spawn and asset effects were subsequently qualified below. No consensus
changes were made.

### Circle spawning and asset commits (2026-10-14)

`circle_effects` validates and commits child Circles plus public and encrypted
asset writes through the shared transaction journal. Direct and nested deployment
reuse one admission/metadata writer. Spawn IDs, caller/parent ownership, origin
metadata and call-code markers match the pinned native node. Asset scope, path
normalization, resource indexes, replacement sizes, quota limits and wrapped
usage arithmetic preserve native ordering. A failed effect restores all staged
application writes. Encrypted asset bodies are stored opaquely; this does not
qualify private access or decryption.

The unmodified native oracle produced **992 epochs (1,008 transactions: 448
confirmed, 560 rejected)** across all eight proof, inspection and manifest rule
combinations. Rust matches complete state roots, accounts, fees, nonce journals,
deployment IDs and receipts. Cases include malformed payloads, public/sealed
modes, owner checks, caps, duplicate paths, replacement quotas, child calls,
nested effects and rollback after failure.

A signed transaction test creates a child owned by its parent and publishes
`oct://<child>/index.html`. The page stays unavailable until canonical publication;
the commit supplies the matching durable ExEx transaction and receipt. An
authenticated restart restores the same page and ExEx record. The test uses
fixture validators, without a peer consensus driver or funded VPN settlement.

Checkpoint `out/circle-effects-checkpoint-20261014.json` passes **45 tests in 13
groups**, with **1,966 source hashes unchanged**. Its SHA-256 is
`364351c1c150e1b91cc454d76e4f3eaef90546dca526cac0d599b34f6d3b6d5d`;
the test log SHA-256 is
`2115c378ca955a9b8b645f1f932ad24062e0f586b37fa40b32d7e651db8e094a`.
The two ignored helpers are launched by the browser and crash-recovery harnesses.
Strict Clippy passes across all node/runtime/protocol targets, and formatting
checks pass for changed Rust sources.

Chromium report `out/circle-effects-chromium-20261014.json` passes **16 application
checks**, with all **73 source hashes verified** and its approval screenshot
visually reviewed. Its SHA-256 is
`2c11990a670feec85ff6a1dc5e124eac519d441673fc3c4e3427234350bc7efe`.
It continues to exercise the upstream counter site; the newly spawned page is
covered by the signed canonical resolver/restart test.

Full node/mainnet qualification remains open: OCTB/AML admission and execution,
authenticated HFHE/private and compute transitions, production proposal assembly,
cross-language consensus/recovery, funded VPN settlement and OS protocol
launching still need implementation or qualification. No consensus changes were
made.

### Legacy OCTB admission and Circle installation (2026-10-14)

The Rust `octb` module decodes all **139 instruction forms**, retains native
constant/cell offsets and byte strings, and reproduces canonical encoding.
State, proof, emission and veil metadata preserve the active/prior distinctions,
canonical validation and error priority. Repeated constants share immutable
values, including large integers. The verifier checks registers, call spans,
labels, reserved keys and capability kinds before applying native opcode policy;
admitted effects retain first-occurrence order.

All **6,910 unmodified native comparisons pass**, including malformed operands,
lazy integer conversion, unused constants, metadata duplicates, prior/active
opcodes, deterministic malformed streams and mixed-policy refusal priority.
This qualifies wire values and legacy admission. OCPG attestation, Program type
flow, AML compilation/proofs and OCTB execution are still unavailable.

Circle deployment and updates now use legacy admission before address/owner/size
checks at the same points as native execution. A separate **248 native epochs
(256 transactions: 52 confirmed, 204 rejected)** match complete state roots,
accounts, fees and nonce journals. These include independent execution/standard
rule modes, invalid code, ownership/limit/balance precedence and rejected updates
followed by another transaction using the same nonce. Unsupported OCPG admission
still aborts and restores the whole attempt, including earlier deployments and
fees. No consensus rules were changed.

`out/octb-admission-checkpoint-20261014.json` records **3 protocol tests and 7
Circle integration tests**, all passing, with **1,976 source hashes verified**.
The full source snapshot was captured during compilation before runtime tests;
the protocol inputs also match their separately recorded earlier snapshot.
The packet SHA-256 is `8b14f86a2afcb02364666d40e94a90e0593157bcf2d848b28c79a680b3ff63ab`.
Current regression includes all prior WASM lifecycle/journal/spawn/asset epochs,
operational rollback and signed page publication with durable ExEx restart.
Strict Clippy passes for node/runtime/protocol across all targets, and changed
Rust formatting checks pass. Existing vendored interpreter dead-code warnings
remain; the vendor is outside the selected Clippy packages.

The 45-test node checkpoint and 16-check Chromium report above precede the OCTB
addition and retain their original source snapshots. The new focused tests do
not replace full-node, peer-consensus or funded VPN qualification. The next
execution work is the OCTB VM and authenticated private/compute context, followed
by complete proposal/node assembly and combined consensus/recovery qualification.

### OCTB execution core and shared work budgets (2026-10-14)

The Rust runtime now implements **71 of the 139 OCTB instruction forms**:
integer arithmetic/comparisons, registers, memory, typed and bulk storage,
checkpoints, internal control flow, context reads, balance/transfer hooks,
capability checks/closing, events, text and integer parsing, blobs, SHA-256,
Keccak-256 and Ed25519 verification. Execution values retain native byte strings
and arbitrary precision integers. Run and step use the same state machine.
Missing instruction families return an operational error before partial metering
can turn them into a consensus refusal. Hosts must supply authenticated balances,
transfers and capability liveness; the default host cannot invent these results.

The unmodified pinned VM produced **13,528 execution cases**. Rust matches both
whole-program and stepped execution, including registers, memory size/content,
storage, blobs, effort, stopping position, output status, events, capability
closures, host calls and remaining budgets. Coverage includes signed arithmetic,
strict/coercing values, typed defaults, invalid storage, internal call depth,
nested undo, parsing and paging boundaries, partial prior-rule writes, active
preflight refusal, signature encoding, event caps and allocation/effort failures.
The native oracle also checks that its run and step outcomes agree. It uses
controlled balance, transfer and capability callbacks; it does not exercise a
network or funded ledger.

The shared `octb::work` module separately matches **2,148 native comparisons** for
integer effort, overflow-safe costs, byte plans, allocation/receipt limits and
event serialization. WASM receipt accounting now delegates to this same budget,
preparing the shared budget needed by mixed-runtime nested execution.
The existing seven Circle regression tests pass after this refactor, covering
the native lifecycle/journal/spawn/asset/admission epochs and signed page
publication through canonical ExEx delivery and authenticated restart.

Checkpoint `out/octb-execution-checkpoint-20261014-v2.json` passes **10 tests in
three suites**, with **1,989 source hashes unchanged**. Its SHA-256 is
`1900ba10fd083753264ea79f6d2371747475e841d9f4918cd4c55e829d33abab`.
Strict Clippy passes across all node/runtime/protocol targets; changed Rust
formatting passes. Keccak uses the existing locked `sha3` version through a new
runtime dependency edge. The earlier broad node and Chromium reports retain
their historical source snapshots.

That checkpoint qualified the VM core. Circle transaction integration and
cross-Circle calls were still unavailable; the qualification below covers those
new boundaries. VM spawning, OCPG certificate/type-flow admission, private/HFHE
and compute/object execution remain incomplete. Complete proposal/executable node
assembly, cross-language consensus and recovery, funded VPN settlement, and OS
`oct://` launching are still open. No consensus behavior was changed.


### OCTB Circle execution and mixed-runtime journals (2026-10-14)

Legacy OCTB calls now execute through the same transaction journal as WASM.
The dispatcher and parameter slots match the native VM, including unchanged
memory size, arbitrary precision integers and byte strings. Context comes from
the admitted transaction and authenticated parent: caller/origin, value, epoch,
epoch time, parent root, target and transaction hash. OCTB retains its native
fuel limit; the WASM twenty-million clamp does not apply.

Both engines share stable-storage loading and effort, effect authorization,
value transfers, native return values, ordered multi-value events and receipt
budgets. Cross-Circle calls preserve storage during reentry, carry the selected
child-call effort rule, and roll back value/storage effects together on failure.
A failed child still consumes its shared receipt budget. An unavailable opcode
aborts the entire speculative batch, restoring earlier calls, fees and nonces.
The Rust VM now implements **72 of 139 instruction forms**, including XCALL.

Unmodified production execution at the adopted `7f9be44` pin produced **787
native epochs containing 1,387 transactions**:

- **304 direct-call epochs:** 888 transactions, 684 confirmed and 204 rejected.
  These cover deployment/update/dispatcher lifecycle, native parameters and
  context, balances and transfers, storage limits, reserved writes, event caps,
  Require reasons, fuel exhaustion and rollback across eight independent rule
  combinations.
- **483 mixed-runtime epochs:** 499 transactions, 264 confirmed and 235 rejected.
  These cover OCTB-to-OCTB, OCTB-to-WASM and WASM-to-OCTB calls, reentry, depth,
  child fuel rules, byte-valued returns, ordered events, shared budget exhaustion,
  disabled call markers, successful children followed by a parent failure, and
  later transactions after rollback.

Rust matches complete epoch state roots, account records, fees, nonce journals,
refusals and raw receipt bytes. Each oracle run verifies all **1,158** pinned
native source hashes and uses no source instrumentation. Fixture SHA-256 values:
`f037403016c208c1ccf47865fef141d275f41fe75f15b59440996fc93b628cdb`
(direct calls) and
`c0ae9ffc18720bf2d5f9d5f3dda46e6fd3f1a3c7e5df2b324ac744a084586c02`
(mixed journals).

Checkpoint `out/circle-octb-checkpoint-20261014.json` passes **60 tests in 18
suites**, with **1,995 source hashes unchanged**. It includes the 13,528 VM-core
and 2,148 work-budget comparisons; all new and existing Circle epoch fixtures;
canonical publication/crash recovery; receipt replay; and combined peer,
WireGuard, browser and ExEx service tests. The two ignored helpers are exercised
by the Chromium and subprocess-crash harnesses. Strict Clippy passes for every
node/runtime/protocol target, and changed Rust sources pass formatting checks.
Checkpoint SHA-256: `68094164714af35d294b2eb0b8dd62b888fea62b479e55f5bf3f17702506e643`.
Test-log SHA-256:
`87e000c7a34960709367cf48c692a37e8a667fed46027f1b32781a81842f55a0`.

The fresh Chromium report `out/circle-octb-chromium-20261014.json` passes all
**16 application checks** against the pinned upstream counter site. Its **73
recorded source hashes** remain unchanged, and the approval screenshot was
visually checked. It covers script isolation, navigation, explicit approval,
signing/admission, canonical execution and durable ExEx receipt delivery. Report
SHA-256: `d3ec6e3e94b560986f75bda561059409b6927a4d8eaa382880da5f61177a345b`.
This browser fixture continues to execute the WASM counter; OCTB is qualified by
the native epoch comparisons above.

At that checkpoint, VM spawning and byte-preserving transaction refusals were
still open; the qualification below covers those additions. Full-node
qualification, OCPG certificates/type flow, private/HFHE and compute/object
execution, production proposal/executable assembly, cross-language consensus and
recovery, funded VPN settlement and OS `oct://` launching remain open. The
combined service fixtures use development validators and synthetic VPN settlement.
No consensus behavior was changed.

### OCTB child Circles and binary transaction failures (2026-10-14)

Transaction refusals now retain native byte strings through sender execution,
BFT outcomes and auxiliary receipts. OCTB `SPAWN` and `SPAWN2` bring the VM to
**74 of 139 instruction forms**. Both follow native decode preflight, shared
fuel/allocation budgets, register/depth guards and suspended-host completion.
The internal spawn nonce survives a VM storage rollback; Circle child indices
count successful deferred effects independently. Child ownership, structural
validation and final runtime admission reuse the existing Circle deployment and
effect-commit paths. A parent refusal discards its deferred children.

Unmodified native source produced these fixtures, with all 1,158 pinned hashes
verified and no source instrumentation:

- `circle-byte-errors.json`: **168 epochs / 720 transactions**, including binary
  Require reasons, deployment/commit refusals, method/event names, exact receipt
  bytes, retained fees and nonce reuse after a refused deployment.
- `octb-spawn.json`: **996 opcode comparisons**, covering synchronous/suspended
  completion, raw/base64 inputs, nonce overflow, storage rollback, register and
  depth boundaries, view guards, child scope and exhaustion before/after a host.
- `circle-octb-spawn.json`: **280 epochs / 1,072 transactions**, covering caller
  and parent ownership, repeated children, the four-child cap, deferred OCTB/WASM
  admission, parent rollback, complete state roots, fees, accounts and receipts.

All three fixtures pass. `out/circle-spawn-checkpoint-20261014.json` passes
**70 tests in 20 suites**, including browser, WireGuard, canonical consensus
services, ExEx and crash recovery; its **2,003 source hashes** were unchanged.
SHA-256: `cd54b5f83c4c3f26b664e653ed95a8cd541b9b7024a38eb58aac9ea93302e121`.
A subsequent cleanup only removed an infallible `Result` wrapper from the charged
rejection helper. `out/circle-spawn-cleanup-checkpoint-20261014.json` rechecks all
**17 affected Circle tests** against the final **2,003 unchanged source hashes**.
SHA-256: `1947f3f8c96bd9fc455bdaffed0b3e647725a46fdea34b7f33b023edaaa34737`.
Strict Clippy passes for all node/runtime/protocol targets, and changed Rust
sources pass formatting checks. Exact fixture, log and source evidence is indexed
in `network-consensus-inventory.json` under `local_octb_spawn_qualification`.

Full-node qualification remains open. Nested cross-runtime spawn composition,
OCPG certificates/type flow, private/HFHE and compute/object execution, standalone
contracts, native JSON syntax exceptions, production proposal/executable assembly,
cross-language consensus/recovery and funded VPN settlement require more work.
At that checkpoint OCTB browser views and native OS URL registration remained
open; the browser fixture executed the upstream WASM counter. The following
qualification adds OCTB views while preserving the adopted consensus behavior.


### OCTB Circle queries and browser execution (2026-10-14)

The browser now executes the implemented OCTB instruction subset alongside WASM.
It receives the full anchored view profile and reads one immutable canonical tree.
The OCTB host follows native balance/context rules, dispatcher metadata and legacy
contract subviews, including typed arguments, the eight-level call limit and a
shared allocation budget. Subviews resolve through legacy contract storage, as
in the native RPC host. Views cannot publish storage, transfers or deployments.
Public reads enforce privacy, provenance, profile epoch and encoded-code limits.
Native result JSON retains byte strings; the browser refuses results that cannot
be represented as UTF-8 JSON. JavaScript clients use decimal strings for large
integers; raw native integer literals remain covered by the query engine tests.

Unmodified native sources produced **688 view cases**, with all **1,158 pinned
source hashes** verified and no instrumentation. Rust matches complete receipts,
effort, events and unchanged state roots. Browser tests additionally compare
**624 descriptors and 608 representable fixed-limit views**. The other cases
exercise custom fuel limits or native integer literals outside the browser JSON
number transport. Depth exhaustion and combined child allocations are tested;
the latter refuses a second child even though each child fits independently.

Signed OCTB counter transactions now pass the existing admission, fee, canonical
publication, ExEx and restart/checkpoint test shared with the WASM counter.
The broad checkpoint passes **76 tests across 22 suites**, with **2,009 source
hashes unchanged**, including WireGuard, peer recovery and live quorum services.
Only the browser test fixture and Chromium runner changed afterwards: the second
app opens at the latest committed head after the first app's write. The final
fixture checkpoint passes **3 tests** against the final unchanged source set.

Real **Chrome 155** passes **21 application checks**, reusing the pinned upstream
counter UI for both engines. Approved WASM and OCTB writes occur consecutively on
one development chain, produce canonical state/fees and durable ExEx receipts,
and leave retained browser views pinned. Opaque-origin isolation, explicit review,
frame revocation and cross-Circle navigation remain covered. Strict Clippy passes
for all node/runtime/protocol targets and again for the final fixture; changed
Rust sources pass formatting. Exact source, fixture, log and report hashes are in
`network-consensus-inventory.json` under `local_octb_view_qualification`.

Evidence: `out/circle-query-checkpoint-20261014.json`,
`out/circle-query-browser-final-checkpoint-20261014.json` and
`out/circle-query-chromium-20261014.json`.

This remains development-chain qualification. Full-node parity, OCPG/proof
admission, private/HFHE and compute/object execution, standalone transaction
execution, production proposal/executable assembly, cross-language recovery,
funded VPN settlement and OS URL launching remain open. No consensus behavior
was changed.

### Private encrypt/decrypt balance execution (2026-10-14)

`private_crypto` ports the native FheBalance encoding, amount and remaining-balance
proof checks, ciphertext addition/subtraction, and six/eight-base-layer recovery
limits. It uses the Rust HFHE implementation with explicit historical/active
proof rules and scalar arithmetic. Native arithmetic exceptions and local resource
failures abort execution rather than producing a transaction-invalid verdict.

`private_balance` parses native first-field/unique-field payloads and returns an
opaque verified plan. Withdrawals verify a range proof against the computed
remaining ciphertext. Application checks the transaction and current ciphertext
again before charging. Its ledger journal restores balance, supply, nonce,
spent-nonce tracking and dirty accounts on failure. Prepared transition hashes use
the native transcript. Epoch admission remains separate: this API does not itself
check signatures, fee floors, self-targeting, operation caps, consensus-bound key
availability, KAT, or certified preverification receipts.

The fixtures use deterministic, small test keys and real native proofs. The
unmodified OCaml oracle invokes the isolated native PVAC worker for ledger plans;
all 1,158 adopted source hashes are checked. This is execution-component evidence,
not signed private epoch admission, mainnet cryptographic parameter qualification,
or funded VPN settlement. Stealth, claim and key-switch transitions, the private
operation host, and production proposal/executable assembly remain open.

The broad checkpoint passes **41 tests across 15 suites** against **2,019 unchanged
source hashes**, including 66 native ledger cases, canonical recovery, signed
Circle applications, ExEx and VPN services. One child-process crash helper is
intentionally ignored by the test runner and invoked by its parent test.
A final decoder review narrowed private range input to bound proofs; the follow-up
checkpoint passes all **259 native crypto cases** with unchanged sources. Only the
decoder, generator and fixture changed between those checkpoints; archived broad
versions retain their exact tested hashes. Strict library and focused-test Clippy
checks pass. Evidence is indexed under `local_private_balance_qualification`.

### Private epoch admission and publication (2026-10-14)

`private_epoch::Epoch` applies encrypt/decrypt admission inside the existing epoch
savepoint executor. It preserves native self-target, operation cap, encrypted-debit,
key binding and receipt precedence. The key source is lazy and content-addressed:
malformed payloads and missing receipts precede blob loading, while missing or
corrupt local blobs abort the attempt. Counters advance only after successful
application. Disabled legacy private/recrypt operations retain native refusals.

Active rules verify real proofs and then match any certified transition hash.
Historical rules may prepare and apply an exact certified transition without
rechecking its proofs; this route is private to the epoch host. The public balance
API always verifies proofs. The outer executor checks receipt/head/source bindings
before state changes, and canonical publication separately authenticates quorum
signatures and the resulting state. Proof-artifact reuse remains unimplemented;
active execution currently verifies the proof again.

A signed development-chain test executes a withdrawal followed by a deposit using
native proof material, active account packing and epoch fee/reward accounting.
Both epochs publish under quorum signatures, enter the durable ExEx outbox, and
survive database close/reopen with finality re-audit. Stale source/head receipts,
missing blobs and corrupted quorum signatures leave canonical state unchanged.
This test passed against the new epoch host; it does not use a peer consensus
proposal driver or a production key-discovery service.

The production import executor/executable, sender-path KAT behavior, stealth,
claim, key-switch, complete VM operation coverage, cross-language recovery,
funded VPN settlement and OS URL launching still require implementation or
qualification. Existing Circle/VPN/ExEx service qualification uses development
validators and synthetic settlement. No consensus behavior was changed.

The native epoch oracle contributes **48 exact cases**, all matching Rust; nine
confirm transactions and the remainder exercise receipts, proofs, limits, key
availability and disabled operations. Both oracle suites verify all **1,158
pinned source hashes** without instrumentation. The combined regression passes
**19 tests across 6 suites** against **2025 unchanged source hashes**, including
all 66 native ledger cases after the certified-plan refactor. The separate signed
publication test passes, and strict library/focused-test Clippy checks pass.
A sandbox-only socket failure was rerun with loopback access and no code changes.
Exact reports, logs and hashes are in `local_private_epoch_qualification`.

### Private output storage (2026-10-14)

`private_outputs` implements native stealth record allocation, reads, claim
mutation, unclaimed totals, claim-hash scans and legacy scan JSON. It preserves
byte strings, field order, duplicate keys, optional legacy fields and native
integer-counter behavior. Claim replay returns the native refusal and leaves the
record unchanged. Standard JSON serialization errors, including non-finite
numbers in retained fields, also leave the record unchanged. Parsing and retained
JSON serialization use iterative traversal.

Mutations require the existing speculative state batch; restoring its savepoint
also restores the allocation counter. This is storage support for the remaining
private send/claim execution work. It does not authorize claims, verify ownership
or replace private transaction proof checks. Committed pagination and by-ID RPC
query adapters remain separate work.

All **54 native storage cases** match Rust, including exact stored bytes and
Irmin roots, with **1,158 pinned native hashes** checked and no instrumentation.
The focused checkpoint passes against **2030 unchanged source hashes**. Three
state-batch recovery tests and strict library/test Clippy checks also pass. Only
the new storage module, oracle, fixture, test and module export changed after the
private epoch checkpoint. Existing execution sources remained unchanged.
Evidence is indexed under `local_private_output_qualification`.

### Concrete finalized import execution (2026-10-14)

`octra_node::executor::Native` replaces the service tests' simplified import
executor. It composes the existing public-money, validator, Circle call/code and
private-balance hosts against the authenticated parent snapshot. It returns
staged effects; the existing publisher still validates the resulting root and
atomically commits state, retained history and ExEx. Unsupported operations abort
without publishing an invented result.

The publisher now retains the exact validator set and receipt policy that
authenticated the certificate in its execution context. Imports and catch-up use
that captured authority for bundle admission and reward attribution. Historical
readiness roots are restricted to the captured parent; missing reads are cached.
Signatures, enabled-operation rules, minimum fees and native proposal byte/count/
scheduled-cost limits cover ordinary rejection candidates as well as confirmed
transactions. Finalized replay continues to exclude ordinary rejection effects
and retain the complete original consensus receipts.

Private execution loads the native `pvac/blobs/<hash>.pk` layout and validates
content hashes. Missing or corrupt blobs leave canonical state and ExEx unchanged.
One blocking worker is shared by executor clones; cancelling its async caller
keeps the permit held until synchronous execution actually finishes. Application
services therefore remain responsive without allowing cancelled imports to
accumulate unrestricted CPU workers.

The combined checkpoint passes **19 tests across six suites**, against **2,033
unchanged source hashes**. It covers authenticated peer imports, live quorum
publication, consecutive and agreed-range recovery, signed Circle execution,
browser HTTP, WireGuard admission/revocation, durable ExEx and process-crash
recovery. Three focused tests cover rejected-candidate admission, native resource
accounting and cancellation ownership. Strict Clippy checks pass. One ignored
crash helper is invoked by its parent test.

A subsequent mixed-import test executes a private withdrawal using native golden
ciphertext followed by a signed public transfer in the same epoch. It checks the
complete expected state, fees and transaction index, absent/corrupt/valid key
files, replay refusal, ExEx and restart. This uses the historical certified
transition profile with local development authority; active proof verification
remains covered by the earlier native crypto/epoch oracles. Only this test changes
after the combined checkpoint; its previous source is archived with a matching
hash. Exact reports and logs are indexed under `local_native_executor_qualification`.

This closes the concrete **finalized import** adapter gap. Production proposal
generation/verification and executable startup remain open, along with the full
Circle HFHE callback adapter, remaining private and VM operations, funded VPN
settlement, OS `oct://` launching and cross-language whole-node recovery. The live
driver test still supplies fixture proposals and synthetic VPN funding. Proposal
verification must generate its own private preverification evidence before voting;
it cannot reuse the certified-transition shortcut reserved for authenticated
finalized imports. No adopted consensus rule was changed.

### Canonical proposal authentication (2026-10-14)

`finality::Publisher::authenticate_proposal` binds signed proposal framing to
one locally resolved validator set, a consecutive canonical parent and historical
execution rules. Parent certificates must match locally retained finality and
membership. A different valid quorum for the same parent block is accepted, as
in the native implementation. Previous epoch time comes from the signed parent
header; database commit dates cannot substitute for consensus time.

Startup requires explicit genesis time and the native protocol activation policy.
With the current protocol active, a missing parent certificate is refused. Local
first-epoch integration tests now explicitly use legacy version 3 before the
version 4 activation at epoch two. This is a development configuration, not a
change to public network activation. Missing time remains unavailable, and native
historical reproposal timing is preserved.

The authenticated context has private fields and exposes no finalized execution
authority. A proposer cannot use it to enter the historical private transition
shortcut. `Node::proposal_candidate` pairs it with the same serving snapshot and
revocation lease. Suspension, resume and canonical advancement invalidate old
candidates. Authentication checks for canonical advancement again after its
asynchronous history reads. Callers must check freshness after execution and
before durable precommit.

The checkpoint passes **30 tests across eight suites**, with **2,036 unchanged
source hashes**. Six focused tests cover forgery, parent mismatch, alternative
quorum signers, signed time, missing startup evidence, restart and a concurrent
commit during authentication. The live four-validator test uses this boundary
and checks candidate revocation alongside Circle browser state, VPN admission,
ExEx and restart. Finalized imports, receipt binding and crash recovery also pass.
One ignored process-crash helper is invoked by its parent test. Strict Clippy and
scoped formatting checks pass; the vendored WASM host retains two existing
dead-code warnings outside the selected Clippy packages.

Publicly retained evidence:

- [Checkpoint and source hashes](checkpoints/2026-10-14/proposal-authentication.json)
- [Combined test log](checkpoints/2026-10-14/proposal-authentication.log)
- [Clippy log](checkpoints/2026-10-14/proposal-authentication-clippy.log)

That checkpoint qualifies proposal **authentication**, not proposal execution or
a vote. The subsequent execution integration is described below. Executable
startup, remaining private/VM/Circle operations, the concrete HFHE callback,
funded settlement, OS `oct://` launching and whole-node native/Rust qualification
remain open. The GitHub development checkpoint retains the accumulated work and
native fixtures without claiming those gates are complete.

### Production proposal execution (2026-10-14)

`executor::Native::verify_proposal` now consumes an authenticated, revocable
candidate and runs local proof preparation, Circle receipt capture, the complete
candidate outcome preview, and the final confirmed/charged partition. It compares
locally generated receipt bytes, rejection records, the ledger/index root and
transaction index against the signed proposal. It returns execution evidence
without granting finality authority or publishing state.

Proposal execution and finalized imports share one staged operation host and
bounded blocking worker. Cancellation retains the worker permit until the job
ends. Private encrypt/decrypt preparation verifies proofs even under historical
non-strict profiles; an incoming transition receipt cannot bypass verification.
Missing or corrupt content-addressed public key files remain unavailable rather
than invalidating the peer's proposal. Circle calls capture their own transcript.
The live consensus test now uses this verifier and checks its candidate again
before durable precommit. Proposal construction and activation are still supplied
by the development fixture.

`preverify_batch` matches **502** cases from the adopted OCaml implementation:
private dependencies, snapshot isolation, ordered Circle capture admission,
resource work limits, callback order and retry coverage. The native oracle exports
an existing private helper through a recorded `.mli` prefix; it does not change
the implementation. Proof verdicts in this selection oracle are supplied inputs,
not a cryptographic qualification. Separate integration tests exercise actual
private proofs and reject forged transition receipts and invalid proof payloads.

The new proposal regression also checks a Circle call with an ordinary rejected
public successor, false rejection reasons, forged Circle bindings, state-root and
transaction-index mismatches, and prepared-candidate revocation across suspension
and resume. Private proposal execution is compared with the golden native
ciphertext/state, then independently finalized, archived, delivered through ExEx
and reopened. These are local fixtures, not whole-node OCaml/Rust interoperability
or funded VPN settlement evidence.

The repository-wide GitHub checks for checkpoint `c90f47a` are not green. The
simulator used the legacy signer and the privileged WireGuard test had an invalid
length peer key; both are corrected in this change. Remaining failures include
unpublished sibling octra-foundry CLI/Kani changes, formatting of maintained and
vendored sources, Docker build context/toolchain drift, a client test Clippy lint,
benchmark regressions, and dependency advisories. The audit reports Quinn
`0.11.16` and Rustls `0.23.45` vulnerabilities, plus maintenance/yanked warnings.
Those checks remain required; the focused node checkpoint does not replace them.

Recorded qualification: **35 tests across 11 suites**, with **2045 unchanged
source hashes**. Two ignored tests are recorded: the process-crash helper is
invoked by its parent test, while the privileged Linux WireGuard lifecycle is
not exercised on this macOS host. Scoped strict Clippy and formatting pass.

- [Checkpoint and source hashes](checkpoints/2026-10-14/proposal-execution.json)
- [Combined test log](checkpoints/2026-10-14/proposal-execution.log)
- [Clippy log](checkpoints/2026-10-14/proposal-execution-clippy.log)
- [Earlier GitHub CI failures](checkpoints/2026-10-14/github-ci.json)
