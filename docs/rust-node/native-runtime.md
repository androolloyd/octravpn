# Native execution adoption

Current release status is summarized in [status.md](status.md). The
[2026-10-15 paid-node checkpoint](checkpoints/2026-10-15/native-vpn.json)
records actual application deployment, private administration, funded UDP/TUN
traffic, TCP continuation across operator restart, matching ExEx and canonical
gateway delivery on an isolated four-validator chain. The
[formal checkpoint](checkpoints/2026-10-15/formal.json) records its exact bounded
proof/model scope. The final local node and HFHE release runs passed 40 and 49
tests respectively; the broader runtime and final Chromium gates retain their
own results. Public snapshot import/join/restart and external Tailscale/TLS
qualification remain open.

## Historical adoption and implementation records

The dated entries below preserve the evidence and limitations of each earlier
snapshot. Their "unbuilt", "untested", "missing" and "remaining" statements
describe that implementation pass, not the current release status. Later source
integration does not retroactively extend an older oracle's qualified input
scope. Use the current status and exact checkpoint hashes for release claims.

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

Startup separates handshake admission from validator membership, matching native
`p2p_config`. Validator lifecycle mode or the exact
`OCTRA_CONSENSUS_ALLOW_DYNAMIC_PEERS=1` setting opens handshake key admission;
authenticated membership independently classifies peers and authorizes votes.
Connecting a new key does not select a validator.

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
The current qualification candidate shares ordered directory pages across
transaction savepoints using pinned `imbl` 7.0.2. Immutable nodes memoize their
native Irmin commitments; edits invalidate only their ancestor path. Authenticated
read proofs reuse these commitments for blinded subtrees. Canonical readers share
one authenticated snapshot, installed after the SQL commit. Subsequent commits
stream changed objects against that persisted parent; initial writes visit
children first and restoration consumes object payloads as it builds the tree.
Native byte-key ordering, hash preimages and stored object encodings are retained.
Public-size bootstrap and final recovery qualification remain required.

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
published Rust store snapshot. It binds the chain identity and typed origin, epoch,
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
node and signer capabilities. Local policy binds the chain/origin/Circle and caps
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

### Dependency and build qualification (2026-10-14)

The signed HTTP lifecycle exposed a deterministic JSON transport bug: the default
float parser changed `1791993600.0000021` to `1791993600.000002`, invalidating the
signature. The shared native signer now requires correctly rounded float parsing.
The regression fails before the fix and passes across 4,096 adjacent timestamp
values afterward. Foundry wallet commands reuse the existing native encoder;
the explicit model signing domain remains separate. No consensus rules changed.

Foundry's AML runner, fail-closed compilation/deployment checks, wallet work bound,
Kani visibility repair and zero-commission mock settlement are published on main.
All 20 sibling checkouts in this repository's workflows pin commit
`995e51af02155bc7178af629c00a74ab0f8f5816`. Regular build/lint jobs use Rust 1.96.0,
matching the repository pin; fuzzing keeps its required nightly toolchain.
The Foundry full suite passed 351 tests; after its dependency security updates,
103 HTTP/CLI/adapter tests, full workspace Clippy and strict audit passed.

The workspace lockfile updates Rustls to 0.23.46, Quinn-proto to 0.11.18, and the
yanked ChaCha20 release to 0.10.2. Its audit has zero known vulnerabilities but
still fails on `unsafe-libyaml` through the headscale CLI. The two build-time
maintenance exceptions already documented in `deny.toml` now also apply to
`cargo audit`. Browser MPL dependencies have package/version-specific license
entries. These are explicit policies, not a claim that every audit warning was
removed.

The Docker builder includes the required vendor tree and uses the pinned compiler
and locked manifests. Both VPN binaries and mock RPC build successfully. The old
Compose lifecycle scripts still assume legacy unsigned submission/events and are
not qualified by this build. Formatting checks every maintained workspace member;
vendor hashes are checked separately. The Circle session adaptation's stale
manifest/patch was regenerated and independently reproduced from the adopted pin.

Recorded node qualification: **17 tests across 7 suites**, no failures or ignored tests,
with **2157 unchanged source hashes**. Both workspace Clippy configurations,
the timestamp regression, and 41 AML tests plus four negative controls passed.
Local source hashes include sibling working trees; fresh-checkout CI remains a
separate gate. Production proposal construction/startup, remaining private and VM
operations, concrete Circle HFHE callbacks, full cross-language recovery and
funded VPN settlement remain open. This is not full-node or mainnet qualification.

- [Checkpoint summary and remaining gates](checkpoints/2026-10-14/security-build-summary.json)
- [Node source hashes and test command](checkpoints/2026-10-14/security-build.json)
- [Node test log](checkpoints/2026-10-14/security-build.log)
- [Current audit findings](checkpoints/2026-10-14/security-audit.json)


### Selected proposal construction (2026-10-14)

`Publisher::proposal_build_context` captures the next epoch, authorized creator,
receipt policy, historical execution rules and authenticated parent certificate
before execution. It derives time from the signed parent (or explicit genesis
configuration), enforces the native interval and checks canonical freshness again
after asynchronous reads. `Node::proposal_draft` binds that context to a serving
snapshot and revocation lease. It grants no finality privileges.

`Native::build_proposal` now derives proposal commitments from a selected staging
batch: signature/payload/budget admission, local private proofs, Circle capture,
candidate outcomes, stable confirmed/charged replay, state/index root and exact
receipt bytes. Build and verification share proof preparation and the staged
operation host. Invalid or unavailable work cannot produce a fallback root.
The live four-validator service test now builds from signed pending transactions;
it no longer supplies a precomputed header or bundle to the leader. The previous
fixture execution remains an independent expected-state assertion.

The builder accepts an already selected canonical batch. Full native staging
selection, private slots, Circle turn/refill, bounded stabilization retry, round
freezing and the production activation/precommit/startup host remain open.
In particular, an ordinary failed VM call followed by a dependent successor can
change the finalized partition; this adapter defers that batch. The host must
reselect it using native policy before retrying. This is an implemented execution
boundary, not a claim that the complete upstream proposal scheduler is ported.

The checkpoint passes **19 tests across 5 suites**, with **2,159 unchanged source hashes**. It covers real private proofs with absent/corrupt/valid key files, exact native
private-state expectations, empty and rejected candidate construction, invalid
signatures, unstable partitions, parent/time authority, concurrent canonical
advancement, lease revocation, native preverification/partition fixtures and live
Circle/browser/VPN/ExEx publication and restart. Strict Clippy passes for both
changed crates and all their targets. Development activation and VPN escrow remain
fixtures; full cross-language node and funded settlement qualification are open.

A final integration refinement retains locally built execution evidence for the
leader's durable precommit; it need not wait for its own proposal to return through
a peer. Both locally built and peer-verified evidence must still have a current
canonical lease. All **seven service tests** and strict Clippy passed again with
the final source hashes. Only that test host and the `Built` API comment changed
after the 19-test checkpoint; both earlier sources are retained and checked against
its source hashes.

The latest GitHub AML run executed all 41 positive tests but its negative-control
log check failed because `rg` was absent. The script now uses standard `grep`;
41 tests and all four negative controls pass with `PATH=/usr/bin:/bin` locally.
The published parent revision passed Lean, TLC, Tamarin, Kani, Clippy, formatting,
headscale parity and privileged WireGuard smoke. Its audit still rejects the
headscale YAML maintenance advisory. Docker built successfully but node startup
failed opening `./state/receipt-vault.bin` as the unprivileged container user;
that writable-directory fix and the old signed lifecycle assumptions remain
required. The benchmark comparison remains unresolved.

- [Scope, remaining gates and evidence hashes](checkpoints/2026-10-14/proposal-build-summary.json)
- [Test log](checkpoints/2026-10-14/proposal-build.log)
- [Source checkpoint](checkpoints/2026-10-14/proposal-build.json)
- [Clippy log](checkpoints/2026-10-14/proposal-build-clippy.log)
- [Final leader checkpoint](checkpoints/2026-10-14/proposal-build-leader.json)
- [Final service log](checkpoints/2026-10-14/proposal-build-leader.log)
- [Portable AML checks](checkpoints/2026-10-14/aml-portable.log)


### Ordered proposal recovery and Linux qualification (2026-10-14)

The selected proposal builder now follows the adopted native ordered recovery
algorithm. Each preview starts at the same immutable parent. It checks exact
candidate coverage, separates paid and unpaid outcomes, cuts off dependent sender
nonces, defers unavailable work and carries ordinary refusal records into the
final proposal. Four previews share one budget and at most one refill; after that,
two reserved previews can retain unaffected senders. A revoked context cannot
return a proposal. The final state comes only from a stable confirmed/charged
preview, checked again against the finalized partition.

The reusable `proposal_build::Host` separates queue selection, local execution and
epoch-bound refusal/hold effects. **661 traces** match unmodified upstream
`Consensus_proposal.make_proposal`, including exact preview requests, rejection
bytes, evictions and holds. The oracle validates all 1,158 adopted source hashes
and uses no source instrumentation. Its execution responses are scripted; actual
Circle/private execution is covered by the separate node tests.

The real `Native::build_proposal` adapter now recovers a failed Circle call followed
by a nonce-dependent successor, and the resulting proposal passes incoming local
verification. The four-validator test also builds from a valid Circle call, a
failing transfer and its dependent successor. It reaches quorum and canonical
publication with the independently expected state, then checks browser reads,
VPN revocation/re-admission, ExEx delivery, duplicate publication and restart.
All **11 tests across four suites** pass with unchanged source hashes. Activation
and escrow are still development fixtures.

The adapter still accepts a selected canonical batch. Full staging selection,
private slots and Circle turn policy, persisted queue changes, typed per-transaction
resource failures, frozen rounds and production startup/activation/precommit
wiring remain open. General operational failures still defer the selected build.
The reusable scheduler's refill callback does not establish that these queue
boundaries are connected to the executable node.

GitHub's workspace test job had failed because its Linux runner consumed the
macOS-only noise budget fixture. A shared CI preparation action now builds the
registry WASM and generates budget evidence from the adopted source pin on that
runner. It is shared by workspace test/coverage and the Circle workflow; the
platform assertion remains mandatory.

Independent Linux ARM/GCC 12.2 reproduction then exposed an actual Rust rounding
mismatch at cancellation boundaries: the native budget was `(0, 10)` while Rust
returned `(0, 7)`. Rust had selected fused multiply/add for every ARM target. It
now retains fused rounding for the qualified Apple Clang ARM build and separate
rounding for Linux/GCC, matching all **326 native Linux budget cases**. The
Linux encryption/decryption regressions also pass **220 recorded vectors** across
four tests. Compiler,
OS and architecture remain part of the qualification scope. Nonstandard budget
vectors do not establish a reachable public-chain consensus bug.

After the integration checkpoint, only that Linux-specific arithmetic choice
and scheduler fixture-provenance assertions changed. Earlier sources are archived
and checked against the checkpoint. Final targeted scheduler/macOS budget tests
and strict Clippy cover the final sources. See the summary for exact commands,
source hashes and remaining full-node gates.

- [Scope and evidence hashes](checkpoints/2026-10-14/proposal-recovery-summary.json)
- [Integration source checkpoint](checkpoints/2026-10-14/proposal-recovery.json)
- [Integration test log](checkpoints/2026-10-14/proposal-recovery.log)
- [Final source checkpoint](checkpoints/2026-10-14/proposal-recovery-final.json)
- [Final test log](checkpoints/2026-10-14/proposal-recovery-final.log)
- [Linux native budget evidence](checkpoints/2026-10-14/hfhe-budget-linux.json)
- [Linux regression before](checkpoints/2026-10-14/hfhe-budget-linux-before.log)
- [Linux regression after](checkpoints/2026-10-14/hfhe-budget-linux-after.log)
- [Linux encryption/decryption regressions](checkpoints/2026-10-14/hfhe-linux-crypto.log)


## Executable local devnet (2026-10-14)

The [local devnet launcher](devnet.md) runs four persistent Rust validators with
authenticated peer services, canonical proposal execution/publication, ExEx,
transaction RPC/gossip, Circle browsing and embedded VPN sockets. Validator
startup now captures canonical membership, restores durable pending locks after
local replay, and catches up through authenticated peer history. Proposals freeze
per round and precommits require current execution evidence plus a durable journal.
Queue admission has a separate canonical lease, so the native proposal time
interval cannot prevent transactions from entering staging between epochs.

Native staging now supplies fee/nonce ordering, selection caps, private slots,
Circle turns and parent-bundle checks to bounded proposal recovery. Confirmed
transactions and recorded refusals retire after canonical publication. The new
selection corpus matches **962 cases** generated from the adopted unmodified
OCaml source; the previous bounded-recovery corpus still passes.

The final combined checkpoint passed **15 tests across six suites**, with
unchanged source hashes. It covers signed transfer propagation, a committed
Circle asset, progress with one of four validators offline, restart/catch-up,
identical transfer ExEx events, genesis tamper rejection, private proof execution
and the existing VPN/browser/recovery integration cases. Strict Clippy, format
and native source integrity checks pass. A separate four-process deployment
was started, cleanly stopped and restarted with retained keys and journals;
all four processes resumed with matching committed roots.

The Docker runtime now owns its relative state directory. A built image running
as its unprivileged user successfully writes the declared volume while its root
filesystem is read-only. This validates the permission repair, not the entire
container deployment or workspace CI.

The local launcher denies funded VPN sessions until a settlement Circle is
configured; it does not synthesize escrow. Circle HFHE callbacks remain
unavailable. Remaining VM/private operations, complete RPC compatibility,
persisted pending queues, legacy lock reconciliation, public-node interoperability,
OS URL registration and broader CI gates are still open. This checkpoint does
not qualify the complete lite node or a mainnet deployment.

- [Scope and evidence hashes](checkpoints/2026-10-14/native-devnet-summary.json)
- [Source checkpoint](checkpoints/2026-10-14/native-devnet.json)
- [Combined tests](checkpoints/2026-10-14/native-devnet.log)
- [Strict Clippy](checkpoints/2026-10-14/native-devnet-clippy.log)
- [Persistent deployment after restart](checkpoints/2026-10-14/native-devnet-restarted.jsonl)


### Native Groth16 and VPN private administration (2026-10-14)

The Rust VM now implements `GROTH16_VERIFY_BN254`, bringing its executable
instruction subset to **75 of 139 forms**. It reads native `OG16V1` verification
keys and `OG16P1` proofs with canonical big-endian BN254 coordinates and scalars,
rejects infinity and invalid curve/subgroup points, and preserves the native
32-public-input cap. The implementation uses the existing pinned Arkworks
versions already used by the private-admin prover.

Execution preserves the native 50,000 fixed effort and 20,000 per public input,
including the native false result when dynamic effort is insufficient. Update
verification requires all three native proof-execution, FHE-work and math gates.
A verifier outage remains operational unavailability for active updates; view
refusal and resumed-host state follow native behavior. Circle updates and views
use this verifier through their authenticated execution context.

The unmodified pinned OCaml/MCL reference supplies 169 cases for raw/base64 input,
strict types, malformed encodings, canonical field limits, infinity, activation,
effort, synchronous/stepped/asynchronous completion and missing workers. Public
algebraic verifier vectors cover 0, 1, 6, 31 and 32 inputs, plus over-limit
rejection. These vectors are not deployment keys.

A second native oracle compiles the current `program/main-v5.aml` and replays its
constructor and private administration with public development proof material.
The Rust differential compares return values, effort, events and committed
storage after every call. It exercises action substitution, cross-program
replay, malformed proof rejection, successful authorization and nonce replay.
The Circle integration test starts from the native constructor's output and
checks real proof execution, rejected-call rollback and a subsequent nonce view.
It does not claim a Circle deployment or funded account transition.

Evidence: [qualification summary](checkpoints/2026-10-14/groth16-summary.json),
[source checkpoint](checkpoints/2026-10-14/groth16.json), and
[test log](checkpoints/2026-10-14/groth16.log). The checkpoint now hashes AML
sources alongside Rust sources, fixtures and sibling dependencies.

The running devnet still denies paid VPN admission. The existing VPN constructor
uses legacy contract deployment; Circle deployment installs code without running
that constructor. An authenticated Circle initialization/deployment path and a
pinned canonical settlement reader remain required before funding and tunnel
qualification. Other missing VM families, OCPG admission, Circle HFHE callbacks,
public-network interoperability and full recovery qualification remain open.

### Snapshot checkpoint and manifest verification (2026-10-14)

`octra-node-protocol::state_sync` ports checkpoint commitments, manifest layout
and hashes, draft binding, certificate parsing, signer configuration, checkpoint
quorum and exporter signatures from the adopted `7f9be448` source. Bootstrap
signer sets retain the native base64 public-key representation in their set
commitments. Quorum verification uses the chain's epoch-dependent weight rules.

The native oracle covers 812 cases: valid commitments and signed messages,
duplicate fields/signers, malformed keys and signatures, hash substitution,
expiry boundaries, chunk gaps/overlaps, path traversal, integer overflow and
reference-snapshot file restrictions. It compiles the unmodified adopted source
in an offline container and records every source hash. The Rust differential
passes all 812 cases and checks the oracle, generator and runner hashes. Strict
Clippy and formatting pass; qualification confirms unchanged source hashes
before and after execution.

Certificate parsing and draft verification do not authenticate a public
snapshot. Finalized authority still requires the native `Sync_anchor` validator
transition chain and Irmin state proofs, followed by authenticated snapshot
download/import and public-network startup. No import authority or canonical
state is produced by these low-level APIs; the running gateway remains on the
isolated Rust devnet. Native snapshot export/signing and filesystem I/O are
outside this checkpoint's scope.

Evidence: [qualification summary](checkpoints/2026-10-14/state-sync-summary.json),
[source checkpoint](checkpoints/2026-10-14/state-sync.json),
[Rust comparison](checkpoints/2026-10-14/state-sync.log), and
[strict Clippy](checkpoints/2026-10-14/state-sync-clippy.log).

### Program admission implementation in progress (2026-10-14)

The current worktree adds the native OCPG compiler-attestation domain, ordered
certificate parsing, bytecode/provenance/facts commitments, effect-graph
summaries, internal-call cycle/depth limits and bounded fixed-point type flow.
The JSON writer preserves byte strings, integer literals and duplicate fields;
attestation payloads sort object keys with the native stable byte ordering.
Allocation failures remain operational failures at the runtime boundary.

Admitted profiles now travel through Circle deployment/update checks, calls and
read-only views. Program calls decode parameter kinds from the selected entry's
facts and run with strict values; opted-in Circle calls use declared storage
kinds. Public-network runtime construction captures the configured program
release keys. Descriptor reads use source-style certificate validation, as the
adopted native descriptor path does. Opaque deployments still require a trusted
compiler attestation. This does not enable source-package compilation: independent
AML recompilation remains an unfinished integration boundary.

The worktree also adds native `STATE_PATH_KEY` execution with state-reference
normalization and its separate hash domain. These changes are unbuilt and
untested. They do not extend the qualified opcode count or the evidence recorded
above. Native differential comparison, negative certificate/type-flow cases,
combined node recovery and final end-to-end qualification remain pending until
the requested implementation phase is complete.

### HFHE VM and Circle host implementation in progress (2026-10-14)

The worktree now implements the OCTB HFHE key/cipher serialization, arithmetic,
seeded multiplication, commitments, Pedersen point operations and zero/range/
bound verification families over the Rust PVAC library. Native resource planning
covers projected cells/layers/words, sampling effort, key I/O and gross retained
volume. Nested VM calls share the retained-volume capability; journal rollback
does not refund consumed volume. Proof input/shape caps, prior/active decoding,
capability checks and operational verifier failures remain explicit.

Circle OCTB updates and views load HFHE permissions from the committed inline
policy records. Ordinary calls carry no scoped active key or relay. The public
key capability resolves an address through canonical `pvac_hashes`, then reads
and hashes a bounded regular blob; missing/corrupt bound data is unavailable.
The launcher shares that content-addressed reader with private preverification.

WASM `fhe_` methods now receive the direct-call policy capabilities and public
keys rather than an unconditional unavailable result. Native key loading costs
reduce the available fuel, and the signed execution binding includes the sorted
capabilities and public-key inputs. Non-HFHE methods retain their empty context.
Scoped key-pair/relay/receipt contexts still require the remaining private Circle
integration; these direct-call paths do not imply that those contexts exist.

This is unbuilt and untested implementation work. It does not extend the
qualified VM/HFHE counts above. Full native differential, resource-exhaustion,
stateful Circle and combined sync/restart/tunnel gates remain for the final test
phase after implementation is complete. The running pinned devnet and gateway
have not been replaced by this worktree.

### Object and integer/Q16 execution implementation in progress (2026-10-14)

Object membership queries and atomic transition planning now have Rust paths.
The planner normalizes references, parses member deltas, checks bundle hashes,
policy windows, transition permissions, proof/receipt shape, quorum and previous
state, then produces ordered writes. The VM charges the complete plan and checks
value sizes before writing through its undo journal. Circle updates and views
carry the historical object-scan rule. The default quorum conversion retains the
adopted native machine-integer behavior; exact comparison is an explicit VM
option, not a change to the public-network profile.

Integer matrix/dot/elementwise operations, byte loaders, ReLU and shift rounding
now have VM paths. Activated integer work captures operands before charging;
the prior path reads live memory, preserving its behavior when spans overlap.
The Q16 layer implements the native integer exponential series, rounded matrix
products, normalization, SiLU, rotary positions, grouped attention, byte loading,
vector append and argmax. Allocation, numeric parsing and retained-vector charges
follow the native execution paths. These operations use no host floating point.
Native admission still rejects the separate host-float instruction families.

All of this remains unbuilt and untested. Existing differential runners can now
select the object and math modes, but no new oracle fixtures or qualification
results have been generated. Source compilation, scoped private Circle contexts,
managed private execution, funded VPN settlement and combined final qualification
remain unfinished. The qualified counts and live pinned services are unchanged.

### Stealth send/claim implementation in progress (2026-10-14)

The worktree adds native V5 private-transfer plans. A send checks its ciphertext
commitment, both range proofs and the amount-binding proof before debiting the
encrypted balance and creating a key-bound stealth output. A claim checks the
recipient-bound secret, output status/marker, ciphertext commitment and proof
against the output's stored amount commitment before crediting the claimant's
encrypted balance and marking the output consumed. Public value moves only for
the declared fee. The output records retain native field ordering and claim
serialization through the existing storage adapter.

Plans are bound to the transaction and current encrypted balance; claims also
retain their source output for rechecking. Ledger fees, nonce changes, encrypted
balances and output writes share a rollback boundary. Epoch execution now carries
both FHE and stealth caps and the shared encrypted-debit limit. Proposal
preverification emits native transition hashes for sends/claims, while active
epoch execution repeats the proof checks and compares the certified transition.
Historical receipt replay remains limited to its exact prepared hash. Local
resource failures remain unavailable rather than invalid transactions.

These paths are unbuilt and untested. No new native fixtures, stateful results or
qualification claims have been published. Independent source compilation,
remaining Circle/private contexts, funded VPN
settlement and combined final testing are still required. The live devnet still
uses its previously qualified pinned executable.

### Key-switch and migration implementation in progress (2026-10-14)

The worktree adds the native key registry envelope/canonicalization rules,
migration selector and compatibility-field parsing, ciphertext/key classifiers,
and sealed key-switch plans. Empty-balance registration, equality-proof refresh,
public-history and commitment-history migration, verified zero reset, historical
owner proof and historical-cipher/current-range proof paths are implemented in
source. Their source hashes, refresh limits, proof profiles, short key hashes and
prepared-transition commitments follow the adopted native paths. Epoch admission
retains owner/cipher activation checks, self-targeting and the FHE operation cap.

Historical authorization comes from the independently configured entitlement
artifact. Public startup verifies its commitment and history floor, and compares
its snapshot root against retained canonical history when that epoch is present.
The execution host receives the sealed parsed artifact, captured modes and actual
epoch. Missing, inactive or mismatched entitlements cannot provide authorization.

The file adapter writes immutable public-key blobs and backend metadata through
temporary files, exclusive publication and file/directory fsync. The canonical
tree receives the full public-key hash only after persistence succeeds. Fees,
nonce, ciphertext and key binding share rollback; old blobs remain available for
retained history. Backend metadata is addressed by the blob hash so speculative
execution does not overwrite another key's address metadata. The stored-blob
transport bound is separate from the unchanged 5MB incoming registry envelope.

Proposal proof preparation now emits state-bound key-switch receipts, including
the native zero hash for an absent old key. Active execution verifies proofs
again and compares its prepared transition; historical certified replay can
apply only the exact prepared hash. Shared private failure handling distinguishes
canonical, user and preverification messages from operational unavailability.

These changes are unbuilt and untested. They have not extended the qualified
private-operation counts or replaced the running pinned devnet. Stateful key
rotation/migration, failed persistence, recovery and adversarial native comparison
remain for the final test phase. Source compilation, remaining Circle operation
hosts, scoped private HFHE contexts, paid VPN settlement and full sync/browser/
ExEx/tunnel qualification remain incomplete.

### Circle operation implementation in progress (2026-10-14)

The source now routes adopted direct Circle operations through resource, policy,
key lifecycle, signed transport and private-cell hosts. Resources share locator
derivation and asset writes with VM effects while retaining their distinct native
validation rules. Policy snapshots retain native defaults, field ordering and
clear/remove behavior. Terminal delivery-key changes materialize outbox and live
claim resolutions in the same speculative transaction.

Outbox open, relay claim, relay cancellation and ingress commit include registered
relay signature checks, claim windows, replacement/capacity rules, count/weighted
quorum, ingress selection and delivery-key checks. Their records preserve native
JSON field order and string-encoded Int64 values. No traffic commission is added.

Balance/register cells now have payload normalization, descriptor/policy/cell
snapshots, HFHE proof-receipt authentication, prepared transition hashes and PVAC
worker resource/proof checks. Proposal preparation checks the complete fee and
storage transition in an isolated preview and creates state-bound receipts;
execution reconstructs their hashes and repeats cryptography under the active
standard rule. Fees, stable storage, resource metadata, ciphertext and indexes
remain inside the existing epoch savepoint. Stored HFHE policy interpretation is
shared with ordinary VM capability checks.

This is **unbuilt and untested WIP** against the adopted `7f9be448` source. It adds
no qualified coverage or public-network result and has not replaced the pinned
devnet executable. Exact JSON lexer conformance and exception rendering remain
incomplete; affected inputs fail operationally rather than receiving invented
consensus outcomes. Independent AML/OCPS source compilation, scoped VM HFHE
contexts, authenticated VPN application initialization/settlement, remaining RPC
compatibility, bootstrap recovery/export and combined native differential,
security, sync, restart, browser, tunnel and ExEx testing remain open.

The adopted lockfile and installed parser source both identify Yojson 3.0.0.
Its Safe value type has no tuple or variant constructors; adding such containers
is not part of this parser port. Its supported extensions include byte strings,
non-finite floats, comments and unquoted identifier keys.

### JSON lexer and exception implementation in progress (2026-10-14)

The parser now has classified modes for `Json_tree.read`, `read_plain`, and
`Yojson.Safe.from_string`. The source follows the pinned Yojson 3.0.0 lexer for
incomplete numeric tokens, comments, byte/line positions, error snippets,
malformed escapes and surrogate pairs. OCaml 4.14 string-argument rendering uses
decimal byte escapes. The wrapped JSON exception constructor was identified in
the installed 3.0.0 bytecode/native library as `Yojson__Common.Json_error`.

Direct Circle operations and code admission use the classified parser. Circle
parameter syntax failures follow the native charged exception path; private-cell
syntax failures retain their native fixed rejection message. Spawn parsing
selects the adopted plain/safe mode. Unclassified and allocation failures remain
operational. Legacy parser callers keep their existing error API.

This is an implementation change, not parser parity evidence: no oracle, build,
test or deployment was run. Full valid/invalid-input comparison, arbitrary-byte
diagnostics, deep nesting, resource failure and transaction savepoint/fee checks
remain in the deferred final test phase.

### Scoped HFHE implementation in progress (2026-10-14)

Local execution can now carry a typed, host-owned scope with the native optional
key, intent and relay identifiers and an optional keypair capability. It is not
deserializable from transaction or RPC parameters. Public transaction contexts
and gateway reads continue to supply no scope.

The runtime resolves live-key policy and active/selected relay status from the
captured state. OCTB updates and typed OCTB views share these checks. WASM update
calls can receive an authorized active keypair for encrypt/decrypt; key image and
secret serialization costs are included in native key effort. HFHE context
bindings include the active key ID and public key, excluding secret material.
Receipt-linked permission follows capture/consume mode, and historical OCTB
receipt execution suppresses verifier capabilities as upstream does.

The WASM host adaptation retains ordinary UTF-8 key-ID inputs and adds base64 ID
transport for local byte-string scopes. Keypair debug output redacts secret
material. The adaptation patch and provenance hashes describe source changes;
they do not represent a successful reproduction or qualification run.

These paths remain unbuilt and untested. Transport-bound key-size edge cases,
private client authorization, and final permission, serialization,
context-binding, nested-call and negative-proof comparisons remain open. Public
deployment and the running devnet have not changed.

### Shared native views and payload admission in progress (2026-10-14)

The query host now has source paths for both OCTB and WASM over one immutable
snapshot. Public application reads use that host without an HFHE scope; trusted
local callers can supply the explicit typed scope. Compute reads have a separate
entry point and retain the native declaration checks and two-billion fuel cap.
Ordinary WASM views keep their twenty-million cap. Return-value byte accounting
is shared with the VM, and view effects never reach canonical publication.

Update and query payloads share native full-input measurement, receipt-entry
reservation, and the sixteen/sixty-four MiB direct/session limits. Measurement
counts native byte strings, including the raw scoped key ID when the local
adapter carries it as base64. Temporary payload JSON and serialized input wipe
their own secret-key copies when released; this does not guarantee wiping all
copies inside the adopted engine. A private admitted-input type authorizes the
base64 metadata expansion at the local engine handoff; protocol admission still
measures the original key bytes. Session replies keep their native limit. Missing
cache capacity remains operationally unavailable.

These are unbuilt and untested source changes. Compute execution, scoped policy,
input boundaries, failure effort, native output accounting, engine-copy handling
and the public bridge all remain in the final qualification phase.

### Resumable snapshot staging in progress (2026-10-14)

Bootstrap now retains a private, destination-bound download workspace and its
last authenticated certificate. Every invocation rechecks that certificate
against current independent trust and combines it with current source manifests.
Verified final files and contiguous partial-file chunks can be reused only after
their size and hashes are rechecked. Torn tails are truncated at the last valid
chunk, and new chunks are synced before they count as resumable work.

An exclusive workspace lease follows blocking file tasks through cancellation.
Each canonical import still uses a fresh temporary directory; only the complete
verified import is published with no replacement of an existing destination.
Reports separate accepted download bytes from reused bytes. The cache is local
recovery material, not finality authority or a published state-sync service.
The active and immediately preceding manifest directories are retained; older
download caches are removed under the exclusive lease during source rotation.

This recovery path is unbuilt and untested. Cancellation, crash/torn-write,
changed trust, corrupt cache, source rotation, concurrent import, disk exhaustion,
reopen and publication fault checks remain deferred. Complete signed snapshot
packaging and serving still require implementation before combined qualification.

### Native ledger export in progress (2026-10-14)

The ledger writer emits the adopted default flat `octra-ledger-image-3` format,
including empty directories, ordered byte-string paths, full-width lengths,
bounded output and the sorted set of external PVAC blob hashes. Tree traversal
is iterative and keeps traversal state proportional to depth.

The `export-ledger` CLI reauthenticates the retained public-network store, captures
one committed head/tree, and writes a private temporary file. Root and byte-count
checks precede fsync and publication to a new output path. Existing files are
never replaced. The report identifies the captured epoch, folded state root,
ledger root and local Irmin commit. It does not produce checkpoint or exporter
signatures, a full reference bundle or a serving endpoint.

This source is unbuilt and untested. Exact native bytes, round-trip roots,
arbitrary-byte paths, empty trees, PVAC references, output limits, cancellation,
concurrent head advance and publication faults remain final-phase checks.

### Legacy view context corrections in progress (2026-10-14)

Committed legacy programs with native `admission="source"` metadata now reload
through source-envelope/fact validation, as upstream does. This marker is read
only from the captured tree; new source deployments still require independent
compilation. Binary deployments retain compiler-attestation checks. Legacy views
have an explicit query entry point and share the native single-verifier allowance
through nested RPC subviews, independently of the calling Circle's HFHE policy.

Canonical application queries now obtain the folded state root from their
sealed captured provenance. OCTB `TREEHASH` and WASM public-read commitments use
that root. Unanchored raw-tree queries retain an empty `TREEHASH` context; update
public reads retain native batch-ledger-root binding. These source changes remain
unbuilt and untested, including boundary, nested permission and root comparisons.

### AML frontend implementation in progress (2026-10-14)

The protocol crate now contains a byte-string lexer and lazy token stream for
the adopted source language, plus native source-versus-prior/forms selection.
The source covers the keyword table, nested comments, newline behavior, decimal
integers with underscores, raw string bytes, the limited escape set, punctuation,
nesting bound, and native line/column error data. Source ownership selection
preserves its lookahead and returns false on lexical failure.

The syntax model now covers the adopted declarations, imperative statements,
expressions and direct forms. Expressions, statements and interned types use flat
arenas, so long operator chains do not recursively clone or destroy syntax.
The parser preserves product association, optional/refined parameters, storage
update desugaring, function modifier ordering, declaration duplicate checks,
locations, imports and trailing-source diagnostics. Lexical and parse errors
retain separate classifications.

Imported syntax is relocated into the destination arena and prepended in native
import order. Scope resolution retains local/constant shadowing, callable-name
handling for `balance`, direct-form opacity and the separate pure-loop index
check. Iterative block/expression traversal handles long statement and else-if
chains. The source shape and diagnostic helpers retain native distinctions.

The `Oct_types` and `Oct_check` ports add directional compatibility, return-flow
checks, storage/map/list paths, inferred constants and cycle checks, expression
and statement validation, optional values and native built-in return classes.
Explicit inference frames preserve validation order; direct AML effects and
uses still require their own elaborator. These checks do not substitute for
that elaborator, bytecode generation, verification or source recompile admission.

The bytecode generator now has its own native type-inference rules, separate
from `Oct_check`, and source implementations of register/label allocation,
storage encodings, option and netstring operations, arithmetic and control flow,
internal/external calls, cryptography/vector builtins and Circle metadata
operations. Iterative emission handles expression, constant and statement
chains. Constructor/function dispatch, parameter/refinement guards, payable and
reentrancy templates retain upstream instruction order and compatibility modes.
The imperative emission entry point requires contracts containing forms to use
the separate linker. Linked emission now accepts the direct-entry set and sealed
host-effect evidence, emits canonical call wrappers and returns their seals
separately from the instruction stream. Whole-image artifact binding remains a
separate required step.

The ABI projection retains native public-function/event ordering, fixed effort,
view/pure flags and fallback argument classes. Program static-storage metadata
preserves field order and declared-enum handling. Runtime scalar input parsing
preserves canonical decimal, tagged/detached encodings, byte strings, unsigned
bounds and public-method/arity errors. The structured core bridge now projects
typed feed values into machine literals and flattened VM arguments, retaining
the native distinction between invalid values and unavailable machine types.

The sealed-form foundation now includes native AML rule identities/schedules,
bounded diagnostic bytes, flat named/core type and term arenas, type validity,
resource-kind and equality-work calculations, unbounded resource arithmetic and
flat effect flows. Flow location order retains both fork branches and zero-count
loop sites. Named lowering preserves binder numbering, validation order, scope,
generated-name avoidance and structural limits.

The independent core checker now implements native linear use, erased bindings,
branch agreement, fold capture restrictions, scalar/aggregate/capability rules,
resource bounds and located/named diagnostics. Its traversal uses explicit
continuations rather than the host stack. Static host-effect sealing runs that
checker, validates declared state/event/fault bindings, records per-origin quotas
and derives host instruction blocks with native register-alias checks. Compiler
blocks and runtime metering share the fixed instruction-cost table.

The core evaluator now has source implementations of flat runtime values,
canonical field values, typed input validation, global capability uniqueness,
sequence padding and iterative evaluation. Static resources, runtime steps/work
and integer-work reservations retain separate native limits and diagnostics.
Erased initializers remain unevaluated; action traces retain upstream ordering.
Host planning combines origin and payload checks, per-site quotas, trace matching,
storage work, failure ordering and unsupported-close diagnostics. Planning
describes host operations; it does not execute them or grant deployment authority.

The artifact codec now includes the generic code tree, canonical natural/signed
integer bits, bit packing, padding checks and transcript framing. Type, ordered
effect-row, resource, value and snapshot records have their native raw/canonical
projections. Resource records retain large derived bounds rather than clamping
to natural limits. AF1 feed transport includes the core lexer, typed value
grammar, attachment and capture-aware substitution. AR1 plain-data results and
the minimal closed-literal OCTB encoder are also present as source implementations.

The machine path now includes shapes, distinct width/cell measurements,
continuation lowering, stack flow, effect indexing and size accounting. Its
independent replay preserves linear slots, native fuel behavior, action ordering
and active sequence folds. Source-mark trees, feed substitution mark transfer,
instruction locations and code-map agreement feed a checked machine-image
constructor for open and closed core programs. Replay and register-layout
vectors share flat immutable lists, keeping cons and unhead constant time
without recursively owned data or repeated shared-tail copying.

The C_octb path now has continuation-to-register lowering, branch joins,
unrolled vector folds and conditional sequence folds. Allocation, free-list
order, erased input registers, linear slots and temporary effect scratch
selection retain their native distinctions. Marked assembly preserves source
spans, live-slot rows and effect layouts. Raw, scalar-open and aggregate-open
encoders include native argument/result guards and sequence padding checks.
An independent machine-profile decoder reconstructs canonical constants,
schemas, open wrappers, result headers and body jumps; image construction checks
open output against that reconstruction. Source and liveness map codecs retain
native coordinate, multiplicity, duplicate-ID and canonical-image checks.
Host-effect layout expansion also checks static site counts and exact block
attachment before resolving expanded labels. Checked program artifacts now have
native term/binder encoding, raw reconstruction and canonical decoding, including
the distinct vector-spine fuel and fold-length reconstruction rules. Static
certificates bind the selected epoch rule to a rechecked program, output type,
ordered effects and resource bounds. These paths still require their final
differential and boundary qualification. Whole-source artifact packaging,
proof-bound map checking, stateful artifacts and source admission integration
remain incomplete.

### AML call evidence and direct-form linking in progress (2026-10-15)

Host-effect evidence now has a canonical full-record codec. Decoding restores
the registry, rechecks and seals the program, regenerates layouts, host blocks
and cost metadata, and compares the complete record. Definition conflicts,
duplicate atoms, binding kinds and event width preserve separate validation
steps. Restored fault codes retain signed OCaml 63-bit values; cost metadata
uses integers rather than the more restrictive natural profile.

The call-evidence layer scopes labels, builds scalar input/output guards,
regenerates call segments and binds the proof collection to the enclosing image
hash. Verification checks bytecode structure, unique entries, exact segments,
non-overlap and the final image stamp. Label identity remains 63-bit until
verification, preserving the distinction from OCTB's 32-bit wire operands.

The C_fun port adds definition validation, capture modes, declared effect and
resource bounds, lexical renaming and explicit function expansion. C_orbit adds
fixed-count and bounded dynamic-count expansion, with type and structural checks
before copying loop bodies. Named syntax uses flat term arenas and iterative
traversal for deep expressions and continuations.

The Oct_form source path now elaborates forms and eligible pure functions,
checks direct calls and explicit uses, and lowers supported bindings, pairs,
branches and bounded orbits. The linker checks callable uniqueness, call-depth
and recursion, source expression use and transitive effect reachability. Pure
functions reject reachable marked forms; view functions reject reachable writes
and closes. Constants and invariants reject reachable marked forms. Strict
expression checks use their own build cache, preserving the linker's direct
entry set. Form lowering and host-effect evidence construction feed the linked
instruction emitter; a failed link leaves the input AST intact.

The Aml_source composition now connects parsing, shape and loop checks, form
linking, generation, bytecode verification and state metadata. It encodes call
proofs against the image without a proof field, encodes the final bytecode, and
verifies the proof binding before returning a raw compiled artifact. Single
sources and interface imports use their distinct native paths. Bundle loading
caches source bytes, imports only selected interfaces and preserves source-path
diagnostics. The verifier exposes typed failures for source diagnostics while
the existing admission wrapper retains its previous failure messages and order.

The Oct_compile fact projection now records constructor memory, scalar storage,
entry points, instruction ownership and typed internal calls. External-call ABI
attachment retains the count and capacity checks. These facts still require
policy completion and type-flow verification before they can support admission.

These are source implementations against the adopted upstream, not executed
parity evidence. The prior-core parser/packaging path, proof-bound artifacts and
stateful execution still need their remaining integration. No build, test,
oracle, commit, push or deployment has been run for these changes. Validation
remains deferred until implementation is complete, as requested.

### Source and Preview Program packaging in progress (2026-10-15)

The compiler now has source paths for the native existing and structured Source
ABI formats, including their distinct string quoting and constructor/parameter
metadata. The advisory Aml_verify report includes ordered findings, write/call
summaries, signed-value and unsigned-arithmetic heuristics, transfer warnings and
derived/declared supply invariants. Report serialization retains its native rule
trace and field order because the exact bytes feed the verification hash. The
report's `verified` field is the upstream AST classification; it does not show
that Coq ran or establish a theorem about this implementation.

Program policy completion now shares graph computation with policy verification
and derives each entry's transitive effects. Facts retain separate compiler JSON
and canonical hash projections. The compiler combines bytecode, report and source
hashes into native certificates, checks typed bytecode facts, and packages the
certificate and code in an OCPG envelope. Optional Ed25519 attestation accepts a
typed signing key and replaces existing attestation fields without serializing
the secret key. No signing operation has been executed for this work.

Source and Preview OCPS paths normalize bundles, reject unused sources,
independently rebuild their envelopes, compare the full bytes, and then perform
source admission. Preview retains the native fallback to Source when rebuilding
the supplied envelope. Operational unavailability remains separate from a
deterministic rejection. Protocol/prior compiler mode has not been aliased to
Source. The historical Protocol and frozen Prior paths are described below.

These paths are still unbuilt and untested. Source admission is now wired in the
speculative Program deployment source described below; no live deployment or
admission policy has been enabled. Compiler qualification, the standalone core
surface grammar, remaining artifact/RPC integration and final native byte
comparisons remain open.

### Historical Protocol compiler in progress (2026-10-15)

The emitter now has an explicit historical backend, separate from Forms/Source
surface syntax. It preserves Protocol map separators, path/list suffixes, option
presence keys and the reentrancy lock namespace. Protocol inference retains
its weaker scalar/container classification, operand visit order, context-name
shadowing rules and direct-form rejection. The backend shares unchanged emission
primitives with Source rather than translating historical programs through the
Source compiler.

Protocol call emission retains missing-argument zero filling and ignored extra
arguments. Historical list deletion, unchecked list pop, tuple unpacking, option
key reevaluation and range-register allocation have their own source paths.
The loop compatibility flag retains the adopted historical scope behavior.
Source-only type/arity checks and source guard templates are not silently added
to those paths. Native generator failures and source diagnostics keep their
different projections.

The Protocol compiler composes these paths with optional checked-source
validation, native ABI/report generation, certificates and Program envelopes.
Its strict and first-interface loaders retain separate selection, duplicate,
ambiguity, missing-source and provenance rules. Package mode selection now
includes Protocol when point operations are active, along with Source, Preview
fallback and source-to-Protocol transition admission. Each implemented package
path rebuilds and compares the envelope before returning source admission.

The pre-activation frozen Prior path now has explicit lexer, parser and emitter
modes. It retains its older type grammar, context expressions, unlocated
statements, compound-update desugaring, duplicate-declaration behavior and lack
of scope resolution or trailing-source checking. It excludes newer Pedersen
helper builtins and uses pre-activation opcode admission. The compiler preserves
the frozen single/multi-source exception boundaries, including its facts-first
Program result projection. Reports share unchanged rules over the frozen AST
domain. OCPS pre-activation compilation now selects this path.

All new compiler paths remain unbuilt and untested; native diagnostics,
bytecode, report/hash, package, boundary and historical-rule comparisons remain
required. No qualified parity count, published release or running deployment
has changed.

### Program execution integration in progress (2026-10-15)

Native contract identity, upgrade payloads, metadata, ABI records and immediate
storage entries now have Rust source paths. A Program journal carries deploys,
guarded upgrades, storage overlays, Circle overlays and native snapshot effort.
Opaque binaries require normal admission and attestation. Source artifacts can
enter execution only after rule-selected package rebuilding and full envelope
comparison; persisted source markers are read from authenticated host state.

Constructor and dispatcher execution retain typed entry parameters, storage
kinds, epoch opcode checks, duplicate-deploy behavior, arity diagnostics,
constructor limits and active/legacy rollback boundaries. Program calls and
SPAWN use the Circle/value journal for nested execution. The SPAWN host now
receives the caller's live storage and reloads it after a successful child;
constructors remain outside the staged storage map until successful deployment.
Failed child effects restore value, Program and tree snapshots while retaining
consumed execution budgets.

The speculative epoch source now dispatches deploy, Program deploy, contract
call, Program exec, multi-exec and upgrade operations to this host. It retains
fee/refusal ordering, source-address checks, guarded owner/hash upgrades, native
receipt projections and shared multi-call budgets. Startup captures the native
multi-exec call limit. Successful Program effects stage before value commits,
and confirmed transaction archives receive their auxiliary receipts.

This is **unbuilt and untested WIP**. Remaining source surfaces include standalone
core parsing, view/receipt RPCs, compute transitions, complete signed
snapshot serving, VPN settlement qualification and public-network startup.
Final compilation, lint, native differential, adversarial transaction, nested
reentrancy, persistence/restart, sync/recovery, ExEx, VPN and cross-device HTTPS
qualification has not begun. The pinned running devnet and qualified evidence
remain unchanged.

### Compiler tooling RPC source in progress (2026-10-15)

The compiler RPC projection now covers single-source and multi-file AML,
automatic Program package selection, source/path/file limits, positional
parameter diagnostics and deterministic contract-address derivation. Program
requests return the envelope and deploy package; ordinary contracts use the
native Forms/Source selection. Verification and certificate JSON remain separate
response fields. A native assembler text emitter supplies disassembly, including
raw quoted bytes and numeric argument counts. Its opcode names come from the
adopted Bytecode.op_tag table.

Native HTTP/JSON-RPC source now exposes compilation and address derivation on
the operator listener. Request framing retains batch order, native parameter
depth/string and admission-count limits, positional parameters and byte-preserving
IDs. Response limits measure IDs before serialization and retain the native
bounded-ID refusal. An exclusive compiler worker holds its permit through
blocking completion, including when the requesting HTTP future is cancelled.
Compiler rule selection comes from the captured canonical epoch; assembly
compilation retains its native pre-activation admission policy.

Assembly input preserves signed machine operands until verification and policy
checks, retaining duplicate-label and register diagnostic priority before wire
truncation. Its accepted instruction surface is taken from the adopted parser,
separately from the broader disassembly table. Zarith invalid-digit diagnostics
come from the locked 1.14 source. Immutable Program reads now project metadata,
native list pagination, explicit storage keys and bytecode. Public storage dumps
retain their native disabled response.

These source paths remain **unbuilt and untested**. Source-record and ABI/source
integration are described below. View/receipt source additions follow; the remaining
read/write RPC methods still require implementation. No compiler RPC has been enabled on the
running node. Request/response limits, worker cancellation/concurrency, assembly
diagnostics and wire bytes, captured modes and storage/metadata comparisons all
remain final-phase qualification work; this adds no qualified compiler evidence
or deployment authority.

### Program source records in progress (2026-10-15)

Source verification now has native string/project input shapes, main-path
reservation, bundle limits and historical compiler search. Source-admitted
Programs try all seven upstream compiler/loop configurations in their native
evaluation and selection orders. Binary deployments try the Source/Forms and
historical Protocol paths. Matching uses the complete deployed artifact hash;
candidate selection retains existing compiler buffers rather than duplicating
their bytecode for the search. Noncanonical stored base64 is rejected.

A private verification result binds the requested address, source bytes, ABI,
AST report, certificate and deployed-code hash. Binary matches return metadata
with `published=false`. Source-admitted matches recheck the current code hash and
admission marker before publishing. Verification jobs retain their own exclusive
lease through compilation and publication, including HTTP cancellation. This
`verified` response means the supplied source reproduces a deployed artifact; it
does not establish that Coq ran or prove the program secure.

Auxiliary records use the native versioned JSON and address/hash keys, including
the legacy-key read fallback. A SQLite write transaction acquires its lock before
checking either key, refuses conflicting content and confirms the saved record
before committing. These records do not enter the ledger tree, consensus
certificates, canonical epoch history or ExEx. ABI/source reads recheck current
metadata after record lookup, and derived ABI methods remain the fallback when
no usable published ABI exists.

This is **unbuilt and untested source**. No record has been compiled, published or
qualified through these paths. Compiler fallback, conflict/race/cancellation,
malformed-record, byte/hash/JSON, storage-failure and restart cases remain part of
the final test phase. View/receipt source additions follow. Remaining RPCs,
standalone core parsing, compute, signed snapshot serving, VPN/public-network
integration and combined qualification remain unfinished. The running pinned
devnet and all qualified counts remain unchanged.

### Program views and receipt publication in progress (2026-10-15)

Program calls now use one captured committed tree and its next-epoch anchored
rule profile. Nested legacy calls share the native byte/FHE budgets and single
verifier allowance. JSON argument subtrees share an immutable arena without
serializing or copying their payloads. Source admission reloads use the same
artifact loader as transactions. Optional storage comes from the captured tree,
with the native 64-name page and 4096-byte value limit.

The view slot is separate from consensus and compiler workers. A shared
monotonic ten-second deadline stops VM instructions on timeout or cancellation;
the blocking worker keeps its lease until it exits. Views accept no canonical
writer. Program-call aliases project native result values and error categories.

VM receipts now travel from the final replay through publication, including
calls rejected after charging a fee. Auxiliary hash/epoch records publish in the
same SQLite transaction as state, finality history and ExEx. Each must belong to
a confirmed or rejected transaction in the authenticated epoch; overlapping
confirmed archive receipts must agree. Lookup is bounded by the caller's
published snapshot and checks the retained bytes' checksum. Reopening an older
store indexes confirmed receipts already retained in its outbox in bounded
pages; absent historical failed-call receipts cannot be reconstructed. Receipt
RPC aliases retain native Safe JSON and legacy raw-string projections.

All of these changes are **unbuilt and untested source**. No new deployment or
parity evidence is claimed. Cancellation, concurrency, anchored profiles,
snapshot consistency, receipt rollback/restart/rejection handling and native
RPC comparisons remain for the final qualification phase. The live isolated
devnet and Tailscale gateway still use the previously qualified binary.

### Circle RPC read integration in progress (2026-10-15)

Circle info, raw program, descriptor and view routes now have public and
authenticated aliases. Their gates follow upstream privacy classes: sealed
metadata can be public, private program/view reads require the owner, and a
storage snapshot always requires the owner's signature. Public view calls use
the native zero caller. Authenticated subjects retain Safe JSON parameter
hashes, v2 length framing, safe public-key checks and the guarded legacy signature
fallback. These signatures authorize reads and do not replace transaction nonce
or private-admin replay checks.

Browser and RPC descriptors share one snapshot-bound implementation for code
hash validation, OCTB method extraction and WASM manifest descriptions. RPC
Circle views use the captured next-epoch profile, native parameter limits and
two execution slots. The deadline includes authorization work. A cancelled
blocking worker retains its slot; OCTB instructions consult the shared stop
clock, while synchronous WASM execution remains bounded by its native fuel
allowance and retains capacity until it returns. Metadata, address derivation,
ABI fallback and receipt decoders share a separate bounded read worker pool.

This remains **unbuilt and untested source**. No live RPC or browser service was
replaced. Native privacy/signature/error/JSON comparisons, concurrency and
cancellation, browser regression, and recovery qualification are deferred to
the final phase. Additional owner-authorized reads follow below. Private-cell
and asset routes, compute RPC and transitions, general node RPCs, standalone core parsing, snapshot serving,
VPN/public-network integration and combined qualification remain unfinished.

### Circle policy, transport and record reads in progress (2026-10-15)

Owner-authorized RPC source now covers transport/HFHE/key policy, stable keys and
bounded storage pages, slot/state policy, state descriptors, outbox claims,
intents and status, ingress packets, and balance/register bindings and workflows.
Each has the upstream public refusal and authenticated aliases. Public refusals
validate required string parameters before touching the store. Authenticated
reads resolve the owner, subject and returned data against one immutable tree.
Epoch-dependent key/lease results use that tree's next epoch. Workflow and
binding references normalize before authentication where upstream does; locator
signatures retain the submitted reference bytes.

Policy encoders preserve native field order, byte strings and the distinction
between integer counters and epoch strings. Storage pages count raw child names
before filtering malformed entries, retain native hash-key traversal order and
refuse blob-backed values. Descriptor materialization follows stored-field
presence. Binding/workflow materialization follows successfully normalized
fields, with absent/default values projected explicitly.

Outbox status computes effective expiry, claim exhaustion and terminal delivery
key resolution without persisting a transition. Relay ranking, eligibility,
quorum/weight summaries and stored resolution precedence follow the adopted
source. Existing transaction status defaults remain separate from optional RPC
reads, so missing status records do not become invented open intents.

These are **unbuilt and untested source changes**. They add no parity, security,
deployment or finality qualification. Final-phase coverage still needs native
signature/normalization/JSON comparisons, privacy negative cases, malformed
storage, page boundaries, key/lease expiry, relay ranking/quorum cases and
snapshot/restart checks. No live service, database or key material was changed.

### Circle object queries in progress (2026-10-15)

Object RPC source now includes reference discovery, filtered summary lists,
individual summaries, member summaries, object detail and individual member
detail, with public refusals and owner-authenticated aliases. Single-member
authentication validates all required strings before normalizing the object and
member references, then signs their upstream combined subject. Reads load one
captured Circle storage table and receive no writer.

The reusable query layer preserves the upstream distinctions between discovered
keys, indexed member references and materialized member records. RPC member
references sort the extracted names; the VM's existing key-index traversal is
unchanged. Summary counts can therefore include an indexed reference whose
stored record is invalid, while member summaries omit unmaterialized records.
Discovery normalizes object references and summary lists filter unmaterialized
objects. Object details retain absent/default binding, policy and transition
projections; a descriptor equal to the native default remains unmaterialized
in object detail even when its fields were stored explicitly.

Binding/workflow record schemas now also cover object bindings, members,
policies and transitions. Optional false values retain materialization and
encode as JSON booleans; epoch/version/quorum fields retain native string
encoding. Summary-only member reads do not load unrelated descriptor fields.

These additions are **unbuilt and untested source**. Native RPC/signature/JSON
comparisons, malformed fields, prefix-related member ordering, empty and default
records, object discovery filtering and privacy negative cases remain part of
final qualification. No running node or database was replaced. Asset/private-cell
source additions follow. Compute, remaining node RPCs, standalone core parsing, snapshot
serving, VPN/public-network integration and combined qualification remain open.

### Asset and private-cell RPCs in progress (2026-10-15)

Native asset RPC source now includes public plaintext reads and ciphertext reads
by path, resource key, slot reference and state reference, with the upstream
owner-authenticated ciphertext variants. Input plans retain their native JSON
arena and validate/normalize locators before snapshot capture. Signatures bind
canonical paths or the upstream original locator/resource subjects. Resource
indexes and returned metadata remain tied to one immutable snapshot.

Ciphertext visibility follows the stored locator policy, metadata fallback
epochs, tombstones/revocation and effective delivery-key state. Slot policies
retain the legacy mailbox fallback; state policies do not. Key reads still run
when another flag hides the asset, preserving operational failures rather than
turning a corrupt read into absence. Shared policy rendering also backs the
existing locator-policy RPCs.

Public ciphertext routes use the upstream redaction policy. Opaque metadata
omits address fields; authenticated responses add sensitive metadata, effective
delivery-key status and state descriptors in native field order. RPC reads
return stored encoded bodies without invoking decryption or the browser's
separate bounded serving policy. Metadata schema refusals produce absence;
JSON, integer and allocation failures remain operational failures.

Balance/register cell reads now authenticate the owner against the submitted
state reference, apply ciphertext visibility, and return descriptor, policy and
typed commitment/proof metadata with native materialization flags. Stored
cell-record schemas normalize commitments and proof fields without inventing a
cell from invalid values. Their source paths have no canonical writer.

All of this is **unbuilt and untested source**. Final-phase native comparisons
must cover locator/signature normalization, public/authenticated and
opaque/revealed metadata, missing/corrupt records and indexes, key/epoch
visibility, policy fallback, cell materialization, byte strings and browser
regression. No live service or database changed. Compute, remaining node RPCs,
standalone core parsing, snapshot serving, VPN/public-network integration and
combined qualification remain unfinished.

### Resource-compute evidence source in progress (2026-10-15)

The adopted compute request model now carries native fee, memory, guest and
fuel limits, chain/model/state/program/executor roots, caller/session/sequence
and input/output bounds. Request IDs apply the upstream base, fuel, guest,
memory and fee domains in order. Compute headers retain a distinct caller
intent, coordinator signing digest and caller-signed intent ID. Method/parameter
hashing binds the original parameter JSON bytes rather than normalizing them.

Header source includes the bounded native OCE1 codec, optional-field order,
signed counter interpretation and unsigned memory-size decoding. Header
construction is sealed behind shape checks. It does not authenticate coordinator
membership, authorize a payer, prove funding, or certify execution by itself.

Certificate agreement source validates the captured request and selected signer
set, filters signatures and execution budgets, deduplicates identical votes and
excludes equivocating nodes. Distinct complete-result groups retain independent
count/weight thresholds; multiple qualified groups remain conflicting. Signers
sort by native byte-string node ID for certificate roots. Callback refusal,
nonpositive weights, duplicate votes and the upstream weight-callback evaluation
order retain their separate handling.

These are **unbuilt and untested source additions**. Compute fund/return/settle
transactions remain unwired pending funding permissions, deposits, bills,
anchored inputs and staged ledger integration. Selection/capability/network and
compute RPC/service integration also remain unfinished. Final-phase work still
includes native wire/hash/signature/decision comparisons, equivocation and
conflict cases, optional-limit boundaries and malformed/trailing-byte cases.
No live node, ledger, deployment or qualified count changed.

### Compute funding and billing source in progress (2026-10-15)

Signed funding source now binds payer/public key, chain, target, nonce, fee cap,
coordinator-signed call hash and payment deadline. Header-derived terms preserve
the upstream resource, identity and signature check order. Permissions remain
sealed behind signature verification; deposit records retain native reserve,
strictly-after-expiry return and paid closure states. Their bounded codecs and
request/deposit ID checks preserve ordinary refusal versus operational failure.

Measured work and bills also have sealed constructors. Measurement binds exact
output bytes, trace root, steps, operations and canonical stop outputs. Bill
verification checks the supplied validator-set root, caller and coordinator
signatures, certificate agreement and measured-result equality. Charges use
exact integers, unused funds return to the payer, and certified payees receive
equal shares with the remainder assigned in native sorted-address order. The
host must still anchor the supplied validator set and execution inputs.

Payment-message framing, native fee calculation and the pinned compute-bill
consensus identity now have source implementations. Shared OCE1 framing checks
trailing bytes even after an ordinary decoder refusal, while operational
exceptions remain operational. Nested funding-request decoding retains header
and permission evaluation/error priority. The runtime deposit adapter binds
records to `compute/funds/<request-id>` inside the caller's speculative tree;
it owns no publication or ledger transaction.

All additions remain **unbuilt and untested source**. Anchored input capture,
compute records/replay, transaction fund/return/settle effects, selection and
capability messages, service/RPC wiring and combined qualification remain open.
Final-phase gates include native signing/hash/codec comparisons, nonce/scope and
expiry boundaries, malformed nested/trailing data, payee rounding, stored-record
corruption, duplicate payment, atomic rollback and restart/recovery. No actual
funds moved and the running qualified devnet remains unchanged.

### Anchored compute inputs and execution source in progress (2026-10-15)

The next source batch implements the native public tensor graph parser, stable
JSON graph/layout/model roots, shard manifests and deterministic model cache
plans. Input preparation verifies the retained call origin, validator root and
coordinator signature, then captures public program records and the model graph,
shard manifests and segment assets. Native byte, entry and pin-fee limits apply
to every copied leaf, including repeated copies. Content hashes, stored metadata
and model layout must agree before a plan can be retained. Session model pins
and ordered request uses retain the native 64-use capacity and replay checks;
expired-fund returns release those references. Root records share one checked
codec across the rolling origin ring, per-job inputs and session model storage.

The speculative executor now routes compute fund/return/settle operations to a
dedicated host. Fund and return effects couple nonce/debit, escrow movement,
deposit records and input retention under the epoch savepoint. Active-mode soft
refusals restore attempted effects before charging the declared fee. Operational
failures abort the attempt. Settlement effects handle repeated request IDs,
same-root paid records, aggregate escrow debit, refunds and payee credits, but
require an injected record/session verifier and deterministic replay service.

Protocol source now covers provider capabilities, commit/reveal selection,
offers, cancellation delivery and acknowledgements, fetch/answer messages and
all native message tags, preserving historical limit extensions. Retained job,
read-context and scope codecs bind optional validator extensions to the request;
they do not establish origin finality. Runtime selection admission checks the
anchored origin, signatures, capacity, commitments, reveals, duplicate evidence
and committee root. Session admission checks ownership/model identity, sequence,
epoch order and aggregate work/input budgets. Its bill projection verifies
measurements and rejects a stopped call preceding later session steps.

The settlement admission service loads pinned inputs, checks every deposit,
requires at least one unpaid request, resolves prior origins, seals the session
and requires replay measurements before deriving bills. **The native executor
still has no concrete provider replay implementation connected**: settlement
therefore fails operationally, and this source must not be used for funded public
operation. Provider execution/model loading, compute history and service/RPC
integration remain open, alongside the compiler, snapshot, network, VPN and
cross-device qualification backlog described above.

All changes in this batch are **unbuilt and untested**. Only explicitly scoped
source formatting was run. No tests, builds, native oracles, commits, pushes or
deployments were run; the user's final-phase testing instruction remains in
effect. Required final evidence includes native graph/cache/message/record
comparisons, malformed and conflicting evidence, session replay and expiry,
escrow conservation, charged-refusal and operational rollback, interrupted
capture/release, restart/recovery and real provider replay before settlement is
enabled. The qualified Git HEAD and live isolated devnet are unchanged.

### Native compute replay wiring source in progress (2026-10-15)

The executor now supplies the settlement service with a concrete native CPU
replay implementation. It checks the public program at the model origin and
every call origin, verifies program continuity and code digests, checks the
native executor self-test identity, and loads the retained model. The loader
verifies graph and model roots, exact shard manifests, content types and asset
modes, segment/chunk/shard hashes and cache identity. It streams segments into
bounded chunks and retains a native cache lease through replay. A warm cache
still causes the supplied shard data to be checked, as in the adopted node.

The host adapter adds safe Rust ownership wrappers around upstream cache build,
status and hold operations. Builder close/drop retains the upstream generation
and retirement logic. No interpreter, compute trace, tensor operation, consensus
hash or effect rule was changed. The reviewable adapter patch and provenance
hashes were regenerated as source artifacts; independent patch reproduction has
not been run in this implementation phase.

Replay encodes native OCWR1 requests and the adopted compute replay payload,
retaining the 8,000,000-byte aggregate payload budget and session scope. The
upstream interpreter executes the shared session. Native receipt decoding and
observation rules produce completed, stopped or fuel-exhausted measurements;
the session verifier derives bills from those measurements and signed votes.
Local replay timeout or unavailable cache resources remain operational failures.
The fund/return/settle executor routes are now connected in source, superseding
the missing concrete replay connection recorded in the preceding source batch.

Native provider prepare/execute/self-test/prepared/executed JSON codecs and
environment configuration now also have source implementations. They retain
exact field sets, integer-versus-string numeric rules, ordered storage entries,
duplicate/key/value/aggregate storage checks, address/hash admission, resource
limits and native encoding field order. Replay consumes the shared self-test
decoder. This does not yet implement the external provider service, its model
owner/channel lifecycle, durable compute history, node compute RPCs or network
offer/commit/reveal/result routing.

Everything above remains **unbuilt and untested source**. Only explicit-file
formatting and source adapter/provenance generation were performed. No final
qualification, native oracle, build, test, commit, push or deployment occurred.
Required final evidence includes cache build/drop/lease races and cancellation,
stream boundaries and corrupt model data, executor identity, native replay
receipts and stop/fuel behavior, measurement/bill equality, fee/refund/payee
conservation, atomic failures, restart/recovery and combined node/VPN/ExEx/HTTPS
execution. The broader implementation backlog and public-devnet prerequisites
remain open. The qualified HEAD and running isolated devnet remain unchanged.

### Provider lifecycle and canonical dependencies source in progress (2026-10-15)

The provider owner state machine now has source implementations for native
model preparation, a two-key cache working set, LRU touches and victim selection,
shared cache bindings, generation-bound operation tokens, merged snapshot
aliases, execution leases, recent spent-job IDs, stale-model removal and closure.
The service wraps those transitions with bounded data/control queues, control
priority, request deadlines and native cache holds. Model registration commits
the owner transition only after its native cache hold succeeds. Missing or
changed native cache entries invalidate owner metadata before another reserve.

Preparation and execution run as owned operations. Caller cancellation or expiry
signals the work without discarding its finish/release path. Execution keeps its
cache lease until the worker has actually completed, including after a timed-out
caller has received an error. Stopped providers refuse new work, cancel reads and
model loading, wait for preparation and execution leases to drain and then remove
their model keys. The recent-job list preserves the native bounded in-memory
semantics; durable compute history remains a separate unimplemented boundary.

Concrete provider dependencies now capture immutable canonical historical heads
and compare requested epoch/state roots before using their snapshots. Missing
retained heads are distinguished from database or contradictory-history errors.
Program and storage lookups use bounded read workers; native execution and model
loading use owned bounded workers. The bounded committed-storage reader preserves
raw row order, strict row admission, duplicate raw keys, row-count/byte limits
and encoded-entry size limits. Input-retention and canonical-provider model
loading share the same checked asset/chunk pipeline, with provider cancellation
checked during copying. The native cache drop wrapper retains upstream busy
behavior and guard ownership.

The native provider executes only its captured program/model and stored snapshot
data; caller-supplied program/storage fields are cleared before execution. Single
compute calls share receipt observation rules with replay and use the native
module cache, falling back to full-code transport on cache miss. Provider output
checks retain native fuel, counter, trace and output-limit ordering. GPU settings
remain unavailable with the adopted native CPU engine. This source service is
not yet constructed by node startup or connected to compute network messages or
node submit/status/cancel RPCs.

All changes remain **unbuilt and untested**. Only source inspection, explicit
formatting and adapter/provenance regeneration were performed. The independent
adapter reproduction check is deferred with builds and tests. Required final
gates include owner transition comparisons, queue saturation and canceled replies,
in-flight timeout/shutdown, stale cache identities and eviction races, canonical
root mismatch and historical absence, bounded malformed storage, model-load
cancellation, single-call/cache transport parity, actual provider execution and
combined restart/recovery. No commit, push, deployment or live-devnet update was
performed; the broader compiler, history, service/RPC/network and integration
qualification work remains open.

### Durable compute history source in progress (2026-10-15)

Native compute history key/row codecs now cover integer framing, current and
archived scopes, session readiness/reservation/completion/cancellation, padded
reply allocations, planned/funding/issued/stored job rows, cancellation notices
and relay records. The page-size map-limit policy retains the native 64 MiB
work budget and cancellation/acknowledgement space calculation. Decoders preserve
record-tag priority, bounded lengths, padding checks and corruption refusals.

The new local `octra-lmdb` adapter pins `heed = 0.22.1` for native LMDB storage.
It owns a private user-only directory and the native directory-flock boundary,
uses the same four named byte maps and transactions without TLS, and exposes
scoped reads/writes with actual LMDB page statistics. Only open and initial
resize cross its documented unsafe boundary; runtime resizing, raw environment
clones and mapped byte references are not exposed. This preserves a path to
native page-allocation comparisons rather than replacing them with logical byte
counts from a different database. The adapter is original local source and is
not itself a qualified third-party or upstream artifact.

History startup now binds chain/node identity transactionally. Session creation,
monotonic scope archives, reply reservation, idempotent completion, saved reply
lookup and atomic reserved-space checks have source implementations over the
adapter. Completion compares actual live pages before and after the transaction
and aborts if storage grew beyond the reservation. Closed history blocks new
operations; in-progress transactions retain ownership until they finish. Scope
search uses ordered cursor traversal without imposing an extra archive limit.

Cancellation state/deadline transitions and durable minute-window send, forward,
relay and transit quotas now have source implementations. Queued cancellation
delivery, fair round selection, acknowledgement retention and deduplicated relay
records are transactional and retain the native expiry and capacity rules.

Durable jobs now have source paths for planning, reference-index migration,
funding waits, issuance, padded result storage, fetch counters and idempotent
reads. Reserved transitions compare actual LMDB live pages; shrinking stored
results preserves the native page floor. Incremental pruning uses durable seek
cursors and batches of 32, retaining issued work, stored results and referenced
or paid cancellation records. Orphaned ready sessions and scope archives are
removed only when their final job reference is removed.

Funding observations are sealed values minted from authenticated canonical
history. Observation checks the epoch, chain, ledger root or folded index
commitment, snapshot epoch metadata and native escrow permission. The history
funding transition additionally binds the observation epoch/root, header ID and
stored session scope. Decoding a deposit or presenting a signed header cannot
construct this evidence. Compute service/RPC/network integration remains open.

All changes are **unbuilt and untested source**. The new dependency and its
transitive lockfile expansion have not been resolved. No build, test, native
oracle, adapter reproduction check, store opening, commit, push or deployment was
performed. Final gates must compare native LMDB versions and page behavior,
record bytes and malformed records, identity/permission/ownership failures,
capacity and reserved completion, cancellation deadlines/quotas, concurrent
transactions, job migration/pruning/reservations, funding observation tampering,
interruption, crash/reopen and recovery. Broader node/VPN/ExEx/HTTPS
implementation and qualification gates remain open; the live devnet is unchanged.

### Compute coordination source in progress (2026-10-15)

The compute service now has source components for a captured host view, offer
and capability authentication, bounded offer evidence, delayed reveal promotion,
native committee selection, resource admission and signed call verification.
Distinct signed records remain keyed by their record IDs so selector-level
equivocation exclusion is preserved. Pending reveals retain native total and
per-node limits; offer lookup selects by ordered offer ID. The captured view is
host input and does not establish finality itself.

Client request shape checks and unsigned offer/call construction retain native
caller terms, model commitments, expiry clipping, JSON-list parameters and input
hashing. Request admission requires a sealed funding observation whose header,
current epoch and folded state root match the host view. Provider result checks
bind selected signer, request, output bytes/hash, fuel budget and signature.
Coordinator result admission first updates its durable issued-job record; a
failed history transition cannot add the vote. Provider reservation and retained
reply decoding use the existing durable session history boundary.

Certificate collection uses the native signer/weight floors and complete result
evidence tuple. Retained job restoration rechecks the saved validator extension,
historical request/model roots, coordinator and caller signatures, capability
evidence, commit/reveal selection, resource support and unique result signers.
Decoding a retained job alone does not authorize restored execution or payment.

Provider-flow source now maps offers/calls into captured provider preparation and
execution requests, signs capacity/commitment/reveal/result messages, waits for
the reveal epoch and delegates publication/result admission back to the host.
Execution results are published only after the durable save callback accepts.
Provider completion saves the signed reply and read context against the matching
request, local signer, session and sequence. Coordinator completion projects the
agreed certificate's exact votes and requires the durable issued record to match
before storing a completed job. Saved-plan verification and the planned-to-funding
transition bind the original signed client intent and reserve final record space.

Committee lease source now binds caller/public key/session, model/program/executor
identity, validator commitment and the retained request head. It selects provider
capacity records by signed record ID, derives minimum capacity/expiry across the
committee and rejects reuse when roots, limits or identity differ. Lease storage
prunes expired entries and evicts by earliest expiry with session-key tie breaking;
reused calls retain the original request head and selection with clipped expiry.
The session key uses the native OCE1 domain-separated cancellation-key framing.

Job-registry source now owns active caller leases, result observers, completed
job retention order and abortable computations with actor-mediated completion.
Successful computations must pass the durable completion callback before their
result is exposed. Abort handling runs completion outside the aborted computation;
lease release is idempotent across normal completion, cancellation and shutdown.
Cancellation capacity includes both remembered sessions and active job leases.
Expired cancellation reservations are pruned independently of completed jobs.

Cancellation authorization source verifies caller identity/signature, round origin
and acknowledgement key/address bindings. It can recover matching caller/session
scope from live request evidence or durable current/archived scopes, with pinned
validator checks and current-validator fallback. Retained acknowledgement reads
recheck the notice, complete cancellation message, origin, expiry, round and unique
signers. Committee membership remains a separate receipt-projection check.

The owned history worker now has a bounded queue and one blocking transaction
lane. Queue admission and transactions survive abandoned callers; shutdown is
also owned, drains preceding work and closes history only after active blocking
work finishes. Startup/identity failures are retained as explicit failures rather
than replaced by empty ephemeral history. These lifecycle properties remain
unqualified until cancellation, queue saturation, panic and close/reopen testing.

These are **unbuilt and untested source components**. The service actor,
full job admission/resumption and cancellation/fetch orchestration,
transport delivery, submit/status/cancel RPCs and startup wiring remain open.
Source formatting does not prove type correctness or runtime parity. Final gates
must compare native offer/call rejection order, malformed/equivocating records,
reordered reveals, capacity, funding freshness, history write failure, certificate
conflicts, retained validator changes and full restart/recovery. No tests, builds,
lockfile dependency resolution, commit, push, deployment or live-devnet changes
were performed in this source pass.
Job gates additionally include abandoned observers, cancellation during history
work and finalization, duplicate completion, queue retention, caller/session
capacity, panic/cancellation error mapping and shutdown races. Cancellation gates
include rotated validator sets, corrupt scope archives, forged key/address pairs,
expired/repeated acknowledgements and cached notice replay.

### Compute actor and node wiring source (2026-10-15)

The service actor now owns bounded control/data queues, offer/request/job tables,
funding-read reservations, cancellation routes, committee leases and reveal
delivery. Admission, funding, completion, retained status recovery and signed
result fetches have staged history-worker transitions. A funding timeout leaves
the owned observation running until its reservation is released. Direct compute
waiters cancel their shared job on abandonment; submitted job observers retain
their work. Cancellation, shutdown and replay behavior still require qualification.

Node startup now has source wiring for this service and its native provider
configuration. The host obtains historical roots and sealed funding observations
from authenticated canonical history, takes the active validator snapshot from
the existing peer authority and checks cancellation-round activation against the
anchored rule graph. Message `0x41` has a separate bounded ingress lane; RPC routes
submit/status/cancel through the signed runtime gateway. Shutdown stops compute
and closes its durable history before the canonical node closes. These local
service changes do not alter consensus rules.

Provider opt-in is available through `--compute-provider` on `run` and
`run-network`, the optional `compute_provider` configuration field, and the native
`OCTRA_COMPUTE_PROVIDER`/resource limit settings. Coordination remains present
when provider execution is disabled; unavailable history prevents provider work.

The canonical store also retains a monotonic cache of its verified published
head. Compute and peer announcements use that head independently of temporary
browser/VPN serving suspension during publication. SQLite commit and cache update
run under one owned task, so abandoning the publication caller cannot leave its
previous head cached after the commit completes. This lifecycle change remains
unqualified until final cancellation and recovery testing.

This supersedes the earlier open actor/RPC/startup source items above. It is
**unbuilt and untested WIP**, with source review still in progress. Parsing and
formatting are the only checks performed; dependency resolution, type checking,
native comparisons, restart/recovery, saturation, full node/VPN/ExEx/browser
qualification, commits, pushes and deployment remain deferred. The existing live
devnet still runs its previously qualified binary.

### Native VPN and read RPC source (2026-10-15)

The source pass adds a canonical transaction/rejection lookup index, native
account/history RPC adapters, and durable local queue-drop retention. Lookups
authenticate returned transactions against their containing committed epoch;
rejects are checked against the retained finality/receipt record. Checkpoint-only
history and unavailable observation timestamps remain explicit failures. Status
and proof families still require their genuine native host capabilities.

VPN settlement is now an asynchronous pinned Circle/Program adapter. It checks
current code, receipt domain/key, zero protocol commission, eligibility and escrow
against one immutable tree, with exactly authenticated opening transactions.
Canonical publication notifies lease refreshes; transient failures pause packets
without extending authorization. The client and node now have source for actual
WireGuard session framing, connected UDP return flows and opt-in validated IPv4
TUN transport. Operator discovery uses immutable resources read back before the
anchor changes. See [native VPN source integration](native-vpn.md) for boundaries.

Standalone AML source now includes checked source parsing/lowering and the
session, root, seal, certificate, replay, project and folio artifacts. Public API
coverage is being tracked against the adopted native interface inventory in
`crates/octra-node-protocol/src/aml/core/upstream-api.json`; inventory or source
review is not differential parity evidence.

These additions are **unbuilt and untested WIP**. Only explicit source formatting
and inspection have run. The full implementation pass, dependency resolution,
type checking, native comparison, combined sync/restart/recovery and deployment
qualification remain unfinished. No commits, pushes or live service changes were
performed in this source pass.
