# Rust node qualification status

The [current audit-cache candidate](checkpoints/2026-10-21/audit-record-cache.json)
passes both funded two-hop matrices, all 257 ordinary Linux node tests, 17
signed-finality/cache regressions and strict runtime/default/private lint. Each
matrix verifies actual private funding, nested traffic, restart, provider outage,
finite exhaustion, ExEx agreement and independent encrypted-journal accounting;
owned cleanup is verified. The 8 GiB suite limit peaked at 5,992,402,944 bytes
with no OOM kills. Earlier fixture-environment failures remain recorded.

Resume auditing now rereads exact persisted evidence before reusing successfully
authenticated work. It freshly resolves historical authority and relief on every
record; cache misses authenticate the same captured bytes. Cold startup, root
quarantine, quorum and serving freshness remain mandatory. The generated-fixture
speedup does not establish sustained public-network serving.

The closed nonvoting devnet replacement is restoring the original state and
wallets. The exact restricted cloud UDP rule is approved and saved. Local ingress
activation and an actual funded public traffic/restart/withdrawal canary remain
launch gates. One public operator does not establish a public multi-operator
network. See the [private alpha guide](../operators/devnet-private-alpha.md).

The [previous qualification](checkpoints/2026-10-21/private-funded-multihop.json)
retains its frozen binary hashes, results and initial resource-limit failure.

## Earlier qualification records

The Rust node now integrates native transaction execution, authenticated peers,
the validator driver, canonical SQLite/Irmin-compatible commitments, ExEx,
Circle browsing and a paid VPN service. The adopted reference is lite_node
`d3e834919bd586e81f947d0dae91becc6c43c756`, recorded as source-equivalent to
the pinned `7f9be4489870645cfcc95439638cde40f5da9f50`. Implementation and local qualification
are substantially beyond the earlier implementation-pass records; complete
upstream behavioral parity and public-network deployment remain unqualified.

The normal public observer exited at `2026-10-20T09:36:18Z` with
`queue publication precedes retained cursor`. It was not OOM-killed. Its state
and stopped container are preserved. The
[queue-ordering fix](checkpoints/2026-10-20/pending-cursor.json) passes all 252
release node library tests and both strict host configurations. Its real RPC/QC
regression removes the historical transaction while retaining the newer queue
cursor, rejects stale admission and bad record roots, and closes/reopens the
original journals twice. The minimal deployed-source backport also passed Linux
strict lint, all 240 normal library tests and 36 service integration tests; the
separate Chromium fixture remains ignored. Its source and every executable were
verified, with only the node binary changed. The replacement nonvoting observer
and its existing helpers are running on the original state, keys, configuration,
endpoint and paid plan. Cold restore has completed and the RPC responds. At
`2026-10-20T12:08:51Z`, the observer reported 26 peers and epoch 1,723,019, with
admission suspended for `auditing canonical history`. Current-head and sustained
paid serving remain unqualified. No runtime state or payment plan was reset, and
a stopped-state rollback copy is retained.
The current [packet-guard checkpoint](checkpoints/2026-10-20/private-packet-guard.json)
closes the reproduced composite IPv4 binding bypass with real UID-1000 packet
checks, five Linux scope/recovery checks and strict Linux client lint. Its host
checks pass 380 client tests. Full funded private multihop, legacy standalone
host-exit enforcement and sustained public service remain open.

The [shared-channel class runner](checkpoints/2026-10-20/private-class-bundle.json)
now seals finite allowances for several tariff classes on one channel and receipt
identity, with one shared spending ceiling and relayer fee policy. Partial payment
cannot admit the accepted transport. Recovery reauthenticates every class and
retains every entry-proof quarantine ticket. Both strict host configurations and
all 252 release node library tests pass. Both exact Linux private-payment scenarios
also pass, including real WireGuard traffic, client/operator restart and unchanged
ExEx files after reopen; their containers and volumes were removed. This remains
single-hop qualification. Funded private multihop and the remaining public and
cryptographic launch gates are open.

The [offline initializer](checkpoints/2026-10-20/private-offline-init.json) now
creates payer/index books from the exact node's audited retained state. An
optional `payer.index_seed` path supplies public leaf hints when an empty pool
baseline has been pruned. Its scope, native epoch/root and reconstructed note and
nullifier roots must match retained canonical state. Initialization cannot
publish a serving lease; index sync, spending and transport admission still need
fresh synchronization. Explicit initialization refuses existing stores, and
normal startup never reseeds them. Route consent seals an existing proving-key
path without parsing proving material. Both strict configurations, 252 release
node tests and both exact Linux payment/tunnel/restart cases pass. The reopened
signed-checkpoint test seals two-operator consent offline, checks zero reserved
fees and no head advancement, then reopens the initialized index after genuine
node resume. Linux ExEx recovery preserves all 85 archive files; owned containers
and volumes were removed. This does not qualify funded private multihop.

The [payer startup follow-up](checkpoints/2026-10-20/private-payer-startup-deferred.json)
fixes a reproduced startup cycle: a standalone payer opened its fresh index
before attestation could start. Preparation now validates existing consent and
waits without spending. All 253 release node tests and both strict host
configurations pass. Both earlier funded kernel profiles stopped before any
private pool exchange or native fee attempt and verified owned cleanup. The
corrected funded multihop/recovery/accounting rerun is still pending.

The public observer later exited at `2026-10-20T14:43:47Z` awaiting head
attestation. Its retained state and original container were restarted at
`23:09:49Z`; helpers rejoined the new namespace and the existing NAT rule was
restored. At `23:59:30Z` it had 25 peers and epoch 1,723,940, with admission
suspended for `lag_1493`. It is importing history; current-head equality and
sustained paid service remain unqualified. The payer startup fix does not
establish a cause or fix for this separate public observer exit.

The [public private-service startup](checkpoints/2026-10-20/private-public-startup.json)
now accepts explicit operator, payer or route configuration on adopted devnet.
Offline actions reuse the same retained authority, execution graph and captured
crypto settings; mixed genesis/network inputs refuse before runtime creation.
Native activation anchors and current-head checks remain unchanged. The main
pass has 254 passing node tests, four CLI tests and both strict configurations;
the final factory follow-up passes its three scope/key tests and four CLI tests.
Public stateful private funding and combined sustained service remain open.

`octra.to` now points to the existing relay with TTL 300. Caddy has a valid
public TLS certificate and forwards only to the Circle gateway over a loopback
SSH tunnel. Verified HTTPS returns `503 Node is synchronizing` while the
observer is suspended. `/rpc`, `/app` and `/circles/*` return 404, and HTTP
redirects to HTTPS. Existing relay firewall rules were preserved; only its
previously approved IPv4 TCP 80/443 web rule was added. Public DNS-over-HTTPS
confirms the new A record; the Mac still caches the earlier negative response.
The portal and paid private service are not yet qualified for alpha testers.

The [private proof tracing follow-up](checkpoints/2026-10-20/private-proof-tracing.json)
reproduced 6,600,316 witness-bearing Arkworks spans reaching an enabled host
subscriber. Synchronous proving now uses a thread-local disabled subscriber;
the proof rules and verification remain unchanged. The regression observes zero
constraint spans while preserving the two surrounding diagnostic events. All 29
private-payment package tests and strict package/node lint pass; the integrated
node rerun and corrected funded Linux profiles remain pending. Both prior
profiles stopped before any private exchange or fee attempt and verified cleanup.
One timed out at 600 seconds; the other's old diagnostic omitted its child exit
code. Qualification now records exact child return codes, container states and
failure reasons, with 6 GiB fixture memory/swap ceilings.

The public observer was OOM-killed at `2026-10-21T00:11:33Z` (exit 137), during
those overlapping runs. Its same container, retained state and identity were
restarted at `00:25:54Z`; both helpers rejoined its new namespace and its exact
existing VPN NAT rule was restored. Cold restore is running. HTTPS plumbing is
configured, but portal availability and sustained paid serving are unqualified.

## Successor implementation awaiting qualification

The [earlier observer restart](checkpoints/2026-10-20/devnet-observer.json)
retained its state, identity and paid plan. After cold restore, a five-minute
sample advanced 41 epochs with two to four authenticated peers; the driver was
unavailable in 25 of 30 samples. Current-head and sustained paid admission remain
unqualified. The [indexed restore follow-up](checkpoints/2026-10-20/canonical-restore.json)
passed 38 distinct host storage/recovery checks and strict runtime lint. Its
90 GB stopped-copy experiment returned exactly the same 1,875,192 physical
edges in 175 seconds versus 354 seconds for the old query. This measures that
SQL read, not total startup, and has not been deployed. Cache settings remain
unchanged. The [delegated receipt follow-up](checkpoints/2026-10-20/private-route-delegation.json)
preserves separate public payer and receipt signer identities while retaining
private pseudonym checks. Its 376 client tests and both nested kernel route
cases passed with verified cleanup. Those route cases use public Circle
payments with pinned private TLS, and do not qualify shielded multihop payments.
The [native payer follow-up](checkpoints/2026-10-20/private-payer-routing.json)
adds paused same-book operator groups, complete-target job discovery and explicit
operator-income attachment, including combined experimental node startup. Its
69 release payment tests, 376 client tests and strict checks pass. A new real
native purchase uses the shared book; checkpoint recovery requires both original
income wallets and preserves the 87/77 OU balance assertions. Its single-hop
Linux kernel/ExEx regression passed both exact tests with clean exits and
verified resource cleanup; the private route coordinator is still open.
The [purchase/client phase bridge](checkpoints/2026-10-20/private-route-phases.json)
now opens channels without payment, prepares encrypted client state offline and
binds its transport to the original finite purchase consent before quoting.
Missing state refuses further payment, and standalone scheduling cannot advance
a route-owned purchase. Its 69 release payment tests, 378 client tests, four
benchmark checks and strict client/experimental/default-node checks pass. Both
exact Linux private-payment and tunnel/restart/ExEx regression cases passed on
the same executable, with verified resource cleanup. The native phase test
admits the second purchase; kernel payload still uses the existing first client.
Global route intent,
ordered private funding, staged chain access and funded private multihop remain
unfinished.
The [all-hop consent follow-up](checkpoints/2026-10-20/private-route-consent.json)
now seals complete route consent and creates each job atomically with its
ownership. Receipt keys, targets, prices, caps, fee policies, endpoints and paths
cannot change on resume. Route ownership and single-hop client-phase digests are
anchored in the original purchase, so missing marker records cannot downgrade
them to standalone jobs. Its 69 release payment tests, 378 client tests, four
benchmark checks and strict client/experimental/default-node checks pass. The
two-operator fixture covers interrupted initialization, actual encrypted-book
cold resume and missing-record refusal without operator requests or fees. This
initialization API does not yet fund or open the complete route; no kernel or
public-network qualification was added in this stage.

The ordered private-route controller candidate now composes native funding and
the shared route supervisor. It reserves the host namespace before entry payment,
records arming before changing routes, and moves authenticated native P2P onto
the paid entry before buying downstream capacity. Its device-bound chain scope
uses a separate Linux routing table; ordinary applications remain blocked until
all hops are live. Experimental node, protocol and client all-targets build and
strict checks pass, as do 16 native peer regression tests. These results do not
qualify the new kernel policy, funded multihop operation or cold restart.
Full process recovery and combined native/kernel/ExEx execution remain
unqualified. See the
[controller checkpoint](checkpoints/2026-10-20/private-route-controller.json).

The [startup and retained-entry follow-up](checkpoints/2026-10-20/private-route-recovery.json)
wires resume-only route configuration before P2P startup, starts its controller
alongside initialization and defers spending indexes until a fresh publication.
Its offline consent command seals the original finite jobs. An armed entry can
authenticate an already settled purchase against retained signed execution while
serving is suspended; this creates no fresh publication or new spending authority.
Quarantine revokes the recovery ticket, and replay preserves a later proof anchor.
All 69 release payment tests, 10 publication/quarantine tests, 378 client tests,
four benchmark checks and strict experimental/default-node checks pass on frozen
sources. The same frozen Linux image passed three exact checks for device-bound
connections, authenticated native frames and the table 185/186 policy, including
carrier removal and owned cleanup. Both exact paid tunnel/restart cases passed
with canonical/ExEx reopening, clean exits and verified resource cleanup.
That qualified snapshot still refuses stale kernel state after a crash, and the full funded
multihop/process-restart gate is open. See the
[startup and recovery guide](private-route-recovery.md).

The retained network-plan follow-up is implemented but not qualified.
It seals host ownership before route changes and checks exact retained routes,
policy rules, namespace and device identities before repair. It preserves global
blockers while replacing the detached entry policy, rejects foreign state and
checks privileges before spending. Missing sealed plans cannot become fresh
routes. This does not change Circle accounting or consensus; full funded private
multihop remains unqualified.

The [socket-mark follow-up](checkpoints/2026-10-20/private-socket-mark.json)
passes both strict host configurations, 69 release payment tests and 378 client
tests. Four isolated Linux socket/capability checks pass, but the combined routing
test fails. A real UID-1000 UDP probe confirms that forced interface binding can
evade route-only blocking; adding a terminal unreachable policy also fails to
prevent that packet. Packet-level enforcement is required before qualifying
the private route or deploying this candidate. The failed test and probe
evidence are retained locally, and all owned containers were removed. This
candidate was not deployed. The subsequent packet-guard checkpoint above
supersedes this route-only candidate for composite enforcement.

The [Circle-first prepaid candidate](checkpoints/2026-10-18/circle-first-candidate.json)
derives its receipt domain from the configured public-devnet chain origin and
builds factory-owned Circle custody. Operator and portal Circle assets are the
separate publication targets. The changed AML adds reservation,
charge-intermediate and earnings bounds, plus a same-slot operator-signature
equivocation slash that locks the bond for the affected payer until the
operator's seven-day deadline. Its 51 Rust payment
tests include compiled-AML uint64 overflow and slashing regressions. The pinned
native 15-scenario Circle oracle checks those boundaries; one runtime replay,
the CLI domain-source test and narrow Lean accounting/replay lemmas also pass.
The adopted AML safety report now reports zero errors and four warnings for
the Circle artifact. This checks the native verifier rules, not complete
functional correctness on its own. The
earnings-withdrawal follow-up adds two abstract Lean lemmas and a compiled-AML
wallet-transfer regression while the bond remains locked; the 48-theorem Lean
target and all 23 payment integration tests pass. This remains short of a
compiler/bytecode refinement proof. The
[public devnet deployment](checkpoints/2026-10-18/devnet-circle-deployment.json)
now has a confirmed factory-owned payment Circle, separate finalized
initialization, matching code hashes and on-chain terms. A devnet operator
posted the required 100 OCT bond, pinned its receipt key, published a
byte-verified tariff Circle and sealed a 1,000 OU/MiB offer. A public-devnet
accounting canary registered a payer, deposited 1 OCT, bought a signed 1 MiB
allowance for 1,000 OU, withdrew the operator's 1,000 OU earnings, then returned
the payer's unspent 999,000 OU. The old plan became unable to forward. This did
not deliver Internet traffic. The new Rust
binary adopted the observer's retained state and read both portal and tariff
assets byte-for-byte; that earlier observer kept payment transport unconfigured. The separate
octra.to portal Circle has all six onboarding assets finalized. Public DNS and
TLS are still unconfigured, so the hostname does not yet serve this Circle.
The source-bound receive-only observer rejoined public devnet after a cold
retained-state audit. Its bounded local gateway served all six published
portal assets in one concurrent serving window; another Circle and `/resolve`
were refused. Canonical audits still produce intermittent HTTP 503s, so this
is not sustained website availability. The exact publication and local route
check are recorded in the [site checkpoint](checkpoints/2026-10-19/octra-to-site.json).
An [isolated paid observer candidate](checkpoints/2026-10-19/devnet-paid-observer.json)
now has the same Circle configured, a fresh payer with a confirmed 1 OCT
deposit and 100,000 OU plan, a private control link and a Linux TUN. Its first
signed byte authorization was durably recorded, but the nonvoting observer
correctly refused local claim submission. An explicit HTTPS claim-intake path
for observers has passed focused host tests and the release image's payment
suite, with unchanged locally compiled Circle bytecode. The patched candidate
replayed that exact authorization to public-devnet finality: 1 MiB was purchased
for 1,000 OU, the operator withdrew those earnings, and its Circle earnings
balance returned to zero. The isolated client initially received HTTP 403 on a
paid-control poll while the devnet head was stalled. Once the official head
advanced to epoch 1,717,003, the observer matched its root and admitted the
resumed client. Two HTTP requests to 1.1.1.1 went through the paid TUN and
returned 301 responses; client and operator journals agreed on 2,284 committed
bytes with no uncertain bytes or additional operator earnings. This is bounded
public-devnet traffic evidence, not sustained exit availability. The payment
lease intentionally expires after two minutes without a new canonical
publication. The generic 403 does not identify the exact check that rejected
the earlier poll.
The subsequent source-bound client image adds opt-in `payments --reconnect`:
after a temporary control refusal it reopens the same durable journal without
buying another allowance. A closed-connection regression, client lint and the
image payment suites passed. On the restarted devnet observer it remains alive
through repeated 403s with the original 1 MiB allowance and no queued claim.
When the observer matched the public head, the client reopened its TUN and one
Internet HTTP request returned 301. Client and operator meters both recorded
3,413 total committed bytes with no uncertain bytes; on-chain operator earnings
remained zero after the earlier withdrawal. The paid gate still flaps during
canonical catch-up, so sustained availability remains open.
On a later retained-state restart, the Rust observer authenticated 76 epochs
from the current public secondary state-sync source, reported a successful
HTTP join, and reopened RPC. Its epoch 1,717,317 state root matched the
official RPC, and 15 native peers were observed after bootstrap. The client
then reconnected in a serving window and routed another HTTP request through
the TUN; both journals advanced to 4,542 bytes with zero uncertain bytes,
without another purchase or claim. Canonical-history auditing still closes
paid admission between windows, so this is not sustained paid-exit
qualification.
A later nonvoting replacement retained the same paid client, observer state
and Circle plan. It joined from the secondary source after authenticating 32
epochs, then routed a further HTTP request through the reopened paid TUN.
Client and operator journals now agree on 5,671 committed bytes of the same
1 MiB purchase, zero uncertain bytes and no new claim; the earlier 1,000 OU
operator withdrawal remains final. In a 90-second active-head sample, 102 of
179 half-second status polls found the observer auditing its canonical prefix,
while only 31 found it serving. The diagnostic paired-path image did not
materially shorten the approximately 34-second audit transition. A smaller
SQL read consolidation passed the retained-finality regressions and was
deployed with a receive-only consensus follower. The
source-bound Linux image passed its private four-validator paid TUN gate and
replaced the public devnet observer on the same retained state. It authenticated
78 state-sync epochs, reopened RPC, matched the official root at epoch 1,717,778,
and advanced past epoch 1,717,792 without voting. A 45-second public sample
still found only five serving observations, 30 full-prefix audit observations,
seven driver-stopped observations and three HTTP catch-up observations. The
reconnected client reopened its TUN and received an HTTP 301 from 1.1.1.1
through an explicit paid route. Client and operator journals both reached
6,588 committed bytes of the unchanged 1 MiB purchase with zero uncertain
bytes, an empty claim queue and zero operator earnings after the previous
withdrawal. This follower has not resolved active-head availability; the previous
image remains stopped for rollback. Its exact result is in the
[follower checkpoint](checkpoints/2026-10-19/devnet-follower.json). The earlier
candidate is recorded in the
[paid observer checkpoint](checkpoints/2026-10-19/devnet-paid-observer.json).
A five-minute public-devnet observer soak sampled 30 status responses: its
canonical epoch advanced from 1716663 to 1716687 and peer count reached 18,
but serving was admitted in only five samples. Catch-up and peer continuity
must improve before the observer can back a public paid exit.
A second five-minute soak at the unchanged official head admitted serving in
all 30 samples and matched the official state root. That establishes idle-head
stability, not active-epoch availability.
The paid transport now emits the new operator service statements with a
durable sequence, and the client verifies and journals them, including a
same-slot conflict pair. The [source-bound prepaid kernel gate](checkpoints/2026-10-18/prepaid-kernel-gate.json)
passed with four local validators, real TUN traffic, canonical purchases,
restart, withdrawal, and four agreeing ExEx claim sinks. A Rust-signed
conflicting pair also slashes through compiled AML in the same build. Circle
custody passed a separate [exact-source stock Tailscale 1.104.1 gate](checkpoints/2026-10-18/devnet-circle-deployment.json)
with Headscale 29.5: four local validators, prepaid TCP/UDP/ICMP, direct and
DERP carriage, trusted Circle HTTPS, MagicDNS, exhaustion, instant withdrawal,
restart, reenrollment, replay refusal and four agreeing ExEx sinks. The fixture
cleaned up its Docker resources. Public paid service remains unqualified. No
arbitrary Internet non-delivery proof exists.

The [macOS TUN name gate](checkpoints/2026-10-18/macos-tun-name.json) fixes
logical interface names that previously failed before kernel setup; its 85
crate tests, lint and dependent-package checks pass. Privileged macOS route
setup and a public paid session remain separate tests.

The [native interface successor](native-interfaces.md) and
[compact source map](interface-scope.json) describe the current visibility,
BFT intake/warmup and operator-tool repairs. Canonical snapshot signing requires
an independently authenticated finalized Anchor; local storage consistency alone
cannot grant signing authority. Native physical maintenance remains explicit
unchanged-backend reuse. Profile API comparisons, trusted legacy private-genesis
workloads and public entitlement are separate scopes. The final combined source,
normal artifact and native/workload results are still pending; no historical
count or `full_rust_node_complete` flag is upgraded by these implementation edits.

Private proof reuse now retains opaque local artifacts across unrelated heads.
Required work may promote or join owned jobs, then rebind current source/policy
and create fresh receipts; ordered execution retains nonce, debit, claim and
limit checks. This implementation remains subject to the final combined
qualification and does not change the recorded deployment or parity boundaries.

Public-network startup now captures proposal grace, epoch-tag retention and CLI
proof-worker limits from the same configured profile. Recovery keeps the captured
grace; supplied library runtimes retain their caller-owned limits. These changes
and the cancellation-safe nested traffic diagnostics have source review, with
eight targeted startup/recovery regressions passing. Broader combined execution
remains pending. The [candidate checkpoint](checkpoints/2026-10-18/interface-candidate.json)
records the preceding passing suite and the unresolved mixed Stealth and nested
UDP failures separately. The retained public observer has not adopted this candidate.

The [public Circle reader checkpoint](checkpoints/2026-10-18/sealed-reader.json)
records 335 passing client tests and 371 passing Foundry tests with seven explicit
Foundry exclusions. Public responses no longer need sensitive plaintext hashes;
sealed reads still authenticate every envelope and validate all provided metadata.
Policy cache reuse requires fresh authentication and full policy equality. Key
defaults now agree for programmatic and omitted-table configuration. Strict
workspace lint and formatting pass. The preceding baseline workspace separately
passed 2,774 tests across 241 logical targets with 15 exclusions; those historical
counts are not added to the successor results.

A later mixed-workload child run reached 54 matching epochs across a clean
four-process restart, with independently checked certificates, receipts and
ExEx transactions. Its outer qualification remained false: other jobs changed
the shared Docker inventory during cleanup. This bounds functional evidence
for that earlier source snapshot; the current candidate still needs an
exclusive, source-bound combined run. The combined normal artifact, Linux
traffic scenarios and operator tooling remain pending.

## Recorded local evidence

- The [native integration observer adoption](checkpoints/2026-10-18/native-integration-public-adoption.md)
  installed normal release `fbe1684` after a clean exit on retained epoch
  1,711,611. Two read-only audits preserve the existing canonical/ExEx/archive
  prefix and verify 66 new epochs with 491 transaction events. The later
  guarded RPC sample reached 1,711,685 with exact process/environment identity.
  Catch-up was active, serving suspended and connected peers zero. Paid service
  remains unconfigured; public P2P retention, sustained serving, onboarding,
  DNS/TLS and Mainnet remain unqualified. The saved GitHub snapshot has Headscale
  parity and kernel WG smoke passed, with CI, Proof and Coverage still running.
- The [native integration checkpoint](checkpoints/2026-10-17/native-integration.json)
  records 35 passing scoped gates, 3,516 distinct passing Rust test identities
  across 280 logical targets and nine explicit exclusions. Twenty-one Python
  fixture tests are separate. Seven Linux scenarios executed freshly: framed
  prepaid traffic, stock Program and Circle custody, both two-hop exhaustion
  directions, legacy-v5 private Single and three-hop Program traffic. They cover
  canonical purchases, direct/DERP carriage, paid Circle HTTPS, independent
  hop limits, restart, carrier-loss blocking, immediate withdrawal and ExEx.
  Native comparisons, browser and physical recovery retain their own recorded
  scope; retained Rust results keep their original execution labels. The node
  and administration tool use release builds; the kernel client/operator tools
  use debug builds. The [adversarial review](../audit/octranet-native-integration-2026-10-17.md)
  preserves failures and fixture corrections. These finite results certify
  neither every native profile/schedule nor public paid deployment or Mainnet.
- The [mixed-validator checkpoint](checkpoints/2026-10-17/mixed-validators.json)
  records sixteen finalized epochs with two production Rust validators and two
  hosts around unchanged native consensus/execution libraries. One Standard
  transfer finalized before a clean four-process restart at epoch eight and
  another afterward. Canonical roots, authenticated headers, transaction IDs,
  receipt roots and immutable ExEx transactions agree; retained prefixes and
  validator identities survive the restart. All four validators appear in
  finalized quorums and both implementations create proposals. The
  [review](checkpoints/2026-10-17/mixed-validators.md) preserves initial fixture
  failures and a disclosed report-list alias. This finite Prior/private-genesis
  fixture adds no Rust test count and does not qualify the stock OCaml launcher,
  mixed Circle/private-proof workloads, crash recovery or public deployment.
- The [core parity checkpoint](checkpoints/2026-10-17/core-parity.json) closes
  the concrete gaps found in the current active-node review: driver recovery,
  proposal/proof reuse with fresh authority checks, owned private worker
  processes, captured cache limits, native legacy staging, epoch metadata,
  account summaries and live mesh relay admission. The broad workspace result
  plus corrected complete targets and unchanged HFHE component cover **2,616
  passing nonignored tests across 237 targets**; overlapping reruns are not
  added to that count. Strict lint, normal-feature Service tests and the normal
  production build pass. The [review](checkpoints/2026-10-17/core-parity-review.md)
  preserves initial failures, source applicability and host storage differences.
  Separate actual Rust/OCaml peers, private-process failures, Chrome application
  and gateway checks, four-validator prepaid kernel traffic, Single-mode traffic,
  and stock Tailscale persistence/forced-DERP/live-ACL checks have their exact
  scope recorded. That checkpoint's stock-client tests use a standalone
  self-hosted mesh; they do not qualify paid stock onboarding, system DNS,
  public `octra.to` TLS or portal funding. Its public observer adoption is
  recorded separately below. Complete
  upstream behavioral equivalence, whole experimental HFHE library parity and
  Mainnet are not certified by these local results.
- The [retained-audit checkpoint](checkpoints/2026-10-17/audit-reuse.json) records
  1,744 passing tests across 23 targets, 39 unchanged bounded Lean theorems,
  strict lint and a normal-feature Service regression. Audit-only reuse keeps
  fresh evidence and validator-authority reads on every lookup; startup,
  publication and exported records retain full verification. Six deterministic
  controls and the composed service test cover the corrected shutdown race.
  [Review and limits](checkpoints/2026-10-17/audit-reuse.md) preserve initial
  failures and separate local validation from sustained public serving.
  The pinned Headscale API component passes 786 tests under its own lockfile.
  Demo artifact integrity has nine regressions; fresh remote rendering remains
  a separate gate. The [normal observer adoption](checkpoints/2026-10-17/audit-reuse-public-adoption.json)
  preserves the existing chain at epoch 1,708,425 after a clean old-process exit.
  RPC has opened and authenticated catch-up has advanced to epoch 1,708,443.
  Serving remains suspended during catch-up and paid service is unconfigured.
  A later local join-client change backs off an HTTP origin for 30–300 seconds
  after a 429 response (60 seconds without a numeric Retry-After). The running
  public observer still uses its frozen binary; this change has not been adopted
  or qualified on the public network.
- The [prepaid channel revision](../audit/octranet-prepaid-2026-10-17.md) qualifies
  1,719 passing tests across 20 targets, 39 bounded Lean theorems, strict lint
  and a frozen-source four-validator/two-kernel gate. It covers
  exact byte purchases before forwarding, immediate withdrawal of available
  channel OCT, exit-earnings reuse and 24-hour replacement-rate notice.
  Operator unstaking remains seven days and protocol commission is zero.
  Older credit-based payment checkpoints below retain their original scope.
  Public paid service remains unqualified. Settled purchases
  are final and do not prove Internet delivery or provide non-delivery insurance.
- The [offline legacy repair checkpoint](checkpoints/2026-10-17/legacy-repair.json)
  records 173 native codec/finality vectors and 26 passing physical recovery,
  process-death, signed-proof corruption and ownership cases. The
  [command](legacy-repair.md) resumes an existing locally trusted staged plan
  through an unchanged pinned native backend. It neither rewinds modern Rust
  canonical history nor supplies automatic fork selection or an all-Rust
  Irmin/chaindata backend. The normal release passes the same 26 physical
  cases; its code is included in the combined candidate validation above.
- The [guarded public release adoption](checkpoints/2026-10-17/service-public-adoption.json)
  installed frozen normal release `2516b7c` after a clean old-process
  exit at epoch 1,708,032. Existing canonical/outbox/archive prefixes,
  checkpoint bindings, key, configuration and relay were preserved. The new
  supervised process remains alive. A [later read-only prefix audit](checkpoints/2026-10-17/service-public-progress.md)
  records 319 new epochs and 2,816 transaction events with matching canonical/ExEx
  continuity. An intermediate sample reported serving admission enabled, while
  its separate public status request timed out. Sustained public availability
  remains unqualified. Payments are
  unconfigured. [Operational scope](checkpoints/2026-10-17/service-public-adoption.md)
  distinguishes launch from public service and Mainnet qualification.
- The [automatic Service liveness checkpoint](checkpoints/2026-10-17/service-liveness.json)
  records 287 passing tests across 12 composed targets, four standalone ignores,
  strict lint, formatting and the unchanged 19-theorem abstract payment model.
  The actual Service and Node host automatically realign the existing actor,
  preserving canonical/ExEx/floor state and Circle/VPN access. Hard quarantine
  stops that actor and revokes both services. The same regression also passes
  without test helpers. Local dependency source snapshots bind validation to
  the release candidate. [Review and limits](checkpoints/2026-10-17/service-liveness.md)
  keep public adoption, legacy repair and Mainnet qualification separate.
- The [native liveness checkpoint](checkpoints/2026-10-17/native-liveness.json)
  records 320 passing tests across 24 composed targets, four standalone ignores,
  strict lint, formatting, 14 compiled payment AML tests and 19 abstract Lean
  theorems. Rust matches 1,012 cases from unchanged adopted OCaml policy. Actual
  driver tests retain a restored lock and durable votes, refuse conflicting
  proposals, block reset during pending finalization and reject stale workers,
  timers and polls across publication. The [review](checkpoints/2026-10-17/native-liveness.md)
  records captured-setting and peer-fixture corrections. Automatic supervisor
  triggering and actual Node flag projection were initially reviewed in source;
  the Service follow-up above now covers a forced positive automatic fallback
  under that complete production host locally. The unchanged prior public observer was catching up at epoch 1,707,929
  with three peers at 10:06:02 UTC and payments unconfigured. This candidate is
  not installed there; public recovery, legacy repair and Mainnet remain open.
- The [persistent-directory checkpoint](checkpoints/2026-10-17/persistent-directories.json)
  records 522 passing tests across 123 composed targets, seven standalone ignores,
  strict lint, formatting, 14 compiled payment AML tests and 19 abstract Lean
  theorems. Cached native commitments and authenticated page reuse match 10,564
  native tree operations across two corpora. Bounded hot-edit counts avoid full-width
  walks; cold load, public throughput and RSS remain separate concerns. Fresh
  native references cover 33 admin calls, 42 settlement methods and nine Circle
  cases. The [review](checkpoints/2026-10-17/persistent-directories.md) preserves
  initial fixture failures, the isolated-method harness correction and source
  boundaries. Seven-day operator unstake remains fixed from the first request;
  payer exit remains 24 hours and commission is zero. The public observer is
  unchanged; candidate deployment and Mainnet remain unqualified.
- The [cause-sensitive recovery checkpoint](checkpoints/2026-10-17/quarantine-recovery.json)
  records 311 passing tests across 26 composed targets, four intentional helper
  ignores, strict lint, formatting, 14 compiled payment AML tests and 19 abstract
  Lean theorems. Rust matches 37,302 cases from unchanged adopted OCaml quarantine
  policy. Actual signed-peer tests distinguish count from weighted recovery,
  preserve hard causes, clear failed targets and self-attest a real QC-backed
  successor despite withheld successor-root replies. Browser/VPN admission and
  durable ExEx are checked. The [review](checkpoints/2026-10-17/quarantine-recovery.md)
  records the initial checkpoint-wait race and final source boundaries. This
  batch is not installed on the public observer. At that checkpoint, native
  stalled-voter realignment, actual legacy repair, persistence CPU scaling and
  public qualification remained open; the follow-up above addresses bounded
  hot-directory work locally.
- The [peer diagnostics and recovery checkpoint](checkpoints/2026-10-17/peer-recovery-diagnostics.json)
  records 305 passing tests across 25 composed targets, four intentional helper
  ignores, strict lint, formatting, 14 compiled payment AML tests and 19 abstract
  Lean theorems. Local connection counters are bounded and independent of native
  wire diagnostics. Checkpoint opening releases an independently authenticated
  floor before restoring a distinct current head; corruption of either tree
  remains rejected. The [review](checkpoints/2026-10-17/peer-recovery-diagnostics.md)
  preserves the initial TCP fixture failures and final source boundaries.
  Separately, public observer `f69473b` resumed its retained state: 63 epochs and
  525 transactions matched canonical history and ExEx. A bounded later sample
  saw serving admission enabled with 20 peers, while the requested old Circle
  asset returned 404 through loopback and tailnet HTTPS. Payments remain
  unconfigured; the new diagnostics/allocation changes are not installed there.
  Stable public Circle delivery, paid service and Mainnet remain unqualified.
- The [native health admission checkpoint](checkpoints/2026-10-17/recovery-health-policy.json)
  records 265 passing tests across 17 final targets, with four intentional helper
  ignores. It includes 1,898 comparisons against adopted OCaml policy bodies,
  real connected observer/voter quarantine and recovery, startup refusal before
  attestation, a configured three-peer threshold, initial one-epoch soft-lag
  admission and HTTP recovery despite stale head advertisements. Canonical
  history, vote journals, VPN permits, Circle documents and ExEx are checked.
  Strict lint, formatting, 14 compiled payment AML tests and 19 abstract Lean
  theorems pass. The [review](checkpoints/2026-10-17/recovery-health-policy.md)
  records the initial test-fixture failure, later lint corrections and proof
  limits. Full native health orchestration, legacy repair and public recovery
  remain separate gates; this batch leaves the public observer running unchanged.
- The [root quarantine checkpoint](checkpoints/2026-10-17/root-quarantine.json)
  records signed root-conflict checks before connected recovery shortcuts.
  The final node run passed 128 tests; nine unchanged protocol/runtime targets
  passed 109 tests, including all 14 compiled payment AML tests. After a final
  test-only lint correction, the affected service target passed all 20 tests;
  strict lint, formatting and 19 abstract Lean theorems also passed. Stale
  heads/tokens, service revocation, signed TCP replies and immutable canonical
  history/ExEx are covered. The [review](checkpoints/2026-10-17/root-quarantine.md)
  records initial fixture failures and proof limits. Legacy nonjournaled repair,
  complete native health-loop parity and public recovery remain separate gates.
- The [P2P upgrade checkpoint](checkpoints/2026-10-17/p2p-upgrades.json)
  records trusted upgrade/rollback settings reaching production transport and
  the native voting-readiness gate. The combined release suite passed 236 tests;
  496 new native parser cases match Rust, and real TCP tests cover mixed binaries,
  conflicting schedules, activation, rollback and profile transitions. The
  [review](checkpoints/2026-10-17/p2p-upgrades.md) distinguishes the canonical
  consensus hash from the transport hash and records the final source checks.
  These are local checks; installed-binary attestation and public deployment
  qualification are outside their scope.
- The [reusable paid client checkpoint](../audit/octranet-client-service-status.json)
  records the Rust library and shared CLI service: explicit startup and shutdown,
  actual interface metadata and durable recovery. The combined release suite
  passed 1,585 tests across 20 targets; seven isolated Linux migration and
  WireGuard/TUN checks, strict lint and the public API example also passed.
  The strengthened four-validator paid kernel gate passed with five matching
  canonical claims across all ExEx sinks, credit recovery and exit enforcement.
  Its [review](../audit/octranet-client-service-2026-10-17.md) records cancellation,
  blocked IO, journal ownership and freshness fixes. Stock Tailscale payment
  bindings, constrained DERP relay, portal onboarding and the macOS paid route
  guard remain integration gates.
- The [Octranet payment checkpoint](../audit/octranet-payments-status.json)
  records the separate payment-plan candidate at `d6e5fa5`: 1,558 release tests,
  strict lint, abstract Lean checks and the isolated four-validator paid kernel
  gate passed. It covers differential rates, bounded credit, client/operator
  crashes, same-plan recovery, canonical claims, exit revocation, fixed seven-day
  operator unstake and matching ExEx. The public observer was separately seen
  serving canonical state with paid settlement unconfigured. Reusable client
  changes are qualified separately above; stock Tailscale, portal onboarding,
  public TLS and Mainnet remain open gates.
- The [durable mesh enrollment checkpoint](checkpoints/2026-10-16/mesh-enrollment.json)
  records 515 passing tests on frozen source and strict lint. The standalone
  mesh CLI and enabled Hub now share persistent users, device registrations,
  hashed preauth credentials, admin APIs and wire redemption. The actual CLI
  test crashes and restarts the process, registers a device, verifies atomic
  single-use redemption and replay rejection, revokes a reusable credential,
  restarts again and verifies refusal. Requested TTL, malformed JSON, hidden
  bearer failures and absence of raw tokens in state files are checked. The
  actual Hub router shares that backend and counts successful redemption once.
  This does not establish stock-client enrollment through deployed HTTPS,
  durable operator ACL/API-key policy or the native node's mesh-control launcher.
- The [native-host P2P relay checkpoint](checkpoints/2026-10-16/p2p-proxy.json)
  records 16 passing transport, swarm, launcher and four-validator executable
  tests, plus strict protocol/node lint. An optional loopback SOCKS5 connector
  carries every bootstrap/discovered-peer dial and DNS lookup through its
  selected relay, with a bounded deadline and no direct fallback. Native peer
  authentication, validator membership and source agreement are unchanged.
  The existing observer stopped cleanly at epoch 1,706,324 and restarted with
  the same database and identity; only `p2p_proxy` changed in its configuration.
  Its retained-state audit completed in the follow-up below. Two disposable live relay probes verified
  responder signatures but were closed after the handshake, so they do not
  establish sustained peer admission. Full relay-backed catch-up, stable
  serving, canonical gateway HTTP 200 and public native-host ingress remain
  open. This TCP relay does not carry paid VPN or HTTP recovery traffic.
  Its [live recovery follow-up](checkpoints/2026-10-16/p2p-proxy-recovery.json)
  verified 57 consecutive post-restart epochs and 552 transaction events against
  the canonical ExEx outbox and archive. Interrupting only the SSH relay dropped
  peers to zero with no direct P2P fallback; restoring it reconnected the same
  node process. Peer availability still fluctuated, and the canonical gateway
  remained suspended with HTTP 503 in the sampled request.
- The [receipt retry and paid integration checkpoint](checkpoints/2026-10-16/retry-admission-paid-gates.json)
  records a canonical-opening check for vaulted receipt retries and the same
  frozen image passing both 34-step private Single and four-validator BFT paid
  gates. Real client/node OS TUN traffic, exact on-chain settlement, canonical
  ExEx records, Circle gateway reads and restart recovery passed. The current
  release binary restarted the nonvoting public observer on its retained state.
  It advanced more than 90 authenticated epochs, and its epoch 1,705,432 root
  exactly matched the official signed primary head. A bounded later check at
  epochs 1,705,494–1,705,496 saw at most six matching signed root replies;
  the active 27-validator set requires at least nine signers for source
  agreement. Serving admission remains suspended, so the current Tailscale
  HTTPS Circle request returns 503. The public VPN is still unconfigured;
  paid admission and stable Circle HTTPS
  remain open. This local observer advertises a loopback P2P address; the next
  public qualification needs a reachable P2P endpoint or enough verified
  outbound validator links to satisfy the existing source-agreement gate.
  A raw TCP 8443 Funnel forwarding configuration is prepared locally, but
  this tailnet has Funnel disabled. Enabling it or providing a public host is
  required before the observer can advertise a reachable endpoint; the
  existing tailnet-only Circle HTTPS service remains unchanged.
- The [bounded public observer recovery checkpoint](checkpoints/2026-10-16/public-prefix-recovery.json)
  records commit `23466d5` passing the executable devnet, node library,
  service and strict lint gates. A nonvoting observer now binds diagnostics
  while suspended, recovers its durable queue only after authenticated
  catch-up, and does not run a consensus driver. HTTP join chooses a bounded
  consecutive range beside the retained head as an availability target;
  certificate, execution and publication checks still decide every import.
  The retained public-devnet observer is being requalified on this exact
  binary; stable Circle HTTPS and paid VPN remain open gates.
- The [Headscale 0.29.5 pinned VPN checkpoint](checkpoints/2026-10-16/headscale-v0295-native-vpn.json)
  records an exact-source image at `b120007` and Headscale `7b6b71b` passing
  both 34-step paid private Single and four-validator BFT gates. The host
  VPN/Headscale suite passed 700 tests, and a clean pinned Headscale checkout
  passed all 16 CLI passthrough comparisons. Public paid service and later
  recovery changes require separate qualification.
- The [final host release gates](checkpoints/2026-10-16/release-validation.json)
  passed segmented VPN/Headscale, runtime, node/protocol/ExEx/browser and doc
  suites on committed snapshot `6e72d5d`, plus strict workspace lint and offline
  dependency policy checks. The checkpoint records exact log hashes and the
  separate suite boundaries.
- The [full-prefix audit follow-up](checkpoints/2026-10-16/full-prefix-audit.json)
  checks every retained finality record on startup and recovery resume with four
  concurrent reads. It rejects modified older certificates and receipts. Its
  runtime, node service, executable devnet, strict lint and release build gates
  pass. The public observer restarted on the same identity and advanced two
  epochs, but had zero authenticated peers in the sampled status and remained
  suspended. Both configured state-sync heads timed out from this host, public
  devnet RPC returned 502, and the current Circle HTTPS request returned 503.
- The [2026-10-16 combined checkpoint](checkpoints/2026-10-16/combined-native-vpn.json)
  records a pinned frozen-source image passing both the paid private Single run
  and a four-validator BFT run. Each completed 34 stateful steps with zero
  process failures, covering private handoff/rotation/replay, paid WireGuard,
  exact settlement and refunds, real client/node OS TUN forwarding, canonical
  ExEx, Circle gateway reads and restart recovery. Later lint, test-only, and
  read-only gateway publication changes mean that image is not byte-identical
  to the current checkout.
  These are isolated activated genesis qualifications; public-chain paid
  activation is separate.
- [Native VPN checkpoint](checkpoints/2026-10-15/native-vpn.json): a fresh,
  isolated four-validator chain deployed the actual factory/main-v5 application,
  exercised private administration and paid escrow/settlement, and ran the real
  client through WireGuard UDP and both client/node OS TUNs. TCP, UDP and ICMP
  returned through kernel forwarding/NAT. Operator restart retained the same
  funded openings and receipt floors; the original TCP socket continued.
  Settlement ExEx records matched on all four validators, and the canonical
  gateway served the committed Circle asset. The checkpoint includes 51
  focused tests and 39 native comparisons, exact source/image/binary hashes,
  charges, refunds and restart results.
- [Formal checkpoint](checkpoints/2026-10-15/formal.json): the pinned Lean build,
  three bounded TLC safety models, required zero-margin counterexample, six
  Tamarin lemmas on supported Maude 3.5.1, and five Kani production primitive
  harnesses passed their stated gates. These are scoped models and harnesses;
  they do not refine compiled main-v5 or the whole Rust node.
- The [composed node checkpoint](checkpoints/2026-10-15/node.json) records 82
  release tests across Node, ExEx and the native PVAC adapter. The same frozen
  host run passed 90 selected runtime tests, 18 browser tests and strict linting.
  The later [shared service extraction](checkpoints/2026-10-15/service-facade.json)
  separately passed 56 node tests and eight actual Chrome checks. The Rust HFHE full
  release run passed 49 tests, with 13 native key/wire/proof regressions rerun
  after the final equivalent style changes. The [Chromium checkpoint](checkpoints/2026-10-15/browser.json)
  records 21 actual upstream WASM/OCTB wallet, fee, canonical state and ExEx
  checks in Chrome 155.
- [Runtime checkpoint](checkpoints/2026-10-15/runtime.json): the native inode
  follow-up passed 187 tests across all 58 library/integration targets in release
  mode. Its strengthened unit follow-up retains the same production bytes;
  the earlier 164-test qualification is preserved as history. Four actor ownership
  and cancellation regressions passed; two existing browser/crash helpers are
  excluded as standalone passes. Exact source and dependency deltas are recorded.
  The later [storage batching follow-up](checkpoints/2026-10-15/canonical-storage.json)
  records its changed source and separate regression and lint qualification.

The paid fixture explicitly enables application rules in a dedicated private
genesis. Its activation profile is committed to that genesis and is refused for
the public chain identity. It establishes the recorded local application and
transport behavior, not a public-devnet activation or Mainnet result. Later
dependency changes and other source snapshots retain their own qualification.

## Remaining release boundaries

The official public snapshot has authenticated against the independently pinned
[network authority](network-authority.json). Its completed
[import checkpoint](checkpoints/2026-10-15/public-devnet.json) records
37,830,616,510 downloaded bytes and 3,326,792 ledger records restored at epoch
1,697,760. The observer subsequently authenticated 722 consecutive epochs through
1,698,482; every retained ExEx archive matches its canonical cursor, parent and
durable event outbox. Its supervised SIGTERM stop exited successfully in 3.453
seconds, and it restarted with the same state and identity using the qualified
ledger-handoff, storage-authentication and retained-gateway build. A separate
early-start cancellation gate exited in 0.098 seconds without changing either.

The previous flat storage grew approximately 76.7 MiB per committed epoch in its
measured window. The adopted [native inode storage](checkpoints/2026-10-15/native-inode.json)
passed its full isolated release suite and combined Node/protocol/runtime gates.
Its bounded fixture allocated 32–52 KiB per individual account update. An actual
364-second public window committed 51 verified epochs at 8.4 epochs per minute,
with approximately 1 MiB of logical SQLite growth per epoch. This short window
does not establish sustained throughput or a completion forecast. A second,
fresh authenticated snapshot import completed in a separate directory at epoch
1,700,640. It has not replaced the running observer or its retained history;
final-binary restart and catch-up from that snapshot remain pending for that
separate import. The [final retained-state restart](checkpoints/2026-10-16/public-restart.json)
used the current release binary, stopped gracefully, and resumed the same
nonvoting identity from epoch 1,702,159; its authenticated head advanced past
1,702,211. The observer continues startup windows only while each durably
advances. Complete catch-up and stable healthy serving remain pending.
Voting requires the existing native membership, readiness and serving gates.

The [retained public gateway](checkpoints/2026-10-15/gateway.json) passed 34
functional tests, nine exact native registry comparisons and eight actual Chrome
checks, including canonical publication between HTML and its pinned stylesheets.
Inline CSS, imports, images and fonts use the captured public resource scope.
Pinned snapshots retain their captured visibility policy for at most 120 seconds
or 32 entries; new navigation uses the current verified head, or its last
committed public asset view for at most 15 seconds while a successor publishes.
Tailscale Serve
now maps the host's tailnet HTTPS address to the loopback Circle gateway. The
[public Circle HTTPS canary](checkpoints/2026-10-16/public-circle-https.json)
deployed a public static asset, matched its official RPC bytes, matched both
transactions in the Rust observer's ExEx outbox, and returned its rendered page
over Tailscale HTTPS during an admitted serving window. Later requests returned
503 during catch-up. The gateway-guard binary restarted with the same
retained identity and advanced beyond its prior head, but its sampled HTTPS
requests, including 24 in a bounded two-minute check, returned 503 while it
verified secondary-exporter history.
Stable availability, an HTTP 200 on the current release, and navigation from another tailnet
device or application remain integration gates. Circle HTTPS addresses
translate automatically at that
gateway; a VPN or DNS connection alone cannot teach arbitrary applications to
interpret a bare `oct://` scheme. The supported address preserves the Circle's
case-sensitive identifier in the HTTPS path.

Production deployment still needs the intended network and independently trusted
configuration, funded operator/relayer identities, reviewed private-admin proving
setup and custody/handoff procedure, application/code/domain pins, and operator
routing/NAT/Tailscale configuration. The local proof setup and test funds do not
satisfy those production requirements. Public activation and production upgrade
authority require their own qualification.

The [devnet canary tooling](checkpoints/2026-10-15/devnet-canary-tooling.json)
binds its selected RPC, independently pinned network configuration, checkpoint
origin, source and compiler artifacts before wallet use. Its local compiler and
artifact path and bounded fee/replay runner passed their recorded hermetic gates;
the final runner passed 76 controls, including bounded read-only 429 retry and
safe journal resume. Our running Rust node compiled both
applications locally: its bytecode,
ABI, verification, certificate and complete compiler response match the pinned
native reference, as recorded in the [local compiler checkpoint](checkpoints/2026-10-15/local-compiler.json).
The user selected local compilation, so no source was sent to the team's RPC.
Canary broadcast consumes caller-hash-pinned artifacts and cannot fall back to
a source compiler at the submission endpoint.
The [public devnet RC checkpoint](checkpoints/2026-10-16/devnet-canary.json)
records confirmed factory and VPN child deployment, private pause/unpause,
on-chain replay rejection, independent RPC readback and 203,000 OU of relayer
spend within a 204,000 OU cap. The nonvoting Rust observer independently
matched all four confirmed canary transactions and receipts to its canonical
SQLite ExEx outbox and archive. The canary deposited no escrow or operator stake.
Funded VPN service and independent public-chain replay remain unqualified.

There is no VPN protocol commission: operators receive the agreed traffic charge
in OCT, with ordinary chain transaction fees separate. The historical v5
settlement checks the opening's immutable tariff and exact claimed amount. Its cooperative two-step
protocol still depends on timely operator claim and client confirmation; it does
not establish adversarial payment fairness when a party refuses to cooperate.
Only one funded exit is supported. Multi-hop selection is refused before escrow.

The [source inventory](network-consensus-inventory.json) distinguishes mapped
implementation boundaries, finite native comparisons and optional activation
surfaces. The adopted optional resource libraries cover 121 native APIs with
1,070 exact oracle comparisons; production activation remains disabled exactly
as in the reference. The [private Single execution core](checkpoints/2026-10-15/single-core.json)
has been adopted after 31 complete native execution comparisons, 227 policy/cache
comparisons, crash/restart tests and strict linting. Its asynchronous proof
workers and Single RPC/browser/VPN/ExEx service adapter passed the combined
private Single qualification above. This does not establish complete upstream
behavioral parity on the public network.
The standard `run-network` command dispatches an explicitly tagged private
Single configuration to its native producer and service launcher. It requires
an isolated private genesis; the public network path remains BFT-only. This
local integration does not establish upstream public-network parity.
A mapped source file or passing local fixture does not establish full
native parity. Dated reports in [the adoption history](native-runtime.md) preserve
their original snapshot and should not be read as current completeness counters.

The opt-in [private admission checkpoint](checkpoints/2026-10-19/private-admission.json)
adds encrypted-wallet funding to the shared packet authority. The Circle browser
and VPN must belong to one node publication, with public and shielded accounting
kept explicit. The canonical private-service test, encrypted recovery, HTTP
shutdown/cancellation ownership and all 1,274 node/core/VPN library tests pass.
Private purchase/client transport, funded kernel routes and public-network
qualification remain incomplete; released shielded routes still refuse to start.

The [local payer checkpoint](checkpoints/2026-10-19/private-payer.json) adds
canonical owned-note import, encrypted purchase reservations, matched-key local
proving, input-preserving rebase and change reconciliation. The actual node
flow covers restart, stale transaction refusal, expiry, cancellation and exact
two-input payments; 241 node tests, 27 pool tests and 120 offline native proof
cases pass. That stage covered the local wallet API; later checkpoints below
add native submission and withdrawal. Private client/kernel qualification is separate.

The later [private control checkpoint](checkpoints/2026-10-19/private-control-rpc.json)
adds opt-in same-node onboarding, signed quote/receipt RPC, atomic encrypted
retry records and a payer request outbox. The reusable HTTPS client requires
accepted CA and TLS key pins, refuses redirects/proxies, bounds replies and
authenticates the operator plus exact request. The combined library gate passes
1,616 tests; the final TLS-key-pinned client rerun passes all 341 client tests.
Strict lint and the normal node build pass. Canonical loopback RPC and real
TLS transport are tested separately. That stage left native submission,
withdrawal, operator-income handoff and a funded private routed client unfinished;
released `shielded_required` mode stays disabled.

The [native wallet checkpoint](checkpoints/2026-10-19/private-native-wallet.json)
adds durable native signing/intake, immutable fee/nonce reservations,
consolidation, partial/full withdrawals and canonical reconciliation after
later note appends. That checkpoint records 241 node tests and 28 pool tests; strict lint passes for both. Full withdrawal creates no dust note.
This is a local BFT/native-intake qualification. Long-lived relayer-journal
scaling, operator-income handoff, multiple operator views, automatic routed
client recovery and funded private kernel/public-network qualification remain
unfinished at that stage. Its experimental attempt cap was 16; the later
journal checkpoint removes that ceiling. Released shielded traffic stays gated.

The later [relayer journal checkpoint](checkpoints/2026-10-19/private-relayer-journal.json)
replaces the inline 16-attempt journal with individually encrypted records and
bounded configurable capacity. Atomic migration preserves original limits and
signatures. Native signing/broadcasting now refuses changed proof roots. The
canonical flow exercises 18 confirmed transactions on one relayer, concurrent
nonce contention, missing-record refusal and expiry/replacement under a new
head. That stage left operator-income handoff, multiple operator views and
funded private routed/kernel qualification unfinished.


The [income checkpoint](checkpoints/2026-10-19/private-income.json) adds exclusive
local assignment of canonically earned operator notes to one payer book and
shared price-consent views across operators on the same node and pool. The
operator wallet retains its spend keys and must be unlocked and reattached on
reopen. A real canonical flow spends earned exit income at a second operator,
combines earned and directly owned notes, and preserves customer byte floors,
reservations and relayer counters across restart. All 242 node tests pass,
including the SQLite sidecar-cleanup regression; strict lint and the normal
node build pass. The circuit, proof format, AML and Lean sources are unchanged.
That stage left canonical pool indexing, automatic routed-client recovery and
a funded private multi-node/kernel/ExEx gate unfinished. Released shielded traffic stays gated.


The [index checkpoint](checkpoints/2026-10-19/private-index.json) adds automatic
reconstruction from the first retained initialized empty pool state, encrypted
cursor/update recovery and revocable current views. Direct exchanges use
canonical calldata; nested Circle calls supply untrusted event hints that must
reconstruct each epoch's actual canonical roots and count. The real BFT flow
covers partial sync/reopen, wrong-key and missing-segment refusal, resource
budgets, suspension, unchanged-root epochs and a nested withdrawal through a
separate Circle. All 244 node tests and 28 standalone pool tests pass; strict
lint and the normal build pass. The adopted one-Circle-call-per-epoch limit,
proof circuit, AML, proof format and Lean model remain unchanged. That stage left
authenticated pruned-history bootstrap, automatic routed-client recovery and
funded private kernel/multi-node/ExEx qualification open.

The [bootstrap checkpoint](checkpoints/2026-10-19/private-bootstrap.json) adds
public tree seeds authenticated against the importing node's own canonical
snapshot, encrypted seed recovery and explicit reanchoring. Reanchoring preserves
resource limits and the consumed update budget. A signed native checkpoint has
the original state root, a new local sequence and Irmin commit, and no retained
history for an existing note's creation. The test rebuilds the pool and spends
that note through an actual native withdrawal, then checks restart, missing
seed-segment refusal, regressing-seed refusal and explicit repair. All 245 node
tests, 29 standalone pool tests, four protocol checks and 26 canonical runtime
checks pass. Strict lint passes for node and pool; the normal node build passes. Original
private genesis opt-in proofs survive checkpoint import without trusting a
mutable flag. Consensus rules, the circuit, AML and Lean sources are unchanged.
That stage left financial-wallet recovery, private CLI origin-proof wiring,
automatic routed-client recovery and funded private kernel/multi-node/ExEx
qualification open.

The [payer recovery checkpoint](checkpoints/2026-10-19/private-payer-floor.json)
adds spending from existing directly owned payer notes whose creation history
is below an imported floor. The original encrypted journal and keys must agree
with authenticated current membership; this grants no new receipt or traffic
capacity. A real native-intake withdrawal preserves reservations and the exact
signed retry across restart, reconciles finalized execution and reopens with
the note spent and fee budget intact. Imported-floor clocks now use their
verified finalized QC, surviving store reauthentication without using commit
dates or changing checkpoint acceptance. All 245 node tests and 26 canonical
runtime tests pass, with strict node/runtime lint and the normal node build.
That stage left operator income and traffic-credit recovery, confirmations older
than the imported floor, private launcher wiring and funded private routed-client
qualification unfinished.

The [operator recovery checkpoint](checkpoints/2026-10-19/private-income-floor.json)
adds current canonical ownership checks for earned notes in original encrypted
operator journals. The existing book recovers its assignments, then claims a
previously unassigned 20 OU payment from a second operator wallet. A real native
flow consolidates 15 OU of directly owned funds with a 10 OU earned note, preserves
the exact signed retry through restart and withdraws another 10 OU earned note.
The final 76 OU balance and both relayers' fee reservations survive reopen;
unspent income still requires its original wallet unlocked. Both operators'
customer records remain byte-identical, excluding assignment rows, and channel
verification still refuses missing historical funding. All 245 node tests pass,
with strict lint and the normal build. Crypto, AML, runtime and consensus sources
are unchanged. Customer-credit recovery, old confirmations, private launcher and
routed-client wiring, and funded private kernel/multi-node/ExEx qualification
remain unfinished. Released shielded traffic stays gated.

The [portable history checkpoint](checkpoints/2026-10-19/private-history.json)
adds bounded encrypted execution witnesses for the missing original funding.
Signed native parent commitments link back from this node's exact authenticated
checkpoint certificate. Complete fixed-path state proofs include both custody
accounts; a projected subtree never acquires canonical snapshot authority.
Customer credit, an incoming 1 OU/50,000-byte receipt, a pending purchase with
3 OU change and a full 5 OU withdrawal recover after original transaction history
is absent. Duplicate receipts add no credit; a missing encrypted witness chunk
refuses until explicit authenticated repair. The flow also extends witnesses to
a successor certificate and rejects anchor regression. Existing earned income
still combines and spends, ending with 77 OU in the expanded fixture.

All 245 node tests pass for this extension. The checkpoint records the affected
protocol/runtime checks and source pins. No consensus rules, AML, circuit or
Lean proof sources change in this stage; no new formal theorem is claimed.
This is bounded local recovery: 4,096 ancestry certificates, 32 MiB evidence and
8 MiB per certificate/subtree, with existing signed parent links required at
each backward hop. Original journals, keys and evidence saved before pruning
remain necessary. Long-history recovery, private launcher/client wiring,
production ceremony/review and funded private kernel/multi-node/restart/ExEx
qualification remain open. Released shielded traffic stays gated.

The [private launcher checkpoint](checkpoints/2026-10-19/private-launcher.json)
connects original private genesis proofs and trusted checkpoint recovery to the
isolated BFT launcher. It reconstructs configured genesis, verifies the original
folded root, and passes the same proven graph to native execution and views.
`checkpoint_trust` must retain the original chain and genesis validator set;
missing trust/imports, wrong authority and ambiguous stores refuse. Existing
configuration JSON remains compatible, with relative paths resolved against its
directory. Offline snapshot prepare and ledger export can read an ordinary
private genesis store; public-network startup trust remains unchanged.

The native test deploys and initializes a Circle, publishes 65 signed epochs,
exports through the existing prepare/assemble APIs, imports the checkpoint,
executes another Circle call and reopens its state. ExEx observes the actual
successor cursor. All 247 node tests and both CLI tests pass, with strict lint,
the normal build and an actual private-feature CLI build. Four real CLI processes
then peer and reach epoch 2 with matching state/ledger/index roots and canonical
archive cursors. All processes stop cleanly and their temporary keys are removed.
The report pins 59 selected recovery sources, eight additional CLI entrypoints,
the executable and raw evidence. No consensus, AML, circuit or Lean proof changes
are introduced in this stage. Private wallet/service startup and payer/client
scheduling, long-history recovery and funded private packet-route qualification
remain open; released shielded traffic stays gated.

The [private operator startup checkpoint](checkpoints/2026-10-19/private-operator-startup.json)
wires an encrypted operator wallet into the isolated experimental launcher.
`init-private-wallet` explicitly initializes a new book while offline; ordinary
startup only resumes existing data. It uses a separately protected master-key
file, the native operator identity, accepted Circle/VK pins and explicit request
allocation limits. Missing/incompatible wallets, duplicate initialization,
incorrect keys and exposed private HTTP refuse. Normal builds and public network
configuration cannot select this mode. Startup uses the same canonical private
purchase, admission and metering services; public payment routes are absent.

All 248 node tests and three experimental CLI tests pass. The three normal CLI
tests also pass, including refusal of the experimental initialization command.
Both builds pass strict lint and the normal build check. A four-node CLI run
explicitly creates one operator wallet, refuses duplicate initialization, starts
its private service and restarts that process against the same wallet. All four
nodes reach matching epoch-2 state/ledger/index commitments and archive cursors,
then exit cleanly. Source/evidence hashes and executable provenance are recorded.

The added canonical startup wallet buys no bytes from quotes; exact requests
replay after restart, changed terms refuse, and a fresh quote refuses when the
canonical view is unavailable. Existing genuine private purchase/meter tests also
pass. The live CLI pool is undeployed and unfunded, so this does not qualify paid
kernel traffic. Routed client scheduling and recovery, long-history witness
coverage, funded private per-hop kernel/restart/ExEx and production cryptographic
review remain open. No consensus, circuit, AML or Lean theorem changes are
introduced; the released shielded client mode stays gated.

## Private payer purchase scheduling

The [private payer runner checkpoint](checkpoints/2026-10-19/private-payer-runner.json)
connects an encrypted finite purchase job to the canonical index, local proving,
durable native signing/submission, original-epoch confirmation and private
operator receipt RPC. The reusable client supplies CA/SPKI-pinned HTTPS through
the shared `PrivateExchange` interface. Each job fixes the independently accepted
source, tariff, quantities, price and native fee policy before network access.
Per-job receipt identities remain distinct from the public native relayer.

All 248 private node tests pass, including genuine paid purchase/restart flows.
The TLS transport and private wire tests also pass, for 250 distinct named tests;
other client/core tests were not rerun in this stage. Strict all-target checks pass
for ordinary and experimental node/client builds. The new scenarios reject
signed ceiling increases and forged receipt credit IDs, replay lost responses
with identical requests, retry one staged envelope without another fee, and
recover a transaction confirmed before the scheduler's submission step. An
earlier completed job stays paid after another purchase appends notes.

Testing found and fixed exact staged retransmission being refused as a duplicate
nonce. The adapter compares the complete envelope in the healthy owned pool;
ordinary admission and consensus rules are unchanged. A fixture price assumption
was also corrected to use its canonical tariff, with separate operator books.
The checkpoint pins 76 selected sources and records both earlier failed runs.

This is a caller-driven single-purchase service. The application must retain the
job ID; job discovery, routed client connect/status and automatic replenishment
remain open. Existing authenticated notes, a funded relayer and accepted proving
material are prerequisites. Funded per-hop kernel/restart/ExEx, general
long-history recovery, production ceremony and independent cryptographic review
remain release gates. No consensus, circuit, AML or Lean theorem changes were
made, and the released shielded route mode remains disabled.

## Private client admission and encrypted transport recovery

The [private client checkpoint](checkpoints/2026-10-19/private-client.json) adds
`AcceptedPrivatePlan`, `PreparedPrivateClient` and `PrivatePaymentClient` library
services. The same CA/SPKI-pinned HTTPS control client now authenticates private
status. Preparation refuses a missing purchased floor before UDP/TUN startup;
the payload opener rechecks admission and reuses the existing WireGuard/TUN
driver. It has no native signing key and submits no payment. Routing and shutdown
remain caller-owned, and the released multihop selector stays gated.

Private transport journals seal all records under a scoped receipt-secret key.
Original leases, atomic/fsynced installation, ambiguous-write poisoning and
conservative interrupted handoff accounting are preserved. Signed funding,
purchase, delivery-slot, connection and canonical-clock observations cannot
regress on reconnect. Held counters may change within a delivery slot, while
committed counters cannot conflict in that slot. Operator observations never
increase locally accepted caps or stand in for chain finality. Private summaries
expose bytes without presenting a quote ceiling as available native OCT.

All 369 client tests pass: 347 library and 22 external integration cases, with
no ignored tests. All 248 private node tests pass too, for 617 distinct named
tests. Strict ordinary and experimental all-target checks pass. The canonical
flow now purchases through pinned HTTPS, refuses client preparation before
payment, then admits on sequence 2 after genuine private funding and resumes on
sequence 3 after another purchase. Its original prepaid capacity is preserved.
The checkpoint pins 88 selected sources and records encrypted tamper/key/scope,
uncertain handoff, post-install failure and status rollback regressions.

This stage qualifies private control/preparation only. The private payload
opener compiles but no private UDP/TUN/kernel forwarding was executed here.
The Linux image recipe still needs the optional experimental package included;
native payer daemon/job discovery, per-hop private route orchestration and funded
kernel/restart/ExEx remain required. Production ceremony, cryptographic review,
general history/key-custody recovery and private service-claim integration also
remain gates. No consensus, circuit, AML or Lean theorem changes were made.

## Native private funding

The [funding checkpoint](checkpoints/2026-10-19/private-funding.json) adds native
OCT deposits into newly reserved owned notes. The exact signature and its fee
reservation commit together. A consumed nonce does not authorize a second
deposit; new funding requires explicit consent with another ID. Encrypted
restart retains the original envelope, and only its exact successful canonical
exchange creates spendable value.

All 248 private node tests pass, including an actual consumed-nonce transaction,
encrypted restart, duplicate staging, funded deposit and two private purchases.
Ordinary and private strict node checks pass. The Linux recipe and source
manifest now include the optional experimental package; a complete locked
package graph and private all-target Linux compilation pass with 91 selected
host sources pinned. This stage does not build a qualified private release image
or execute private kernel transport, and reuses the prior unchanged client
results instead of claiming they were rerun. Crypto, AML and Lean sources remain
unchanged.

The [private payer service guide](private-payer.md) describes offline consent,
finite deposit/purchase job recovery and node startup. Funded private kernel,
per-hop routing, combined restart/ExEx, general history/key-custody recovery,
production ceremony and independent cryptographic review remain open.

## Private payer startup and finite consent

The [payer service checkpoint](checkpoints/2026-10-19/private-payer-service.json)
qualifies encrypted deposit/purchase discovery and a supervised node service.
Offline `init-private-payer` creates fresh payer/index books against the accepted
deployed pool. `private-payer-consent` imports bounded private request files with
explicit IDs and immutable terms. Ordinary startup only resumes existing books
and consent. Legacy purchase records require their original IDs before automatic
discovery; migration does not guess or regenerate identities.

The startup configuration validates protected master/relayer files, the local
compressed proving key against the accepted VK, HTTPS CA/SPKI pins and the same
canonical node/pool. The deposit runner stages and retransmits one exact native
envelope, then imports its note after successful canonical confirmation. Existing
movements must match deposit action, amount, time window and relayer. Job errors
pause the job; they do not terminate consensus or create more consent. Shutdown
releases the exclusive recovery leases.

All 249 library and four feature-enabled CLI tests pass. Four ordinary CLI tests
also pass, exercising refusal without the private feature. Strict ordinary and
private all-target checks and offline private Linux compilation pass. The
checkpoint pins 95 host sources and the staged Linux context. Its canonical flow
recovers one deposit and two purchases with no further signature fee or native
submission. A newly initialized, unfunded supervised purchase opens and quotes,
then pauses before any native signature; cancellation shuts it down cleanly.

See the [service guide](private-payer.md) for the local workflow. Automatic income
attachment, per-hop client/route orchestration, funded private kernel transport,
combined restart/ExEx and production cryptographic qualification remain open.
This stage changes no consensus rules, circuit, AML or Lean theorem and enables
no released shielded multihop mode.

## Funded private kernel and ExEx recovery

The [private kernel checkpoint](checkpoints/2026-10-19/private-kernel.json)
qualifies a funded private operator hop through real WireGuard/TUN devices.
An isolated second kernel receives TCP, UDP and ICMP through the paid route.
The encrypted client journal and operator wallet/service reopen, traffic repeats,
and committed counters advance while purchased capacity stays fixed. The target
observes 9,340 UDP and 9,728 TCP payload bytes across both phases, with no packet
link errors or rejections.

The launcher now shares its existing archive through `octra_node::archive::Archive`.
Its checkpoint name and immutable file format are unchanged. The fixture
registers this production ExEx, compares each retained epoch with the canonical
source and validates both paid native transactions against canonical receipts.
Reopening the actual canonical and SQLite checkpoint stores preserves the
checkpoint and all 83 archived files.

Both exact canonical tests pass from the same release executable: the explicitly
selected privileged kernel test and the ordinary private regression. Strict
ordinary and feature-enabled all-target checks also pass. All 103 selected host
pins and 4,914 staged inputs match the frozen context. This stage does not rerun
the earlier full suite, change consensus/circuit/AML/Lean rules, qualify a public
deployment or enable released shielded multihop. The fixtures use in-process
signed QCs and disposable containers with external networking disabled.

See the [runner guide](private-kernel.md) for reproduction. Automatic operator
income attachment, per-hop private client/route orchestration, private claims,
broader parity/history/key-custody recovery and production cryptographic
qualification remain open.

## Private composite client candidate

The [private route guide](private-routes.md) describes the new
`MultiPrivatePaymentClient` and its file/options adapters. Public and private
clients share one composite route supervisor, including ordered admission,
blocker retention on error/cancellation, worker ownership and clean shutdown.
The public journal identity format remains unchanged. Private route identities
use encrypted snapshots scoped to the entry receipt secret and bind every hop's
plan, public receipt key, journal path, interface, socket pins and MTU.

Private local preparation creates all encrypted journals before contacting any
operator. It makes no payment and cannot fall back to public custody. Each
operator's accepted private funding floor must pass before its TUN opens.
Mandatory public IPv4 pins avoid operator DNS lookups; pinned TLS still checks
the accepted hostname, CA and SPKI. Downstream management uses the preceding
paid interface. Two or three operator hops use independent receipt keys and
journals; each Octranet's pool/directory is accepted separately on the same chain.

All 375 client tests and four benchmark checks pass on the frozen candidate.
Tests cover encrypted route resume, changed order/keys/pins/caps/MTUs, missing
state, invalid transport consent, offline all-hop preparation and a real pinned
TLS request to a deliberately unresolvable hostname. Strict client and private
node all-target checks pass. The funded single-hop/kernel/ExEx regression passed
before the final cross-Octranet validation adjustment; its transport and shared
supervisor sources remain unchanged. A fresh native build is running. The
[client checkpoint](checkpoints/2026-10-20/private-route-client.json) records the
source pins and distinguishes the two validation snapshots.
These checks do not establish
funded private multihop, daemon-managed per-hop funding or public qualification.
The released public-format `shielded_required` refusal remains in place.
