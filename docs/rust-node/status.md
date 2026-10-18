# Rust node qualification status

The Rust node now integrates native transaction execution, authenticated peers,
the validator driver, canonical SQLite/Irmin-compatible commitments, ExEx,
Circle browsing and a paid VPN service. The adopted reference is lite_node
`7f9be4489870645cfcc95439638cde40f5da9f50`. Implementation and local qualification
are substantially beyond the earlier implementation-pass records; complete
upstream behavioral parity and public-network deployment remain unqualified.

## Successor implementation awaiting qualification

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

The latest mixed workload reached 34 matching epochs, including its eight
pre-restart transactions. Its fixture then refused Rust's receipt-storage JSON
shape before restart. Independent audits found matching receipt bytes and roots;
the corrected fixture still needs its full 54-epoch run and restart qualification.
The combined normal artifact, Linux traffic scenarios and operator tooling remain
pending, and the retained public observer is unchanged.

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
