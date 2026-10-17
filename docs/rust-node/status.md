# Rust node qualification status

The Rust node now integrates native transaction execution, authenticated peers,
the validator driver, canonical SQLite/Irmin-compatible commitments, ExEx,
Circle browsing and a paid VPN service. The adopted reference is lite_node
`7f9be4489870645cfcc95439638cde40f5da9f50`. Implementation and local qualification
are substantially beyond the earlier implementation-pass records; complete
upstream behavioral parity and public-network deployment remain unqualified.

## Recorded local evidence

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
in OCT, with ordinary chain transaction fees separate. Settlement checks the
opening's immutable tariff and exact claimed amount. Its cooperative two-step
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
