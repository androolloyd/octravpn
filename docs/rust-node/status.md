# Rust node qualification status

The Rust node now integrates native transaction execution, authenticated peers,
the validator driver, canonical SQLite/Irmin-compatible commitments, ExEx,
Circle browsing and a paid VPN service. The adopted reference is lite_node
`7f9be4489870645cfcc95439638cde40f5da9f50`. Implementation and local qualification
are substantially beyond the earlier implementation-pass records; complete
upstream behavioral parity and public-network deployment remain unqualified.

## Recorded local evidence — 2026-10-15

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
fresh authenticated snapshot import is running in a separate directory to reduce
catch-up time; it has not replaced the running observer or its retained history.
The observer continues
startup windows only while each durably advances. Complete catch-up, healthy
serving and public restart qualification remain pending.
Voting requires the existing native membership, readiness and serving gates.

The [retained public gateway](checkpoints/2026-10-15/gateway.json) passed 34
functional tests, nine exact native registry comparisons and eight actual Chrome
checks, including canonical publication between HTML and its pinned stylesheets.
Inline CSS, imports, images and fonts use the captured public resource scope.
Pinned snapshots retain their captured visibility policy for at most 120 seconds
or 32 entries; new navigation uses the current verified head. Actual Tailscale Serve/TLS
and navigation from another tailnet device or application remain external
integration gates. Circle HTTPS addresses translate automatically at that
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
origin, source and compiler artifacts before wallet use. Its 54 offline controls
passed. Public source compilation at the separate devnet endpoint awaits approval;
the latest balance query still reports the relayer account absent. No public
contract deployment or funded service is claimed.

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
as in the reference. Native Single-mode execution is still being implemented
and qualified in an isolated candidate. A mapped source file or passing local fixture does not establish full
native parity. Dated reports in [the adoption history](native-runtime.md) preserve
their original snapshot and should not be read as current completeness counters.
