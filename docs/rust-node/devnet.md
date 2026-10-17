# Rust node local devnet

The `octra-node` executable runs the canonical Rust node, native validator driver,
authenticated peer services, transaction queue, ExEx, Circle browser and embedded
VPN sockets in one process. `scripts/devnet/native.py` manages four independent
validator processes on loopback. This is an isolated development chain.

## Run

From this repository, with the existing sibling dependencies available:

```sh
cargo build --locked -p octra-node --bin octra-node
python3 scripts/devnet/native.py init
python3 scripts/devnet/native.py start
python3 scripts/devnet/native.py status
```

Initialization requires a new directory. It generates fresh validator and faucet
keys, a shared genesis commitment, and four configurations under
`out/native-devnet`. That directory is ignored by Git. Keys are private regular
files; startup rejects permissive or symlinked key files. Genesis binds the local
validator list, timestamp and activation settings. Changing those settings
requires a new chain.

The default endpoints are:

| Validator | Peer TCP | RPC HTTP | Browser HTTP | VPN control HTTP | WireGuard UDP |
| --- | --- | --- | --- | --- | --- |
| 0 | 19870 | 19871 | 19872 | 19873 | 19874 |
| 1 | 19880 | 19881 | 19882 | 19883 | 19884 |
| 2 | 19890 | 19891 | 19892 | 19893 | 19894 |
| 3 | 19900 | 19901 | 19902 | 19903 | 19904 |

The Circle address is in `genesis.json`; each node log prints its browser URL.
Use `http://127.0.0.1:19872/open?u=oct://<circle>/index.html`. The browser resolves
assets from a committed snapshot; a new commit invalidates URLs tied to the old
snapshot. This launcher does not install an OS-wide `oct://` handler.

## HTTPS access through Tailscale

The optional gateway translates ordinary HTTPS requests into canonical Circle
asset reads. Any HTTP client on the tailnet can use the same URL, including a
browser, `curl`, or an application fetching JSON. No protocol handler or browser
extension is required. The URL is:

```text
https://<node>.<tailnet>.ts.net/circles/<CircleAddress>/index.html
```

The Circle address stays in the path because its case is significant. DNS names
cannot preserve that distinction. This translates Circle HTTPS URLs; arbitrary
applications still cannot interpret a bare `oct://` scheme through DNS.

After connecting the host to Tailscale, obtain its `Self.DNSName` from
`tailscale status --json` (remove the trailing dot). Add this optional field to
`out/native-devnet/node-0/config.json`, using that exact hostname:

```json
"gateway": {
  "listen": "127.0.0.1:19875",
  "origin": "https://<node>.<tailnet>.ts.net"
}
```

Restart with the existing state, inspect `tailscale serve status --json` for
conflicting routes, then publish the gateway privately:

```sh
python3 scripts/devnet/native.py stop
python3 scripts/devnet/native.py start
tailscale serve --bg --yes http://127.0.0.1:19875
tailscale serve status
```

Tailscale Serve supplies HTTPS and tailnet access control. Keep the backend on
loopback and publish only this gateway port. Its exact Host check is independent
of forwarded headers. The local browser's wallet/application routes and node RPC
are not mounted on the gateway.

The gateway serves published public resources. Sealed resources and resources
requiring local approval remain denied. JSON/binary bodies preserve their bytes;
HTML uses the existing bounded, script-free renderer. Links resolve automatically,
and subresource URLs carry the captured snapshot. Responses include
`X-Octra-Chain`, `X-Octra-Epoch` and `X-Octra-State-Root`. During canonical
publication, the gateway may serve the last verified public asset view for at
most 15 seconds. Catch-up and errors return 503; stale snapshot resources fail
rather than mix roots.

An HTTPS gateway backed by this local launcher still serves the isolated local
chain. Tailscale connectivity does not join Octra's public devnet. The
public-network launcher below has a separate authenticated snapshot and observer
state; its gateway must be configured and qualified independently.

## Public-network startup (public qualification pending)

`octra-node init-identity --key /private/path/node.key` creates a private node
key without replacing an existing key and prints only the public identity.

`octra-node bootstrap --config bootstrap.json --directory /new/data/path`
downloads into a private staging directory. It verifies configured network trust,
finality and validator transitions, exporter signatures, chunk/file hashes,
ledger roots, the source HEAD, recent finalized roots and migration admission
before atomically publishing a new directory. It never replaces an existing
directory or derives the chain's configured origin from the downloaded snapshot.
The operator configuration must supply the independent chain identity, trusted
validators/exporters, configuration hash and minimum checkpoint epoch.

`octra-node run-network --config network.json` reauthenticates that import and
uses the captured native `network.env` settings for execution, peer compatibility,
validator readiness and profile transitions. Paths in `network.json` resolve
relative to that file. Trust comes from this operator configuration, not the
`network.json` retained beside the downloaded snapshot. Public startup shares
the canonical node, ExEx, browser, VPN admission and shutdown lifecycle with the
local launcher. Voting defaults to false. Lifecycle-enabled permissionless startup can admit a
nonactive operator, while actual proposal and vote duties still require native
membership, readiness and serving admission. Conflicting registered keys fail
startup. The RPC, browser bridge and control service
remain on loopback; the HTTPS gateway has its own bind and Host policy.
The loopback operator RPC also serves `/operator/peers` with aggregate
connection counts, source diversity, risk labels and score reasons. It omits
peer identities so an operator can diagnose admission without publishing the
peer address book.

The same `run-network` command also accepts an explicitly private Single
configuration shaped as `{"role":"single","single":{...}}`, where `single`
contains the existing `run-single` configuration. Its chain must have a fresh
`octra-single-local-` genesis origin and `settings.mode` must be `single`.
Private Single uses its own canonical store, execution and services; it does
not join the public BFT chain or provide BFT finality. Public `network.json`
keeps its existing shape and rejects a Single consensus mode.

The official public-devnet snapshot completed authenticated download and import
against the pinned network authority. A separate observer has committed a
bounded live window and restarted with retained history. It remains nonvoting
and advances only authenticated canonical history. The
[final retained-state restart](checkpoints/2026-10-16/public-restart.json)
resumed the same nonvoting identity and advanced past its pre-restart head.
Complete catch-up and stable gateway serving remain qualification gates. The
host's Tailscale Serve now proxies private HTTPS port 443 to the public
observer's loopback gateway at `127.0.0.1:20805`. The
[public Circle HTTPS canary](checkpoints/2026-10-16/public-circle-https.json)
returned its rendered page over TLS after both public transactions appeared in
the observer's canonical ExEx outbox. Later requests returned 503 during
catch-up. The gateway-guard binary advanced past its pre-restart
head, but its sampled HTTPS requests also returned 503 during authenticated
catch-up (24 attempts over two minutes). Stable availability, current-release
 HTTP 200, and external-device navigation have not passed. A subsequent
 [full-prefix-audit observer restart](checkpoints/2026-10-16/full-prefix-audit.json)
 reauthenticated the retained state and advanced two epochs. Its sampled
 operator status had no connected peers; both configured state-sync heads timed
 out, public devnet RPC returned 502, and its Circle HTTPS request returned 503.
The [zero-escrow public devnet RC](checkpoints/2026-10-16/devnet-canary.json)
deployed the factory and VPN child, exercised private pause, replay rejection
and unpause, and was observed again in our Rust node's canonical ExEx history.
It deposited no operator stake or escrow, so it does not activate a paid VPN
service. The isolated paid-node qualification is recorded separately in the
[combined native VPN checkpoint](checkpoints/2026-10-16/combined-native-vpn.json).

Stop and restart without deleting state:

```sh
python3 scripts/devnet/native.py stop
python3 scripts/devnet/native.py start
```

The supervisor retains keys, canonical databases, vote and pending journals,
receipt journals, evidence and ExEx checkpoints. It never force-kills a validator.
`node-N/node.log` contains diagnostics. A service failure stops the node and
revokes service admission. Startup reauthenticates retained history, catches up
from peers with certificate and execution verification, and restores a pending
precommit lock only after local replay. Unresolved legacy locks stop startup.

## RPC and retained history

The implementation candidate mounts native JSON-RPC at `POST /rpc`, native
HTTP status at `GET /status`, and native state-sync head, range, readiness and
snapshot routes under `/state-sync/`. Optional loopback gRPC uses the captured
upstream `OCTRA_GRPC_*` settings and shares the JSON-RPC handlers. These new
routes have implementation and local test coverage; public interoperability and
the broader runtime's final result remain separate qualification gates.

Local operator tools use these separate endpoints:

- `GET /operator/status`: chain, committed epoch/root, serving state, suspension
  reason, peers and queue size.
- `GET /account/<address>`: committed balance and nonce, with the captured epoch.
- `POST /transactions`: native signed transaction JSON. A `202` response means
  durable queue acceptance; inclusion must be checked in canonical history/ExEx.

Transactions undergo native signature, payload, fee, nonce, proof and active-rule
admission. Peer gossip and pending recovery share the transaction checks without
inheriting the observer RPC submission restriction. Accepted queue changes are
journaled before acknowledgment. Recovery binds the journal to canonical history,
removes finalized transactions and recorded refusals, revalidates candidates and
preserves their original age. Checksum, chain and cursor conflicts stop recovery;
persistence failure stops admission. Clients should retain signed transactions
until canonical inclusion. No endpoint exposes or signs with a faucet key.

`node-N/exex/<sequence>.json` contains immutable canonical execution events. The
archive extension uses atomic durable writes and durable checkpoints. Replayed
writes must match existing bytes. Canonical publication retains its writer lease
and serialization guard through SQL commit and head-cache publication even when
the caller is canceled. Applications remain suspended after interrupted
publication until explicit recovery.

## Qualification boundary

The running isolated devnet and each captured qualification image are different
artifacts. The [current status](status.md) links the combined paid VPN/node
and formal checkpoints and records the remaining public and production gates.
The final local node release run passed 40 tests; the broader runtime and final
Chromium gates have independent results. Neither source inventories nor those
bounded local results establish full native parity or deployment readiness.

The candidate now contains native AML compilation/admission and OCTB execution,
Circle resource/state/policy and sealed-cell operations, HFHE and private proof
hosts, key lifecycle/migration, compute services, validator enrollment/duties,
transaction/history APIs and authenticated snapshot/bootstrap paths. These source
paths have received compiler reproduction, native differential, stateful and
bounded cancellation/restart checks at their recorded snapshots. The final
whole-runtime gate is still being reconciled; coverage is not an assertion that
every native input or operational failure has been proved equivalent.
Missing retained journal observations remain explicit history gaps; local footer
checksums do not create new signed fee authority.

The default isolated launcher starts the current proposal format at epoch two, enables
preverification receipts from genesis, uses `devnet_full_v1`, static genesis
validators and no issuance. These settings do not describe Octra's public devnet.
Public startup requires independently supplied chain/origin identity, validator
and exporter trust, configuration hash and checkpoint floor, together with usable
snapshot or authenticated prefix access. A downloaded configuration cannot grant
itself trust. A completed import still needs combined P2P/HTTP catch-up, replay,
disconnect/rejoin, restart, vote-lock and ExEx recovery qualification.

Native VPN admission and the paid client now share Circle/Program application
configuration, code and receipt-domain pins, committed escrow and signed opening
receipts. The default isolated launcher has no settlement application and denies
funded admission. The separate paid qualification fixture passed actual funding,
publication, receipt, rotation/replay, UDP and client/node kernel TUN/NAT tests
with the application profile bound to its private genesis. Only one
funded exit is implemented; multi-hop selection is refused before escrow.
See [native VPN integration](native-vpn.md) and
[validator duty integration](validator-duty.md) for source behavior and limits.

The combined paid fixture exercises node/VPN/ExEx and the canonical gateway
backend together, including operator termination/restart and active traffic
recovery. It does not qualify external HTTPS/Tailscale deployment, public source
failover or every durable publication boundary. Broader runtime cancellation and
recovery tests retain their own results. Historical passing reports apply only
to their pinned artifacts; the paid image does not establish public deployment.

The end-to-end regression is:

```sh
cargo test --locked -p octra-node --test devnet -- --nocapture
```

It starts four real validators, submits a signed transfer, reads a committed
Circle asset, stops one validator while the other three progress, restarts it
through peer catch-up, compares ExEx output, and shuts down cleanly. Consult the
checkpoint report for the actual result of a particular run.
