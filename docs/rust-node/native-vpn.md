# Native VPN source integration

The [2026-10-15 checkpoint](checkpoints/2026-10-15/native-vpn.json) records a
passing combined funded transport/recovery gate, reproduced with
`docker/native-vpn/run.sh`. It includes actual main-v5/factory deployment,
private administration, paid UDP and client/node OS TUN/NAT TCP/UDP/ICMP traffic,
same-opening recovery and TCP continuation after operator restart, matching
four-validator ExEx and canonical gateway delivery. Its result applies to the
captured source/image and isolated application activation profile. It does not
establish a public-devnet join, external Tailscale/TLS deployment or Mainnet
readiness. [Current status](status.md) keeps those gates separate.

The Rust node captures one immutable committed tree for Circle browsing and VPN
admission. Canonical publication revokes the preceding tree's packet permits
before exposing a new tree. Publication notifications refresh admitted sessions;
temporary unavailability pauses packets without extending the last verified
lease. Revalidation may retain an existing WireGuard handshake. Definitive
refusal, lease expiry and shutdown close packet admission.

`vpn` in the node configuration selects the receipt domain, application address,
bytecode SHA-256, operator Circle and compiler storage layout. `application` is
`circle` or `program`; `layout` is `source` or `protocol`. The adapter verifies
the configured code, zero protocol commission, operator receipt key, eligibility,
escrow, session lifetime and both client/opener signatures. An opening must be
an exactly authenticated transaction in the captured canonical prefix, with the
matching successful opening receipt. Cached opening evidence remains bound to
its containing canonical head and never substitutes for current state checks.

The client has a real userspace WireGuard driver and session framing. Every
outbound onion layer uses a fresh ephemeral key; cached receive keys apply only
to their original ephemeral public key. Only one funded exit is currently wired.
Multi-hop selection is refused before escrow because authenticated inter-relay
transport and per-hop funding are not implemented.

`connect` and `connect-v3` accept either `--udp-target IPv4:PORT` with an optional
loopback `--udp-bind`, or `--tun-name INTERFACE`. UDP forwarding pins one local
source to a connected public destination. Node flow queues, sockets and idle
lifetimes are bounded. The return path is framed and encrypted to the same
authenticated peer; ordinary internet replies never enter the WG listener.

Raw IP mode requires an anchored `ip_tunnel_v1: true` policy and an explicitly
configured node interface. Native-node configuration uses
`vpn.ip_tunnel = {"name":"octra-exit"}`; standalone operator TOML uses
`[tun.ip_tunnel] name = "octra-exit"`. The node opens a dedicated TUN at
`198.18.0.1/15`; clients derive a session/WG-bound address and open a `/32` TUN.
MTU is 1280. Complete IPv4 TCP, UDP and ICMP packets are checked for lengths,
checksums, source ownership and public destinations. Options, fragments, IPv6,
private destinations and source spoofing are refused. Address collisions are
refused. Before forwarding a first packet, the node fsyncs its session/WG
address ownership in a private, exclusively locked journal. Ownership survives
restart; active routes remain bounded separately. Partial unused tail records
are recoverable, while contradictory records or checksum failures stop IP mode.
The finite `/15` pool is never silently reassigned to another transport identity.
That identity is the session ID and client WireGuard key. The supported client
creates a fresh ephemeral key for each new funded session and retains it during
live recovery. Deliberately reusing both values across application domains retains
the same transport owner and can retain kernel flow attribution; this journal
does not provide cross-application flow isolation. Canonical admission and signed
receipt storage bind the full chain/application domain independently.

The native ownership journal remains at `data/vpn/ip-owners-<interface>.bin`,
independent of receipt namespaces; standalone nodes use the receipt-journal directory.
`vpn.ip_tunnel.address_book` can select an explicit path. Preserve this journal
while kernel/NAT state can survive. Changing the WG server identity requires an
explicit transport migration; the preceding journal is not silently reset.

Host routes, internet forwarding and NAT must be provisioned separately for the
dedicated interface. The library does not change default routes, firewall rules
or global forwarding settings. Client routing must retain a physical route to
the operator's WG endpoint. This interface mode is separate from the ordinary
HTTPS Circle gateway served over an existing Tailscale connection.

Operator policies commit the WG key, Ed25519 receipt key, receipt chain ID,
application kind, prices, control origin and optional IP capability. The client
checks the independent registered receipt key before funding and bounds its
final signed receipt against locally observed traffic. Client recovery storage
is separated by application and receipt domain. Existing unscoped recovery data
requires explicit migration rather than inferred ownership.

Native receipts and pending claims use private `data/vpn-scopes/<digest>`
directories. Their immutable binding includes the full typed chain origin,
application kind and signed receipt domain; code and transport key rotations do
not create new receipt floors. A fully matching legacy binding can retain its
original files. A matching receipt context without authenticated chain/application
provenance requires an explicit, evidence-verified migration. Startup never
deletes old floors or relabels them as another application.

A running `connect-v3` client can recover the same funded session after an
operator restart or temporary network failure. It pauses application packets,
rechecks the original canonical opening and immutable policy, reannounces the
same identities and completes a fresh WireGuard handshake before resuming.
Signed receipt sequences must increase and byte floors cannot decrease.
Changed domains, keys, opening terms or closed sessions stop recovery. Retries
are bounded and never submit replacement funding. This retains the live client's
ephemeral key and counters; it does not reconstruct a tunnel after the client
process loses that key. Durable receipt settlement/refund recovery is separate.

`octra-node vpn-identity --key PATH` shows only the operator address, receipt
public key, WG public key and plain WG transport descriptor derived by the
native launcher. Use these public values for application registration and
anchored discovery. The command neither registers an operator nor opens the
canonical store.

Register the native operator with the same funded wallet in the standalone
bootstrap configuration. Export only its public descriptor, then pass it to
bootstrap:

```sh
octra-node vpn-identity --key /path/to/node.key > native-identity.json
octravpn-node --config node.toml circle bootstrap --circle oct... --native-identity native-identity.json
octravpn-node --config node.toml circle bootstrap --circle oct... --native-identity native-identity.json --commit
```

The descriptor selects plain WireGuard and avoids loading the standalone WG
secret. Its operator must match the funding wallet; its public keys must be
canonical and safe. The Circle must expose public resources. Prices, control
origin, application, receipt domain and optional IP capability come from the
bootstrap configuration. Public discovery needs no sealed passphrase. Standalone
sealed discovery still requires one and publishes both encrypted resources.

Bootstrap requires a readable committed epoch. It reads back immutable policy
and state-root bytes before submitting the anchor, then waits for the active
registry anchor and receipt key. Existing anchored resources must verify before
reuse or replacement; a corrupt resource never triggers an unverified fallback.
An unchanged active registration performs no funding transaction. `--force`
explicitly resets membership hashes; use `circle update` for ordinary rotation.

Public discovery publication uses immutable paths:

- `/octravpn/snapshots/<policy hash>/policy.json`
- `/octravpn/snapshots/<anchor>/state-root.json`

The operator reads back both resources before submitting the registry anchor and
waits for the committed anchor before recording successful registration. An
unchanged policy retains its revision epoch/timestamp across restarts. Clients
fall back to old fixed paths only when an immutable resource is absent; hash
mismatches never trigger a fallback. These are application resource paths and
off-chain transport changes, not changes to consensus rules.

The checkpoint covers real TUN/NAT and UDP return traffic, receipt accounting,
private credential handoff/rotation/replay refusal, operator restart and combined
node/ExEx/gateway operation. Its 26 focused tests cover additional framing,
revocation and recovery boundaries. It does not claim every publication failure
interleaving or production key lifecycle has been exercised.

Native transaction submission now has source routes for `octra_submit`,
`octra_submitBatch`, `octra_privateTransfer` and `octra_recommendedFee`.
They preserve typed admission refusals and use the durable staging queue;
acceptance does not imply finality. Native observer RPC remains read-only unless
the captured `OCTRA_OBSERVER_RELAY_SUBMITS` flag enables relay submissions.
Peer intake and pending-journal recovery do not inherit that RPC restriction.
The nonce window uses the captured native setting, defaulting to 32.

Canonical commit ownership now outlives the calling Tokio runtime: a dedicated
commit thread retains both serialization and the file writer lease through the
SQLite result and head-cache update. Cancellation keeps application serving
suspended until explicit recovery. The node release gate passed canceled
publication/writer-retention and atomic reopen checks; this is bounded evidence,
not coverage of every runtime teardown or publication failure interleaving.

Native epoch summaries retain actual footer observations in the canonical SQLite
transaction. Reads bind their epoch, proposer, timestamp, QC, reward source and
transaction index to retained finality. Fee totals are checked against confirmed
transactions and the authenticated rejection partition. The native legacy
receipt format does not identify every fee-preserving VM refusal: ambiguous
charges retain an explicit bound and require execution replay for exact proof.
Financial footer fields remain local execution metadata with an integrity
checksum; they do not acquire a new consensus signature. Missing observations
or legacy Tree digests remain summary/page gaps.

Snapshot and recovery qualification must cover native export/assemble/import,
tampered files and chunks, expired or conflicting signing authority, checkpoint
window boundaries, absent legacy metadata, and cancellation before digest
retention, during SQLite commit, and before ExEx notification. Restart must
recover the same canonical prefix and extension cursor, restore only a retained
legacy digest, and keep VPN/browser admission suspended until explicit resume.
Concurrent-writer exclusion, runtime teardown and process termination require
real combined-process tests after source completion.

The optional native gRPC facade is selected by captured `OCTRA_GRPC_ENABLE` and
the upstream `OCTRA_GRPC_*` limits. It binds numeric loopback only. Its seven
unary routes share native JSON-RPC account, transaction, epoch and submission
handlers and admission rules. The protobuf response limit is independent of the
HTTP JSON-RPC envelope limit. HTTP/2 streams,
connections, payloads and deadlines are bounded; response flow control and stream
resets do not depend on a browser or a wallet process. Protobuf, framing,
trailers and slow-reader cancellation passed local HTTP/2 window/worker tests
in the node release gate. Independent native-client interoperability and public
deployment remain separate gates.

HTTP catch-up captures `OCTRA_JOIN_RPC` and `OCTRA_STATE_SYNC_SOURCES` once.
Sources supply bounded native multipart ranges; head advertisements select work
only after independent QC or consecutive-prefix verification. Every imported
epoch still resolves local historical authority and executes against its actual
parent. An unavailable source preserves the committed prefix and lets startup
continue through independent P2P recovery. Voting also requires serving admission
to be active.

A completed HTTP import can publish the native signed `ready_to_vote.json`
statement. Its signer is pinned to launch identity and its epoch/root must remain
in authenticated retained history before it is served. The statement does not
authorize a validator set or a snapshot. Source failover, changing multipart
identity, malformed or excessive parts, unknown validator transitions, partial
import cancellation, stale or forged readiness files, and combined P2P/HTTP
startup remain final end-to-end qualification cases.

The live recovery supervisor detects lost required peers and stalled history.
It suspends serving and voting, stops the old driver, waits for any owned commit,
then imports authenticated P2P or HTTP ranges. It advances journal floors only
through committed history, retains future locks, reconciles staged transactions,
and recreates the driver with the same operator identity and duty handler.
Incomplete recovery remains suspended and retries; replacing an unavailable
history floor still requires a separately verified snapshot and restart.
Local node tests cover stopped-generation joining, authenticated peer recovery,
staged-queue replay and restart of canonical browser/VPN/ExEx services. Sustained
public disconnect/rejoin, validator transitions, same-height lock/duty continuity
and shutdown at every recovery boundary remain broader qualification gates.
