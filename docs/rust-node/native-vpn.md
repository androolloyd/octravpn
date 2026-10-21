# Native VPN source integration

The current prepaid service supports the native framed client, stock Tailscale
clients and explicit nested paid exits. See the [payment guide](../operators/payment-plans.md),
[stock transport and HTTPS configuration](../architecture/stock-paid-exit.md),
[nested client](../architecture/nested-paid-exits.md) and
[Circle custody variant](../architecture/circle-prepaid.md).
The [current qualification status](status.md) identifies which binaries and
runtime paths have completed validation. The v5 evidence below retains its
original application and transport scope.

The [local integration checkpoint](checkpoints/2026-10-17/native-integration.md)
records all seven fresh Linux scenarios, including both stock custody modes and
two- and three-hop Program routes. Its production node is release-built; the
captured paid-client and standalone-operator tools are debug builds. The private
Single scenario covers legacy v5. Public paid onboarding, trusted public DNS/TLS
and Mainnet require their own deployment qualification.

## Legacy v5 transport

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

The legacy client has a real userspace WireGuard driver and session framing.
Every outbound onion layer uses a fresh ephemeral key; cached receive keys apply
only to their original ephemeral public key. Legacy `connect` remains a
single-funded-exit path and refuses multi-hop selection before escrow. The
separate prepaid `multi-payments` client composes two or three independently
funded tunnels, with one accepted plan and durable purchase journal per hop.
It uses Linux route ownership and blocking routes beneath each carrier; it
does not enable the legacy unauthenticated inter-relay forwarding path.

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
On macOS, names such as `octra-exit` and `octrapay0` are logical labels: the
kernel chooses the actual `utunN` interface, which the client and node report
after opening it. A requested `utunN` name is passed through when that exact
unit is needed. Configure routes and NAT against the reported interface name.
macOS IPv4 interface configuration requires a privileged service or sudo.
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

## Shared node execution and recovery

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
Their URL lists are combined, so remove a stale source from both settings.
Before launch, compare each source's `/state-sync/head` with an independent RPC
head and the retained local epoch; omit sources behind the local history.
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

## Isolated application startup and checkpoint recovery

The [private launcher qualification](checkpoints/2026-10-19/private-launcher.json)
covers native Circle execution, export/import, restart and ExEx, plus a real
four-process CLI network. It leaves public-network consensus and activation rules
unchanged. The isolated launcher retains its loopback-only socket policy.

```sh
cargo build --release -p octra-node --features private-payments-experimental --bin octra-node
target/release/octra-node init-devnet --directory /private/tmp/octra-private --activated-applications
target/release/octra-node run --config /private/tmp/octra-private/node-0/config.json
```

Run the other three generated configurations in separate processes. The opt-in
is part of the original genesis commitment; setting a flag on an existing chain
cannot activate it. Startup derives the proof from the configured genesis after
checking its folded root, and shares that graph with execution and views.

Private offline exports use the existing `snapshot prepare` and `snapshot
assemble` commands with an independently accepted bootstrap configuration and
the exact native finalized anchor. Ordinary `canonical.db` sources are supported
only for isolated private genesis exports. Preparing an image does not authorize
it: native finality and exporter signatures are still verified. Public-network
export/startup paths retain checkpoint authority requirements.

After `bootstrap` installs a signed package into a new directory, point the
private node configuration's `data` at that directory and set `checkpoint_trust`
to the independently accepted bootstrap configuration's `network` object. Keep
the original `genesis` unchanged. Trust identity and validators must match that
genesis; downloaded `network.json` never chooses them. Imported stores use
`canonical.sqlite`; both store filenames in one directory refuse. Missing trust
or missing imported data also refuses rather than creating a new chain.

For a new observer, generate a fresh identity and select `voting: false`. Moving
an existing validator requires retaining its native signing records and floor;
checkpoint import does not replace those records. Data/key/faucet paths resolve
against the configuration file directory. Automatic private payer/client
scheduling and funded private kernel routes remain
separate qualification gates; released shielded traffic stays gated.

## Experimental private operator wallet

The [operator startup checkpoint](checkpoints/2026-10-19/private-operator-startup.json)
adds an optional `shielded` object to the isolated BFT node configuration when
built with `private-payments-experimental`. Public network configuration and
ordinary builds reject this option. Keep `genesis.activated_applications` bound
to the original private genesis.

The object supplies the following fields:

| Field | Value |
| --- | --- |
| `application` | Independently accepted Circle directory deployment pins and offer lineage, in the existing payment `Config` shape. |
| `pool` | Accepted shielded Circle/factory, custody ceiling, canonical verification key and its SHA-256 pin. |
| `wallet` | Path to the encrypted operator wallet directory. |
| `master_key` | Separate private 32-byte regular key file, outside wallet and transport recovery data. |
| `purchases` | Explicit `max_channels`, `max_requests`, `max_ceiling_ou` and `max_invoice_lifetime_ms` limits. |
| `ip_tunnel` | Optional existing IP tunnel configuration; `null` leaves kernel forwarding disabled. |

Paths resolve against the configuration directory. The private transport journal
uses `data/private-payments-transport`. Select this mode without legacy/public
payment configuration or stock exit settings. Control HTTP stays on loopback
behind the separately authenticated TLS transport.

Generate a dedicated storage key with the existing identity tool; only its raw
private file is used for wallet encryption. With accepted deployment pins in
the configuration, initialize the wallet once while the node is stopped:

```sh
target/release/octra-node init-identity --key /private/path/operator-storage.key
target/release/octra-node init-private-wallet --config /private/path/node.json
target/release/octra-node run --config /private/path/node.json
```

Initialization creates only a new off-chain encrypted book and opens no service
listeners. It does not deploy, fund, stake or validate delivery. Repeating it on
an existing wallet refuses. Ordinary startup only resumes the existing book;
missing data and incorrect keys never trigger recreation. Master-key files with
shared permissions, symlinks, multiple hard links or incorrect length refuse.
Protect the key separately from encrypted wallet/meter backups. Basic key-file
custody does not add OS keychain integration or rollback/cloned-writer protection.

Startup reuses canonical private purchase, replay and admission checks. A signed
quote still buys no traffic until genuine funding passes canonical verification.
The private operator configuration does not enable the released client shielded
mode; routed client scheduling/recovery and funded per-hop kernel traffic remain gates.

## Experimental private payer runner

The [private payer checkpoint](checkpoints/2026-10-19/private-payer-runner.json)
qualifies the reusable `shielded::payer::runner::Purchase` service. Its encrypted
job binds independently accepted pool/directory/operator pins, bond generation,
tariff hash, class, finite bytes, price ceiling, expiry and a separate native fee
budget. Receipt identities derive locally per job and differ from the relayer.

An application supplies an initialized payer book, canonical index, funded
dedicated relayer and accepted prover. `Pool::offer` exposes canonical directory
facts for constructing consent; an operator response cannot choose those pins.
Keep the original random job ID in the application's durable configuration and
use `Purchase::resume` after restart. Job discovery and a background route daemon
are separate integration work.

```rust,ignore
let control = PrivateControl::new(&origin, target, &accepted_ca, accepted_spki)?;
let purchase = Purchase::create(payer, job_id, accepted_terms).await?;
let state = purchase.step(Services {
    index: &index,
    submission: &submission,
    control: &control,
    relayer: &relayer,
    prover: &prover,
}).await?;
```

Drive another step on canonical progress or an explicit retry. A step performs
at most one control exchange or native submission. Requests retain their exact
IDs and windows after uncertainty; expiry refuses implicit renewal. Native
recovery scans the relayer's bounded encrypted journal before preparing another
proof. An exact healthy staged envelope may be announced again without changing
native duplicate-nonce rules or reserving another fee.

`Submitted` is staging only. `Credited` requires original canonical inclusion,
change reconciliation and the operator's matching receipt acknowledgement. It
does not authorize forwarding: the transport still needs its current plan-bound
funding guard. The released multihop mode remains gated pending per-hop client
integration and funded kernel/restart/ExEx qualification.

## Experimental private transport client

The [private client checkpoint](checkpoints/2026-10-19/private-client.json)
qualifies pinned HTTPS admission/status and encrypted client recovery against
the real canonical operator service. `AcceptedPrivatePlan` specifies the accepted
source, binding, tariff, bond generation, class caps, quote ceiling, TLS CA/SPKI
pins and WireGuard endpoint. Its quote ceiling is an allocation limit, not a
withdrawable native balance. Note purchases remain a separate native service;
this client has only the per-job receipt key.

```rust,ignore
use octravpn_client::{JournalMode, PreparedPrivateClient, PrivatePaymentOptions};

let prepared = PreparedPrivateClient::new(PrivatePaymentOptions {
    plan: accepted_private_plan,
    journal: original_journal_path,
    receipt_key,
    interface_name: "octraprivate0".into(),
    mode: JournalMode::Resume,
}).await?;
let client = prepared.open().await?;
// Provision explicit host routes using client.interface().
let summary = client.run(caller_shutdown).await?;
```

Creation requires `JournalMode::Create` and a genuinely new directory. Resume
requires the original key, plan and intact journal; missing data never implies
creation. Preparation durably advances the connection watermark and authenticates
the operator snapshot. It refuses a missing purchased floor before any UDP/TUN
startup. `open()` rechecks admission before opening WireGuard and TUN. The client
installs no host routes or global signal handlers.

The whole private transport state is XChaCha20-Poly1305 sealed under a separately
derived receipt-secret key and immutable plan/source scope. Public plaintext
journals cannot be loaded as private records. Existing private permissions,
single-writer leases, replacement detection, atomic/fsynced installation and
poisoned-write handling apply. Interrupted handoffs stay held after recovery.
Signed private observations preserve funding, delivery-slot, connection and
canonical-clock floors without increasing local byte caps. A stale observation
does not gain a new deadline when the caller starts its monitor later.

Both client modes use the same conservative packet handoff driver and shutdown
supervisor. Private summaries return byte counters, without an available-OCT
claim. All 369 client unit/integration tests and 248 private node tests pass;
strict ordinary and experimental checks pass. The canonical test uses pinned TLS
for genuine purchases and client preparation before/after funding and restart.
It opens no private payload tunnel or kernel interface. Linux private build,
per-hop native purchase/route orchestration and funded kernel/restart/ExEx remain
qualification work; the released multihop privacy selector stays gated.
