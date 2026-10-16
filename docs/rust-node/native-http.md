# Native HTTP source

The main Rust listener implements the native root, status, metrics and state-sync
HTTP routes. The final 40-test node release run includes native error/query
vectors, local transport preflight/CORS, bounded progress parsing, snapshot
descriptor/lease checks and multipart worker cancellation/shutdown. These local
checks do not establish a completed public snapshot import, public HTTP/P2P
catch-up or all publication/restart failure boundaries. See [status.md](status.md)
for the current release boundary and the separate paid-node/formal checkpoints.

The listener uses the captured launch settings. `OCTRA_STATE_SYNC_ENABLE` accepts
`1`, `true` or `yes`; configuring nonempty `OCTRA_STATE_SYNC_EXPORTERS` also enables
state sync. The head response is the native unsigned advisory projection of the
committed head. Range records carry the actual retained QC, validator set,
transaction and receipt commitments; a client must authenticate them against its
independent network configuration. Neither telemetry nor an observed head grants
validator membership or import authority.

`GET /status` reports the actual SQLite archive backend as `sqlite`. It retains
the native `v3.0.0-irmin` network-version field because the ledger commitments
remain Irmin-compatible. This physical-storage description intentionally differs
from the OCaml listener's `irmin-pack` string.

## Certificate and snapshot placement

The main listener reads `OCTRA_STATE_SYNC_CERT`, or
`<data>/state_sync/certificate.json` when that setting is absent. It verifies the
certificate against the captured chain, `OCTRA_CONSENSUS_CONFIG_HASH`,
`OCTRA_VALIDATORS` and `OCTRA_STATE_SYNC_EXPORTERS`. Serving a manifest never creates
an export or synthesizes missing pack files.

Native chunk routing expects this explicit layout:

```text
<snapshot-root>/<certificate.manifest.snapshot_id>/
  .ready.json
  .certificate.json      # optional archived certificate; current one may match
  HEAD.json
  ledger.dat
  ...                   # only actual files committed by the manifest
```

`<snapshot-root>` is `OCTRA_STATE_SYNC_SNAPSHOT_DIR`, or
`<data>/state_sync_snapshots`. The authenticated snapshot ID is the checkpoint
hash. Every requested path, index and SHA-256 must occur in the verified manifest.
The payload is read from the actual retained file and checked against the chunk
digest before serving. File traversal and the readiness marker use directory
descriptors with `NOFOLLOW`; symlink substitution cannot select unrelated files.

The public-network launcher now has an automatic exporter service in source.
The configured native exporter wallet must match the loaded key and be one of
its first two sorted configured addresses. `--publisher` selects the observer
role and forces exporter selection; `OCTRA_STATE_SYNC_FORCE_PUBLISH` accepts only
empty, `0` or `1`. Neither override creates exporter authority. An ordinary
unselected observer remains dormant and opens no archive.

The cycle polls every 15 seconds, targets each 360-epoch boundary and the latest
applicable native profile activation, and tries the latest retained head before
the rounded target. It uses retained QC/state/index proofs and the independently
configured validator-transition chain, then signs with the loaded identity.
Missing transition evidence prevents publication. Snapshot creation time comes
from the finalized header timestamp, and validity is 2,678,400 seconds. Native
placement and the current certificate pointer are published atomically, with the
pointer last. Restart rechecks the certificate and all committed package files.

The archive retains the two newest snapshots and the current one, plus at most
eight recent download leases. A lease must be no older than 900 seconds and its
snapshot publication no older than 86,400 seconds; timestamps over 60 seconds in
the future are refused. Pruning touches only archive-owned directories, using
pinned descriptors and durable inode-bound removal intents. Unknown directories
and stages remain preserved. A failed image write leaves a marked stage that can
be safely retried after restart. Eight focused host lifecycle/role tests and all
39 pinned native comparisons passed, including corrupt same-head package repair,
foreign authority refusal, validator-set transition proofs and interrupted
removal recovery. Strict Node Clippy passed for all targets with `--no-deps`.
See the [snapshot service checkpoint](checkpoints/2026-10-15/snapshot-service.json)
for exact source, tool, executable and oracle hashes. Public producer and final
combined Linux qualification remain separate gates.

`snapshot_limits` sets local image byte, record and string budgets. The default
byte cap is the existing conservative 8 GiB; a producer for a larger authenticated
image must explicitly raise it. The standalone export CLI still prepares a new
immutable package in an operator-selected directory and its own server can serve
that verified package directly. It shares image and signature validation with
the automatic publisher, while retaining explicit external signature inputs.

Successful native chunk reads renew `download.lease` in the retained snapshot
directory at most once per 60 seconds. This is local download-retention metadata;
it does not modify canonical state or trust. Renewal opens the snapshot directory
and lease by descriptor, rejects nonregular files and symlinks, and updates the
file timestamps without truncating existing lease content. Renewal failure is
logged and does not invalidate an already verified chunk.

## Bounded service behavior

HTTP requests have the native 30-second timeout and `Connection: close` response.
Client-progress telemetry is an unauthenticated bounded JSON object, as upstream;
it only produces a log entry. Readiness returns a genuinely signed local marker
whose epoch/root remains in independently retained canonical history.

Range acquisition has four active/queued slots, one physical read at a time,
15-second request lifetime and a 60-second single multipart cache. An abandoned
request keeps its active slot through its current physical operation, then stops
at the next boundary. Retained multipart bytes stay scoped to this service's
chain; a supplied digest pins a subsequent part to the same response.

Certificate verification has eight active/queued slots, one physical worker at a
time, a 15-second lifetime and a bounded positive/negative cache. Chunk reads keep
their configured physical read permits until the blocking operation completes.
History allocation preflight reads only scalar database lengths bound to the
retained head/outbox. Those hints never authenticate content: the existing full
finality verification follows. Oversized auxiliary archive representations are
reported as operational errors rather than invented missing history. No new
block-acceptance or consensus limit is introduced.
