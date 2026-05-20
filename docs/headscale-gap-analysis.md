# headscale-go → headscale-rs: gap analysis

**Scope.** Catalogues the delta between upstream `juanfont/headscale`
(Go, `main` as of 2026-05-19 — most recent migration in
[`hscontrol/db/db.go`](https://github.com/juanfont/headscale/blob/main/hscontrol/db/db.go)
is `202602201200-clear-tagged-node-user-id`, v0.27.x line) and our
sibling Rust port at `/Users/androolloyd/Development/headscale-rs/`
(sibling-repo layout + dep-resolution strategy:
see [`docs/architecture/headscale-dep-strategy.md`](./architecture/headscale-dep-strategy.md)).
Prioritised by what blocks **stock `tailscale up` (v1.78+) joining a
mesh hosted by an OctraVPN-derived control plane**, as exercised by
`docker/devnet/tailscale-interop/run-interop.sh`.

**Treatment of the in-flight migration.** The seven files in
`crates/octravpn-mesh/src/tailscale_wire/` (controlbase, key_handler,
map, mod, noise, register, wire) already have copies under
`headscale-api/src/tailscale_wire/` — assume "shipped in headscale-rs"
when comparing.

**Priorities.** P0 = blocks `tailscale up` exit 0. P1 = blocks realistic
multi-peer deployment. P2 = operator-grade polish.

**Citations.** `juanfont/headscale@main:<path>` for upstream;
absolute paths under `/Users/androolloyd/` for local. Wire-surface
specifics that already live in
[`tailscale-interop-blocker.md`](./tailscale-interop-blocker.md) are
cited, not re-explained.

## At a glance

| Subsystem            | Upstream (Go) ships                                                 | headscale-rs ships                                              | Gap            | Priority |
| -------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------- | -------------- | -------- |
| `GET /key`           | `tailcfg.OverTLSPublicKey{,Legacy}`                                 | yes (`tailscale_wire/key_handler.rs`)                           | none           | —        |
| Noise IK + controlbase | `controlhttpserver.AcceptHTTP`, h2-over-noise                     | controlbase framing + `NoiseStream` + h2 + EarlyNoise stub      | EarlyNoise unverified | P0 |
| `POST /ts2021`       | Upgrade hijack, runs noise router under h2                          | shipped                                                         | client never reaches it (see below) | P0 |
| `/machine/register` (flat)  | served on noise router (`hscontrol/noise.go`)                 | only `/machine/{node_key}/register` (path-param shape)          | flat path missing | **P0** |
| `/machine/map` (flat)       | served on noise router                                        | only `/machine/{node_key}/map`                                  | flat path missing | **P0** |
| TLS on :443          | yes (`server_tls.go`, autocert + manual cert)                       | none                                                            | client forces 443 dial | **P0** |
| `MapResponse.Stream=true` ndjson | required, streaming chunks                                | single-shot body; 30s keepalives implemented but not wrapped per-chunk | partial | **P0** |
| Full `MapResponse` fields | Node, Peers, PeersChanged{,Patch,Removed}, DNSConfig, DERPMap, Domain, PacketFilters, UserProfiles, SSHPolicy, ControlTime, Debug, CollectServicesDisabled, PingRequest | Node, Peers, DnsConfig, DerpMap, Domain, KeepAlive | majority of fields | P1 |
| Delta map updates    | `PeersChanged` / `PeersChangedPatch` / `PeersRemoved`               | none — full snapshot only                                       | full           | P1       |
| ACL engine           | HuJSON, `policy/v2/`, autoApprovers, ssh, tagOwners, autogroups, ipsets, route approvers | strict-JSON ACL parser, autoApprovers (routes+exitNode), ssh, tagOwners, groups, `autogroup:internet` | HuJSON, autogroups beyond `internet`, NodeAttrs, route auto-approval wiring | P1 |
| Pre-auth keys        | reusable / single-use / ephemeral / tagged, expiry, per-user, bcrypt-hashed | `PreauthMinter` in-process, single-use bearer       | reusable/ephemeral/tagged/expiry/persistence | **P1** |
| OIDC                 | full SSO (`oidc.go`, mockoidc, templates)                           | none                                                            | full           | P2       |
| Embedded DERP server | yes — wraps `tailscale/derp.Server`, serves `/derp`, `/derp/probe`, `/bootstrap-dns`, STUN | DERP *client* + map-emit only; no relay        | full server    | P1 (none for docker-bridge interop) |
| DERP map serving     | merges file + URL + embedded sources                                | builds map from configured servers in `MeshCoordinator`         | URL/file-based loaders | P2 |
| MagicDNS             | `dns/`, MagicDNS, SplitDNS resolvers, extra records hot-reload (`extrarecords.go`), search domains | empty `DnsConfig` shape only                  | full           | P1       |
| Machine lifecycle    | register → expire → renew → logout → delete; ephemeral GC; tag rewrite | register + IP alloc + in-memory record only                  | expire/renew/logout/ephemeral/GC | P1 |
| OIDC + browser flow  | `/register/:auth_id`, `/auth/:auth_id`, templates                   | none                                                            | full           | P2       |
| Persistence          | GORM + 17 versioned `gormigrate` migrations (latest 202602201200)   | sqlx + 4 migrations (`20260118000001..4`)                       | preauthkey/policy/apikey/user tables, no NodeKey rotation history | P1 |
| Operator CLI         | 17 cmd groups (users, nodes, preauthkeys, apikeys, policy, debug, generate, serve, configtest, mockoidc, dump_config, version, health, auth, root) | 5 (server, node, identity, nodes list/show, status, init-config) | users/preauthkeys/apikeys/policy/debug subcommands | P1 |
| gRPC admin API       | `grpcv1.go` — full nodes/users/preauth admin via gRPC               | `headscale-api/src/grpc.rs` exists + proto generated under `generated/headscale.v1.rs` | handler impl & coverage TBD | P2 |
| Metrics / health     | Prometheus, `/metrics`, `/health`                                   | yes (`mesh_metrics`, `/metrics`, `/health{,/ready,/live}`)      | parity         | —        |
| Resource gateway     | —                                                                   | `headscale-api/src/gateway/` (auth/quota/inference/router)      | OctraVPN add-on | n/a    |
| Payment ledger       | —                                                                   | `headscale-payments` (ledger, x402, escrow, channels) — **kept on disk, dropped from workspace.members on 2026-05-20; deletion candidate** | OctraVPN add-on | n/a    |
| DID identity         | —                                                                   | `headscale-identity` (Ed25519, DID, session) — **kept on disk, dropped from workspace.members on 2026-05-20** | OctraVPN add-on | n/a    |
| Resource registry/metering | —                                                             | `headscale-resources` — **kept on disk, dropped from workspace.members on 2026-05-20** | OctraVPN add-on | n/a    |

## 1. Wire protocol — control plane HTTP

Stock `tailscale` v1.78+ wire surface (re-derived in
[`tailscale-interop-blocker.md`](./tailscale-interop-blocker.md):22-30
and the 2026-05-19 continuation §"Wire-format surprise"):

| Endpoint                         | Method | Status in headscale-rs |
| -------------------------------- | ------ | ---------------------- |
| `GET /key`                       | GET    | shipped (`headscale-api/src/tailscale_wire/key_handler.rs`) |
| `POST /ts2021`                   | POST   | shipped (noise upgrade + h2 + inner router) |
| `POST /machine/register` (flat)  | POST   | **missing** (only `/machine/{node_key}/register` exists) — P0 |
| `POST /machine/map` (flat)       | POST   | **missing** (only `/machine/{node_key}/map`) — P0 |
| `GET /machine/ssh/action/{src}/to/{dst}` | GET | missing — required only if SSH ACLs are exposed |
| `GET /derp/probe`                | GET    | missing — only needed if we host an embedded DERP |
| `GET /derp` (upgrade)            | GET    | missing — embedded DERP not in scope for interop |
| `GET /health`, `GET /version`, `GET /robots.txt` | GET | `/health` shipped; `/version`/`robots.txt` missing — P2 |
| `POST /verify`                   | POST   | missing — DERP client verification — P1 (needed if relay added) |
| `GET /register/:auth_id`, `GET /auth/:auth_id` | GET | missing — browser/OIDC flow — P2 |

Upstream's `hscontrol/handlers.go` registers the public side
(see [WebFetch summary]) and `hscontrol/noise.go` chains the inner
router for noise-protected `/machine/{register,map,ssh/...}`.
headscale-rs mirrors this split — public router in
[`headscale-api/src/http.rs:43-58`](../headscale-rs/headscale-api/src/http.rs),
inner noise router built in `tailscale_wire/noise.rs::handle_ts2021_post`.

The `/api/v1/...` JSON routes in `http.rs:43-58` are an OctraVPN-only
admin surface and not part of Tailscale interop; they coexist with the
wire surface rather than replacing it.

## 2. Wire protocol — Noise transport

Upstream uses Tailscale's `controlhttpserver.AcceptHTTP` (delegating
to `tailscale/control/controlbase` for the framed Noise IK and
`tailscale/control/controlhttp` for the upgrade+h2 chain). After the
handshake an `http2.Server` is bound to the encrypted transport;
requests are dispatched against a `chi` router (`hscontrol/noise.go`).

headscale-rs ships in `tailscale_wire/`:
- **Persistent X25519 server key** — `noise.rs::ServerNoiseKey`
- **Controlbase framing** — `controlbase.rs` (3/5-byte headers + 6 unit
  tests, per blocker doc §"Update 2026-05-19 (PR 2 continuation)")
- **Noise IK round-trip via `snow` 0.9** — `noise.rs::drive_ts2021`
- **`NoiseStream`** — `AsyncRead+AsyncWrite` adapter so `h2::server::handshake`
  can run on top
- **EarlyNoise prefix** — `[0xff 0xff 0xff 'T' 'S'][json_len:u32be][json]`
  with stub `{"NodeKeyChallenge":{"Public":"nodekey:00…"}}`
- **Inner router dispatch** via `tower::ServiceExt::oneshot` against axum

**Gap:** EarlyNoise content is unverified against real client bytes
(blocker doc, §"EarlyNoise frame status"). Stock client never reaches
`/ts2021` until §3 below is fixed, so this is currently dead weight on
the wire. **Priority: P0** to validate once flat paths land.

## 3. MapResponse construction

Upstream's `hscontrol/mapper/builder.go` populates a fluent
`MapResponseBuilder` with 15+ fields:

| MapResponse field    | Upstream sets via              | headscale-rs (`tailscale_wire/wire.rs:202-224`) |
| -------------------- | ------------------------------ | ------------------------------------------------ |
| `Node`               | `WithSelfNode`                 | yes                                              |
| `Peers`              | `WithPeers`                    | yes                                              |
| `PeersChanged`       | `WithPeerChanges`              | **missing** — P1                                 |
| `PeersChangedPatch`  | `WithPeerChangedPatch`         | **missing** — P1                                 |
| `PeersRemoved`       | `WithPeersRemoved`             | **missing** — P1                                 |
| `DNSConfig`          | `WithDNSConfig`                | empty stub                                       |
| `DERPMap`            | `WithDERPMap`                  | empty stub                                       |
| `Domain`             | `WithDomain`                   | hard-coded `octra.test`                          |
| `PacketFilters`      | `WithPacketFilters`            | **missing** — P1 (ACL enforcement on client)     |
| `UserProfiles`       | `WithUserProfiles`             | **missing** — P1                                 |
| `SSHPolicy`          | `WithSSHPolicy`                | **missing** — P2                                 |
| `Debug`              | `WithDebugConfig`              | missing                                          |
| `CollectServices`    | `WithCollectServicesDisabled`  | missing                                          |
| `PingRequest`        | `WithPingRequest`              | missing — P2                                     |
| `ControlTime`        | auto                           | missing — P1                                     |
| `KeepAlive`          | per-frame                      | top-level field; not per-frame                   |

**Streaming.** Upstream's `hscontrol/poll.go` runs a session loop:
"streaming requests (Stream=true): continuous long-poll connections",
JSON-marshalled, optionally Zstd-compressed, ~50s jittered keepalives.
headscale-rs (`tailscale_wire/map.rs:45-51`) emits a single body plus
30s `\n` keepalives but is **not** per-chunk MapResponse-framed —
`MAP_KEEPALIVE_INTERVAL` is wired, full ndjson chunked write is not.
**Priority: P0** for interop; raw client probably tolerates the
single-shot path for the first response but rejects when the connection
closes without the streaming continuation.

**Delta updates.** Upstream's `mapper/batcher.go` is ~6 files (batcher,
batcher_concurrency, batcher_scale_bench, batcher_unit, mapper,
node_conn) of incremental-update plumbing. headscale-rs sends every
peer change as a full snapshot — fine for the 2-peer interop test, not
for production. **Priority: P1.**

## 4. ACL / policy engine

Upstream ships two engines: a legacy parser and `hscontrol/policy/v2/`
(matcher, policyutil, autoapprove, route-approval). Key features:

- HuJSON (JSON-with-comments) parsing
- `tailcfg.NodeAttr` resolution
- `autogroup:` (internet, members, tagged, danger-all, self, nonroot)
- `ipset:` macros
- Route auto-approvers + exit-node auto-approvers
- SSH policy compilation into the MapResponse
- `BuildPeerMap` — n×n peer accessibility resolution in one pass
- `ReduceNodes` / `ReduceRoutes` per-node filtering with bidirectional checks

headscale-rs ships in
[`headscale-core/src/acl.rs`](../headscale-rs/headscale-core/src/acl.rs):

| Feature | Status |
| ------- | ------ |
| Strict JSON parser with unknown-field rejection | shipped (`from_json_strict`) |
| `hosts`, `groups`, `acls`, `tagOwners`, `autoApprovers`, `ssh` | shipped |
| `autogroup:internet` | shipped |
| CIDR matching + named hosts + port specs (incl. `[ipv6]:port`) | shipped |
| `evaluate`/`can_reach`/`can_reach_port` | shipped |
| `should_distribute_route` + `can_be_exit_node` | shipped, **but not wired into the wire-protocol path** |
| Property tests for ACL semantics | shipped (`acl::proptests`) |

**Gaps vs upstream:**
- **HuJSON parser** — upstream accepts policies with comments; we
  require strict JSON. P2 (operator nicety).
- **Autogroups beyond `internet`** — `autogroup:tagged`, `autogroup:members`,
  `autogroup:self`, `autogroup:nonroot`, `autogroup:danger-all` are absent. P1.
- **`NodeAttr` resolution** — upstream emits a list of capability flags
  per peer (`funnel`, `ssh`, etc.) that the client honours. P2.
- **PacketFilter generation** — the ACL exists but isn't compiled into
  a `tailcfg.FilterRule` stream that ships in `MapResponse.PacketFilters`.
  Without this the client enforces no policy; ACL evaluation only runs
  if `octravpn-node` does its own L3 gating. **P1** for any non-trivial
  deployment.
- **Route auto-approval wired into register/map flow** — the evaluator
  knows how, but the wire handlers don't call it.
- **`policy/v2/` engine** — upstream's matcher dataflow is more
  efficient at scale; we have a single linear evaluator. P2.

## 5. DERP

Upstream embeds a DERP relay server (`hscontrol/derp/server/derp_server.go`
wraps `tailscale/derp.Server`) and serves `/derp`, `/derp/probe`,
`/bootstrap-dns`, plus STUN on a separate port.

headscale-rs has:
- A **DERP client** for relay fallback
  (`headscale-core/src/derp.rs:69-95`) — useful for `octravpn-node`
  outbound but not what we'd need to *host* relays.
- A `DerpServer` struct (name, hostname, addr, region, stun_enabled) —
  it's a config record, not a running server.
- DERP map generation in `MeshCoordinator::register`
  (`headscale-core/src/mesh.rs:163-192`) from configured servers.

**Verdict.** The docker-bridge interop test doesn't need DERP — both
peers can NAT-traverse directly (blocker doc §Recommendation,
"Why we *don't* implement DERP"). For real WAN deployments, **P1**.
The DERP map URL/file loaders in upstream (`hscontrol/derp/derp.go::GetDERPMap`,
`mergeDERPMaps`, `shuffleDERPMap`) are **P2** — useful for pointing
at external relays without restart.

## 6. MagicDNS / SplitDNS

Upstream's `hscontrol/dns/extrarecords.go` watches a JSON file with
`tailcfg.DNSRecord` entries via fsnotify; supports hot reload with SHA256
debounce. The mapper builder injects `DNSConfig` (resolvers, search
domains, magic dns suffixes) into `MapResponse`.

headscale-rs ships an empty `DnsConfig` shape in `tailscale_wire/wire.rs:249-258`
with `resolvers` and `domains` fields, but no responder, no extra-records
file, no SplitDNS routing, no MagicDNS A/AAAA service. The hard-coded
`Domain: "octra.test"` is emitted but unbacked by a resolver.

**Priority.** P1 for production. The interop test never resolves names,
so this is **not** a P0.

## 7. Machine lifecycle

Upstream (`hscontrol/auth.go::handleRegister` decision tree):
1. Logout-first detection (past expiry timestamp)
2. Auth-key path (`handleRegisterWithAuthKey` → `state.HandleNodeFromPreAuthKey`)
3. Interactive path (`handleRegisterInteractive` → `AuthURL`)
4. Followup resumption (cached auth state)

Plus distinct handling for:
- NodeKey / MachineKey / DiscoKey three-key model
- Re-registration mismatch detection (reject if MachineKey differs)
- Ephemeral node GC
- Tag rewriting at register time
- Logout with expiry update (no key extension allowed)

headscale-rs (`tailscale_wire/register.rs:43-...`):
- Decodes `RegisterRequest`, redeems preauth, allocates tailnet IPv4,
  stores in-memory `MachineRecord`. **One-shot.**

**Gaps:**
- **Re-registration / key rotation** — none. P1.
- **Logout** — none. P1.
- **Expire / renew** — none. The blocker doc's `key_expiry_extension`
  field is wire-only; no time-based machinery. P1.
- **Ephemeral nodes** — none. P1.
- **Tagged registration** — preauth has no tag field. P1.
- **Interactive auth path** — never (preauth-only). P2.
- **Followup state** — never. P2.

## 8. Preauth keys

Upstream supports reusable / single-use / ephemeral / tagged keys,
per-user, with expiry, bcrypt-hashed (migration `202511011637-preauthkey-bcrypt`).

headscale-rs has `PreauthMinter` in
`/Users/androolloyd/Development/octra/crates/octravpn-mesh/src/headscale_bridge.rs`
(noted in the wire-bridge intro: "in-process store so an operator … can
later present it as a bearer credential"). Single-use, in-process,
per-user label only.

**Gaps:**
- Reusable keys — **P1**.
- Ephemeral flag — **P1** (couples to ephemeral lifecycle in §7).
- Tagged keys — **P1**.
- Expiry timestamp — **P1**.
- Bcrypt-at-rest — **P2**.
- DB persistence (survive restart) — **P1** (today the keys evaporate).

## 9. OIDC / OAuth

Upstream: `hscontrol/oidc.go`, `oidc_test.go`, `oidc_confirm_test.go`,
`oidc_template_test.go`, plus `cmd/headscale/cli/mockoidc.go` for a
local IdP. Full SSO with templated browser flow and the
`/register/:auth_id` / `/auth/:auth_id` confirmation pages.

headscale-rs: nothing. `headscale-identity` ships DID/Ed25519 challenge
auth which is the OctraVPN-native model — not an OIDC replacement
because stock `tailscale` doesn't know how to do DID auth.

**Priority: P2.** Not blocking interop (preauth covers the test); becomes
P1 if multi-user web onboarding is a requirement.

## 10. Persistence

Upstream: GORM + gormigrate, 17 versioned migrations
(`202501221827` through `202602201200`), models: User, Node, PreAuthKey,
APIKey, Policy, Route, Migration. Plus IP allocation, version checks,
text serialisers, ephemeral GC.

headscale-rs (`headscale-db/`):
- sqlx + 4 SQL migrations:
  `20260118000001_create_nodes.sql`,
  `20260118000002_create_transactions.sql`,
  `20260118000003_create_resources.sql`,
  `20260118000004_create_sessions.sql`
- Models: `NodeRow`, `payments`, `resources`, `sessions`
- **In-memory only:** `MachineRegistry` in `tailscale_wire/mod.rs`,
  `PreauthMinter` in `headscale_bridge.rs`.

**Gaps:**
- **No `preauth_keys` table** — keys are lost on restart. **P1.**
- **No `policy` table / hot reload from DB** — P1.
- **No `users` / `api_keys`** — P1.
- **`MachineRegistry` is RAM-only** — register survives in-process only.
  Forces every restart to re-bootstrap every node. **P1.**
- **Tests:** upstream has a fixture story via `servertest/`; we have
  `headscale-db::tests::test_database_creation` (in-memory). Not analysed
  per task constraints.

## 11. Operator CLI

Upstream `cmd/headscale/cli/` has 17 files mapping to subcommands:
`users`, `nodes`, `preauthkeys`, `apikeys`, `policy`, `debug`,
`generate`, `serve`, `configtest`, `dump_config`, `mockoidc`, `health`,
`version`, `auth`, `root`, `strings/utils/pterm_style` (helpers).

headscale-rs (`headscale-cli/src/main.rs`) ships:
- `server` — run the control plane
- `node` — run as a mesh node
- `identity {generate, show}`
- `nodes {list, show}` (against the JSON `/api/v1/nodes` admin route)
- `status`
- `init-config`

**Gaps:**
- `users` create/list/delete — **P1**.
- `preauthkeys` create/list/expire — **P1** (right now the only minter
  is the HTTP `/admin/preauth` shim).
- `apikeys` create/list/expire — P1.
- `policy {set, get, check}` — **P1**.
- `debug` (dump map, recompute peer map, validate ACL) — P2.
- `generate` (skeleton config, private key) — partial (`init-config`).
- `configtest`, `dump_config` — P2.

## 12. Out-of-scope-for-now flags

Upstream features explicitly **not** needed for OctraVPN-flavoured interop;
do not file as gaps:

- `mockoidc` (we have no OIDC).
- `apple` / `windows` MDM config generators
  (`https://tailscale.com/.../macos-mdm.plist` / `.reg`) — these served
  by upstream are platform-config blobs the official client downloads.
- Funnel / Tailscale SSH server attribute toggles — proprietary
  service-mesh layer we don't offer.
- Taildrop file-transfer endpoints — not part of the mesh protocol.

## Critical path to exit code 0 on `docker/devnet/tailscale-interop/run-interop.sh`

Ordered, minimum closing set. Per the
[blocker doc 2026-05-19 §"What unblocks exit 0 from here"](./tailscale-interop-blocker.md#wire-format-surprise-newer-tailscale-never-hits-ts2021):

1. **TLS termination on :443.** Add a rustls-axum (or nginx) front;
   self-signed cert trusted in the peer containers. Without this the
   client's `controlhttp: forcing port 443 dial due to recent noise dial`
   path fails before reaching anything we serve. **P0.**
2. **Flat `/machine/register` + `/machine/map` routes.** Resolve NodeKey
   from request body instead of path. Wire them through the existing
   `register.rs` / `map.rs` handlers. **P0.**
3. **Per-chunk MapResponse streaming.** Implement `Stream=true` ndjson:
   write one JSON-marshalled `MapResponse` per `\n` and continue with
   either keepalive chunks or delta chunks. `tailscale_wire/map.rs`
   has the timer skeleton; needs per-chunk writer. **P0.**
4. **EarlyNoise validation in-the-wild.** Once 1–3 land and the client
   actually reaches `/ts2021`, capture bytes and confirm the
   `NodeKeyChallenge` payload matches what the daemon expects.
   The framing is right (`controlbase.rs` unit tests pass); the JSON body
   may need a real challenge. **P0.**

After these four, the test should clear exit 30 → 0 or 40 depending on
whether the long-poll holds open long enough for both peers to learn
each other (current 30s `MAP_LONGPOLL_TIMEOUT` is below stock client's
patience window but matches the interop test's tight loop).

**Out of critical path.** ACL packet filters, DERP, MagicDNS, OIDC,
re-registration, full delta updates — none of these block exit 0.

## Beyond exit 0 — what real-world deployment needs

Ordered roughly by demand:

1. **Persistent `preauth_keys` + `machines` + `users` tables** (P1) —
   the in-process registries lose all state on restart. Schema is
   straightforward; the gap is the absence of any migration today.
2. **Reusable / ephemeral / tagged preauth keys** (P1) — depends on (1).
3. **`PacketFilters` in `MapResponse`** (P1) — without this the ACL
   evaluator's policy never reaches the client. Needs a compiler from
   `AclPolicy` → `tailcfg.FilterRule` shape.
4. **Machine lifecycle** (P1) — logout, expire, renew, ephemeral GC.
5. **Delta `MapResponse` updates** (P1) — full snapshots scale O(n²)
   per change; upstream's batcher is non-trivial but well-tested.
6. **MagicDNS responder + DNSConfig in MapResponse** (P1) — start with
   a single-domain A/AAAA, layer SplitDNS later.
7. **Operator CLI parity** (P1) — `users`, `preauthkeys`, `policy`
   subcommands. The HTTP `/admin/preauth` shim is fine for the interop
   test but operators expect a CLI.
8. **Embedded DERP server** (P1, only for WAN) — wraps the `tailscale-derp`
   primitives if a clean Rust port exists; otherwise vendor and rebuild.
9. **OIDC SSO** (P2) — only if multi-user web onboarding is required.
10. **HuJSON ACL parser + autogroup expansion** (P2) — operator polish.

## Things headscale-rs ships that headscale-go DOESN'T

OctraVPN-native layers, *not* parity gaps:

- **`headscale-identity`** — Ed25519 keypair, DID, session.
  *(As of 2026-05-20: kept on disk but dropped from
  `[workspace.members]` in headscale-rs — only built transitively via
  the active crates.)*
- **`headscale-payments`** — internal ledger, x402 micropayments,
  escrow, payment channels.
  *(As of 2026-05-20: kept on disk but dropped from
  `[workspace.members]`; flagged as a deletion candidate once
  `headscale-db::payments` is refactored off of it. OctraVPN uses the
  Octra chain for payments — this crate is unused in production.)*
- **`headscale-resources`** — provider capability registry, metering,
  allocation.
  *(As of 2026-05-20: kept on disk but dropped from
  `[workspace.members]` — `octravpn-node` reimplemented metering on
  its own primitives.)*
- **`headscale-api/src/gateway/`** — L7 resource gateway: per-request
  auth, quota, metering, proxy, signed receipts. Beyond upstream's scope.
- **`headscale-core/src/swarm_transport.rs`** — mesh message bus.
- **`headscale-core/src/authorization.rs`** — `authorize_forward{,_ip}`
  per-packet helpers binding ACLs into the datapath.
- **DID-based control-plane auth** (`headscale-api/src/control_auth.rs`)
  for the admin JSON surface — signed-request + nonce-store, not API keys.
- **`octravpn-mesh::headscale_bridge::PreauthMinter`** — auth-key
  primitive lifted out of any DB so it can be backed by chain or RAM.
- **`/metrics`** merges mesh + resource counters in one Prometheus dump.

## What I couldn't analyse cleanly

- **gRPC admin surface coverage.** `headscale-api/src/grpc.rs` + the
  generated `headscale.v1.rs` exist, but per-RPC handler completeness
  was not enumerated. Listed at P2.
- **policy/v2/ matcher dataflow.** Upstream's matcher engine is its own
  package; GitHub tree view only showed names. Couldn't benchmark our
  linear `AclEvaluator` against it.
- **DERP server internals + test fixture parity.** Skimmed only.
