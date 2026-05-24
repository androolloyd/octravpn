# headscale-go → headscale-rs: gap analysis

**Scope.** Catalogues the delta between upstream `juanfont/headscale`
(Go, `main` as of 2026-05-19 — most recent migration in
[`hscontrol/db/db.go`](https://github.com/juanfont/headscale/blob/main/hscontrol/db/db.go)
is `202602201200-clear-tagged-node-user-id`, v0.27.x line) and our
sibling Rust port at `/Users/androolloyd/Development/headscale-rs/`
(sibling-repo layout + dep-resolution strategy:
see [`docs/architecture/headscale-dep-strategy.md`](./architecture/headscale-dep-strategy.md)).
The implementation notes below were refreshed against headscale-rs
`201fc8c` on 2026-05-24; set `HEADSCALE_RS_PATH` in Octra scripts when
the checkout is not at the default sibling path.
Prioritised by what blocks **stock `tailscale up` (v1.78+) joining a
mesh hosted by an OctraVPN-derived control plane**, as exercised by
`docker/devnet/tailscale-interop/run-interop.sh`.

**Treatment of the wire migration.** The Tailscale-wire routes now live
under `headscale-api/src/tailscale_wire/` in headscale-rs. Octra owns
the harness, `POST /admin/preauth` shim, and embedding points; route
existence for `/key`, `/ts2021`, and `/machine/...` should be evaluated
in headscale-rs, not in old Octra-local copies.

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
| Noise IK + controlbase | `controlhttpserver.AcceptHTTP`, h2-over-noise                     | controlbase framing + BE-nonce transport + h2-over-Noise        | behavioural validation remains in Wall 5 | P0 |
| `POST /ts2021`       | Upgrade hijack, runs noise router under h2                          | shipped (`tailscale_wire/raw_tls.rs`, `noise.rs`)               | none for route existence | — |
| `/machine/register` (flat)  | served on noise router (`hscontrol/noise.go`)                 | shipped; keyed compatibility route retained                     | none for route existence | — |
| `/machine/map` (flat)       | served on noise router                                        | shipped; keyed compatibility route retained                     | streaming/lifecycle semantics remain | P0/P1 |
| TLS on :443          | yes (`server_tls.go`, autocert + manual cert)                       | raw rustls listener shipped; Octra harness binds/cert-distributes | deployment config only | — |
| `MapResponse.Stream=true` ndjson | required, streaming chunks                                | chunked MapResponse stream + canonical `{"KeepAlive":true}` frames | Octra packaged-path stock-client regression | P0/P1 |
| Full `MapResponse` fields | Node, Peers, PeersChanged{,Patch,Removed}, DNSConfig, DERPMap, Domain, PacketFilters, UserProfiles, SSHPolicy, ControlTime, Debug, CollectServicesDisabled, PingRequest | core fields plus PacketFilters["base"], UserProfiles, SSHPolicy, ControlTime, Debug, keepalive and ping support | long-tail optional fields + restart/lifecycle replay | P1 |
| Delta map updates    | `PeersChanged` / `PeersChangedPatch` / `PeersRemoved`               | connected long-poll deltas implemented; batching/restart parity still under audit | production semantics | P1 |
| ACL engine           | HuJSON, `policy/v2/`, autoApprovers, ssh, tagOwners, autogroups, ipsets, route approvers | HuJSON/raw round-trip, `acls` alias, versionless policy default, PacketFilters, autoApprovers (routes+exitNode), ssh, tagOwners, groups, `autogroup:internet` | autogroups beyond `internet`, NodeAttrs, ipsets, packaged route wiring | P1 |
| Pre-auth keys        | reusable / single-use / ephemeral / tagged, expiry, per-user, bcrypt-hashed | persistent admin store + gRPC/HTTP CLI support; Octra shim remains in-process | shared Octra shim wiring/lifecycle polish | P1 |
| OIDC                 | full SSO (`oidc.go`, mockoidc, templates)                           | none                                                            | full           | P2       |
| Embedded DERP server | yes — wraps `tailscale/derp.Server`, serves `/derp`, `/derp/probe`, `/bootstrap-dns`, STUN | DERP *client* + map-emit only; no relay        | full server    | P1 (none for docker-bridge interop) |
| DERP map serving     | merges file + URL + embedded sources                                | builds map from configured servers in `MeshCoordinator`         | URL/file-based loaders | P2 |
| MagicDNS             | `dns/`, MagicDNS, SplitDNS resolvers, extra records hot-reload (`extrarecords.go`), search domains | empty `DnsConfig` shape only                  | full           | P1       |
| Machine lifecycle    | register → expire → renew → logout → delete; ephemeral GC; tag rewrite | register + IP alloc + persistent admin adapters; lifecycle ops partial | renew/ephemeral GC and replay validation | P1 |
| OIDC + browser flow  | `/register/:auth_id`, `/auth/:auth_id`, templates                   | none                                                            | full           | P2       |
| Persistence          | GORM + 17 versioned `gormigrate` migrations (latest 202602201200)   | sqlx + 12 migrations covering nodes, users, preauth keys, API keys, policy, routes | production wiring/restart replay audit | P1 |
| Operator CLI         | 17 cmd groups (users, nodes, preauthkeys, apikeys, policy, debug, generate, serve, configtest, mockoidc, dump_config, version, health, auth, root) | admin groups include users, nodes, preauthkeys, auth, apikeys, policy, tailnet, debug; standalone still carries serve/generate/configtest/mockoidc/version/health | remaining parity details and hidden/non-admin groups | P2 |
| gRPC admin API       | `grpcv1.go` — full nodes/users/preauth/admin API                    | generated proto + service handlers wired for the embedded CLI groups | exact long-tail errors/coverage still expanding | P2 |
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
| `POST /machine/register` (flat)  | POST   | shipped; keyed compatibility route retained |
| `POST /machine/map` (flat)       | POST   | shipped; keyed compatibility route retained |
| `GET /machine/ssh/action/{src}/to/{dst}` | GET | missing — required only if SSH ACLs are exposed |
| `GET /derp/probe`                | GET    | missing — only needed if we host an embedded DERP |
| `GET /derp` (upgrade)            | GET    | missing — embedded DERP not in scope for interop |
| `GET /health`, `GET /version`, `GET /robots.txt` | GET | `/health` shipped; `/version`/`robots.txt` missing — P2 |
| `POST /verify`                   | POST   | missing — DERP client verification — P1 (needed if relay added) |
| `GET /register/:auth_id`, `GET /auth/:auth_id` | GET | missing — browser/OIDC flow — P2 |

Upstream's `hscontrol/handlers.go` registers the public side
(see [WebFetch summary]) and `hscontrol/noise.go` chains the inner
router for noise-protected `/machine/{register,map,ssh/...}`.
headscale-rs mirrors this split: public wire routes are built in
`tailscale_wire::router`/`serve`, while the inner noise router is built
in `tailscale_wire/noise.rs` and dispatches flat `/machine/register`
and `/machine/map` plus the keyed compatibility routes.

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

**Gap:** This is no longer a missing-route item. The remaining risk is
end-to-end behaviour under the stock client flow: Wall 5 now lives
around map streaming, keepalive framing, lifecycle, and peer convergence
rather than absence of `/ts2021`, `/key`, or flat `/machine/...` routes.

## 3. MapResponse construction

Upstream's `hscontrol/mapper/builder.go` populates a fluent
`MapResponseBuilder` with 15+ fields:

| MapResponse field    | Upstream sets via              | headscale-rs (`tailscale_wire/wire.rs:202-224`) |
| -------------------- | ------------------------------ | ------------------------------------------------ |
| `Node`               | `WithSelfNode`                 | yes                                              |
| `Peers`              | `WithPeers`                    | yes                                              |
| `PeersChanged`       | `WithPeerChanges`              | shipped for connected long-poll changes; restart replay still under audit |
| `PeersChangedPatch`  | `WithPeerChangedPatch`         | type + patch path present; exact upstream batching remains P1 |
| `PeersRemoved`       | `WithPeersRemoved`             | shipped for connected removal deltas; restart replay still under audit |
| `DNSConfig`          | `WithDNSConfig`                | runtime DNS store + MagicDNS root; SplitDNS/responder still P1 |
| `DERPMap`            | `WithDERPMap`                  | runtime DERP map store; URL/file loaders still P2 |
| `Domain`             | `WithDomain`                   | derived from configured DNS base domain |
| `PacketFilters`      | `WithPacketFilters`            | shipped as reduced `PacketFilters["base"]` from the shared policy store |
| `UserProfiles`       | `WithUserProfiles`             | shipped for self/visible peers |
| `SSHPolicy`          | `WithSSHPolicy`                | shipped; broader stock-client variants covered in headscale-rs |
| `Debug`              | `WithDebugConfig`              | shipped for logtail disable/debug-mapresponse support; long-tail flags partial |
| `CollectServices`    | `WithCollectServicesDisabled`  | shipped as disabled collection |
| `PingRequest`        | `WithPingRequest`              | shipped via the ping tracker/debug path |
| `ControlTime`        | auto                           | shipped |
| `KeepAlive`          | per-frame                      | shipped as separate canonical `{"KeepAlive":true}` frames |

**Streaming.** Upstream's `hscontrol/poll.go` runs a session loop:
"streaming requests (Stream=true): continuous long-poll connections",
JSON-marshalled, optionally Zstd-compressed, with keepalive frames.
headscale-rs now emits framed MapResponse chunks for stream=true and
uses the canonical `{"KeepAlive":true}` keepalive payload in the same
compression mode. The remaining Octra risk is not missing writer
support; it is packaged-path stock-client coverage through the
`octravpn-node` embedding and lifecycle/restart scenarios.

**Delta updates.** Upstream's `mapper/batcher.go` is ~6 files (batcher,
batcher_concurrency, batcher_scale_bench, batcher_unit, mapper,
node_conn) of incremental-update plumbing. headscale-rs has connected
long-poll deltas for peer, policy, and route changes, but exact batching,
restart replay, and large-tailnet behaviour still need production-grade
parity coverage. **Priority: P1.**

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
| HuJSON parser with raw byte round-trip | shipped |
| Versionless upstream policy default + `acls` alias | shipped |
| `hosts`, `groups`, `acls`, `tagOwners`, `autoApprovers`, `ssh` | shipped |
| `autogroup:internet` | shipped |
| CIDR matching + named hosts + port specs (incl. `[ipv6]:port`) | shipped |
| `evaluate`/`can_reach`/`can_reach_port` | shipped |
| `should_distribute_route` + `can_be_exit_node` | shipped, **but not wired into the wire-protocol path** |
| Property tests for ACL semantics | shipped (`acl::proptests`) |

**Gaps vs upstream:**
- **Autogroups beyond `internet`** — `autogroup:tagged`, `autogroup:members`,
  `autogroup:self`, `autogroup:nonroot`, `autogroup:danger-all` are absent. P1.
- **`NodeAttr` resolution** — upstream emits a list of capability flags
  per peer (`funnel`, `ssh`, etc.) that the client honours. P2.
- **`ipset:` macros** — upstream policy can name reusable IP sets. P1/P2.
- **Packaged route auto-approval regression** — headscale-rs has route
  and exit-node auto-approval logic; Octra still needs an embedded
  daemon regression that proves the packaged path applies it end-to-end.
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

headscale-rs now has a persistent admin-side preauth store
(`PersistentPreauthAdmin`) backed by the `pre_auth_keys` migration,
plus gRPC/HTTP admin paths and CLI support for reusable, ephemeral,
tagged, expiring keys. Octra still keeps the legacy
`POST /admin/preauth` shim backed by `octravpn-mesh::PreauthMinter`
for the demo/interop harness.

**Gaps:**
- Shared Octra shim wiring — **P1** if we want `/admin/preauth` to use
  the same persistent headscale admin store instead of the in-process
  harness minter.
- Ephemeral lifecycle and GC — **P1** (the key flag exists; node
  lifecycle semantics still matter).
- Operator migration from the legacy shim to `headscale preauthkeys`
  workflows — **P2** documentation/runbook work.

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
- sqlx + 12 SQL migrations:
  `20260118000001_create_nodes.sql`,
  `20260118000002_create_transactions.sql`,
  `20260118000003_create_resources.sql`,
  `20260118000004_create_sessions.sql`,
  `20260520000005_create_preauth_keys.sql`,
  `20260521000006_create_api_keys.sql`,
  `20260521000007_create_users.sql`,
  `20260521000008_create_policies.sql`,
  and follow-up node/auth-key/route/user-FK migrations.
- Models/admin adapters cover nodes, users, API keys, policy, and
  persistent preauth keys. Octra's local `PreauthMinter` remains
  in-process only when using the compatibility `/admin/preauth` shim.

**Gaps:**
- Verify production wiring uses the persistent adapters everywhere the
  daemon is expected to survive restarts. **P1.**
- Confirm route/lifecycle persistence under real `tailscale up` replay
  rather than only admin-unit coverage. **P1.**
- Keep the Octra compatibility shim's in-memory behavior explicit until
  shared preauth admin wiring lands. **P2.**

## 11. Operator CLI

Upstream `cmd/headscale/cli/` has 17 files mapping to subcommands:
`users`, `nodes`, `preauthkeys`, `apikeys`, `policy`, `debug`,
`generate`, `serve`, `configtest`, `dump_config`, `mockoidc`, `health`,
`version`, `auth`, `root`, `strings/utils/pterm_style` (helpers).

headscale-rs (`headscale-cli/src/main.rs`) ships:
- `server` — run the control plane
- `node` — run as a mesh node
- `identity {generate, show}`
- admin groups exposed directly and embeddable through
  `headscale_cli::AdminCmd`: `users`, `nodes`, `preauthkeys`, `auth`,
  `apikeys`, `policy`, `tailnet`, `debug`
- non-admin / standalone groups: `serve`, `generate`, `mockoidc`,
  `health`, `version`, `completion`, `configtest`, `dumpConfig`,
  `status`, `init-config`

**Gaps:**
- Parity details remain for some upstream command shapes and hidden
  non-admin groups, but the former P1 Octra-facing gaps (`users`,
  `preauthkeys`, `apikeys`, `policy`, `debug`, `auth`) are no longer
  missing surfaces.
- Octra's embedded CLI docs/tests must track the gRPC-first admin
  model: migrated commands default to the local Unix socket; explicit
  `--server` selects the legacy HTTP path.

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

Ordered, minimum closing set after the 2026-05-24 boundary refresh:

1. **Per-chunk MapResponse streaming.** Implement `Stream=true` ndjson:
   write one JSON-marshalled `MapResponse` per `\n` and continue with
   either keepalive chunks or delta chunks. `tailscale_wire/map.rs`
   has the timer skeleton; needs per-chunk writer. **P0.**
2. **Post-register stock-client replay.** Capture the current stock
   client flow through `/ts2021` and `/machine/map`, then close any
   remaining response-framing or lifecycle mismatch. **P0.**
3. **Peer-convergence regression.** Keep both flat and keyed routes in
   coverage while proving two stock clients learn each other and
   `tailscale ping` succeeds. **P0.**

After these, the test should clear exit 30 → 0 or 40 depending on
whether peer convergence or final ping is the remaining failure.

**Out of critical path.** ACL packet filters, DERP, MagicDNS, OIDC,
re-registration, full delta updates — none of these block exit 0.

## Beyond exit 0 — what real-world deployment needs

Ordered roughly by demand:

1. **Persistent-adapter production wiring audit** (P1) — the tables and
   adapters exist; verify every serve/admin path uses them in the
   production daemon and not only in tests.
2. **Octra `/admin/preauth` convergence** (P1) — decide whether to keep
   the in-process compatibility shim or wire it to the persistent
   headscale preauth admin.
3. **Packaged ACL regression** (P1) — headscale-rs emits reduced
   `PacketFilters["base"]`; Octra still needs a packaged-daemon stock
   client denial/allowance regression.
4. **Machine lifecycle** (P1) — logout, expire, renew, ephemeral GC.
5. **Production `MapResponse` delta parity** (P1) — connected deltas
   exist; restart replay, batching, and large-tailnet semantics remain
   to be audited against headscale-go.
6. **MagicDNS responder + DNSConfig in MapResponse** (P1) — start with
   a single-domain A/AAAA, layer SplitDNS later.
7. **Embedded DERP server** (P1, only for WAN) — wraps the `tailscale-derp`
   primitives if a clean Rust port exists; otherwise vendor and rebuild.
8. **OIDC SSO** (P2) — only if multi-user web onboarding is required.
9. **Autogroup/ipset/NodeAttr expansion** (P2) — operator polish beyond
   the shipped HuJSON parser and base ACL translation.

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
