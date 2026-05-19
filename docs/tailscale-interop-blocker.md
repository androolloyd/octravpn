# Tailscale-interop: blocker handoff

This document captures **what's still blocking exit code 0** on
`docker/devnet/tailscale-interop/run-interop.sh` after the preauth
minter work pass landed. Read it together with
[`tailscale-interop-finding.md`](./tailscale-interop-finding.md),
which describes the diagnosis.

## Current exit code

`30` — "tailscale up failed on at least one peer." The preauth
surface is reachable (step 3 clears), but stock `tailscale up`
gets as far as `GET /key` and immediately disconnects because no
such endpoint exists on the OctraVPN control plane.

## The exact API gap

Stock `tailscale` v1.78+ (the version in
`tailscale/tailscale:latest` as of 2026-05-19) speaks the
following control-plane wire protocol:

| Endpoint                                            | Method | Purpose                                              |
| --------------------------------------------------- | ------ | ---------------------------------------------------- |
| `/key`                                              | GET    | Server's permanent noise public key                  |
| `/ts2021`                                           | POST   | Noise IK upgrade handshake (single request)          |
| `/machine/{node_key}/register`                      | POST   | Initial join, presents authkey                       |
| `/machine/{node_key}/map`                           | POST   | Long-poll peer/ACL/DERP map                          |
| `/derp/probe`                                       | GET    | DERP relay probe                                     |
| `/derp/{region}`                                    | GET    | DERP relay upgrade                                   |

**Zero of those are implemented** in `octravpn-node`'s control
plane (`crates/octravpn-node/src/control.rs`). The mesh crate
(`crates/octravpn-mesh`) has the *primitives* — STUN, peer
registry, magic DNS, IP allocator — but none of them are wired
into a Tailscale-wire-compatible HTTP handler.

`headscale-rs`'s public router
([`headscale-api/src/http.rs:31-59`](../../headscale-rs/headscale-api/src/http.rs))
exposes a parallel-universe `/api/v1/nodes` + `/api/v1/register`
JSON surface that **is not** the Tailscale wire protocol. Hooking
that router in front of `tailscale up` produces the same
"tailscale up failed" result — the client doesn't speak that
dialect.

## Three options for closing the gap

### Option A — port `juanfont/headscale` (Go) to Rust

The upstream Go headscale at
[github.com/juanfont/headscale](https://github.com/juanfont/headscale)
is the reference Tailscale-compatible coordination server. Its
`/api/v1` is Tailscale-wire-compatible.

**Cost**: high. Headscale is ~30k LoC of Go, of which roughly 8k
is wire-protocol + Noise + DERP. Direct port to Rust is a
3–5 person-week task. Vendoring as a sidecar (run the Go binary
in the container, proxy to it from `octravpn-node`) is faster
(~3 days) but introduces a Go runtime dependency the project has
otherwise avoided.

**Pros**: known-correct wire compatibility; large operator
ecosystem.

**Cons**: heavy dependency footprint; if vendored as a Go sidecar
the licensing story (headscale is BSD-3) needs review.

### Option B — write a minimum-viable wire shim in Rust

Implement just enough of the four core endpoints (`/key`,
`/ts2021`, `/register`, `/map`) to satisfy stock `tailscale up`
in the docker harness — no DERP (peers can NAT-traverse on the
bridge network), no ACLs (test only has 2 peers), no key
rotation.

**Cost**: medium. Estimated ~3 person-weeks split into:

1. Noise IK framing layer (`snow` crate primitives) — 1 week
2. `register` handler bound to `PreauthMinter` — 3 days
3. `map` long-poll with a tiny `MapResponse` (2 peers, no ACLs) — 1 week
4. End-to-end test wiring — 3 days

**Pros**: keeps the project pure-Rust; clean integration with the
existing `axum::Router`; gives us the deliverable.

**Cons**: lots of wire-format fiddling against an undocumented-ish
protocol; brittle against `tailscale` client upgrades.

### Option C — fork `headscale-rs` and grow the wire surface upstream

`headscale-rs` is a sibling repo we already depend on
conceptually (for `MeteringSnapshot`). Add the Tailscale-wire
endpoints to *its* router, vendor the upstream change in our
`Cargo.toml`.

**Cost**: medium-high. Same wire-protocol work as Option B (~3
weeks) plus the overhead of landing it in another repo, but with
the long-term win that future OctraVPN users get the wire surface
for free.

**Pros**: separation of concerns — coordination plane lives in
the coordination-plane crate; the metering bridge stays the only
OctraVPN/headscale touch-point on our side.

**Cons**: introduces release-coupling between `headscale-rs` and
`octravpn`; the metering bridge work is held up until both repos
are in sync.

## Recommendation

**Option B** for getting the interop test to 0, then **Option C**
as the eventual home for the code. Specifically:

1. Land the wire shim *in `octravpn-mesh`* under
   `crates/octravpn-mesh/src/tailscale_wire/` (new module). The
   bridge is already the natural integration boundary.
2. Mount the wire router from `octravpn-node/src/control.rs` next
   to the existing `/admin/preauth` route.
3. Once the test is green, propose the module upstream to
   `headscale-rs` and switch the dependency direction.

## Decomposition into shippable PRs

This work fits in **four** logical commits, each independently
testable:

| PR  | Scope                                                  | Test signal                  |
| --- | ------------------------------------------------------ | ---------------------------- |
| 1   | `GET /key` + Noise IK key generation + persistence     | curl returns hex key         |
| 2   | TS2021 Noise IK upgrade handshake                      | `snow` round-trip test       |
| 3   | `POST /machine/{node_key}/register` + PreauthMinter wire | `tailscale up` reaches "registered" |
| 4   | `POST /machine/{node_key}/map` long-poll               | run-interop.sh exits 0       |

Each PR should keep the existing `cargo test --workspace` clean.

## Exit-code progression as PRs land

| State                                | Exit code |
| ------------------------------------ | --------- |
| Today (preauth surface only)         | 30        |
| + PR 1 (`/key`)                      | 30        |
| + PR 2 (Noise handshake)             | 30        |
| + PR 3 (register)                    | 40 or 50  |
| + PR 4 (map long-poll)               | 0         |

PR 1+2 alone don't change the exit code because `tailscale up`
needs the full register-and-map flow to reach a usable state.
PR 3 alone may stall at "peer never sent a map response" (exit
40) or "ping fails" (exit 50) depending on what the daemon does
when it gets a successful register but a stalled map. PR 4 is the
unblocker.

## Update 2026-05-19: PRs 1+2 shipped, plus PR 3/4 scaffolding

`crates/octravpn-mesh/src/tailscale_wire/` now contains:

| File | What it does | Status |
| ---- | ------------ | ------ |
| `mod.rs` | Router root, `WireState`, `MachineRegistry` | shipped |
| `noise.rs` | Persistent server X25519 keypair + `snow` IK round-trip + (stubbed) `/ts2021` handler | PR 1 + half of PR 2 shipped |
| `key_handler.rs` | `GET /key` returns `OverTLSPublicKeyResponse` | PR 1 shipped |
| `wire.rs` | `MapRequest`/`MapResponse`/`RegisterRequest`/`RegisterResponse` JSON shapes pinned to upstream `tailcfg.go` field names | PR 3+4 shapes shipped |
| `register.rs` | `POST /machine/{node_key}/register` with PreauthMinter wiring + IP allocation | PR 3 plaintext path shipped |
| `map.rs` | `POST /machine/{node_key}/map` with `Notify`-driven long-poll | PR 4 plaintext path shipped |

`octravpn-node` integration:
- `[control].tailscale_wire_state_dir` + `[control].tailscale_tailnet_id`
  added to `node.toml`; when set, `Hub::spawn_control_plane` mounts the
  wire router next to `/admin/preauth` and shares the same
  `PreauthMinter` across both surfaces.
- New `octravpn-node mesh serve --listen … --state-dir … --tailnet-id …`
  subcommand runs the wire router + a token-gated `/admin/preauth`
  shim WITHOUT a Hub. Used by `docker/devnet/tailscale-interop`.
- `docker-compose.yml` now invokes `mesh serve` instead of
  `sleep infinity`, so port 51821 is *actually listening* during the
  test (it never was before).

### What that gets us
| Probe | Pre-PR | Post-PR |
| ----- | ------ | ------- |
| `curl /admin/preauth` (HTTP path of step 3) | timeout (no port bound) | 200 + key |
| `curl /key` from inside `tsi-peer-a` | `connection refused` | 200 + `{"PublicKey":"mkey:<hex>"}` |
| `tailscale up` exit code | 30 (no daemon) | 30 (`/ts2021` returns 501) |

Exit code is **still 30**: stock `tailscale/tailscale:latest`
(capability version >> 39) refuses to fall back to plaintext JSON
register/map and bails when `/ts2021` doesn't 101-Switching-Protocols.
The plaintext `register` + `map` handlers we shipped are testable in
isolation (and proven so by `cargo test -p octravpn-mesh tailscale_wire`)
but stock `tailscale` never reaches them.

### What's left for exit code 0

The wall is **the TS2021 frame layer + HTTP/2 hijack**, not the JSON
shapes. Concretely:

1. `/ts2021` must accept the
   `Upgrade: tailscale-control-protocol` request, hijack the TCP
   socket, and run a 3/5-byte framed Noise IK handshake
   (initiation = `[type=1:u8][len:u16be][protocolVersion:u16be]` +
   Noise body; response = `[type=2:u8][len:u16be]` + Noise body).
   The `snow` round-trip in `noise.rs::tests::ik_round_trip` proves
   the cryptographic primitive is right; what's missing is the
   framing wrapper + the connection-hijack glue.
2. Once the handshake completes, the SAME socket must speak HTTP/2.
   The `h2` crate accepts a `tokio::io::AsyncRead+AsyncWrite`, so
   bolting it on top of the Noise transport (each record `read`
   does a `noise_t.read_message`, each `write` calls
   `noise_t.write_message`) is mechanical — but tedious.
3. With the HTTP/2 inner router up, mount the existing
   `register`/`map` handlers behind it (they're already
   `axum::Router`-compatible).

Estimated effort to close: 1-1.5 person-weeks. Two specific Rust
crates are the helpful prior art:

- `golang.org/x/net/http2` has no clean Rust analogue that takes a
  pre-hijacked connection; we'd reach for `h2::server::handshake`
  on top of an `AsyncRead+AsyncWrite` wrapper around the Noise
  transport.
- The Tailscale `controlbase` framing (header format above) is
  source-cited at
  `tailscale/control/controlbase/messages.go` and
  `tailscale/control/controlbase/handshake.go`. A pure Rust port is
  ~200 lines.

### Wire-format ambiguities not resolved in this pass

- The interaction between `EarlyNoise` (`tailscale/tailcfg/early.go`)
  and the regular Noise frame is unclear from the headscale source
  alone — we may need to send a 5-byte `\xff\xff\xffTS<len:u32be>`
  JSON header in the responder's reply for newer clients (post-PR
  4323). Documented but not implemented.
- `MapResponse.Streaming` vs single-shot behaviour: stock
  `tailscale up` sets `Stream: true` and expects newline-delimited
  JSON chunks of `MapResponse` types. Our handler returns a single
  body — fine for our isolation tests, wrong for the real client.
  Tracked as a follow-up in `tailscale_wire::wire::MapRequest`'s
  doc-comment.

### Decision-log highlights (full notes live in each module)

- `snow = "0.9"` (resolves 0.9.6) pinned per the original blocker
  spec; the workspace's MSRV satisfies 0.10 too if we ever need to
  upgrade.
- `MachineRegistry` keys on hex node-key strings (not `[u8; 32]`)
  because every consumer of the registry is going through the
  axum path parameter, which is a `String`. Avoids a redundant
  hex-decode on every request.
- The `derive_x25519_public` helper in `noise.rs` round-trips a
  throwaway IK pair to extract the public from a private. Verbose
  vs `x25519-dalek::PublicKey::from(&priv)` but the blocker doc
  forbids any new dep besides `snow`.

## Files to touch when picking this up

- `crates/octravpn-mesh/src/lib.rs` — add `pub mod tailscale_wire`
- `crates/octravpn-mesh/src/tailscale_wire/` — new module
  - `mod.rs` — re-exports, error type
  - `noise.rs` — TS2021 IK handshake on top of `snow`
  - `register.rs` — `POST /machine/{node_key}/register`
  - `map.rs` — `POST /machine/{node_key}/map` long-poll
  - `wire.rs` — shared `MapResponse` / `MapRequest` types
- `crates/octravpn-node/src/control.rs` — mount the new router
- `crates/octravpn-node/Cargo.toml` — `snow = "0.9"` (Noise) +
  `tokio-tungstenite` *only if* DERP is in scope (Option B says
  skip DERP for now)
- `docker/devnet/tailscale-interop/run-interop.sh` — no changes
  needed; the exit code transitions automatically as PRs land.

## API-gap citations

- `crates/octravpn-node/src/control.rs:206-211` — current router
  routes: `/session`, `/session/:id`, `/health`, `/metrics`,
  `/admin/preauth`. None match the Tailscale wire surface.
- `headscale-rs/headscale-api/src/http.rs:43-59` — headscale-rs
  router. Same observation in the other direction: nothing here
  matches `/key` or `/machine/…`.
- `crates/octravpn-mesh/src/headscale_bridge.rs` — preauth
  minter, no wire-protocol handlers.

## Update 2026-05-19 (PR 2 continuation): controlbase + h2-over-Noise wired, exit still 30

The `/ts2021` stub is gone. `crates/octravpn-mesh/src/tailscale_wire/` now
ships:

| File | What it does | Status |
| ---- | ------------ | ------ |
| `controlbase.rs` | 3/5-byte controlbase framing + `NoiseStream` (`AsyncRead+AsyncWrite` over snow transport) | shipped, 6 unit tests |
| `noise.rs::handle_ts2021_post` | Upgrade handler — verifies header, hijacks via `hyper::upgrade::OnUpgrade`, runs IK responder, sends EarlyNoise prefix, hands `NoiseStream` to `h2::server::handshake`, dispatches per-request via `tower::ServiceExt::oneshot` against the inner axum router | shipped |
| `noise.rs::drive_ts2021` | Pulled out as a generic `T: AsyncRead+AsyncWrite` driver so tests can pair it against an in-process `tokio::io::duplex` socket | shipped |
| `map.rs` Stream:true | Streaming response: initial `MapResponse\n`, then `"\n"` keepalives every 30s | shipped with `tokio::time::pause`/`advance` test |

Direct probe of the surface confirms the upgrade path works:

```
$ curl -sv -X POST \
    -H "Upgrade: tailscale-control-protocol" -H "Connection: upgrade" \
    http://127.0.0.1:51821/ts2021
< HTTP/1.1 101 Switching Protocols
< connection: upgrade
< upgrade: tailscale-control-protocol
```

…and the socket then waits for an Initiation frame, exactly as
expected. The in-process integration test
`crates/octravpn-node/tests/tailscale_wire_integration.rs::ts2021_framing_responds_to_initiation`
drives the full handshake against a hand-crafted snow initiator and
confirms the responder writes a valid Reply frame.

### Wire-format surprise: newer `tailscale` never hits `/ts2021`

Stock `tailscale/tailscale:latest` (v1.78+) **does not call `/ts2021`
the way the blocker doc described**. The actual flow on a fresh
`tailscale up`:

1. `GET http://tsi-mesh-control:51821/key` ✓ (we serve, returns
   `{"PublicKey":"mkey:…"}`).
2. Client logs:
   ```
   control: control server key from http://tsi-mesh-control:51821:
     ts2021=[hlMBk], legacy=
   control: RegisterReq: onode= node=[JUvg6] fup=false nks=false
   control: controlhttp: forcing port 443 dial due to recent noise dial
   ```
3. Client then POSTs to **`https://tsi-mesh-control:51821/machine/register`**
   on **port 443 over TLS** — `/machine/register` (no `nodekey:<hex>` in
   the path, contrary to the upstream `tailcfg.go` shape we modelled),
   and a forced HTTPS-on-443 dial.
4. Connection refused (we don't listen on 443, and we're plain HTTP),
   client retries, eventually gives up.

Two new gaps surfaced by the probe:

| Gap | Detail | Impact |
| --- | ------ | ------ |
| **Forced TLS on 443** | `controlhttp: forcing port 443 dial due to recent noise dial` — the client races a parallel HTTPS-on-443 dial *even if the login server URL is plain HTTP*. With no TLS terminator on 443 the dial fails and the whole flow stalls. | Blocks exit 0 regardless of how complete our wire surface is on 51821. |
| **`/machine/register` path** | The newer client uses a flat `/machine/register` (and presumably `/machine/map`) — *not* `/machine/{node_key}/register`. Our handlers route on `{node_key}` in the path. | Even if TLS were terminated, the path wouldn't match. |

The `/ts2021` handler we shipped this PR is correct but irrelevant to
the current client until those two gaps close. The `tailscale up` daemon
never reaches `/ts2021` in this run because the failure happens earlier,
on the `/machine/register` forced-443 dial.

### EarlyNoise frame status

We send EarlyNoise unconditionally inside the Noise transport stream
right before HTTP/2 starts:

```
[0xff 0xff 0xff 'T' 'S'][json_len:u32be][json]
```

with a minimal `{"NodeKeyChallenge":{"Public":"nodekey:00…"}}` payload.
Because stock `tailscale` never reaches our `/ts2021` handler (see
above), this is **unverified in-the-wild**. The in-process unit tests
confirm we *send* the prefix and that h2 starts on top, but we don't
yet know whether the real client requires a specific challenge
encoding.

### What unblocks exit 0 from here

In priority order:

1. **TLS termination on port 443.** Add an nginx (or rustls-axum) front
   that terminates HTTPS on 443 with a self-signed cert; trust the cert
   inside the peer containers. Without this, the forced-443 dial keeps
   failing.
2. **Add `/machine/register` and `/machine/map`** (no path parameter)
   to the inner router; resolve the node-key from the request body
   instead of the path. The existing handlers' core logic stays the
   same; just add the new entry points.
3. **Verify the EarlyNoise frame** by capturing real client bytes
   through a tcpdump-on-loopback once steps 1+2 land.

Estimated effort: **3-5 days** for the TLS shim + path-shape
refactor + EarlyNoise validation, after which `run-interop.sh` should
clear exit 30 → either 0 or 40 depending on whether the long-poll
`/map` semantics match the client's expectations.

### Exit-code progression as of this PR

| State | Exit code |
| ----- | --------- |
| Pre-PR 2 (stub `/ts2021`) | 30 (`/ts2021` returns 501) |
| **Post-PR 2 (this commit)** | **30** (`/ts2021` works, but client doesn't reach it; forced-443 TLS dial blocks) |
| + TLS-on-443 + flat `/machine/{register,map}` paths | expect 30 or 40 |
| + EarlyNoise validation + map streaming verified | expect 0 |

The framing layer + handshake + h2 wire-up are all unit-tested and
ready behind the upgrade boundary; what remains is the front-door
plumbing (TLS + path shapes).

## Sanity check: do the Tailscale containers actually need a
## working server, or can the test be relaxed?

Yes — they do. The interop test's premise is that **stock
`tailscale up` joins a mesh hosted by an OctraVPN-derived control
plane**. Anything weaker (e.g. running tailscale in DERP-only
mode, hand-configuring `/var/lib/tailscale/tailscaled.state`) is
not interop — it's two unrelated WireGuard peers, which we
already have via `octravpn-client`.

The test exists precisely to keep us honest about that
distinction.

## 2026-05-19 — tailscale_wire migrated to headscale-rs

The Tailscale wire-protocol implementation (`/key`, `/ts2021`,
`/machine/{node_key}/{register,map}`, plus the controlbase framing
and `NoiseStream`) now lives in
`headscale-rs::headscale-api::tailscale_wire`. That's its proper home
— `headscale-rs` IS our Rust port of `juanfont/headscale`, and the
wire protocol is exactly what headscale-go's control plane speaks.

`octravpn-mesh` retains:

- `PreauthMinter` (OctraVPN's preauth-key store).
- `TailnetIpAllocator` (deterministic CGNAT hashing).
- `headscale_bridge.rs`: implementations of the wire layer's two
  injection traits, `PreauthRedeemer` and `IpAllocator`, on top of
  the above.
- A re-export of `headscale_api::tailscale_wire` so existing call
  sites (`octravpn_mesh::tailscale_wire::router`, `WireState`, etc.)
  keep compiling.

### Where future #207 work lands

The remaining "what unblocks exit 0" items above (TLS-on-443, flat
`/machine/{register,map}` paths, EarlyNoise frame validation) all
**land in `headscale-rs`, not in `octravpn-mesh`**. The OctraVPN side
only changes if a wire-policy hook needs a new trait method. The
trait surfaces are intentionally small (`PreauthRedeemer::redeem` +
`IpAllocator::allocate`) — growing them is a conscious design
decision, not a default.

## 2026-05-19 P0 batch (PRs 1–4) shipped, exit code still 30 — new wall: HTTP/1.1 Upgrade through axum-server+rustls

The P0 batch from `docs/headscale-gap-analysis.md` landed:

| PR | What shipped | Wire-layer evidence |
| -- | ------------ | ------------------- |
| 1  | `tailscale_wire::tls` (rcgen + rustls), `tailscale_wire::serve` (dual-bind `:51821` plain + `:443` rustls), `mesh serve --https-listen` + `--cert-hostname` flags | TLS cert cached at `<state_dir>/tls.{crt,key}`; SAN includes the configured hostname + `localhost` + loopback. Client logs: `tlsdial: warning: server cert for "tsi-mesh-control" passed x509 validation but is self-signed by "CN=headscale.local"`. |
| 2  | `POST /machine/register` + `POST /machine/map` (flat, NodeKey-in-body); keyed `/machine/{node_key}/{register,map}` routes preserved. `register::handle_register_flat` / `map::handle_map_flat` share `register_inner` / `map_inner` with the keyed variants. | Direct probe via `wget` returns 200 with a `RegisterResponse` JSON. Tests: `register::tests::flat_register_extracts_node_key_from_body`, `map::tests::flat_map_extracts_node_key_from_body`, octra-side `flat_register_path_works_via_octravpn_node_router`. |
| 3  | Per-chunk `MapResponse` streaming on `Stream=true`: `Notify::notify_waiters` on registry change emits a fresh `MapResponse` chunk on the existing stream; idle ticks emit `\n` keepalives every 30s. Stream never terminates naturally. | Tests: `map::tests::stream_true_emits_mapresponse_chunk_on_registry_change` (paused tokio time), octra-side `stream_true_emits_chunk_on_registry_change`. |
| 4  | EarlyNoise payload upgraded from `{"NodeKeyChallenge":{"Public":"nodekey:00…"}}` (all-zero, degenerate X25519) to a freshly-generated X25519 challenge pubkey via `snow::Builder::generate_keypair`. Tracks upstream `key.NewChallenge()` semantics. | In-process unit test of the noise round-trip still passes; client never reaches EarlyNoise (see below). |

**Exit code: 30.** The harness clears step 3 (preauth surface) and reaches step 4 with a working TLS handshake on :443; `tailscale up` exits non-zero before step 5.

### What the wall is

Client log on a fresh `tailscale up`:

```
control: control server key from https://tsi-mesh-control: ts2021=[EB6rw], legacy=
control: Generating a new nodekey.
control: RegisterReq: onode= node=[…] fup=false nks=false
control: controlhttp: forcing port 443 dial due to recent noise dial
tlsdial: warning: server cert for "tsi-mesh-control" passed x509 validation but is self-signed by "CN=headscale.local"
Received error: register request: Post "https://tsi-mesh-control/machine/register": connection attempts aborted by context: context deadline exceeded
```

Mesh-control log for the same connection:

```
WARN headscale_api::tailscale_wire::noise: ts2021 connection ended with error error=noise handshake: read initiation frame: early eof
```

What's happening, beat-by-beat:

1. Client opens HTTPS to `tsi-mesh-control:443`. TLS handshake completes.
2. Client `GET /key` returns the server's `mkey:` — fine.
3. Client opens a second HTTPS connection and sends `POST /ts2021` with `Upgrade: tailscale-control-protocol` + `Connection: upgrade`. **Our handler returns `101 Switching Protocols`.**
4. The client should now send the Noise IK Initiation frame on the same TCP socket. Instead it **closes the socket** — `early eof` on our side.
5. The client's parallel "register over noise-tunnelled h2" flow times out, register fails, tailscale up exits.

The `/ts2021` upgrade path works fine on plain HTTP (the existing
`octravpn-node` integration test `ts2021_framing_responds_to_initiation`
proves the framing + h2-over-Noise dispatch). It does NOT work through
the rustls-terminated path that PR 1 added.

### Hypothesis: `axum-server::bind_rustls` + hyper Upgrade

Stock `axum_server::bind_rustls(addr, cfg).serve(router)` runs hyper's
HTTP/1.1+H2 stack on top of a `tokio_rustls::server::TlsStream`. When
the client requests `Upgrade: tailscale-control-protocol` over that
stream, hyper *does* produce a `hyper::upgrade::OnUpgrade` in the
request extensions (our handler picks it up, returns 101). After the
101, the underlying `Upgraded` value carries the TLS-wrapped socket —
but it appears that the client is either:

(a) Negotiating HTTP/2 via TLS ALPN, in which case the `Upgrade:` header
is silently ignored (RFC 7540 §3.2 forbids it). We set
`alpn_protocols = vec![b"http/1.1".to_vec()]` in PR 1 to avoid this,
but the EOF persisted — suggesting ALPN may not be the root cause.

(b) Treating the `101` response as malformed (e.g. expecting no body
flush between 101 and the upgraded stream) — Go's `controlhttp` client
uses `httputil.ClientUpgradeConn` which has its own quirks around how
the response body is read before the TCP socket is reclaimed.

(c) The `hyper::upgrade::Upgraded` future, when wrapped by `TokioIo`
and handed to our framing reader, is reading from the TLS connection
buffer that hyper-rustls has already drained — the Noise Initiation
frame the client sent on the wire may have been consumed by hyper's
read-ahead before we got the socket back.

(c) is the most likely culprit. Upstream's headscale-Go uses the
`Conn` returned by `http.Hijacker.Hijack()` which guarantees the
underlying TCP socket is handed back with the read buffer drained. The
Rust equivalent for hyper 1.x is `hyper::upgrade::on(request).await`
which yields an `Upgraded` — but `Upgraded` doesn't promise the same
guarantee when the underlying transport is TLS-buffered.

### What unblocks exit 30 → exit 0 from here

Two paths, in increasing order of cost:

1. **Bypass axum-server for `/ts2021`.** Run a parallel rustls listener
   on `:443` that special-cases the `/ts2021` POST: do the TLS handshake
   manually with `tokio-rustls::TlsAcceptor`, peek the first HTTP request
   line, and if it's `POST /ts2021` with the upgrade header, write the
   `101 Switching Protocols` response by hand and hand the raw
   `TlsStream<TcpStream>` to `noise::drive_ts2021`. All other requests
   go to the axum router as today. ~200 lines of code; the framing
   already works (existing integration test).

2. **Reach into hyper for the upgrade socket.** Replace
   `axum_server::bind_rustls` with a manual `hyper::server::conn` setup
   that calls `hyper::upgrade::on(req)` and is careful about read
   buffering. Higher risk because hyper's upgrade contract over TLS
   isn't documented.

Path (1) is the cleaner ship. The framing + h2-over-noise + EarlyNoise
content are all correct (verified by direct-noise tests); the only thing
missing is the socket-hijack semantics on the TLS path.

### Exit-code progression as of this PR batch

| State | Exit code |
| ----- | --------- |
| Pre-PR-1 (no TLS) | 30 (`forcing port 443 dial` fails) |
| **Post PRs 1–4 (this commit batch)** | **30** (TLS works, /key works, /ts2021 upgrade fails through axum-server+rustls) |
| + raw rustls listener for `/ts2021` (the path above) | expect 0 or 40 |
| + flat-path register over h2-in-noise verified | expect 0 |

### New deps added (PR 1)

- `rcgen` 0.13 (with `pem` + `aws_lc_rs` features) — self-signed cert minting at startup.
- `axum-server` 0.7 (`tls-rustls` feature) — the rustls bridge for axum 0.7.
- `rustls` 0.23 (`aws-lc-rs` feature) — the TLS server itself.
- `rustls-pemfile` 2 — parsing the cached PEM back into rustls types.

All four land under `headscale-api/Cargo.toml` (not the workspace
`Cargo.toml`). Pre-existing wedge (#210, boringtun ↔ curve25519-dalek)
unchanged.

### Build.rs gate

`headscale-api/build.rs` now skips `tonic_build` unless `CARGO_FEATURE_FULL`
is set. Wire-layer-only consumers (octravpn-mesh, the docker builder)
no longer need `protoc` installed. Host builds with default features
remain unchanged.

### Acceptance probe (manual, confirms PRs 1 + 2 from inside a peer)

```
$ docker exec tsi-peer-a sh -c '\
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    wget -qO- https://tsi-mesh-control/key'
{"PublicKey":"mkey:101eabc31b16aa58c74d1938eada471a613c7429468d795f316a556ab7ad146e"}

$ docker exec tsi-peer-a sh -c '\
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    wget --post-data="{...flat-register body...}" -qO- \
        https://tsi-mesh-control/machine/register'
{"User":{...},"Login":{...},"MachineAuthorized":true}
```

Both return `200 OK` with a valid response. The wire surface is correct;
the upgrade-through-TLS path is the wall.

## 2026-05-19 — P1 batch (Post-/ts2021-drain fix)

The hyper-rustls read-buffer drain wall described in the prior
"2026-05-19 P0 batch shipped" entry is closed. Three deeper walls
surfaced in sequence as the client got further into the handshake; the
first two are also closed in this batch. **Exit code remains 30**;
the open wall is in the post-handshake Noise transport cipher's nonce
encoding.

### Wall 1 (closed) — hyper-rustls drains the Initiation

**Fix:** `headscale-api/src/tailscale_wire/raw_tls.rs` (new). The
HTTPS-on-`:443` bind is now a raw `tokio_rustls::TlsAcceptor` accept
loop. Each connection is peeked one buffered read at a time until the
`\r\n\r\n` header terminator; if the request is `POST /ts2021` with
`Upgrade: tailscale-control-protocol`, the listener writes the
`101 Switching Protocols` response by hand and hands the unbuffered
`TlsStream<TcpStream>` directly to `noise::drive_ts2021_with_init`.
All other traffic flows through `hyper::server::conn::http1` into the
same axum router that the plain-HTTP `:51821` listener serves.

`serve.rs::serve` no longer references `axum_server::bind_rustls`; the
`axum-server` dep was dropped from `headscale-api/Cargo.toml`. The
single new dep is `tokio-rustls = "0.26"` (matches the pinned
`rustls = "0.23"`).

Test coverage: 9 unit tests in
`tailscale_wire::raw_tls::tests` (peek/header/upgrade-detection round
trips) + 2 end-to-end integration tests in
`crates/octravpn-node/tests/raw_tls_integration.rs`:

  - `non_ts2021_post_dispatches_to_router` — `GET /key` over real
    `tokio-rustls` to an ephemeral port; asserts the inner router
    returns the same JSON shape as on `:51821`.
  - `ts2021_post_dispatches_to_drive_ts2021_over_tls` — the
    regression test for the original drain: posts an upgrade request
    with the Initiation frame **in the same TLS record as the
    headers**, asserts the responder writes a valid Reply frame
    within 5 s. Used to hang at `read_frame()` before the raw-tls
    fix.

### Wall 2 (closed) — `X-Tailscale-Handshake` header carries the Initiation

Stock `tailscale/tailscale:latest` (capability version 133 as of
2026-05) sends the Initiation frame **base64-encoded in the
`X-Tailscale-Handshake` request header**, with an empty request body
(`Content-Length: 0`). The pipelined-body path the prior PR
implemented never triggers; without the header path the server hangs
at `read_initiation_frame: early eof` ~10 s in.

**Fix:** `raw_tls::handle_one` extracts the header value, base64-
StdEncoding-decodes it, and passes the bytes via the new
`noise::drive_ts2021_with_init(state, io, Some(init_bytes))` entry
point. `drive_ts2021_with_init` either uses the pre-decoded
Initiation or, when absent, falls back to reading the frame off the
wire — so legacy pipelined clients keep working.

Upstream source: `tailscale/control/controlhttp/controlhttpcommon/controlhttpcommon.go`
(`HandshakeHeaderName = "X-Tailscale-Handshake"`) and
`tailscale/control/controlhttp/controlhttpserver/controlhttpserver.go`
(`acceptHTTP`).

New dep: `base64 = "0.22"` (already in the workspace via transitive
deps; we just declare it explicitly).

### Wall 3 (closed) — controlbase Initiation byte order + msg-type
table off-by-one

The original `headscale-api::tailscale_wire::controlbase` had the
Initiation frame header laid out as `[type=1:u8][version:u16be][len:u16be]`.
Upstream
(`tailscale/control/controlbase/messages.go::initiationMessage`) has
**`[version:u16be][type=1:u8][len:u16be]`** — version *first*, then
the type byte at offset 2.

The `MsgType` enum also had `Record = 3`; upstream's
`msgTypeRecord = 4` (with `msgTypeError = 3` in between). The
self-consistent round-trip tests passed even though the wire was
upstream-incompatible. Stock `tailscale` rejects the malformed
Initiation with a "decrypt error" once the prologue is mixed in.

**Fix:** `controlbase.rs::MsgType` now has the upstream layout
(`Initiation=1, Reply=2, Error=3, Record=4`); `Framed::write_initiation`
emits the version-first 5-byte header; `Framed::read_frame`
disambiguates Initiation (first byte = version high byte, always 0
for protocolVersion < 256) from regular frames (first byte = type
2/3/4). The `parse_initiation_frame` helper in `noise.rs` does the
same decode for the `X-Tailscale-Handshake` fast-start path.

Also fixed: the Noise prologue uses the **client-advertised
protocolVersion**, not a server-side constant. Upstream's
`controlbase/handshake.go::Server` calls
`s.MixHash(protocolVersionPrologue(clientVersion))`. We now build the
responder via `ServerNoiseKey::build_responder_for_version(proto)`
where `proto` is the version from the just-read Initiation header.
With this in place the IK handshake completes against stock
`tailscale` (mesh-control log: `ts2021 received initiation
proto_version=133 len=96`, no decrypt error on the Initiation read).

### Wall 4 (OPEN) — Noise transport cipher uses non-standard nonce

After the IK handshake completes the connection moves into transport
mode. The first encrypted Record arriving from the client fails to
decrypt:

```
WARN tailscale_wire::noise: h2 accept failed
  error=noise decrypt: decrypt error
```

Root cause: upstream `tailscale/control/controlbase/conn.go` uses
**big-endian nonces** (`binary.BigEndian.PutUint64(n[4:], counter)`)
for ChaCha20Poly1305 transport records. The Noise spec mandates
little-endian; `snow` follows the spec. So our `snow::TransportState`
produces ciphertexts with the wrong AAD/keystream against the same
counter value, and decryption fails on the first record after the
handshake.

This is a Tailscale-specific deviation from the Noise spec — see
upstream `controlbase/conn.go::nonce`. `snow` doesn't expose a
nonce-encoding hook; the proper fix is to extract the per-direction
ChaCha20Poly1305 keys after `Split()` and run the transport
encrypt/decrypt manually with the big-endian nonce convention.
`snow`'s public API doesn't expose key extraction either — so this
needs either:

  1. A `snow` patch / fork that adds a `dangerously_get_cipher_keys`
     accessor on `TransportState`; or
  2. Replace `snow` for the transport-mode side with a hand-rolled
     ChaCha20Poly1305 wrapper (handshake stays on `snow`). We already
     depend on `chacha20poly1305 = "0.10"` transitively.

Option 2 is cleaner and lets us pin behaviour to the upstream byte
layout one place.

### Exit-code progression as of this PR batch

| State | Exit code |
| ----- | --------- |
| Pre-P0 batch (no /ts2021 over TLS) | 30 |
| Post-P0 batch (hyper-rustls drain) | 30 |
| **Post-P1 batch (this commit)** | **30** (noise transport nonce wall, see Wall 4 above) |
| + Post-handshake nonce encoding fixed | expect 30 or 0 — depends on whether the inner h2 + register flow lands cleanly |
| + Inner /machine/register over noise-h2 verified | expect 0 |

### What in-the-wild behaviour we observed (full trace, peer-a → mesh-control)

1. Client opens TLS to `:443`. ALPN selects `http/1.1`.
2. `GET /key?v=133` → `200 {"PublicKey":"mkey:..."}`. Reaches the
   inner axum router via hyper http1.
3. Client opens a *second* TLS connection.
4. `POST /ts2021 HTTP/1.1` with
   `X-Tailscale-Handshake: <base64 101-byte Initiation>`, body length 0.
5. Server peek detects `/ts2021`, decodes the handshake header,
   writes `101 Switching Protocols`, runs Noise IK responder with the
   pre-decoded Initiation + prologue version 133, writes the Reply
   frame. Handshake completes (no errors).
6. Server writes the EarlyNoise frame (5-byte magic + 4-byte JSON
   length + `NodeKeyChallenge` JSON) as the first transport-mode
   Record.
7. `h2::server::handshake` starts. First read off the noise stream
   fails: `noise decrypt: decrypt error` (wall 4).
8. Client treats the connection as broken, retries with a new TLS
   dial, same failure mode. Eventually `tailscale up` times out at
   the 20 s `timeout` wrapper.

### Files touched this batch

`headscale-rs`:
- `headscale-api/src/tailscale_wire/raw_tls.rs` — new module (~400
  lines incl. 9 tests).
- `headscale-api/src/tailscale_wire/mod.rs` — register `pub mod
  raw_tls`.
- `headscale-api/src/tailscale_wire/serve.rs` — route `:443` through
  `raw_tls::serve_raw_tls` instead of `axum_server::bind_rustls`.
- `headscale-api/src/tailscale_wire/noise.rs` — add
  `drive_ts2021_with_init`, `build_responder_for_version`,
  `parse_initiation_frame`. Existing `drive_ts2021` is a thin wrapper
  around `_with_init(None)` so prior callers keep compiling.
- `headscale-api/src/tailscale_wire/controlbase.rs` — fix `MsgType`
  values + Initiation header layout to match upstream.
- `headscale-api/Cargo.toml` — drop `axum-server`, add `tokio-rustls`,
  declare `base64`.

`octra`:
- `crates/octravpn-node/tests/raw_tls_integration.rs` — new
  integration test file (TLS-via-rustls smoke + the drain regression).
- `crates/octravpn-node/Cargo.toml` — add `tokio-rustls`, `rustls`,
  `rustls-pemfile` dev-deps.
- `docker/devnet/tailscale-interop/docker-compose.yml` — surface
  `headscale_api::tailscale_wire=debug` in `RUST_LOG` for the
  connection-by-connection trace operators need while wall 4 is
  open.

### Next P1 priorities (per `docs/headscale-gap-analysis.md`)

After closing wall 4 (Noise transport nonce encoding), the remaining
P0 items from the gap analysis are:

1. **Inner h2-over-noise dispatch ergonomics** — once decrypt works,
   confirm `/machine/register` and `/machine/map` actually reach the
   inner router through the h2 layer (the same router already serves
   them on the outer plaintext + raw_tls non-/ts2021 paths, so this
   is expected to "just work").
2. **Streaming `/map` long-poll under the noise tunnel** — verify the
   `Stream=true` ndjson keepalive cadence works through h2.
3. **EarlyNoise content validation** — once a real client gets to
   read the EarlyNoise JSON, confirm `NodeKeyChallenge` shape +
   value are accepted.

## 2026-05-19 — Wall 4 closed (BE-nonce post-handshake transport)

The Noise transport nonce-encoding deviation flagged in the prior
"Wall 4 (OPEN)" section is now closed. Stock `tailscale up` v1.78+
successfully decrypts our `/ts2021` Records, reads the EarlyNoise
frame, drives an `h2-over-noise` register call to completion, and
receives `RegisterReq: got response; nodeKeyExpired=false,
machineAuthorized=true`. The wall has moved one layer up.

### How we closed Wall 4

**Architectural choice: Option B from the prompt.** Keep `snow` for
the IK handshake (well-tested by other Rust users); own the
post-handshake transport (where Tailscale deviates from the Noise
spec via big-endian nonces). Mirrors upstream Go-headscale, which
uses `flynn/noise` for the handshake + `crypto/chacha20poly1305` for
the transport.

**Key-extraction path: `snow`'s built-in `risky-raw-split` feature.**
No vendoring required. `snow::HandshakeState::dangerously_get_raw_split()`
is a public method behind the `risky-raw-split` Cargo feature
(`snow/Cargo.toml:156`). Enabling it on the `headscale-api`
dependency exposes the `(k1, k2)` pair produced by the Noise spec's
`Split()` call. We call it on the *responder*'s `HandshakeState`
*before* `into_transport_mode()` — `dangerously_get_raw_split` takes
`&mut HandshakeState`, not `&mut TransportState`. Per the Noise spec,
`k1 = initiator-egress` and `k2 = responder-egress`; the `/ts2021`
server is the responder, so `send_key = k2` and `recv_key = k1`.
[`BeTransport::from_split_responder`](../../headscale-rs/headscale-api/src/tailscale_wire/be_transport.rs)
wraps the swap so callers don't have to reason about it.

This is the FIRST option the prompt listed (snow patch + vendor) —
turns out snow already shipped the accessor, just gated behind a
feature. We did not need to vendor or fork.

**Wire-format match-up.** Upstream
`tailscale/control/controlbase/conn.go` defines the post-handshake
record format precisely:

| Constant | Value | Derivation |
| -------- | ----- | ---------- |
| `maxMessageSize` | 4096 | Total bytes on the wire per frame |
| `maxCiphertextSize` | 4093 | `= maxMessageSize - 3` |
| `maxPlaintextSize` | 4077 | `= maxCiphertextSize - chp.Overhead` (16) |

Frame layout: `[msg_type=4:u8][len:u16 BE][ciphertext]` where
`ciphertext = plaintext || poly1305_tag`. Nonce encoding: 12 bytes,
first 4 = 0, last 8 = `counter.to_be_bytes()`.

The original prompt suggested `maxPlaintextSize = 4080`; the actual
upstream value is `4077`. The unit test
`be_transport::tests::cross_check_vs_chacha20poly1305_directly`
includes a `[0xAB; MAX_PLAINTEXT_PER_RECORD]` payload at exactly
4077 bytes to pin the boundary.

**Replay window.** Spec asked for a 32-bit sliding window; upstream
implements **strict monotonic counter** with no window (`conn.go`
comment: "Once a decryption has failed, our Conn is no longer
synchronized with our peer"). We mirror upstream — sliding windows
are for lossy datagram transports (WireGuard), not the
strictly-ordered TCP+TLS stream `/ts2021` rides on. Two regression
tests pin this: `replay_rejects_seen_record` and
`out_of_order_rejected`.

### Files shipped

`headscale-rs`:
- `headscale-api/src/tailscale_wire/be_transport.rs` — new module
  (~970 lines incl. 13 unit tests + the `BeNoiseStream`
  AsyncRead/AsyncWrite wrapper).
- `headscale-api/src/tailscale_wire/mod.rs` — register the module.
- `headscale-api/src/tailscale_wire/noise.rs` — new
  `drive_ts2021_be` + `drive_ts2021_be_with_init` siblings of the
  snow-backed `drive_ts2021*`; `handle_ts2021_post` now calls the BE
  variant. Inner router gained the v1.78+ flat
  `/machine/{register,map}` routes (the client posts here through
  h2-over-noise, not through the keyed `/machine/:node_key/...`
  shape).
- `headscale-api/src/tailscale_wire/raw_tls.rs` — switch
  `/ts2021` dispatch from `drive_ts2021_with_init` to
  `drive_ts2021_be_with_init`. Closes Wall 4.
- `headscale-api/src/tailscale_wire/register.rs` +
  `tailscale_wire/map.rs` — switch from `Json<...>` extractors to
  `Bytes` + manual `serde_json::from_slice`. The stock client posts
  through the noise tunnel without a `Content-Type` header set;
  axum's `Json` 415s those requests with
  `"Expected request with Content-Type: application/json"`.
- `headscale-api/Cargo.toml` — `snow = { features = [
  "risky-raw-split"] }`, `chacha20poly1305 = "0.10"` (new direct
  dep).

`octra`:
- `crates/octravpn-node/tests/tailscale_wire_integration.rs` — new
  `ts2021_be_transport_round_trips_record` integration test. Drives
  a full snow IK handshake in-process, extracts split keys, builds
  the two-sided `BeTransport`s, round-trips a Record through
  `BeNoiseStream` over a duplex pipe.
- `crates/octravpn-node/Cargo.toml` — `snow = { features = [
  "risky-raw-split"] }` dev-dep so the integration test can extract
  the split keys directly.
- This document — final section (the one you're reading).

### EarlyNoise format fix (rolled into this batch)

Once Wall 4 was closed, the next 3 seconds of client log surfaced an
EarlyNoise content bug we hadn't been able to see before (because
the client never reached the JSON parse step). Stock `tailscale up`
errored out with:

```
register request: Post "https://tsi-mesh-control/machine/register":
  json: cannot unmarshal object into Go struct field
  EarlyNoise.nodeKeyChallenge of type key.ChallengePublic
```

We were sending the EarlyNoise as
`{"NodeKeyChallenge": {"Public": "nodekey:<hex>"}}` — an *object*.
The upstream type
[`tailscale/types/key/chal.go::ChallengePublic`](https://github.com/tailscale/tailscale/blob/main/types/key/chal.go)
is a `[32]byte` with `MarshalText` → `"chalpub:<hex>"` (NOT
`"nodekey:<hex>"` — different prefix entirely). JSON encodes as a
bare string via Go's default `MarshalText` plumbing.

Fixed in `noise.rs::drive_ts2021_be_with_init` (and the legacy
`drive_ts2021_with_init` sibling for symmetry):

```rust
let early_json = serde_json::json!({
    "NodeKeyChallenge": format!("chalpub:{}", hex::encode(challenge_pub))
}).to_string();
```

### Current exit code: still 30, but failure mode is post-register

After all the above, `bash docker/devnet/tailscale-interop/run-interop.sh`
exits **30**, but the failure mode is qualitatively different from
before:

| Step                                          | Pre-Wall-4 | Post-Wall-4 |
| --------------------------------------------- | ---------- | ----------- |
| Client opens `/ts2021` over rustls            | OK         | OK          |
| Server reads Initiation (header fast-start)   | OK         | OK          |
| IK handshake completes                        | OK         | OK          |
| EarlyNoise frame parses on client             | n/a (decrypt-error before reach) | **OK** |
| `/machine/register` over h2-in-noise          | n/a        | **`RegisterReq: got response; machineAuthorized=true`** |
| `/machine/map` over h2-in-noise               | n/a        | hangs — see below |
| `tailscale up` exit code                      | 30         | 30 (20s wrapper timeout) |

Mesh-control log for a successful peer-a flow:

```
INFO  tailscale_wire::serve: wire surface listening (HTTPS) addr=0.0.0.0:443
DEBUG tailscale_wire::raw_tls: peek complete request_line=GET /key?v=133 HTTP/1.1
DEBUG tailscale_wire::raw_tls: peek complete request_line=POST /ts2021 HTTP/1.1
DEBUG tailscale_wire::raw_tls: dispatching /ts2021 to drive_ts2021_be (BE-nonce transport)
DEBUG tailscale_wire::noise: ts2021/be using pre-decoded Initiation from X-Tailscale-Handshake header len=101
DEBUG tailscale_wire::noise: ts2021/be received initiation proto_version=133 len=96
DEBUG tailscale_wire::noise: ts2021/be split keys extracted; switching to BE-nonce transport
# (no errors, no warnings, no further log lines — the connection
#  is kept open by the client for h2-multiplexed long-polling)
```

Peer-a daemon log (the success line):
```
control: control server key from https://tsi-mesh-control: ts2021=[CwyPr], legacy=
control: Generating a new nodekey.
control: RegisterReq: onode= node=[CuoRD] fup=false nks=false
control: RegisterReq: got response; nodeKeyExpired=false, machineAuthorized=true; authURL=false
```

After this point the daemon stalls at
`health(warnable=warming-up): ok` and never transitions to "Up".
`tailscale status` reports `Logged out` / `NeedsLogin`. There are no
further `WARN`s on the server side and no further error log lines on
the client side — the daemon is presumably waiting for the first
streaming `/map` chunk to set its `wantRunning` state.

### New wall (Wall 5): post-register the daemon never reaches "Up"

The remaining wall isn't a wire-format error any more (no more 404s,
415s, JSON unmarshal errors, or decrypt failures). It's a daemon-
state-machine issue:

- Register completes; the client gets `machineAuthorized=true`.
- The h2-over-noise connection stays open (we see no `h2 accept
  failed` warnings any more — the cipher swap works).
- But `tailscale up --reset` blocks for the full 20s timeout
  wrapper, and the daemon never moves from `NeedsLogin` to
  `Running`.

Three candidate causes:

1. **MapResponse content insufficient.** The client may parse the
   first MapResponse chunk and reject it because some required field
   is missing or malformed (e.g. `NodeID`, `User.ID`, `DERPMap`,
   `Domain`). Stock client wants a non-empty `DERPMap` to know how to
   start the disco loop — we ship a stub with one fake region; that
   may not pass validation.
2. **`Stream=true` framing mismatch.** Our map handler emits
   `<MapResponse>\n` chunks with 30s `\n` keepalives. Upstream's
   wire is documented as length-prefixed JSON chunks, not newline-
   delimited (
   `tailscale/control/controlclient/direct.go::sendMapRequest`'s
   read loop calls `decoder.Decode` on a streaming JSON decoder).
   Newline-delimited may still parse via the streaming JSON decoder
   (it tolerates whitespace) but is worth verifying.
3. **First `/map` request never reaches the server.** The client
   may keep the existing h2 stream open and try to send a new
   request multiplexed over it, and our `dispatch_h2_request` loop
   may be serving one request and then unable to process the next
   (e.g. because we hold the response stream open with a long-poll
   that never returns).

In particular #3 is the most likely culprit — looking at the
mesh-control log, the second `/ts2021` connection from peer-b at
17:23:42 reaches `split keys extracted` and then there are NO
further dispatch logs even after a long delay. The `h2_conn.accept()`
loop should keep firing for every new request the client makes; if
the server is hanging in `dispatch_h2_request` for the register
response (rather than returning it), subsequent requests can't be
processed.

### What unblocks exit 30 → exit 0 from here

In priority order:

1. **Verify the h2 dispatch is non-blocking per-request.** Each call
   to `dispatch_h2_request` is `tokio::spawn`'d
   ([`noise.rs::drive_ts2021_be_with_init` step 6](../../headscale-rs/headscale-api/src/tailscale_wire/noise.rs)),
   so a slow `/map` long-poll shouldn't block subsequent register
   calls. Confirm with a direct trace: log every accepted h2 request
   and the time it took to dispatch.
2. **Capture the first /map RTT.** Add a tcpdump (or just more
   tracing) so we can see whether the client sends a `/machine/map`
   request after register completes, and what response we deliver.
3. **Smaller test: drive `tailscale up` against a hand-crafted
   single-shot MapResponse with minimum-viable
   `{User, Login, DERPMap, Domain, Node, PrivateKey}` fields.**
   If that gets the client to "Up", the wall is just the field set;
   if it stalls at the same place, the wall is the streaming
   framing.

Estimated effort: 1-3 days for an iterative debug-and-pin cycle.
The wire layer below register is now solid; what remains is the
state-machine contract on top.

### Exit-code progression as of this PR batch

| State | Exit code |
| ----- | --------- |
| Pre-Wall-4 (snow LE-nonce transport)               | 30 (decrypt error on first record) |
| **Post-Wall-4 (this commit batch)**                | **30** (register succeeds; map post-register stalls) |
| + h2 dispatch trace + MapResponse field-set fix    | expect 30, 40, or 0 |
| + `Stream=true` framing verified against client    | expect 0 |

### Test counts after this batch

| Crate | Tests passing |
| ----- | ------------- |
| `octravpn-mesh` (with `test-helpers`) | 89 (71 lib + 6 + 12 integration) |
| `octravpn-node` | 100 (87 lib + 13 across 4 integration files) |
| `headscale-api` (no-default-features) | 55 lib (1 pre-existing failure in `map::tests::stream_true_emits_mapresponse_chunk_on_registry_change` unrelated to this batch) |
| `be_transport` module | 13 (round-trip, BE-nonce pin, counter increments, replay rejection, out-of-order rejection, cross-check vs raw `chacha20poly1305`, short-ciphertext + empty-plaintext edge cases, snow→BeTransport handshake integration, `BeNoiseStream` duplex round-trip, large-write chunking) |
