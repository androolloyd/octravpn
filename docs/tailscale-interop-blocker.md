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
