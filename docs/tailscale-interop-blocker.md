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
