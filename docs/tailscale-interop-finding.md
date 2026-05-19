# Tailscale interop test — finding (2026-05-19)

`docker/devnet/tailscale-interop/` is a Docker-compose scenario that
runs stock `tailscale/tailscale:latest` CLI clients against an
`octravpn-node` instance acting as the control plane, then runs
`tailscale ping` between them. It was written to catch wire-protocol
drift between our control plane and the upstream Tailscale clients.

Result: the test exits with code 20 ("no preauth-key minting surface
available") **before reaching `tailscale ping`**. This is a load-
bearing finding, not a flaky test.

## What we observed

1. `crates/octravpn-mesh/src/headscale_bridge.rs` is **pin-only** at
   the current commit — its own module doc says "this crate has zero
   Rust-API coupling to headscale-rs … no module here imports any
   `headscale_core::*` symbol, and nothing here links against it."
   It's a compile-time field-name pin, not an implementation.

2. `crates/octravpn-node/src/control.rs` mounts only `POST /session`,
   `GET /session/:id`, `GET /health`, `GET /metrics`, `GET /events`.
   None of the Tailscale coordination endpoints (`/key`,
   `/machine/{mkey}/map`, DERP probe, TS2021 Noise handshake) exist.

3. `octravpn-node`'s CLI has no `mesh`, `preauth`, `auth-key`, or
   `coord` subcommand — no way to mint a preauth key over CLI, RPC,
   or admin HTTP.

4. From inside a `tailscale/tailscale:latest` container, probing
   `http://headscale:51821/key`, `/machine/dummy/map`, and
   `/derp/probe` all return `Connection refused`.

## What this means

The `octravpn-mesh` crate ships Tailscale-shaped primitives — STUN,
IP allocation, magic DNS, connection FSM — but they run **in-process
inside the client/node**, not behind a Tailscale-protocol coordination
server. The existing `octravpn-client` is therefore the only thing
that can talk to whatever the control plane actually is; a stock
`tailscale` CLI has no Tailscale-protocol server to handshake with.

The "decentralized-tailscale" framing in `crates/octravpn-mesh/src/lib.rs`
is accurate insofar as the primitives are Tailscale-style. It is not
yet accurate to call the system "Tailscale-compatible" — that would
require the headscale-rs bridge to actually move beyond field-name
pinning into a real implementation.

## What's actually proven by the scaffolding

- Build path: `octravpn-node` builds in a Docker context that
  rsyncs the repo + the sibling `octra-foundry/` checkout into a
  tmpdir. Cargo build succeeds first try. Tracked in
  `Dockerfile.mesh-control`.
- The interop test will auto-pass step 3 ("mint preauth key") as soon
  as **either** of two hypothetical surfaces lands:
  - `octravpn-node mesh mint-preauth <user>` CLI subcommand
  - `POST /admin/preauth` HTTP endpoint on `control.rs`
- The compose file + run script + Dockerfile are all parameterized
  so the same scenario can be rerun against any future commit
  without changes.

## What needs to happen for the test to pass

1. The headscale-rs Rust API binding has to land in
   `octravpn-mesh/src/headscale_bridge.rs` — currently a name-pin only.
2. `octravpn-node` (or a sibling control-plane binary) must expose
   Tailscale's coordination endpoints — `/key`, `/machine/.../map`,
   `/derp/probe`, the TS2021 Noise handshake — and route them into
   the headscale-rs implementation.
3. A preauth-key mint surface (CLI subcommand or admin HTTP) must
   exist so a fresh `tailscale up` can authenticate.

Once those three exist, `bash docker/devnet/tailscale-interop/run-interop.sh`
should pass with `tailscale ping` confirming end-to-end mesh
connectivity.

## How to rerun the scenario

```
bash docker/devnet/tailscale-interop/run-interop.sh
```

Or by hand (set `OCTRA_BUILD_CTX` to a directory containing both
`octra/` and `octra-foundry/`):

```
OCTRA_BUILD_CTX=/Users/androolloyd/Development \
  docker compose -p octravpn-tailscale-interop \
    -f docker/devnet/tailscale-interop/docker-compose.yml up --build
```

Exit codes:

| code | meaning |
|------|---------|
| 0    | `tailscale ping` succeeded — interop works |
| 10   | mesh-control didn't reach `/health` |
| 20   | preauth-key minting surface not available (current state) |
| 30   | `tailscale up` failed on at least one peer |
| 40   | peers never converged on the IP plane |
| 50   | `tailscale ping` failed despite peers being up |

## Related

- `crates/octravpn-mesh/src/headscale_bridge.rs` — the pin module
- `docs/audit-04-headscale-rs.md` (if present) — earlier audit of
  the headscale-rs integration boundary
- `docs/octra-dev-questions.md` — the open-questions bundle (this
  isn't on the list; it's an internal gap, not a chain-side blocker)
