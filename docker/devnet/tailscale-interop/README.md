# Tailscale ↔ OctraVPN-mesh interop test

What this scenario proves (or disproves): a stock, unmodified
`tailscale/tailscale:latest` CLI client can join an OctraVPN mesh whose
control server is built from THIS repo's `octravpn-mesh` /
`octravpn-node` source and exchange traffic with a peer.

If `tailscale ping` succeeds we've confirmed the wire-protocol contract
across the headscale-rs integration boundary
(`crates/octravpn-mesh/src/headscale_bridge.rs`) is intact. If it
fails, we've caught drift — only our bespoke `octravpn-client` is
compensating, and we should fix the server side, not the client.

## How to run

```
./docker/devnet/tailscale-interop/run-interop.sh
```

Equivalently, by hand:

```
docker compose -p octravpn-tailscale-interop \
  -f docker/devnet/tailscale-interop/docker-compose.yml \
  up --build
```

The script exits 0 on success and uses distinct non-zero codes per
failure mode (see the header comment in `run-interop.sh`).

## Environment

No required env vars. Optional:

- `OCTRA_BUILD_CTX=/path/to/parent-of-octra` — override the auto-
  discovered cargo build context. The script otherwise stages a
  tmpdir holding the live worktree's `octra/` plus the sibling
  `octra-foundry/` checkout (path-deps in
  `crates/octravpn-core/Cargo.toml` require it).
- `DOCKER_BUILDKIT=1` — speeds up the initial build.

The scenario does **not** require an Octra-chain devnet RPC.
`octravpn-node` is started in idle mode (the script then drives
control-plane probes via `docker compose exec`).

## Topology

Three services on a user-defined bridge: `mesh-control` (with a
`headscale` network alias so `--login-server=http://headscale:51821`
resolves), `tailscale-a`, `tailscale-b`. No host-network mode; macOS
and Linux are identical.

## Current finding (2026-05-19)

Running `run-interop.sh` against this commit exits with code **20**.
The `octravpn-node` build from THIS repo's source succeeds; the
control container starts; both stock tailscale containers start
`tailscaled` in userspace mode and sit in `NeedsLogin`. The script
probes `/key`, `/machine/{mkey}/map`, `/derp/probe` and gets
`Connection refused` on all three.

That's the drift this test surfaces:
`crates/octravpn-mesh/src/headscale_bridge.rs` is pin-only ("zero
Rust-API coupling to headscale-rs"); `octravpn-node`'s control plane
(`crates/octravpn-node/src/control.rs`) only mounts `/session`,
`/session/:id`, `/health`, `/metrics`, `/events` — none Tailscale
coordination endpoints. No preauth-mint CLI, no admin RPC, no
TS2021/Noise surface. Once the bridge lands (e.g. `octravpn-node
mesh mint-preauth` or `POST /admin/preauth`), the script
auto-advances past step 3 and asserts an actual `tailscale ping`.
