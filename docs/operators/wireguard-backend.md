# WireGuard backend selection

OctraVPN ships with two WireGuard peer-administration backends. Both
speak the same wire protocol (Noise IKpsk2 + ChaCha20-Poly1305) and are
interoperable with stock `wg` peers. They differ in where the packet
encryption happens and, therefore, in throughput.

| Backend     | Where AEAD runs | Ceiling (per core, per hop) | Onion-peel role |
|-------------|-----------------|-----------------------------|-----------------|
| `boringtun` | userspace Rust  | ~1.23 Gbps                  | yes (default)   |
| `kernel`    | Linux kernel    | ~25 Gbps                    | no              |

The kernel path is **~20× faster per core** because the AEAD transform
and Noise state machine live in the kernel, fan out across CPUs
internally, and avoid the user↔kernel datagram copy on every packet.

## When the kernel backend activates

Two gates apply:

1. **Operator config.** Set `[tunnel.backend] = "kernel"` to opt in.
   The default is `"auto"`, which **does not** select the kernel
   backend even when it is available. See the next section for why.
2. **Host capability.** Linux with the `wireguard` kernel module
   present (5.6+ stock; older distros need the out-of-tree module) and
   `CAP_NET_ADMIN` on the daemon process. The capability check looks
   for `/sys/module/wireguard` first, then falls back to
   `ip link add <iface> type wireguard` + `ip link delete <iface>` as
   a privileged probe.

If either gate fails, boot fails fast with a clear error naming the
missing requirement. To dodge a kernel-side bug at runtime, set
`backend = "boringtun"` and restart — no recompile required.

## Why `auto` ≠ "use the kernel when you can"

The userspace `Server` in `crates/octravpn-node/src/tunnel/mod.rs` owns
the onion-peel + forward/egress data plane. It binds the WG UDP listen
port itself, peels the onion layer on every decapsulated inner packet,
and forwards the result to the next hop. The kernel does not surface
decrypted inner packets back to userspace in a peelable form — it
delivers them to the TUN device.

So a node that runs the kernel backend gives up its onion-routing
role. `auto` keeps the onion role intact; opt into `kernel` once you
have routed onion duty to other nodes in the mesh (or never needed
it — e.g. a pure egress node).

We log a one-line `tracing::info!` at boot when the kernel backend is
*available* but `auto` keeps boringtun. That lets operators discover
the perf knob without reading this page first.

## Operator-config matrix

| OS / privilege                                   | `auto`     | `kernel`        | `boringtun` |
|--------------------------------------------------|------------|-----------------|-------------|
| macOS / BSD (any privilege)                      | boringtun  | boot fails      | boringtun   |
| Linux, no `wireguard` module                     | boringtun  | boot fails      | boringtun   |
| Linux, `wireguard` module, no `CAP_NET_ADMIN`    | boringtun  | boot fails      | boringtun   |
| Linux, `wireguard` module, `CAP_NET_ADMIN` (e.g. `setcap` on the install + `--privileged` container) | boringtun  | **kernel**      | boringtun   |

The Debian package and the RPM both run
`setcap cap_net_admin,cap_net_bind_service+ep /usr/local/bin/octravpn-node`
in their post-install script — so the privileged column applies on
those install paths out of the box.

## Required setup for the kernel backend

```sh
# Verify the module is loaded.
sudo modprobe wireguard
ls /sys/module/wireguard

# Confirm CAP_NET_ADMIN.
sudo setcap cap_net_admin,cap_net_bind_service+ep \
    /usr/local/bin/octravpn-node
getcap /usr/local/bin/octravpn-node

# Switch the operator config.
[tunnel]
listen = "0.0.0.0:51820"
backend = "kernel"
```

Then restart the node. The `/health` endpoint reports the chosen
backend; boot logs include `WG backend selected: kernel`.

## Limitations and behaviour deltas vs. boringtun

| Knob                    | boringtun                                      | kernel                                                    |
|-------------------------|------------------------------------------------|-----------------------------------------------------------|
| `MTU` default           | 1420 (the boringtun in-tree default)           | 1420 (set by `ip link add ... type wireguard`)            |
| Handshake timeout       | 5s init, 5s response — `Tunn` constant         | 5s init, 5s response — `wg`(8) constant                   |
| `persistent-keepalive`  | configured per-peer via `add_peer`             | identical; `wg set ... persistent-keepalive <secs>`       |
| `allowed-ips`           | informational today (data plane routes by source addr) | authoritative — kernel routes by allowed-ips |
| Listen-port collision   | userspace `bind()` racing the kernel ⇒ EADDRINUSE on boot | kernel grabs the port via netlink ⇒ same error path |
| `wg show <iface>` parity| n/a (no kernel iface)                          | identical; the kernel exposes the standard `wg show` interface |
| Per-peer rx/tx counters | bumped in-process by the data plane            | scraped from `wg show <iface> dump` (kernel ledger)       |
| Onion-peel forwarding   | yes                                            | no (kernel does not surface inner IP packets to userspace) |

### Allowed-IPs becomes authoritative

In boringtun the data plane routes by source UDP address (see
`tunnel/mod.rs::handle_packet`); `allowed-ips` is plumbed through the
backend trait but the forwarding role doesn't consult it. The kernel
backend uses the value verbatim — a peer with `allowed-ips = 0.0.0.0/0`
sees all egress traffic, a peer with `allowed-ips = 10.0.0.42/32` sees
only that destination. Operators migrating from boringtun should
audit their `add_peer` callers before flipping the switch.

### Persistent keepalive semantics

Both impls take the same `Option<u16>` seconds value. The kernel
enforces the keepalive in the kernel scheduler; boringtun runs it from
the userspace recv loop. The kernel path is more accurate under load.

### Listen-port handoff

The kernel backend's `up()` writes the listen port via
`wg set <iface> listen-port <port>`. Once the kernel iface is up, the
port is owned by the kernel. The userspace `Server` will fail to
`bind()` on the same port — so the operator MUST disable the userspace
onion-peel role (or run it on a separate listen port) before
switching. Today this means giving up onion-peel on the kernel node;
see "Why `auto` ≠ ..." above.

## Bench results

On a Linux runner with a 4-core Skylake CPU and a single peer
producing 10 GiB of UDP traffic, our `wireguard_throughput` bench
records (see `crates/octravpn-node/benches/wireguard_throughput.rs`):

| Backend     | Single-core throughput | Notes                                       |
|-------------|------------------------|---------------------------------------------|
| boringtun   | 1.18 Gbps              | Matches the upstream ~1.23 Gbps reference   |
| kernel      | 24.7 Gbps              | Matches the upstream ~25 Gbps reference     |

The kernel path's per-core ceiling does not stack across cores
linearly the way boringtun's does (the kernel already SMP-fans-out
internally), but the absolute headroom is so much larger that this
rarely matters in practice.

## Troubleshooting

* `boot fails: "config requests kernel WG backend but probe failed"` —
  either the wireguard kernel module is not loaded (`modprobe
  wireguard`) or the daemon lacks `CAP_NET_ADMIN`. The Debian/RPM
  install paths grant the cap automatically; `cargo install`-style
  installs need a manual `setcap` step.
* `boot fails: "config requests kernel WG backend but this host is not
  Linux"` — the kernel backend is Linux-only by design. Use `auto` or
  `boringtun` on macOS / BSD.
* `ip link add ... type wireguard: RTNETLINK answers: Operation not
  supported` — the `wireguard` kernel module is missing or your
  network namespace was unshared without CAP_NET_ADMIN.
* `wg show wg-octra-51820` returns "No such device" — the daemon
  either failed to bring up the iface (check boot logs) or has
  switched back to boringtun at runtime. Confirm via `/health`.

## CI coverage

The trait-level FSM tests (`MockBackend`, `BoringtunBackend`) run on
every CI matrix entry. The kernel-backend end-to-end exerciser lives
in `crates/octravpn-node/tests/wg_kernel_backend.rs` behind
`#[ignore]` + a runtime `target_os = "linux"` guard. The Linux-only
CI job in `.github/workflows/perf-10-kernel-wg.yml` runs the suite
with `--ignored` inside a privileged container — see that workflow
for the exact `setcap` + `modprobe` boilerplate.
