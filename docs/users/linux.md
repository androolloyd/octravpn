# OctraVPN on Linux — install + first connect

This walks an end-user from a vanilla Linux box (Ubuntu, Debian,
Fedora, Arch — anything systemd-based) to a working WireGuard tunnel
into someone else's OctraVPN tailnet. You will install two pieces:

1. **`tailscale`** (the stock open-source client from
   <https://tailscale.com/download>). This is what speaks WireGuard
   to your peers and the Tailscale-wire control plane to the
   operator's mesh-control endpoint. We use stock Tailscale unchanged.
2. **`octravpn`** (this project's optional client CLI). End users on
   a normal `--login-server` tailnet usually do **not** need it. It is
   only required if your operator told you to use the chain-anchored
   flow described in [`docs/tailnet-user-guide.md`](../tailnet-user-guide.md).

If in doubt, start with just `tailscale` and add `octravpn` later if
you need it.

## 1. Install stock Tailscale

Use the package your distro ships.

### Debian / Ubuntu (apt)

```sh
curl -fsSL https://tailscale.com/install.sh | sh
```

This installs the `tailscale` CLI, the `tailscaled` daemon, and
enables the systemd unit. Alternatively the manual route:

```sh
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$(lsb_release -cs).noarmor.gpg \
    | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$(lsb_release -cs).tailscale-keyring.list \
    | sudo tee /etc/apt/sources.list.d/tailscale.list
sudo apt update && sudo apt install -y tailscale
sudo systemctl enable --now tailscaled
```

### Fedora / RHEL / Rocky / Alma (dnf)

```sh
sudo dnf config-manager --add-repo https://pkgs.tailscale.com/stable/fedora/tailscale.repo
sudo dnf install -y tailscale
sudo systemctl enable --now tailscaled
```

### Arch / Manjaro (pacman)

```sh
sudo pacman -Syu tailscale
sudo systemctl enable --now tailscaled
```

### Direct binary (any distro)

```sh
TS_VERSION=1.78.1   # check tailscale.com/download for current
curl -fsSL https://pkgs.tailscale.com/stable/tailscale_${TS_VERSION}_amd64.tgz | tar xz
sudo install -m 0755 tailscale_${TS_VERSION}_amd64/tailscale /usr/local/bin/
sudo install -m 0755 tailscale_${TS_VERSION}_amd64/tailscaled /usr/local/sbin/
# Then write a systemd unit manually, or run `sudo tailscaled` in a screen.
```

Verify the daemon is alive:

```sh
sudo systemctl status tailscaled
tailscale version
```

You should see version `1.78.x` or newer. OctraVPN's mesh-control
plane is regression-tested against `tailscale/tailscale:latest` from
v1.78 onward (see `docker/devnet/tailscale-interop/`); older clients
may not reach the post-DERP datapath.

## 2. (Optional) Install the `octravpn` CLI

Skip this section if your operator only gave you a preauth key + a
login-server URL. You do not need `octravpn` to join.

You **do** need it if the operator told you any of:

- "Use `octravpn tailnet up`" (the chain-anchored mesh flow).
- "Connect via `octravpn connect-v2` / `connect-v3`" (paid sessions).
- "Run `octravpn doctor` to verify your wallet."

### One-shot installer

```sh
curl -fsSL https://octravpn.org/install.sh | sh
```

This runs [`deploy/install.sh`](../../deploy/install.sh), drops the
client at `/usr/local/bin/octravpn`, and verifies the minisign
signature if you have a pubkey at `~/.minisign/octravpn.pub`.

### From source

```sh
git clone https://github.com/octra-labs/octravpn
cd octravpn
cargo build --release -p octravpn-client
sudo install -m 0755 target/release/octravpn /usr/local/bin/
```

Verify:

```sh
octravpn --help
```

## 3. systemd integration

Two distinct services exist; you almost certainly only want the first.

### `tailscaled` (you, the end-user)

Installed by the Tailscale package above. State lives at
`/var/lib/tailscale/`. Logs land in `journalctl -u tailscaled`.

```sh
sudo systemctl status tailscaled
sudo journalctl -u tailscaled -f
```

### `octravpn-node` (operator only — skip)

The files [`deploy/systemd/octravpn-node.service`](../../deploy/systemd/octravpn-node.service)
and [`deploy/systemd/octravpn-attest.service`](../../deploy/systemd/octravpn-attest.service)
register a paid OctraVPN node — the daemon that runs the mesh-control
endpoint you are joining. **You do not enable these as an end user.**
The hardening block in the unit file (no new privileges, locked
personality, restricted namespaces) and the `[chain].validator_addr`
config requirement make this clear; if you try to start the unit
without a fully-provisioned operator config it refuses with
`/etc/octravpn/node.toml not found` and exits immediately. See
[`docs/operators/mainnet-deployment.md`](../operators/mainnet-deployment.md)
if you are the one running the node.

## 4. Connect to the tailnet

Get from your operator:

- The **login-server URL** — usually `https://<host>:443`.
- A **preauth key** — single-use unless they explicitly told you it
  is reusable.

Then:

```sh
sudo tailscale up \
    --login-server https://mesh.example.org \
    --authkey octrapreauth-YOUR-KEY-HERE
```

Notes:

- `--login-server` overrides the default
  `https://controlplane.tailscale.com`. The URL is exactly the value
  your operator gave you — do not append `/api/...` or any path.
- `--authkey` consumes the key on first use. If you re-run `tailscale
  up` later (after reboot, for example), do **not** pass `--authkey`
  again — the machine is already registered and the state at
  `/var/lib/tailscale/tailscaled.state` is what authenticates.
- Add `--hostname=$(hostname -s)` to override the name your tailnet
  owner sees in their roster. Defaults to your machine hostname.
- Add `--ephemeral` if the operator's policy says so (see
  [`connect.md`](connect.md) §3 for when to pick which).

The command blocks for up to ~60 s during the initial register +
DERP-bootstrap exchange. On success it returns with no output.

## 5. Verify

### `tailscale status`

```sh
tailscale status
```

You should see one entry for "yourself" (your IP, hostname, "offers
exit node" flags) plus an entry per peer in the tailnet:

```
100.64.0.3   andrew@laptop          linux   active; relay "use1"
100.64.0.7   colleague@desktop      linux   idle
100.64.0.9   colleague@server       linux   idle; offers exit node
```

A `relay "..."` annotation means the peer is reachable only via DERP.
"active" / "idle" describe whether traffic is flowing right now. If
the peer shows `-` instead of an IP, your control plane has not yet
delivered that peer in the netmap — wait ~30 s and re-check.

### `ip route` / `ip addr`

```sh
ip addr show tailscale0
ip route show table all | grep tailscale
```

You should see:

- A `tailscale0` interface with a `100.64.x.x/32` address.
- Routes for the tailnet's CGNAT range (typically `100.64.0.0/10`)
  going via `tailscale0`.

If `tailscale0` is missing, the daemon never opened a TUN device —
see Troubleshooting §"Kernel module missing" below.

### Peer reachability

```sh
tailscale ping <peer-hostname>
```

This is the headline working command. It shows whether you reach the
peer **direct** (peer-to-peer WireGuard, lowest latency) or via
**relay** (DERP fallback, higher latency). On the OctraVPN interop
harness, a successful ping is the Wall-7 acceptance signal; if it
returns RTTs you are joined and the datapath is live.

```
pong from desktop (100.64.0.7) via DERP(use1) in 84ms
pong from desktop (100.64.0.7) via 192.0.2.4:41641 in 11ms
```

The second line — a direct UDP endpoint — is the steady-state once
NAT traversal completes.

## 6. Troubleshooting

### `/dev/net/tun` missing → "permission denied opening tun device"

```sh
ls /dev/net/tun || sudo modprobe tun
```

Some minimal kernels (containers, very old VPS images) don't load the
`tun` module by default. `modprobe` is one-shot; persist it:

```sh
echo tun | sudo tee /etc/modules-load.d/tun.conf
```

### NetworkManager fighting WireGuard

Symptom: tunnel comes up, then your default route flips back to the
physical interface a few seconds later.

```sh
nmcli connection show
```

If `tailscale0` shows under NetworkManager management, hand it back:

```sh
sudo nmcli device set tailscale0 managed no
```

This is a one-off — the `tailscale0` interface is created fresh on
each daemon start and is not normally claimed.

### dnsmasq vs systemd-resolved conflict

Symptom: `tailscale status` looks fine but you cannot resolve peer
hostnames.

`tailscale up` programs split DNS via systemd-resolved. If you also
run a local `dnsmasq` (commonly under `libvirt`, `lxd`, or a
hand-rolled config), it may be on port 53 first.

Check who owns 53:

```sh
sudo ss -lunp | grep ':53'
```

If `dnsmasq` is there, either:

- Tell dnsmasq to bind only to its bridge (`bind-interfaces` +
  `listen-address=...` in `/etc/dnsmasq.conf`), or
- Disable Tailscale's DNS handling: `sudo tailscale set --accept-dns=false`
  and use peer IPs directly instead of hostnames.

### `tailscale up` hangs on TLS verify

Symptom: command stalls for the full timeout (≈ 90 s) with no
output, then exits non-zero.

This means your client cannot validate the operator's TLS cert. Two
common causes:

1. **Self-signed cert.** During development or fresh deployments the
   operator may have a self-signed cert. The operator must run
   `update-ca-certificates` on each client host with their CA, or
   provide you the cert PEM to add to
   `/usr/local/share/ca-certificates/`. The interop harness in
   `docker/devnet/tailscale-interop/run-interop.sh` does this by
   mounting the cert into each peer.
2. **Expired cert.** Ask the operator to check; rotation runbook is
   [`docs/operators/tls-rotation.md`](../operators/tls-rotation.md).

### "tailscale up failed" with no clearer error

The control plane may not yet be fully serving the post-DERP
datapath. The walls cleared so far (Wall 5/6/7) bring stock
`tailscale up` to a working `tailscale ping`; see
[`docs/tailscale-interop-blocker.md`](../tailscale-interop-blocker.md)
for the precise state if you are debugging with the operator.

## 7. Removing / uninstalling

Stop and forget:

```sh
sudo tailscale down
sudo tailscale logout
```

`logout` clears the registration so re-joining requires a fresh
preauth key.

Uninstall the package:

```sh
# Debian/Ubuntu
sudo apt remove --purge tailscale

# Fedora/RHEL
sudo dnf remove tailscale

# Arch
sudo pacman -Rns tailscale
```

State directories to remove if you want a fully clean uninstall (see
[`uninstall.md`](uninstall.md) for the cross-platform list):

```sh
sudo rm -rf /var/lib/tailscale
sudo rm -rf /var/log/tailscale
```

If you also installed `octravpn`:

```sh
sudo rm /usr/local/bin/octravpn
rm -rf ~/.octravpn       # bookmarks + per-tailnet config
```
