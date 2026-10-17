# Octra public-devnet relay beside Hyperliquid

The existing Hyperliquid relay is the Toronto `hlx-private-relay-tor1` Droplet.
Hyperliquid owns public TCP 4001/4002, WireGuard UDP 51820, interface `hlx-wg`
and `10.203.0.0/30`. Octra uses **separate** public TCP 20800, WireGuard UDP
51821, interface `octra-wg` and `10.203.1.0/30`. The Octra node remains a
nonvoting observer. No chain consensus setting changes.
This is node-to-node public-devnet P2P transport. It is not a paid OctraVPN
exit, and it does not carry tester application traffic or expose RPC.

The relay host's `inet hlx_relay` input and forward chains have default-drop
policies. A separate Octra nftables table cannot override them. `relay.py`
inserts eight rules tagged `octra-devnet-relay-v1` into the existing chains and
creates only `octra-wg`; `down` deletes only that tag's rules and interface. It
does not flush or replace Hyperliquid's table. It also preserves original
inbound peer source addresses and NATs only Octra's tunnel IP on outbound
traffic. The existing non-public destination set blocks metadata, LAN and
tailnet destinations. The cloud firewall must additionally allow TCP 20800
from public peers and UDP 51821 from the Mac. Do not widen SSH or change the
Hyperliquid ports.

## Prepare without changing either machine

Generate distinct WireGuard keys on their respective endpoints. Keep private
keys in root-only files outside Git; exchange only public keys. On the relay,
make a root-only `relay.json` with:

```json
{
  "wan": "<existing-public-WAN-interface>",
  "public_ipv4": "<relay-public-IPv4>",
  "node_public_key": "<Octra-WireGuard-public-key>",
  "relay_private_key_file": "/root/octra-devnet/wg.key",
  "hlx_ruleset_sha256": "<reviewed-64-character-digest>",
  "backup_path": "/root/octra-devnet/hlx-before-octra.json"
}
```

Before creating that JSON, review `nft -a list table inet hlx_relay` on the
relay and record `python3 relay.py fingerprint` as its
`hlx_ruleset_sha256`. Set `backup_path` to a new absolute path under a
root-only directory, such as `/root/octra-devnet/hlx-before-octra.json`.
`preflight` refuses any difference from that reviewed firewall digest, an
occupied Octra interface, disabled forwarding or a preexisting backup.
`up` writes an exclusive, fsynced JSON backup before a single nftables batch
adds the rules. A failed install removes its tagged rules and new interface;
it never restores the whole HLX table over live changes. After the cloud
firewall has the two narrow additions, run
`python3 relay.py up --config relay.json`. `status` reports only whether the
interface and tagged rules exist. `down` needs no config and removes only
Octra's resources. Save the script, key and JSON on the relay and start it with
a dedicated systemd oneshot unit (`ExecStart=... up --config ...`,
`ExecStop=... down`, `RemainAfterExit=yes`) **after** the existing nftables
service. Do not enable the unit until a live ingress/egress probe passes; a
reboot without that unit removes the Octra tunnel and rules.

## Isolated local node

Run `node_namespace.py` only in a dedicated Linux container with one Docker
transport interface, NET_ADMIN/SYS_ADMIN plus SETUID/SETGID/SETPCAP for the
privilege drop, `ip`, `wg`,
`nft`, `setpriv`, `curl`, Python 3, a **Linux** Octra executable, no Docker
ports, and no host network or Docker socket. Mount the retained data, trusted
network environment and observer identity under paths readable/writable by the
non-root runtime UID. Do not share the retained state with a running host
observer. The node WireGuard key remains a separate root-only file. The local
`relay.json` fields are `public_ipv4`, `relay_public_key`, and
`node_private_key_file` (absolute path in the container).

`prepare.py` makes an exclusive new `network.json` from the retained observer
config. It changes only the three container paths, P2P bind to
`10.203.1.2:20800`, and advertised P2P to the relay's public IPv4:20800. It
refuses voting or publishing configs. Trust roots, native profile, VPN policy
and consensus behavior are copied unchanged. For example:

```sh
python3 scripts/devnet-relay/prepare.py \
  --source-config /path/to/retained-network.json \
  --relay-ip '<relay-public-IPv4>' \
  --container-data /node/state \
  --container-key /secrets/observer.key \
  --container-environment /config/network.env \
  --output /private/staging/network.json
```

The entrypoint creates a fresh `octra-devnet` namespace, keeps the encrypted
WireGuard UDP socket in the container's outer namespace, gives the node only
loopback and `octra-wg`, routes its IPv4 egress through the relay, rejects
IPv6, drops to an unprivileged UID without capabilities, and checks the only
public egress route and an authenticated WireGuard handshake before starting
`octra-node run-network`. It does not contact a third-party IP-echo service.
Run its `probe`
mode before `node`; verify external TCP 20800 reaches the node and preserves
the original peer source. Interrupt and remove the tunnel to prove there is no
home-network fallback. Then qualify authenticated signed heads, enough
validator roots for source agreement, canonical progress, restart and Circle
HTTPS separately. A reachable P2P endpoint by itself does not establish sync.

The retained macOS executable is Mach-O and cannot run in this Linux
namespace. Build the Linux release node from the same source using
`docker/Dockerfile.builder` and `docker/native-vpn/Dockerfile`. For an existing
debug observer image, `scripts/devnet-relay/Dockerfile.release` replaces only
the node executable without rerunning the qualification image's test layers.
Both builds use the workspace's parent directory as their context:

```sh
cd .. # from the octra checkout
docker build -f octra/docker/Dockerfile.builder -t octravpn-builder:latest .
docker build -f octra/docker/native-vpn/Dockerfile \
  -t octra-native-vpn-qualification:local .
docker build -f octra/scripts/devnet-relay/Dockerfile \
  -t octra-devnet-observer:20261016 .
# Only for an existing observer image built before the release-node layer:
docker build -f octra/scripts/devnet-relay/Dockerfile.release \
  -t octra-devnet-observer:release .
```

A safe stop/mount of the 69 GiB retained state is also required. The existing Tailscale HTTPS gateway on the
Mac is separate; moving the observer into this container requires a dedicated
private gateway bridge before tester browser access can move with it. Until
that bridge passes, keep the current tailnet-only gateway and do not advertise
the new observer as ready for testers.

## Native host through a local TCP relay

The public BFT launcher also accepts `"p2p_proxy":"127.0.0.1:21080"` in
`network.json`. It connects every bootstrap and discovered peer through that
local SOCKS5 endpoint, including remote hostname resolution. A refused, missing,
or stalled proxy closes the dial; it never retries through the host's direct
route. Native HELLO/ACK/FINISH authentication, validator membership, finality
and source-agreement requirements remain unchanged.

For an existing SSH alias with a pinned host key and authorized forwarding:

```sh
ssh -NT -o BatchMode=yes -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -D 127.0.0.1:21080 octra-relay
```

This keeps the canonical database and executable on the Mac. The proxy affects
P2P TCP dials only; chain HTTP recovery, Circle HTTPS, and paid VPN traffic retain
their own configured transports. It supplies outbound relay access, not public
ingress. Keep the advertised endpoint unchanged until an independently tested
inbound bridge exists. The existing WireGuard namespace remains the option for
a full isolated Linux node with both ingress and egress.

`cargo run --release -p octra-node --example peer_probe -- NETWORK_JSON PEER_IP:PORT`
uses the same configured connector and a disposable observer identity. It
verifies the responder handshake and reports the first post-handshake frame;
an ACK alone does not prove the peer retained or admitted the observer session.
The connector uses the CONNECT exchange from [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html).

## Rollback

Stop only the Octra container gracefully, then run `python3 relay.py down` on
the relay and remove only TCP 20800/UDP 51821 from its cloud firewall. Verify
Hyperliquid TCP 4001/4002 and UDP 51820 still work, and keep the retained
Octra state and keys. The script does not touch Tailscale Serve, the home
router, Hyperliquid's container or its WireGuard interface.
