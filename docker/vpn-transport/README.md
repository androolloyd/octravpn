This harness exercises the real Rust client and embedded VPN service in a fresh
Linux container. It uses a signed funded-session host adapter fixture; it does
not establish on-chain escrow, finality, AML settlement or private-admin parity.

Prepare the existing `octravpn-builder:latest` image using
`docker/Dockerfile.builder` with the workspace parent as context. Then run:

```sh
bash docker/vpn-transport/run.sh
```

The qualification image copies current workspace source and compiles its test
executable before starting an isolated container. Runtime has no Docker network,
no mounted host directories, a read-only filesystem, one bounded temporary
filesystem, and only the `NET_ADMIN` capability plus `/dev/net/tun`. The public
IPv4 address is an alias of its own loopback; no packets leave the namespace.
The wrapper and tests refuse external interfaces/default routes.

Cases cover real WireGuard handshake/session framing, traffic credit ceiling,
refused private destinations, revocation, public UDP return and exact signed
receipt accounting. The raw IPv4 case crosses the server's real OS TUN, the
kernel UDP/IP stack and the client's real WireGuard driver. It does not install
the client's own OS TUN or qualify external NAT, public routing or TCP forwarding.
Those require separate client/server network namespaces and operator routing.

The builder and runtime must be available locally; image construction can fetch
dependencies. All runtime test state is discarded with the container. Existing
devnet containers, routes, keys and volumes are untouched.
