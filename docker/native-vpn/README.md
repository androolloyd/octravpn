This gate starts four fresh Rust validator processes inside a network-disabled
Linux container, opts their new genesis into the fixed application VM profile,
and deploys the unchanged private-admin factory and VPN AML through signed
ordinary transactions. It uses a newly generated development proving setup,
native operator registration, immutable discovery, canonical `Pinned` admission,
the real client and WireGuard, on-chain operator claim and opener settlement,
and committed Circle asset/ExEx checks. After the paid UDP gate, two actual OS
TUNs carry TCP, UDP and ICMP through kernel SNAT to a second network-disabled
Linux container. A bounded raw-IP Unix socket hop replaces its physical link;
the target uses ordinary kernel TCP/UDP sockets and kernel ICMP replies.
Policy routes prevent direct application-stack bypass; the target must observe
the translated source, and both paid sessions must settle and appear in ExEx.
Each live session also survives an operator process restart: the client pauses,
revalidates its original canonical opening and policy, reannounces the same
identities, completes a fresh WireGuard handshake, then resumes traffic. The
gate checks retained receipt floors and that no extra escrow was funded.
Existing host networks and stores are never mounted. Both containers have only
loopback and explicitly opened TUNs, with no external interface or default route.
A fresh private Docker-managed volume carries the packet-hop sockets and is
removed at exit. A separate volume retains public logs and manifests
until they are copied into the requested evidence directory, then is removed.
All wallet and proving secrets stay in disposable `/tmp` tmpfs.
The container receives `/dev/net/tun`, NET_ADMIN and NET_RAW. Forwarding, reverse
path and local-address acceptance sysctls apply only to its disposable network
namespace; local-address acceptance is needed because both test hosts share it.
Early TCP demultiplexing is disabled in the main fixture so its explicit receive
routes carry replies through both VPN TUNs before reaching the local socket.

Run `bash docker/native-vpn/run.sh /absolute/path/to/new-evidence-directory`.
The builder image must supply the pinned Rust toolchain and sibling source
dependencies. Source and executable hashes are retained. Keys and proving
material remain in disposable container tmpfs and are excluded from evidence.

The application profile is an explicit local qualification policy anchored to
its committed genesis. Public `Graph::new`, validator membership, quorum and
epoch timing remain unchanged. Binary Contract deployments happen inside the
native 64-epoch ProgramSource overlap. This is not a public-chain activation or
Mainnet parity claim. The development trusted setup is not production ceremony
evidence. HTTPS gateway backend checks do not qualify external Tailscale/TLS.
