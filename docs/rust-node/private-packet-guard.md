# Composite packet enforcement

Policy routing alone is insufficient for the composite client: Linux can
synthesize a direct route for a socket bound to an interface. The client now
installs a dedicated `OCTRA_PAID` filtering chain before changing host routes.
It inspects filtering ownership before entry funding. The host needs root,
`CAP_NET_ADMIN`, `iproute2`, and both IPv4/IPv6 iptables save/restore tools.
The bounded Linux qualification uses Debian's iptables 1.8.9 nf_tables backend.

Local IPv4 OUTPUT allows only:

- Loopback and destinations in `100.64.0.0/10` through `tailscale0`.
- The final accepted paid interface.
- The native node's nonzero privileged socket mark through the entry interface.
- Each downstream control TCP port and carrier UDP port through its predecessor.
- The entry's exact control/carrier IP and port on the recorded physical device.

Other local output is rejected. This IPv4 profile permits IPv6 loopback and
rejects other IPv6 output. It does not inspect payloads, grant prepaid capacity,
change Circle accounting, or charge a protocol fee. Root and network-capable
processes remain trusted host principals; the mark is not a secret or payment.
Allowed packets return to the existing host firewall policy.

Transactions use `--noflush` and touch only the dedicated chain and its OUTPUT
jump. Activation succeeds only after both address families are installed and
verified. The first installation is transactional per family, not atomically
across IPv4 and IPv6. Cancellation does not remove installed filtering.

The sealed route plan binds endpoints, names, mark, boot/network namespace and
physical device identities. Recovery derives its expected filtering rules from
that accepted intent. Existing owned rules must match exactly and the guard
must be the first OUTPUT rule. Extra rules, references, reordered rules or a
shadowing jump fail without adopting them. A missing family can be repaired.
Routing recovery also checks exact base routes and policies before repair;
Linux's implicit loopback device is accepted only for IPv6 blackholes.

Only a successful explicit disconnect removes filtering, after route cleanup.
Counters are observations, not ownership authority. No global chain or table
is flushed, and no old paid device route becomes trusted merely from its tag.

The [checkpoint](checkpoints/2026-10-20/private-packet-guard.json) records 380
client tests, strict host configurations, strict Linux client lint, and five
isolated Linux checks. Real UID-1000 sockets have no effective capabilities;
they bind the entry or physical device and are rejected with zero transmitted
packets. Positive controls transmit through the marked entry and paid exit.
Crash recovery, partial installation and foreign filtering/routing state are
covered. Every owned test container is removed and its absence verified.

These checks qualify local composite OUTPUT enforcement and kernel-plan
recovery. Operator FORWARD policy, full funded private multihop, multiple paid
classes on one channel, stock-client onboarding and public-network operation
remain separate gates. The legacy standalone v3 route-only helper still needs
this enforcement integrated before host-exit launch. The final packet-test
image replaces the route test binary on an immutable parent; it does not
requalify the full native paid-kernel fixture or deploy a node.
