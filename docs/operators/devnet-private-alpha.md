# Private devnet alpha

The private profile uses the native Rust node and SDK. Operator admission,
funding and traffic metering run against the node's authenticated canonical
publication. Internet traffic uses encrypted WireGuard interfaces. Operators
receive prepaid OCT directly; the protocol takes no commission.

The launch remains gated on the final funded matrices and a public canary.
This guide describes the invited developer profile. It does not enable public
self-service signup, stock Tailscale private payments or Mainnet.

## Deployment pins

| Field | Accepted value |
| --- | --- |
| Chain | `octra-devnet-9871-cluster` |
| Operator | `oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP` |
| Directory Circle | `oct4qzVq1RsPQnnoYpbXNuqjHYpPPs2LPdDK2inWZDwYCoP` |
| Offer | `0` |
| Default rate | 1,000 OU per MiB, or 0.001 devnet OCT/MiB |
| Tariff hash | `6dbf15ffc4b5db0c2b50170661b79191f2b34c15839bd0c5cfe85769c7ac61ae` |
| Shielded pool | `octFtF7bWUkmko9y6yvYst1LhyPYzbgbMwao1FA3ZHKWqJz` |
| Pool factory | `oct7bVQG5wUTuMSVzYcBtNfuYUai7j9HjjrE3CZqhVqbbjW` |
| Shared pool cap | 1 devnet OCT |

The pool uses a single-party devnet test setup. Its verification-key hash is
`2ae86a97a89f6924d5f7f35285ed5f48c02e48975ba804ee06159228299087f9`.
The [deployment checkpoint](../rust-node/checkpoints/2026-10-20/devnet-private-pool.json)
records its immutable program hashes. This setup has no production ceremony
qualification. Use test funds only.

## Join an invited test

1. Have the operator admit your source IP to the invited test ingress. This
   initial deployment restricts both private control and encrypted data ingress
   to accepted source addresses; it is not a public registration endpoint.
   Obtain the operator's accepted deployment, tariff, HTTPS CA/SPKI and
   WireGuard endpoint pins. Invitations also specify the tested client profile
   and accepted local proving material. A hostname or operator response alone
   does not establish funding or chain identity.
2. Build from the revisions in the repository's [README](../../README.md).
   Enable `private-payments-experimental` for the native node. The qualified
   packet profile uses a dedicated Linux host or Linux network namespace, which
   can run in a VM on a Mac.
3. Generate and keep wallet, relayer and receipt credentials locally. Configure
   independent public-devnet trust and an authenticated bootstrap using the
   [node guide](../rust-node/devnet.md). Follow the
   [private payer guide](../rust-node/private-payer.md) to initialize protected
   books and import explicit finite deposit/purchase consent.
4. Wait for actual native execution and canonical confirmation. The private
   control service's signed reply authenticates its terms, not the money.
   Preserve the original consent IDs, signatures, notes and journals after an
   interrupted operation. Resume them rather than initializing replacements.
5. Install the accepted fail-closed routing and DNS profile before carrying
   application traffic. Confirm the exit's public IP, positive DNS/HTTPS traffic,
   physical-path refusal and unchanged spending across restart.

Never send a wallet seed, spend key, relayer key or witness to an operator or a
Circle page. The operator needs a receipt identity and public inclusion material.
The website serves onboarding assets; signing and custody stay local.

The SDK's `private_interface` example opens a single explicitly funded TUN and
retains its encrypted transport journal. It does not install routing policy or
buy bytes. Its host must own the firewall, DNS, effective MTU and shutdown policy.
The public relay profile has an additional encrypted underlay; its IPv4 canary
uses an effective 1,075-byte client MTU. IPv6 exit service is not qualified.

## Routing and recovery

One published public operator cannot establish a public two-operator route.
The isolated funded matrices use distinct operators and kernels, actual native
proof transactions, nested TCP/UDP/ICMP, canonical ExEx commits, crash/restart,
provider outage, finite exhaustion and independent custody accounting. Their
result does not establish public multi-hop deployment.

The client counts successful local packet handoffs, retained uncertainty and
pending writes. The provider meters its own delivery boundary. UDP loss can make
these counters differ. Neither reconnect nor an outage restores either budget;
traffic stops when the applicable finite budget cannot cover the next packet.
This is not cryptographic proof that arbitrary Internet content was delivered.

Available owned shielded notes can be withdrawn through the native payer's
movement API. Settled byte purchases stay final. An expired quote or failed
connection cannot authorize a replacement purchase or automatic top-up.

## Operating limits

The current public observer is nonvoting and uses the adopted upstream rules.
The relay provides encrypted reachability to the Mac-hosted node. The Mac and
relay must both remain online. This is an invited test deployment with no
availability guarantee.

The observed full-node workload uses roughly 43 GiB of memory and more than
100 GB of retained state. These are measurements from this deployment, not a
validated minimum host size. Measure sustained sync, restart and recovery on
your intended host before offering service.

The [stock paid-exit profile](../architecture/stock-paid-exit.md) covers a separate
Tailscale deployment. The current private profile does not combine that stock
exit with its shielded operator service. The bounded free portal helps users
understand and fund a connection; general Internet traffic requires paid capacity.
