# Operator route network

The target is a graph of independently run OctraVPN nodes. A client chooses a
known entry and a reachable Internet exit, potentially via another operator.
Operators may sell carriage and exit at different rates. An open channel is
funding capacity, **not** a license to forward: each edge requires a specific,
canonically confirmed finite byte purchase. The protocol takes no commission.

## Current boundary

The native Linux `multi-payments` client can run an explicitly accepted two- or
three-operator route. Each hop has its own immutable tariff, accepted plan,
receipt key, purchased allowance and durable journal. The entry carries the
next operator's encrypted UDP; the final exit carries traffic to the Internet.
The isolated multi-hop tests are not a public operator mesh. Stock Tailscale
mesh-to-mesh transit, automatic operator discovery and automatic route
selection are not live. The public-devnet deployment has one bonded operator;
its bounded paid route has not qualified sustained availability.

The current Circle prepaid app uses public addresses, offers, balances and
purchase calls. It does **not** provide shielded route payments, even though
the transport encrypts packets between hops. The final Internet exit can see
the destination IP and port; application content needs its own end-to-end
encryption, such as HTTPS. No operator should advertise anonymous payment or
hide these limits in a tester flow.

The explicit Linux nested route now sends downstream control and WireGuard
traffic through the preceding paid tunnel. Only the entry's management IPs
receive a physical bypass. Hostname resolution before route activation and
public Circle payment metadata remain observable. Route files may set
`payment_privacy: "shielded_required"`; that request fails before loading keys
or preparing journals while shielded settlement is unavailable.

## Route discovery and consent

1. An operator advertises a signed endpoint, route role (carriage or exit),
   supported traffic classes, public tariff asset, bond generation and expiry.
   A client checks the signature and exact canonical Circle offer and refuses a
   stale, slashed, unstaking or superseded operator.
2. The client measures entry and candidate-exit reachability and latency. It
   may use coarse geographic or network-region hints. Probing the user's actual
   destination through candidates leaks that destination to them; do not do so
   without explicit consent. “Closest” means the lowest measured viable route
   under the user's price and hop limits, not a geographic guarantee.
3. Candidate paths contain at most the implemented hop limit, no repeated
   operator or endpoint, and no edge without sufficient finite purchased bytes.
   Show the route, operators, per-hop rates, purchased bytes, total maximum OCT
   and expiry before signing. A reroute needs fresh consent and separate plans;
   it cannot silently top up or reuse a prior authorization.
4. Forward only after every required hop has canonical purchase confirmation.
   One failed hop blocks the route. Durably account for committed, pending and
   uncertain bytes; never reset a journal or fall back to direct Internet.

## Shielded payment requirement

Privacy requires more than encrypted tunnels. A future Circle settlement must
hide the payer-to-route linkage and per-hop amount from public state while
proving conservation, sufficient funded balance, no double spend, bounded
purchase, operator entitlement and withdrawal correctness. It also needs
private route commitments and unlinkable per-hop receipts. The exact Octra
primitive and proof shape require an adversarial review and public-devnet
qualification. If the current host cannot verify those proofs or maintain
private state within Circle rules, that is a feature dependency to resolve;
simply putting ciphertext in a public Circle asset is not a shielded payment.

Transport work must layer encryption so an intermediate learns only its
predecessor, successor and purchased byte allowance. The final exit necessarily
learns its Internet destination. Limit metadata leakage from DNS, timing,
packet sizes and logs as separate release gates. Do not claim “all data is
encrypted” when a public destination or on-chain relationship remains visible.

## Release gates

- Two independent public-devnet operators with signed advertisements, live
  endpoints and distinct bonded identities; authenticated node peering and
  recovery across restart.
- Client selection from at least two candidate exits, with measured health,
  explicit price cap and no destination disclosure during discovery by default.
- Each hop enforces its own confirmed purchase and exhaustion. A downstream
  failure does not create credit, direct-route fallback or automatic top-up.
- Shielded payment proofs verified on the actual chain, including replay,
  double-spend, amount/route-linkage and withdrawal adversarial tests. Until
  then, call the payment path public prepaid settlement.
- Multi-hop payload and DNS behavior tested with packet capture, plus a clear
  statement of what the final exit and colluding operators can still observe.
