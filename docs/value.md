# What OctraVPN provides

A one-page answer for every stakeholder.

## For an individual user

You get the Tailscale UX — every device you own talks privately to
every other device you own, by name, with WireGuard end-to-end
encryption — but without a Tailscale subscription, account, or
coordination server you don't control.

| Concretely you get                                                   | How                                                              |
| -------------------------------------------------------------------- | ---------------------------------------------------------------- |
| One private network across all your devices                          | Tailnet membership on chain; deterministic per-device IP         |
| Reach your home server from your phone over 4G                       | STUN + WireGuard, falls back to paid validator if both NAT'd     |
| `ssh laptop.my-tailnet.octra` works                                  | Magic DNS resolver on the tailnet router IP                      |
| Anonymous internet egress via a paid validator                       | "Exit node" mode of a tailnet; per-byte OU payment from treasury |
| No central party can lock you out                                    | Tailnet state on chain; you hold the wallet                      |
| No telemetry leaks who you talk to                                   | Onion-routed receipts + Pedersen-committed earnings              |
| Same identity across your phone / laptop / server                    | Multi-device registry: one wallet → many devices                 |
| Onboard a new device in 30 seconds                                   | Pre-auth join tokens — owner mints, device redeems on chain      |

What you don't have to do: pay a SaaS subscription, trust a vendor's
ACL evaluator, hope nobody changes their pricing, or wait on a vendor
to fix a vulnerability before you can use your laptop.

## For a small team / family

You get the Tailscale ACL editor + audit log + magic DNS workflow,
billed by actual bytes through the few paid hops you use rather than
per-seat per-month.

| You get                                                                | How                                                       |
| ---------------------------------------------------------------------- | --------------------------------------------------------- |
| ACL-governed private network with groups + tags                        | `SignedAclDoc` distributed off-chain, hash on chain       |
| Audit log of every state change for compliance / forensics             | HMAC-chained JSONL, tamper-detection via `verify-audit-log` |
| Single bill (the tailnet treasury) — no per-user contracts             | Treasury top-up by any member; per-member off-chain       |
| Membership changes are auditable + irreversible-without-trace          | `add_member`/`remove_member` emit on-chain events         |
| You can change ACL policy without redeploying anything                 | `update_acl(new_hash)` is one tx                          |
| Self-hosted exit node for the team (one machine; everyone else routes) | `advertise-subnet` + `exit-node` settings                 |

## For an enterprise / regulated org

You inherit the verified properties of the on-chain program. You get
a system whose security claims are *provable* rather than asserted.

| You get                                                                    | How                                                                  |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Formal proofs of safety properties (TLA+, Tamarin, Lean, Kani)             | `proofs/` — settle-or-refund liveness, receipt unforgeability, etc.  |
| Owner-signed ACL with quorum support (planned)                             | `docs/security-roadmap.md` — multi-sig owner key                     |
| Tamper-evident audit logs                                                  | HMAC chain + `verify-audit-log`; ship `.audit.key` to an auditor     |
| Provable equivocation slashing of misbehaving validators                   | Octra-protocol-level slashing on receipt double-sign                 |
| No single point of governance — your wallet IS your control                | All admin actions are signed transactions                            |
| SOC2-style controls (encrypted secrets, immutable history)                 | `wallet_enc`, audit chain, signed releases via cosign                |

## For an OctraVPN operator

Any actor willing to bond `MIN_ENDPOINT_STAKE` (default 1 000 OCT)
can run a paid endpoint. Three revenue streams come from one stake:
relay (per byte), directory (per signed lookup), signaling (per
NAT-traversal assist). Existing Octra protocol validators are
particularly well-positioned — they already have uptime, public IPs,
and bandwidth — but operator participation is **not** gated on chain
validator status.

| You earn                                                              | How                                                                          |
| --------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| OU per byte relayed × your `price_per_mb` × split                     | `settle_session` credits encrypted-earnings ledger                           |
| OU per directory lookup × your `price_per_lookup`                     | `settle_directory_batch` credits encrypted-earnings ledger                   |
| OU per NAT-traversal assist × your `price_per_assist`                 | `settle_signaling_batch` credits encrypted-earnings ledger                   |
| Encrypted earnings — customers don't see your aggregate revenue       | Pedersen commitments; opened only at your claim                              |
| Privacy-preserving payout via stealth output                          | X25519 ECDH stealth: opaque to anyone but you                                |
| Reputation per successful settle (any service), visible on chain      | `EndpointRecord::reputation` increments monotonically                        |
| Auto-listed in client discovery once registered                       | `list_active_endpoints` returns currently-active, non-slashed endpoints      |
| Stake returns at `unbond_endpoint` after the grace window if honest   | `MIN_ENDPOINT_STAKE` is locked, not paid                                     |

The cost: stake lockup + bandwidth + small per-tx fees at register
and claim. The risk: equivocating on any signed claim is provable on
chain and burns 90 % of your stake (10 % to the submitter). Honest
operation has zero slashing exposure because equivocation evidence
cannot be fabricated — only a real double-sign produces verifying
proof.

## For the Octra ecosystem

OctraVPN is a credible second use-case for Octra besides "be a chain."

| Octra gets                                                            | Why                                                                          |
| --------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| More transactions per epoch                                           | Every session open + settle + claim is a tx                                  |
| A reason to bond beyond chain validation                              | Validators with bandwidth earn paid VPN traffic on top                       |
| A real-world application of HFHE / stealth / Pedersen primitives      | OctraVPN exercises every cryptographic surface Octra is building             |
| External eyes auditing the protocol surface                           | Decentralized-Tailscale users are a different threat model than tx senders   |

## For the open internet

The hardest claim to quantify but probably the most important.

Centralized VPN providers (NordVPN, Mullvad, even Tailscale's coordination
server) are single points of:

- **Compliance pressure** — one subpoena hits the whole user base.
- **Outage** — one operator misconfiguration drops millions of users.
- **Censorship** — one government can lean on one company.
- **Trust degradation** — users can't verify the "no logs" claim.

OctraVPN replaces the "one operator" with N independent Octra validators
plus an on-chain program no single party controls. The trust model
becomes: trust the math (formal proofs), trust the economics (validator
bond > marginal defection gain), trust the diversity (≥ N validators
serving ≥ M tailnets). Anyone can audit any of these.

## What v2 adds (since 2026-05-17, on devnet)

v1 ships on main-net with public operator addresses. v2 (live on
**devnet** as of 2026-05-17, mainnet bring-up gated on the devnet
RPC body cap — see `docs/testnet.md`) uses Octra's public Circles
primitive to offer three properties v1 cannot:

| You get                                                            | How                                                                                                                |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| **Hidden operator exits** (Tor-style)                              | Operators are deployed as Circles, not wallet addresses. The slim registry binds bond to `circle_id`; the operator's IP / WG key / policy live inside the circle, fetchable only by authorized clients via path-private sealed reads. |
| **Per-class routing + per-class pricing**                          | Each operator-circle declares N classes (default 2: `shared` internet egress, `internal` intra-tailnet). Members pick a class at session-open; price snapshots at open-time per the v1 model.                                       |
| **Encrypted metering** (bytes_used stays private)                  | Compute `total_paid = bytes_used × price` inside the circle; only the settled OU amount escapes to main-net. (Mainnet-only until devnet RPC body cap is raised — see `docs/v2-octra-questions.md §7`.)                            |

Unique selling proposition relative to v1 and to Tailscale: **hidden
exits + ACL + encrypted metering on a public chain**. Tor offers the
hidden exits but no ACL or billing primitive; Tailscale offers ACL
but no privacy from the coordination server; OctraVPN v2 is the
first design we know of that gets all three at once without trusting
any single operator.

## Things OctraVPN is **not**

To set expectations:

- **Not a free service.** Per-byte through validators costs OU. Members
  pay into the tailnet treasury.
- **Not a privacy panacea.** Tailnet membership is public on chain
  (by design — it's how peer-to-peer authorization works). The privacy
  guarantee is over *traffic content + who-talks-to-whom + payment
  volumes*, not membership.
- **Not a coin.** OU is the Octra base unit; OctraVPN doesn't issue
  any token of its own. Speculation is not the business model.
- **Not a Tailscale clone for the sake of cloning.** We pick the
  pieces of Tailscale that decentralize cleanly (mesh, magic DNS, ACL)
  and leave the centralized ones (Tailscale's coordination server)
  behind.

## TL;DR

If your "I'd pay for a VPN" was about *privacy from your ISP*, OctraVPN
is overkill — use Mullvad. If your "I want a VPN" was actually about
*linking my devices privately*, Tailscale fits. If you want *both* and
also want to be sure no single party can take it away, OctraVPN is
the option.
