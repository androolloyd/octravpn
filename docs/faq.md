# OctraVPN — FAQ

## What is OctraVPN?

A VPN with Octra-backed operator bonds, offers and prepaid OCT traffic
purchases. The current Circle payment application exposes payer, plan and
purchase data publicly. An explicit Linux client can compose two or three
paid tunnels; automatic operator selection and shielded route settlement are
not deployed. See `docs/architecture/operator-route-network.md` for the
current boundary.

## How is this different from Tor / Mysterium / Sentinel / Orchid?

| Project | Token | Routing | Privacy guarantee | Slashing |
| --- | --- | --- | --- | --- |
| **Tor** | None | Onion 3-hop | Strong (decades of research) | None — relays are altruistic |
| **Mysterium** | MYST | Single-hop | Operator-trust | Reputation only |
| **Sentinel** | DVPN | Single-hop | Operator-trust | None on-chain |
| **Orchid** | OXT | Multi-hop via probabilistic nanopayments | Operator-trust + economic | None on-chain |
| **OctraVPN (current prepaid Circle)** | **OCT only** | Explicit 1–3 paid tunnels | Encrypted carriage; public payment metadata | Bonded-operator signed-receipt equivocation |

The single-token (OCT-only) design is deliberate — see
`docs/economics.md` § 4 for why. The on-chain slashing with
cryptographic evidence is the largest difference from the others.

## Do I need to hold a separate "VPN token"?

No. Everything is denominated in OCT:

- Validator bonds.
- Session deposits.
- Per-MB pricing.
- Earnings ledger (Pedersen commitments to OCT amounts).
- Slash bounties + burn + treasury.
- Refunds.

Introducing a second token would add bridges, oracles, and
front-running surface. See `docs/economics.md` § 4.2.

## Is OctraVPN actually private?

In the current prepaid Circle, payer addresses, operator offers, plan links,
funding and purchases are public. The tunnel encrypts packets between its
authenticated endpoints. In an explicit nested route, downstream control and
WireGuard traffic go through the preceding paid tunnel, but the entry sees the
client IP and the final exit sees the destination IP and port. End-to-end
application content still needs HTTPS or equivalent encryption. An observer
can correlate traffic by timing and size. A `shielded_required` route refuses
to start while there is no verified shielded settlement adapter; it does not
fall back to public settlement.

## What's the cost?

| Action | Cost |
| --- | --- |
| Validator registration | `min_bond` OCT (recoverable; ~10000 OCT recommended) |
| Liveness attestation | 1000 OU (~0.001 OCT) every `attest_grace_epochs` |
| Session open | 1000 OU + your deposit |
| Settle | 1000 OU |
| Claim earnings | 1000 OU + stealth-transfer fee |

Per-MB pricing is set by each validator; the market clears
bilaterally.

## What happens if a node goes offline?

`refresh_attestation` must happen at most every
`attest_grace_epochs`. If it's missed:

1. Anyone can call `slash_offline(validator_addr)` and receive a
   small bounty.
2. The validator's bond is reduced by 1%.
3. The validator is jailed.
4. To resume, the validator runs `refresh_attestation` (which
   auto-unjails if bond ≥ `min_bond`).

## What happens if a node misbehaves?

| Misbehavior | Detection | Penalty |
| --- | --- | --- |
| Double-signs receipts | Anyone with the 2 conflicting receipts | Full bond zeroed |
| Goes offline | Permissionless after grace | 1% of bond + jail |
| Accepts session, no progress | Client after grace | Refund + up to 10% of bond |
| Forged client sig | Settlement rejects | None (attempt is harmless) |

See `docs/attack-cost.md` for the full breakdown.

## Can I run a validator?

Today: only if you are also an Octra validator. Octra's validator
onboarding is currently paused pending decentralization (see
`docs/octra-research.md` § 1). Once Octra opens validator
onboarding, this project's validator-only gate aligns with that.

## Why "validators only"?

Because they already have economic stake on Octra and are
accountable to the network's consensus. Reusing that stake is
cheaper than asking VPN-only operators to bond again, and
slashing-via-existing-stake means there's no separate, weakly-
defended VPN bond to attack. See `docs/economics.md` § 4.1.

## Is the source open?

Yes — dual-licensed MIT OR Apache-2.0 (see `LICENSE`). The Octra
chain itself is closed-source today; the OctraVPN program runs on
the public Octra runtime through the documented JSON-RPC surface
(see `docs/octra-research.md`).

## How is this formally verified?

| Layer | Tool | What's checked |
| --- | --- | --- |
| Protocol state machine | TLA+ (TLC) | 9 invariants + settle-or-refund liveness |
| Cryptographic protocol | Tamarin | Receipt unforgeability (1/3-hop), double-sign slashable, no-link-before-settle (1/2/3-hop) |
| Program semantics | Lean 4 | State + entrypoints + 6 lemmas including conservation |
| Rust implementation | Kani + proptest | Receipt round-trip, parser no-panic, monotonicity |

See `proofs/`.

## What ports do I need?

| Port | Protocol | Use |
| --- | --- | --- |
| 51820 | UDP | WireGuard data plane (node) |
| 51821 | TCP | HTTP control plane (node) |
| 443 | TCP (outbound) | Octra RPC |

## Can I use this behind NAT?

Clients: yes, no inbound needed.
Validators: only with port forwarding (UDP 51820 and TCP 51821 must
be reachable from the public internet for clients to discover and
connect).

## How do I report a vulnerability?

See `SECURITY.md`. **Don't** open a public GitHub issue.

## What's the difference between v1.1 and v2?

v1.1 is the public-registry flow: validators register endpoints on a
single global map, anyone can list them with `octravpn nodes`, and
clients open sessions against an address picked from that list. v2 is
the circle-native substrate: each operator is a **Circle** (Octra's
deterministic-id sub-environment), the operator's endpoint / WG pubkey
/ region / tariff are AES-GCM-sealed inside the circle under a
per-tailnet passphrase, and only tailnet members with that passphrase
can decrypt the row. The two paths live side by side in the same
binary and are selected by `[chain].protocol_version` in `client.toml`
(`"v1.1"` or `"v2"`). The v2 program is live on devnet at
`oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`. See
[`docs/v2-circles-design.md`](v2-circles-design.md) §0 for the live
status snapshot.

## Are operator identities really hidden in v2?

**Conditionally.** The sealed `/policy.json` keeps the endpoint URL,
WG pubkey, region, and tariff invisible to non-members. But the
`deploy_circle` and `register_circle` transactions are normal Octra
txs with `from = <deployer_wallet>` and `to_ = <circle_id>`; that
binding is permanent on chain, scrapable by octrascan, and re-stated
by every owner action (`bond_endpoint`, `update_circle`,
`finalize_unbond`, every slash). So the public can map
`circle_id ↔ deploy_wallet`. **Hidden-exit semantics only hold if the
deploy wallet is fresh, single-purpose, and never touches anything
else.** The full hygiene rules + funding patterns live at
[`docs/v2-operator-key-hygiene.md`](v2-operator-key-hygiene.md), and
the threat-model layer-by-layer analysis is in
[`docs/v2-threat-model.md`](v2-threat-model.md) §1B.

## Can a member be removed retroactively?

No. Removing a member (`remove_member`) blocks them from opening new
sessions in this tailnet immediately, but anything they cached locally
remains decryptable under the passphrase they already hold. The
operational fix is **rotate the sealed-policy passphrase**:
re-`circle_asset_put_encrypted` every authorized circle's
`/policy.json` under a new passphrase and distribute it only to the
remaining members. Live sessions are unaffected — pricing is stamped
at session-open time from the on-chain registry. See
[`docs/tailnet-user-guide.md`](tailnet-user-guide.md) §9.3.

## Why is the sealed passphrase per-tailnet, not per-member?

Trade-off. Per-tailnet keeps provisioning cheap (one new-member call
+ one out-of-band passphrase share) and keeps the sealed assets small
(one ciphertext per circle, not N). The cost is that any member can
defect — leaking the passphrase reveals every authorized operator in
the tailnet, and removing the leaker doesn't undo that. See
[`docs/v2-threat-model.md`](v2-threat-model.md) §P1-3. The roadmap
upgrade is **per-member encrypted wraps**: each member gets their own
AES key, the owner rotates by reissuing wraps and bumping
`policy_version`. That lands after v2 GA.

## Where's the roadmap?

`docs/gap-analysis.md` § Tier A–F is the prioritized backlog.
Future Tier A: transparent system-traffic capture via TUN, full
data-plane wiring, mobile clients. Future Tier C: better tutorials,
comparison docs.
