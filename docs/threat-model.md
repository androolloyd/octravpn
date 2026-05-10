# OctraVPN threat model

## Adversary capabilities

We model a Dolev-Yao adversary at the network layer plus selective
key compromise:

- **Network**: read every packet, drop, reorder, replay, inject; this
  includes off-chain channels (client↔node receipts) and on-chain RPC.
- **Static-key compromise**: the adversary can compromise an arbitrary
  set of validator long-term keys.
- **Session-key compromise**: the adversary can compromise an arbitrary
  set of client session ephemeral keys.
- **Mining majority**: out of scope. We assume Octra's validator set
  remains honest-majority for consensus and finality.

## Properties we maintain

| Goal                                         | Holds unless                                     |
| -------------------------------------------- | ------------------------------------------------ |
| No client funds disappear                    | Octra consensus is broken                        |
| No bond can be slashed beyond its value       | Octra consensus is broken                        |
| Receipts cannot be forged                    | the client's *session* key is compromised       |
| Double-signed receipts always slash          | the validator's wg key is compromised AND the chain runs the slash |
| Active session cannot be linked client↔exit  | the validator's long-term key is compromised AND the adversary is local to both endpoints |
| Settled-amount privacy                        | Octra HFHE soundness fails                       |
| Payout-recipient privacy                      | Octra stealth scheme fails                       |

## Properties we explicitly do NOT claim

- **Exit-node anonymity for destinations**: the exit hop sees the
  plaintext destination IP/host. Mitigations: TLS-only browsing,
  multi-hop diversity (entry hop can't see destinations), Tor-over-OctraVPN.
- **Side-channel resistance**: timing/length correlation between
  client→entry and exit→public is not addressed by v1. Pluggable
  transports (obfs4) are a v2 milestone.
- **Local OS privacy**: anything running on the client OS can read
  everything before the tunnel. Use full-system isolation if that's
  a concern.

## Why validators-only

Restricting VPN nodes to Octra validators:

1. Adds a real economic stake (bond) on top of any per-session escrow.
2. Lets us attribute on-chain misbehavior to a known validator key
   that's already accountable to the network.
3. Reduces Sybil risk: spinning up N fake VPN identities is gated by
   the cost of running N validators.

The tradeoff is centralization pressure: only validators can run nodes.
We accept this in v1 because the alternative (open registration) makes
slashing meaningless without strong KYC. A future relaxation (delegated
"VPN-only" sub-validators) is possible with a small extension to the
registry.
