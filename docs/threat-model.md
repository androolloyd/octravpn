# OctraVPN threat model (v1 archive)

> **Status: ARCHIVE.** This is the v1 threat model. For the current
> live substrate's threat surface, see
> [`docs/v2-threat-model.md`](v2-threat-model.md) (canonical, current
> state). For the high-level overview, see
> [`docs/security.md`](security.md).
>
> The text below is preserved for historical reasoning. Items closed
> by the v2 work are struck through and annotated; items that carry
> over are flagged with the v2-threat-model section they now live
> under.

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

The v2 threat model extends this with an explicit observer/asset
matrix that names: passive on-path, active MITM, the Octra RPC
operator (`devnet.octrascan.io`), malicious operator, malicious
tailnet member, malicious tailnet owner, and a future quantum
adversary. See `docs/v2-threat-model.md §1`.

## Properties we maintain

| Goal | Holds unless | v2 status |
| --- | --- | --- |
| No client funds disappear | Octra consensus is broken | unchanged |
| No bond can be slashed beyond its value | Octra consensus is broken | unchanged |
| Receipts cannot be forged | the client's *session* key is compromised | strengthened — receipt now binds `program_addr / chain_id / circle_id` (P1-5, commit `060903d`); cross-program / cross-chain / cross-circle replay rejected at sig verify |
| Double-signed receipts always slash | the validator's WG key is compromised AND the chain runs the slash | strengthened — receipt journal (P1-8/P1-9, commit `dfc016e`) means restart can no longer re-sign at the same `(session_id, seq)` |
| Active session cannot be linked client↔exit | the validator's long-term key is compromised AND the adversary is local to both endpoints | partially eroded — chain-side `from=deployer → to_=circle_id` binding is permanent; mitigated only by operator-side fresh-wallet hygiene (`docs/v2-operator-key-hygiene.md`) |
| Settled-amount privacy | Octra HFHE soundness fails | partially — HFHE settle is wired and PVAC pubkey registration confirms on devnet (body cap raised 2026-05-18); chain-side AML `fhe_load_pk` still reverts for our contracts (see `octra-dev-questions.md §1`) |
| Payout-recipient privacy | Octra stealth scheme fails | unchanged |

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

## Why validators-only (v1 reasoning)

> Carried over to v2 with one structural change: in v2 the operator
> role lives in a per-circle `operator-circle.aml` program plus a
> `register_circle` entry on `main-v2.aml`. The validator-as-operator
> hybrid (`octra_isValidator` AML host call) is still an Octra-team
> ask — see `docs/security-roadmap.md §0.7`.

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

## v1 → v2 finding carryover

These v1 concerns are now tracked under the unified
`docs/v2-threat-model.md §3` fix queue. Status as of commit `dfc016e`:

| v1 concern | Closed in v2 | Tracked as |
| --- | --- | --- |
| ~~Plaintext `/events` SSE leaks per-session metadata~~ | yes (commit `f4f5e65`) | P0-1 |
| ~~RPC client has no cert pinning~~ | yes (commit `2d933fc`); operator-side enablement still on operators | P0-2 |
| ~~`meter_bytes` auth had an always-false `ed25519_ok` branch falling through to caller-check~~ | yes (commit `b9aedf7`) | P0-3 |
| ~~Receipt replay across program / chain / circle~~ | yes (commit `060903d`) | P1-5 |
| Onion AEAD uses constant zero nonce (safe today by fresh-key-per-call, fragile to refactor) | open | P1-2 |
| Operator wallet ↔ circle binding leaks via `deploy_circle` from/to | doc-only mitigation; chain layer accepts this | P1-3 (see `docs/v2-operator-key-hygiene.md`) |
| Low-entropy sealed-policy passphrase | open | P1-4 |
| ~~Plaintext on-disk wallet / WG keys~~ | yes (commit `dfc016e`); opt-in `seal-keys` subcommand + strict mode | P1-6 |
| WG static key never rotates | open | P1-7 |
| ~~Restart resets in-memory `last_seq=0` allowing receipt replay~~ | yes (commit `dfc016e`); persistent fsync'd journal | P1-8 / P1-9 |
| ~~Sealed-passphrase config string not zeroized on drop~~ | yes (commit `2d933fc`); `Zeroizing<String>` | P1-10 |
| PBKDF2-SHA256-120k brittle to GPU brute force on weak passphrases | open | P2-11 |
| Onion `MAX_HOPS = 3` packet-size fingerprint | open | P2-12 |
| 120s peer-snapshot replay window | open | P2-13 |
| Unauthenticated `/metrics` endpoint | open | P2-14 |
| Pedersen earnings claim reveals amount at claim time | open until PVAC range-proof | P2-15 |
| Canonical-JSON tx writer lacks Unicode normalisation | open | P3-16 |
| Doc/code drift: HFHE claim vs plaintext counter in `operator-circle.aml` | doc fix in progress | P3-17 |
| `peek_initiator_pubkey` name says static, reads ephemeral | open (latent) | P3-18 |

## Verification harness (v1 → v2)

The v1 model was checked by:
- Tamarin: `ReceiptUnforgeability`, `DoubleSignSlashable`,
  `NoLinkBeforeSettle*`.
- TLA+: `ConservationOfFunds`, `NoDoubleSettle`, `SlashLeBond`,
  `MonotonicSeq`, `Liveness_SettleOrRefund`.
- Lean: `completeUnbond_returns_full_bond`, `slash_split_conservation`,
  `settle_advances_seq`.
- Kani + libfuzzer: receipt / onion parser no-panic.
- 49-case adversarial drill (`docker/devnet/e2e-adversarial-v1.sh`).

The v2 model extends with:
- Lean 4 v2 module: 50 new theorems over the circle-keyed registry.
- TLC: 17 invariants, 3.8 M distinct states, 0 violations.
- 30 Rust proptest harnesses covering crypto, tx canonicalisation,
  `wallet_enc`, and the new receipt domain binders.
- 45-case v2 adversarial drill (`docker/devnet/e2e-adversarial-v2.sh`),
  commit `beae338`.
- PVAC sidecar past the chain's AES-KAT pubkey gate on mainnet
  (commit `9e16868`).

See `docs/security.md §2` for the consolidated five-layer view.

## Out of scope (carried unchanged into v2)

- Octra-consensus-layer attacks (51% of stake, fork attacks).
- Side channels on operator hardware.
- Global-passive-adversary traffic analysis.
- Quantum break of Curve25519 retroactively (multi-year roadmap item;
  see `docs/security-roadmap.md §1.5`).
- A compromised Octra RPC operator beyond what cert pinning prevents
  (mitigation: run your own node once the protocol allows).
