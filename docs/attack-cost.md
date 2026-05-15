# OctraVPN — Attack-Cost Analysis

Concrete numbers, with the parameters explicit so you can plug your
own values in.

## Symbols

| Symbol | Meaning |
| --- | --- |
| `B` | `min_bond` (OCT per validator) |
| `D` | session deposit (OCT) |
| `P` | exit-hop `price_per_mb` (OU/MB) |
| `G` | `attest_grace_epochs` |
| `T` | `session_grace_epochs` |
| `K` | `sweep_grace_multiplier` (default 10) |
| `N` | total active validators |
| `Bps_*` | bps splits for slashing (default 1000/5000/4000) |

## 1. Sybil attack: register N fake VPN nodes

**Cost**: `N × B` OCT, locked.

The attacker locks N × `min_bond`. Each fake node:
- Earns nothing if no traffic chooses it (price competition).
- Loses bond on any slashable event.
- Must continually attest (signed-tx every G epochs), so private keys
  are required and fees are paid.

Per-block fee for attestation × G epochs × N nodes ⇒ **ongoing
operational cost** even with no slash.

**Mitigation level**: high. To dominate a region with 100 fake nodes
at `B = 1000` OCT, attacker locks 100,000 OCT — and earns nothing
unless their prices undercut everyone, which they can't sustain since
operating cost is real.

## 2. Grief one specific client (no-show)

The client opens a session with deposit `D`. The attacker's entry hop
either disappears or refuses to forward.

**Client side**: client calls `claim_no_show` after `T` epochs and
gets the full `D` refunded via stealth.

**Slash side**: client *optionally* calls `slash_no_show_with_open`,
revealing the entry hop. The slash is `min(D/10, B/10)`.

**Attacker cost** per griefed session:
- Best case (small deposits): `D/10` OCT lost.
- Worst case (large deposits): `B/10` OCT lost (capped at 10% of
  min_bond regardless of D).
- Plus: validator is jailed if bond falls below `min_bond`.

**Time cost to victim**: T epochs (the grace window) + 1 tx for refund.

**Defense net**: a bad entry hop loses 10% of bond per griefed session
and gets jailed. After 10 grieves, bond is fully gone.

## 3. Double-sign one validator's receipts

Two distinct receipts at the same `(session_id, seq)` signed by the
same validator's `receipt_pubkey`.

**Cost to attacker**: full `B` (entire bond zeroed, jail).

**Bounty to slasher**: `B × Bps_bounty / 10000` (10% by default = `0.1
B`).

The attack is *extremely* cheap to detect: anyone with two receipts
matching the predicate has slash-the-double-signer evidence. There is
no reasonable scenario where a validator profits from double-signing —
the doubled-signed bytes value would have to exceed `B` in net
revenue to break even, which would require absurd bandwidth volumes
that any honest validator could process for the same fee.

## 4. Deanonymize a 1-hop session (in flight)

For an open session with route_commit `[c]`:

- Adversary sees `c = sha512(addr || blind || H_point) + ...` (Pedersen).
- Inverting Pedersen to recover `addr` requires breaking DLP on
  Curve25519 (≈ 2¹²⁸ work).
- Or: compromising the validator's long-term key (which doesn't
  reveal `c`'s opening directly — `blind` is only known to the client).

**Cost**: ≈ 2¹²⁸ classical work, *or* compromise both the validator
hardware and the client process simultaneously.

## 5. Deanonymize a 3-hop session (in flight)

For `route_commit = [c1, c2, c3]`:

- Each commitment is independently hiding (Tamarin
  `NoLinkBeforeSettle_3Hop`).
- Onion layers ensure no single hop knows both predecessor and
  successor — entry hop knows the client IP, exit hop knows the
  destination, no one node sees both.
- To link client→destination, the adversary must control or observe
  *all three* hops simultaneously.

**Cost**: ≈ 3 × per-hop compromise cost. With diverse-region routing,
this requires correlation attacks across at least 3 jurisdictions.

## 6. Force-close (DoS) the chain layer

Octra-level concerns (consensus fork, reorg, validator collusion) are
out of scope here — see Octra's own validator docs. OctraVPN inherits
whatever guarantees Octra provides.

What OctraVPN *adds*: even if a chain reorg replays a `settle_session`,
the chain-id binding in the canonical signing form prevents replay
across chains/forks, and the program's `seq` monotonicity prevents
double-credit on the same session within one chain.

## 7. Lock the program into permanent paused state

`set_paused(1)` is owner-only. If the owner key is compromised or
malicious, sessions can't be opened, but:

- Already-open sessions can still settle (settlement guards on
  `paused == 0`, but `claim_no_show` and `sweep_expired_session` do
  not — sweep is permissionless).
- Validators can still `complete_unbond` (no `paused` check).
- Funds are not stuck.

**Mitigation**: ownership is transferable; once a DAO-style governance
contract is wired in (see `governance.md`), pause becomes a
multi-party action.

## 8. Steal accumulated earnings

A validator's earnings ledger `E_v` is a Pedersen point. To claim,
they must produce `(claimed_amount, claimed_blind)` such that
`E_v == claimed_amount * G + claimed_blind * H`.

To steal `V`'s earnings, an attacker would need either:
- The validator's accumulator file (the off-chain `(amount, blind_sum)`
  state). This is local to the validator's machine.
- Or an algorithm to find an opening to a different value, which
  reduces to DLP on Curve25519.

**Cost**: full system compromise of the validator's host *or* ≈ 2¹²⁸
work.

## 9. Stuck-channel grief

A malicious entry hop deliberately stalls. Client's deposit is locked
in escrow.

**Bound on lockup**: `T + K × T` epochs total (default
`100 + 10×100 = 1100` epochs ≈ a few hours at typical block times).

After that, anyone can call `sweep_expired_session` and get a 1%
bounty; the rest refunds to the client.

**Worst case for client**: 1% of deposit lost, ~hours of capital
locked.

**Worst case for malicious entry**: `slash_no_show_with_open` on top
of the sweep, costing them `min(D/10, B/10)` per griefed session.

## 10. Replay attack across chains/forks

Without chain-id binding, a signature for OctraVPN on chain X could be
replayed on chain Y if the chains share a program address scheme.

**Defense**: today Octra has a single chain and the canonical bytes are
exactly `canonical_json(tx).as_bytes()` (no domain or chain id), matching
the reference wallet (`octra-labs/webcli`). When Octra grows multiple
chains the canonical layout will gain a chain id field; for now replay
between chains is moot because there is one chain. Per-program replay
within a chain is prevented by the program's nonce checks.

**Cost to attacker**: must break ed25519 EUF-CMA.

## 11. Cost summary table

| Attack | Cost | Detection | Slash |
| --- | --- | --- | --- |
| Run 1 Sybil node | B (locked) | passive | 0 if honest |
| Run 100 Sybils | 100 × B | passive | 0 |
| Grief one session | small fee + opportunity cost | claim_no_show after T | up to B/10 |
| Double-sign once | full B | anyone w/ 2 receipts | full B |
| 1-hop deanon | ~2¹²⁸ work | — | n/a |
| 3-hop deanon | 3× hop compromise | — | n/a |
| Steal earnings | full host compromise | — | n/a (off-chain theft) |
| Replay across chains | break ed25519 | — | n/a |
| Lock-up via paused | owner key compromise | governance | revoke ownership |

The bond-staked, single-asset design gives a clean answer to every
"what does it cost?" question: usually `B`, sometimes `B/10`, never
"$0 with profit".
