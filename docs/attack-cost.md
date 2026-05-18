# OctraVPN — Attack-Cost Analysis

Concrete numbers, with parameters explicit so you can plug your own
values in. Covers both substrates: v1.1
(`oct2YehVLezCi2RCcSkURc3nyyYtzxmspwGHHALm6pjkUvJ`) and v2 slim
registry (`oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`). When a
row differs between substrates, both lines are shown.

For the cryptographic-threat costs (DLP, EUF-CMA breaks) see
`docs/security.md §4` and `docs/v2-threat-model.md §1`.

## Symbols

| Symbol | Meaning |
| --- | --- |
| `B_v1` | v1.1 `min_bond` (OCT per validator) |
| `B_v2` | v2 `register_circle` bond (≥ 1 OCT = 1_000_000_000 OU) |
| `D_v2` | v2 `deploy_circle` fixed gas (≈ 200_000 OU) |
| `D` | session deposit (OCT) |
| `P` | exit-hop `price_per_mb` (OU/MB) |
| `G` | `attest_grace_epochs` |
| `T` | `session_grace_epochs` |
| `K` | `sweep_grace_multiplier` (default 10) |
| `N` | total active validators / operators |
| `Bps_*` | bps splits for slashing (default 1000/5000/4000) |

## 1. Sybil attack: register N fake operators

**v1.1 cost**: `N × B_v1` OCT, locked.

**v2 cost**: `N × (D_v2 + B_v2) = N × (200_000 OU + 1 OCT)` per
circle. The `deploy_circle` gas is non-refundable; the
`register_circle` bond is refundable on `finalize_unbond` after the
grace period and only if not slashed.

Each fake operator:
- Earns nothing if no traffic chooses it (price competition).
- Loses bond on any slashable event.
- Must continually attest (signed-tx every `G` epochs), so private
  keys are required and fees are paid.

Per-block fee for attestation × `G` epochs × `N` operators ⇒ **ongoing
operational cost** even with no slash.

**Mitigation level**: high. v2 explicitly priced — 100 fake operators
in a region cost the attacker `100 × (200_000 OU + 1 OCT) ≈ 100 OCT
locked + 20_000_000 OU burned`. They earn nothing unless their
prices undercut everyone, which they can't sustain since operating
cost is real (devnet IP + bandwidth + attestation gas).

## 2. Grief one specific client (no-show)

Same shape both substrates. Client opens a session with deposit `D`;
attacker's entry hop disappears.

- **Client side**: `claim_no_show` after `T` epochs refunds `D` via
  stealth.
- **Slash side**: `slash_no_show_with_open` reveals the entry hop;
  slash = `min(D/10, B/10)`.

**Attacker cost per griefed session**:
- Best case (small deposits): `D/10` OCT lost.
- Worst case: `B/10` OCT lost (capped at 10% of bond regardless of D).
- Plus: operator is jailed if bond falls below the floor.

**Time cost to victim**: `T` epochs + 1 tx for refund.

**Defense net**: after 10 grieves the bond is fully gone.

## 3. Double-sign one operator's receipts (`slash_double_sign`)

`main-v2.aml:382-418` (and `main-v1.aml` equivalent). Two distinct
receipt payloads at the same `(session_id, seq)` signed by the same
`receipt_pubkey`.

> **Note on signature encoding.** The Octra `ed25519_ok` host call
> accepts **base64-encoded** pubkey + sig (not hex). This is the
> contract verified twice on mainnet under commits demonstrating
> successful slash; see `memory/octra_aml_wire_format.md`. A
> would-be slasher who hex-encodes their evidence will be silently
> rejected by `ed25519_ok` and the slash will fail.

**Cost to attacker**: full `B` (entire bond zeroed, jail).

**Bounty to slasher**: `B × Bps_bounty / 10000` (10% by default =
`0.1 B`).

**Replay defense (P1-5)**: receipts now bind
`(program_addr, chain_id, circle_id)` (commit `060903d`). A receipt
minted under v1.1 cannot be replayed against v2; a devnet receipt
cannot be replayed against mainnet; a circle-X receipt cannot be
replayed against circle Y.

**Restart-replay defense (P1-8/P1-9, commit `dfc016e`)**: the
persistent fsync'd receipt journal means an operator who is forced
to restart mid-session (OOM, signal, container kill) cannot
inadvertently produce a "second signature at the same seq" that
slashes them. Floor is read from disk before any new signature.

There is no reasonable scenario where an operator profits from
double-signing — the doubled-signed bytes value would have to exceed
`B` in net revenue to break even, which would require absurd
bandwidth volumes.

## 4. Metering fraud via `settle_confirm` dispute path

Operator submits `settle_claim(sid, bytes_used_inflated)`; honest
client submits `settle_confirm(sid, bytes_used_actual)`.

- **Match** → settle.
- **Mismatch** → public `SettleDispute` event; session stays open.

**v2 cost to operator who attempts inflation**: if they then submit
a *second* `settle_claim` with a *different* `bytes_used`, that is
equivocation and auto-slashes via the in-AML path
(`main-v2.aml settle_claim`). 90% to treasury, 10% bounty, deposit
refunded.

**Equivocating settle-claim auto-slashes** — the v2 drill's E-class
cases assert deposit ≥ payout invariant; commit `beae338` cites 45/45
hold.

**Attacker cost per fraud attempt**: full `B` if caught (essentially
always — the client has the dual-signed receipts they signed off-chain
as evidence).

## 5. Tailnet member impersonation

Two paths.

### 5.a Steal the shared sealed-policy passphrase

The passphrase derives the AES-256-GCM key for `/policy.json`
(`circle.rs:256-261`, salt = `octra:circle:sealed_read:v1: + circle_id
+ : + key_id`). With the passphrase the attacker decrypts the policy
(endpoint, wg_pubkey, region, prices) but **cannot mint a valid
member receipt** without a member's ed25519 receipt-pubkey private
key — the policy alone is read-only.

**Cost to obtain**: depends on how the passphrase is distributed OOB:
- Sealed-passphrase-on-disk (operator host compromise): full host
  pwn — same exposure as Tree C.1.a.
- `OCTRAVPN_KEY_PASSPHRASE` env var (P1-10 fix means the heap copy
  is zeroized on drop; commit `2d933fc`): a co-located process or
  core dump *during* startup; harder than file read.
- OOB social-engineering of a tailnet member: classic phishing cost.

**Defection fragility**: today one leaked passphrase = full tailnet
policy. There is no per-member revocation. The v2.2 milestone
(`docs/security-roadmap.md §2.6`) replaces this with a per-member
encrypted wrap; until then, rotate on any suspected leak.

### 5.b Steal a member's receipt-pubkey private key

Lets the attacker mint signed member acceptance payloads + receipts
*as that member*. Same exposure as 5.a's host-compromise path: the
receipt-pubkey lives next to the wallet key on disk (sealed under
P1-6 if the operator opted in via `[chain].require_sealed_keys =
true`; plaintext otherwise).

**Cost**: full host compromise of one tailnet member.

## 6. The chain-side AES-KAT gate on PVAC pubkeys

**New row.** The chain runs an AES known-answer-test on every
`fhe_load_pk` registration: it derives an AES-256 key from the
candidate pubkey via a domain-tagged hash, encrypts a fixed plaintext,
and compares against an expected ciphertext baked into the runtime.
Pubkeys not produced by the chain-compatible PVAC fork fail this KAT
and are **rejected before signature verification**.

**Implication.** An attacker who fabricates a syntactically-valid
PVAC pubkey (random 4 MB blob with the right header) cannot register
it. They must run the actual fork code to derive a passing pubkey,
which is GPL-isolated and runs only inside the PVAC sidecar (commit
`9e16868`).

**Cost to bypass**: a porting effort — implement the AES KAT compatibly
in non-fork code. Demonstrated infeasible *retroactively* on mainnet:
dummy pubkey rejects, sidecar pubkey accepts. Both transactions are
on mainnet under the registration test path.

This is not a slash — it is a *registration* gate. But it bounds the
ecosystem of pubkeys that can mint encrypted byte counters.

## 7. Deanonymize a 1-hop session (in flight)

For an open session with route_commit `[c]`:

- Adversary sees `c = sha512(addr || blind || H_point) + ...`
  (Pedersen).
- Inverting Pedersen to recover `addr` requires breaking DLP on
  Curve25519 (≈ 2¹²⁸ work).

**Cost**: ≈ 2¹²⁸ classical work, *or* compromise both the operator
hardware and the client process simultaneously.

## 8. Deanonymize a 3-hop session (in flight)

For `route_commit = [c1, c2, c3]`:

- Each commitment is independently hiding (Tamarin
  `NoLinkBeforeSettle_3Hop`).
- Onion layers ensure no single hop knows both predecessor and
  successor.
- To link client→destination, the adversary must control or observe
  *all three* hops simultaneously.

**Cost**: ≈ 3 × per-hop compromise cost. With diverse-region routing,
correlation attacks across at least 3 jurisdictions.

**Caveat**: the v2 chain-side leak `from=deployer → to_=circle_id`
binding (`docs/v2-threat-model.md §1B`) means an observer of the
public chain *trivially* learns who deployed each circle. This does
not link a *session* to a wallet, but it does link an *operator* to
their wallet unless the operator follows
`docs/v2-operator-key-hygiene.md` (fresh, history-free wallet).

## 9. Steal accumulated earnings

Validator's earnings ledger `E_v` is a Pedersen point. To claim,
produce `(claimed_amount, claimed_blind)` such that
`E_v == claimed_amount * G + claimed_blind * H`.

To steal `V`'s earnings, an attacker needs either:
- The validator's accumulator file (local to the validator's machine;
  sealed under P1-6 in strict mode).
- An algorithm finding an opening to a different value (DLP).

**Cost**: full system compromise of the validator's host *or*
≈ 2¹²⁸ work.

## 10. Stuck-channel grief

Malicious entry hop deliberately stalls; client's deposit is locked.

**Bound on lockup**: `T + K × T` epochs (default `100 + 10×100 = 1100`
epochs ≈ a few hours).

After that, anyone calls `sweep_expired_session` for 1% bounty; the
rest refunds to the client.

- **Worst case for client**: 1% of deposit lost, ~hours of capital
  locked.
- **Worst case for malicious entry**: `slash_no_show_with_open` on
  top, costing `min(D/10, B/10)` per griefed session.

## 11. Replay attack across chains/forks

**v2 status**: receipts bind `chain_id` (P1-5, commit `060903d`).
`CHAIN_ID_DEVNET = 0x6F637464` / `CHAIN_ID_MAINNET = …` etc. A signed
receipt from devnet cannot replay against mainnet.

**Defense**: today Octra's canonical tx bytes match
`octra-labs/webcli` and the per-program nonce check prevents
in-chain replay. The new `chain_id` field in `ReceiptContext` extends
this to cross-chain.

**Cost to attacker**: must break ed25519 EUF-CMA.

## 12. Lock the program into permanent paused state

`set_paused(1)` is owner-only. If the owner key is compromised:

- Already-open sessions can still settle on v1.1
  (`docs/octra_v1_pause_bypass.md` — pause halts USER flows only).
- Governance bypasses pause: `withdraw`, `set_params`,
  `finalize_unbond` all proceed.
- `claim_no_show` and `sweep_expired_session` are permissionless.

**Funds are not stuck.** Worst case is a pause until the owner key
is recovered or governance acts (multi-sig / DAO; see
`docs/governance.md`).

## 13. Cost summary table

| Attack | Cost | Detection | Slash |
| --- | --- | --- | --- |
| Run 1 v1.1 Sybil | `B_v1` locked | passive | 0 if honest |
| Run 1 v2 Sybil | `D_v2 + B_v2` (200k OU + 1 OCT) | passive | 0 if honest |
| Run 100 v2 Sybils | 100 × `(D_v2 + B_v2)` | passive | 0 |
| Grief one session | small fee + opportunity cost | claim_no_show after `T` | up to `B/10` |
| Double-sign once | full `B` (P1-5/8/9 close replay vectors) | anyone w/ 2 receipts (base64) | full `B` |
| Metering fraud (settle_confirm dispute) | full `B` if second claim differs | client w/ dual-signed receipt | full `B` |
| Tailnet member impersonation (via passphrase) | OOB phish OR host compromise | post-facto only | n/a |
| Tailnet member impersonation (via receipt pubkey leak) | full host compromise | post-facto only | n/a |
| Register a non-fork PVAC pubkey | AES-KAT port effort (infeasible empirically) | tx reverts at chain runtime | n/a (registration gate, not a slash) |
| 1-hop deanon | ~2¹²⁸ work | — | n/a |
| 3-hop deanon | 3× hop compromise | — | n/a |
| Steal earnings | full host compromise | — | n/a |
| Replay across chains | break ed25519 (chain_id bound in P1-5) | — | n/a |
| Lock-up via paused | owner key compromise | governance | revoke ownership |

The bond-staked, single-asset design gives a clean answer to every
"what does it cost?" question: usually `B`, sometimes `B/10`, never
"$0 with profit". The new P1-5 / P1-8 / P1-9 fixes raise the cost
floor for the receipt-replay and restart-replay corner cases from
"$0 with luck" to "full B if caught, infeasible to engineer".
