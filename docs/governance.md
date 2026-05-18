# OctraVPN — Governance

## 1. Roles

| Role | Capabilities | Today | Target |
| --- | --- | --- | --- |
| Owner | `set_params`, `set_paused`, `transfer_ownership` | single keypair | OCT-staked DAO contract |
| Validator | register, attest, update price, rotate keys, request/complete unbond | each validator | unchanged |
| Client | open session, settle, reclaim | each client | unchanged |
| Slasher | submit slashing evidence (permissionless) | anyone | unchanged |
| Sweeper | call `sweep_expired_session` (permissionless) | anyone | unchanged |

The owner role is **the only privileged role**. Everything else is
permissionless.

## 2. Parameters

`set_params(p: Params)` validates `slash_*_bps` sum = 10000 and that
each numeric param > 0. The Param struct has nine fields:

| Param | Default (illustrative) | Use |
| --- | --- | --- |
| `min_bond` | TBD by Octra validator-stake equivalence | barrier-to-entry; max single-event slash |
| `min_session_deposit` | 0.01 OCT | spam control on session-open |
| `attest_grace_epochs` | 5 | how often validators must refresh attestation |
| `session_grace_epochs` | 100 | how long until `claim_no_show` |
| `unbond_epochs` | configurable | unbond delay |
| `sweep_grace_multiplier` | 10 | `K × session_grace` until `sweep_expired_session` |
| `slash_bounty_bps` | 1000 | 10% to slasher |
| `slash_burn_bps` | 5000 | 50% burned |
| `slash_treasury_bps` | 4000 | 40% to treasury |

**Constraint**: `slash_bounty_bps + slash_burn_bps + slash_treasury_bps
== 10000`. Enforced both in the constructor and in `set_params`.

## 3. Treasury

The treasury accumulates 40% of all slashes. Today it is a counter
inside program state with **no withdrawal entrypoint**. This is
deliberate: until governance is wired up, the treasury is provably
immobile.

Adding withdrawal requires a parameter change (a new Params field
+ entrypoint), so the same governance flow that sets parameters is
the one that mobilizes treasury. The two cannot be unbundled by
accident.

## 4. Path to decentralization

### 4.1 Stage 0 (today)

Owner is a single keypair held by the project. The project is
publicly accountable; ownership transfer is logged on chain.

### 4.2 Stage 1: multisig

Transfer ownership to a multisig program (separate Octra program
with k-of-n threshold over OCT validator addresses). All
`set_params`, `set_paused`, `transfer_ownership` calls must collect
k signatures.

### 4.3 Stage 2: OCT-stake-weighted DAO

Transfer ownership to a DAO program. Voting power is **OCT-staked
into a separate vote contract**, with quadratic or linear weighting.
Proposals execute `set_params` on OctraVPN if quorum + threshold are
met.

This avoids introducing any second token: voting power is tied to
the same asset that secures the network. A holder who controls 10%
of OCT stake controls 10% of governance, and 10% of the slashing
exposure if they're also a validator.

### 4.4 Why no governance token

A separate "veOCTRAVPN" or similar would:

- Decouple governance from skin-in-the-game (token holder may not be
  a user or validator).
- Require its own market and price discovery.
- Add a bridge (governance token ⇄ OCT) for liquid governance.
- Create the possibility of governance attacks via cheap
  market-bought governance tokens.

OCT-stake-weighted governance keeps everything denominated in the
same asset, with the same security assumptions, and no extra
machinery.

## 5. Emergency response

Today: `set_paused(1)` halts new sessions. Already-open sessions can
still settle/refund. Funds are never stuck behind pause because
`claim_no_show`, `sweep_expired_session`, and `complete_unbond` do
not check `paused`.

**Owner-only governance ops intentionally bypass pause.** This
includes `set_params`, `set_paused` itself, `transfer_ownership`,
and (in v2) `withdraw_program_treasury`. The reasoning:

1. A compromised owner can always call `set_paused(0)` to unpause
   themselves first, so gating governance on pause adds no defense.
2. Emergency response (migrations, treasury rescue, ownership
   transfer to a multisig under attack) MUST work while paused.
3. `transfer_ownership` in particular needs to be callable under
   pause — this is the "hand off the keys before they leak further"
   escape hatch.

v1.1 briefly experimented with gating governance on pause; reverted
because of (1) and (2). Tracked as P0-3-adjacent in
`security-roadmap.md`. The pause flag therefore halts **user flows
only** (`open_session`, `register_endpoint`, etc.) and never the
small set of owner-only emergency entrypoints.

Once Stage 1 is reached (multisig), pause becomes a quick-acting tool
for any k-of-n signers; once Stage 2 is reached, an emergency
multisig can be retained as a delegated subset of the DAO with
strict scope (only `set_paused(1)`, never `transfer_ownership`,
never funds movement).

## 6. Upgrade path

The AML program is not directly upgradeable; deploying a new version
means:

1. Deploy `OctraVPN-v2` as a separate program at a new address.
2. Owner pauses v1 (`set_paused(1)` on v1).
3. Owner runs a migration tool: snapshots v1 state, ports validator
   records, sessions, earnings, and treasury into v2 via v2's `init`
   entrypoints (signed by the v1 owner).
4. Owner unpauses v2 and announces deprecation of v1.
5. Validators rotate keys via `rotate_keys` on v2.
6. Treasury is moved by a custom migration entrypoint signed by v1
   owner that locks v1 treasury and credits the same to v2.

The `rotate_keys` entrypoint exists explicitly to make migrations
non-destructive — a validator's bond stays bonded, only the keys
referenced by the registry change.

## 7. Open governance questions

- **Treasury withdrawal policy**: should withdrawals fund grants /
  bug bounty / liquidity provision? Determined by governance.
- **`min_bond` calibration**: aligned to Octra's own minimum
  validator stake? Higher? Lower? Octra's validator economics inform
  this — see `octra-research.md` once the research agent reports.
- **Cross-program interaction**: should OctraVPN integrate with
  other Octra programs (DEXes, lending) for richer use cases? Each
  integration is a governance proposal.
- **Region pricing floors**: should the program enforce a minimum
  price per region to prevent dumping attacks? Currently no; the
  market clears bilaterally.
