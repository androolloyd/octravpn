/-!
# State of the OctraVPN v3 program — Lean 4 model.

Mirrors the chain-minimal state shape declared in
`program/main-v3.aml` (deployed on devnet 2026-05-18).

## v3 design thesis (recap)

The v3 program is the "circle-resident" architecture: the chain
keeps only bonds + slash, session escrow, tailnet treasury, the
program treasury, governance params, and 32-byte sha256
commitments pointing at each role's circle-resident state. ACL
policy, member lists, receipts, and class/price logic all live
off-chain inside the operator/tailnet circles (Octra IEEs); the
chain merely commits to their canonical roots.

Major v3 deltas vs v2 modelled here:

  - No `circles` struct: circle metadata is split across five
    parallel maps (`circle_owner`, `circle_receipt_pk`,
    `circle_state_root`, `circle_state_version`, `circle_active`).
    This mirrors `main-v3.aml:84-90`.

  - No on-chain ACL / member list / class pricing. Tailnets keep
    only `(owner, treasury, members_root, root_version, retired)`.
    `members_root` is the sha256 of the off-chain `members.json`
    sealed in the tailnet-owner's circle.

  - Sessions are class- and price-agnostic on chain. The chain
    sees only `(bytes_used, net)` from a two-tx settle protocol.
    `class` and `price` live in the operator's signed off-chain
    receipt.

  - Earnings are tracked in two parallel fields: a plaintext
    `circle_earnings_total` running total AND a sha256 hash-chain
    `circle_earnings_chain` for off-chain audit. `claim_earnings`
    debits a separate `circle_earnings_claimed` counter so total
    monotonically increases per settle.

  - Constructor / `set_params` minimum: `min_circle_stake ≥ 1e8`,
    `unbond_grace_epochs ≥ 1000`, `slash_burn_bps ≥ 5000`,
    `slash_burn_bps + slash_bounty_bps = BPS_DENOM`,
    `protocol_fee_bps ≤ 200` (`main-v3.aml:148-173, 244-246`).

  - Pause halts USER flows only; governance (`transfer_ownership`,
    `set_paused`, `set_params`, `withdraw_program_treasury`,
    `gov_slash_operator`) intentionally bypasses pause. Matches
    v1.1 / v2 semantics.

## PROOF GAPS (carried in `AmlLink.lean`)

  - `payable` / `nonreentrant` runtime modifiers (`finalize_unbond`,
    `settle_confirm`, `sweep_expired_session`, `claim_earnings`,
    `withdraw_tailnet_treasury`).
  - `ed25519_ok` signature verification (encoded as a `verified`
    flag at the Lean boundary, matching v2's approach).
  - `sha256` collision-resistance (axiom).
  - `CircleId` opacity vs `sha256+base58` derivation.
  - HFHE is NOT modeled in v3: v3 ships the hash-chain era;
    HFHE swap is forward-compatible but out of v3 scope.
-/

namespace OctraVPN_V3

abbrev Addr := Nat
abbrev Bytes := List UInt8
abbrev Epoch := Nat
abbrev OctRaw := Nat
abbrev TailnetId := Nat
abbrev SessionId := Nat

/-- Opaque circle identifier. Off-chain: 47-char `oct…` derived
    from sha256+base58. Modelled as `Nat`; we never inspect bytes. -/
abbrev CircleId := Nat

/-- v3 session status mirrors `SESSION_OPEN/SETTLED/REFUNDED`
    constants at `main-v3.aml:42-44`. v3.2 (C-1 fix) adds
    `disputed` for the post-`settle_confirm`-mismatch waiting
    state — see `main-v3-c1-fix.aml:89` (`SESSION_DISPUTED = 3`). -/
inductive SessionStatus where
  | open      : SessionStatus
  | settled   : SessionStatus
  | refunded  : SessionStatus
  | disputed  : SessionStatus
  deriving Repr, DecidableEq

/-- In-flight unbonding record. v3 stores this across two parallel
    maps (`circle_unbonding`, `circle_unbond_unlock_epoch`); we
    bundle them for ergonomics. -/
structure Unbonding where
  stake       : OctRaw
  unlockEpoch : Epoch
  deriving Repr

def Unbonding.empty : Unbonding := { stake := 0, unlockEpoch := 0 }

/-- v3 session record. No `class_` / `pricePerMb` (v3 is
    class-agnostic on chain). The two-tx settle leaves
    `(operatorClaim, clientConfirm)` as bytes pairs. -/
structure Session where
  tailnetId      : TailnetId
  circle         : CircleId
  opener         : Addr
  deposit        : OctRaw
  openedAt       : Epoch
  status         : SessionStatus
  /-- `operator_claim_set = 1` ⇔ `some bytes`. -/
  operatorClaim  : Option Nat
  /-- `client_confirm_set = 1` ⇔ `some bytes`. -/
  clientConfirm  : Option Nat
  deriving Repr

/-- v3 tailnet record. ACL is entirely off-chain: the chain holds
    only the merkle root commitment. -/
structure Tailnet where
  owner         : Addr
  treasury      : OctRaw
  membersRoot   : Bytes
  rootVersion   : Nat
  retired       : Bool
  deriving Repr

def Tailnet.empty : Tailnet :=
  { owner := 0, treasury := 0, membersRoot := [], rootVersion := 0, retired := false }

abbrev Map (α : Type) (β : Type) := α → β

def Map.update {α} {β} [DecidableEq α]
    (m : Map α β) (k : α) (v : β) : Map α β :=
  fun x => if x = k then v else m x

/-- Governance params. Matches the AML constructor / `set_params`
    arguments at `main-v3.aml:148-173, 235-258`. -/
structure Params where
  minSessionDeposit    : OctRaw
  minTailnetDeposit    : OctRaw
  minCircleStake       : OctRaw
  sessionGraceEpochs   : Nat
  unbondGraceEpochs    : Nat
  sweepGraceMultiplier : Nat
  sweepBountyBps       : Nat
  slashBurnBps         : Nat
  slashBountyBps       : Nat
  protocolFeeBps       : Nat
  /-- v3.2: dispute grace window (epochs). `main-v3-c1-fix.aml:206`. -/
  disputeGraceEpochs   : Nat
  deriving Repr

/-- v3 `bps` denominator (`BPS_DENOM = 10000` at `main-v3.aml:35`). -/
def BPS_DENOM : Nat := 10000

/-- Top-level program state. Mirrors `main-v3.aml:79-142` field by
    field. Circle metadata is intentionally split across parallel
    maps to mirror the AML's `map[address]X` shape; bundling them
    into one record would lose the AML default-value semantics
    that drive several invariants. -/
structure ProgramState where
  programOwner             : Addr
  paused                   : Bool

  -- Circle registry (thin, parallel maps).
  circleOwner              : Map CircleId Addr
  /-- Base64 ed25519 receipt pubkey. -/
  circleReceiptPk          : Map CircleId String
  /-- sha256 hex of operator's `/state-root.json`. -/
  circleStateRoot          : Map CircleId Bytes
  circleStateVersion       : Map CircleId Nat
  /-- `circle_active[c] = 1` ⇔ `true`. -/
  circleActive             : Map CircleId Bool

  -- Bonds + slash.
  circleBond               : Map CircleId OctRaw
  circleUnbonding          : Map CircleId Unbonding
  circleSlashed            : Map CircleId Bool

  -- Tailnets.
  tailnetCount             : Nat
  tailnets                 : Map TailnetId Tailnet

  -- Sessions.
  sessionCount             : Nat
  sessions                 : Map SessionId (Option Session)

  /-- v3.2 C-1: dispute grace deadline per session. `0` for any
      session that has never been in `SessionStatus.disputed`.
      `main-v3-c1-fix.aml:180`. -/
  sessionDisputeDeadline   : Map SessionId Epoch

  -- Earnings (sha256 hash-chain era).
  circleEarningsTotal      : Map CircleId Nat
  circleEarningsClaimed    : Map CircleId Nat
  circleEarningsChain      : Map CircleId Bytes

  -- Program treasury + accounting.
  programTreasury          : OctRaw
  burned                   : OctRaw

  -- Governance params + chain context.
  params                   : Params
  currentEpoch             : Epoch

/-- Predicate-form of AML's `circle_is_active(c)` helper
    (`main-v3.aml:187-192`): NOT slashed AND `active = 1`. -/
def circleIsActive (s : ProgramState) (c : CircleId) : Bool :=
  if s.circleSlashed c then false
  else s.circleActive c

/-- "Available earnings" = total credited minus already-claimed.
    Used by `claim_earnings` upper-bound check (`main-v3.aml:653`). -/
def availableEarnings (s : ProgramState) (c : CircleId) : Nat :=
  s.circleEarningsTotal c - s.circleEarningsClaimed c

end OctraVPN_V3
