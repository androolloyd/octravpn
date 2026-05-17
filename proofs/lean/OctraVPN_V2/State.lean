/-!
# State of the OctraVPN v2 program — Lean 4 model.

Tracks the slim-registry, circle-keyed state machine that ships in
`program/main-v2.aml`. Major shape changes vs v1.1:

- Operators are CIRCLES (Octra IEEs), not wallet addresses. The
  registry maps `CircleId` → `CircleRecord`. `CircleId` is an
  opaque sort here; off-chain it's the 47-char `oct…` derived from
  `sha256+base58(deployer, nonce, deploy_payload)`. We don't model
  the derivation — that's a host-call property out of scope (the
  chain enforces uniqueness by collision-resistance of sha256).
  **PROOF GAP**: `CircleId` opaqueness — the chain accepts the
  derivation as authoritative; the model treats `CircleId` as
  abstract.

- `register_circle` is PAYABLE + ATOMIC: a single transition sets
  `owner`, sets `active=1`, AND adds `value` to `circle_stake[c]`.
  v1.1 had the chicken-and-egg of `register_endpoint` + `bond_endpoint`
  as two separate calls; v2 collapses them.

- Per-class pricing: each circle records both
  `pricePerMbShared` and `pricePerMbInternal`. `open_session`
  stamps one of those into the session at open time. Subsequent
  `update_circle` calls do NOT mutate live sessions.

- Pre-tailnet `charge_internal_traffic` toggle on Tailnet
  governs whether class=INTERNAL sessions pay or are free.

- `authorize_circle` (per-tailnet) replaces the v1.1
  `configure_tailnet_exit`. Authorization is gated by
  `circle_is_active` at authorize-time AND at open-time.

- `slash_*` slashes are keyed on `CircleId`, not operator wallet.

- v1.1 governance semantics carry over: pause halts USER flows only.

- HFHE is the same abstraction: `proofOk : Prop` parameter
  on `claimEarnings`. **PROOF GAP**: FHE soundness is asserted by
  axiom; Lean has no model of HFHE arithmetic.

- AML modifiers `payable` / `nonreentrant`: the chain runtime
  enforces non-reentrancy; the Lean model does not track re-entry
  (each entrypoint is one atomic transition by construction).
  **PROOF GAP**: re-entry rejection is a runtime property.
-/

namespace OctraVPN_V2

abbrev Addr := Nat
abbrev Bytes := List UInt8
abbrev Epoch := Nat
abbrev OctRaw := Nat
abbrev TailnetId := Nat
abbrev SessionId := Nat

/-- Opaque circle identifier. Off-chain: 47-char `oct…` derived
    from sha256+base58 over (deployer, nonce, deploy_payload).
    Here it's just another sort; we never inspect its bytes. -/
abbrev CircleId := Nat

/-- Session class. v2 introduces two pricing tiers: CLASS_SHARED
    (default) and CLASS_INTERNAL (intra-tailnet). -/
inductive SessionClass where
  | shared   : SessionClass
  | internal : SessionClass
  deriving Repr, DecidableEq

inductive SessionStatus where
  | open      : SessionStatus
  | settled   : SessionStatus
  | refunded  : SessionStatus
  deriving Repr, DecidableEq

/-- On-chain circle record under `circles[c]`. -/
structure CircleRecord where
  owner                 : Addr
  receiptPubkey         : String
  registeredAt          : Epoch
  reputation            : Int
  active                : Bool
  region                : String
  pricePerMbShared      : Nat
  pricePerMbInternal    : Nat
  deriving Repr

def CircleRecord.empty : CircleRecord :=
  { owner := 0, receiptPubkey := "", registeredAt := 0, reputation := 0,
    active := false, region := "",
    pricePerMbShared := 0, pricePerMbInternal := 0 }

/-- v2 tailnet record. Adds `chargeInternalTraffic` toggle and
    `memberCount` (the AML uses `members[tid][addr] = 1`, which we
    model as a flat membership map plus a count). -/
structure Tailnet where
  owner                  : Addr
  treasury               : OctRaw
  memberCount            : Nat
  aclPolicy              : String
  createdAt              : Epoch
  /-- 0 = intra-tailnet internal traffic free at settle time;
      1 = bill internal at the operator's internal tariff. -/
  chargeInternalTraffic  : Nat
  deriving Repr

def Tailnet.empty : Tailnet :=
  { owner := 0, treasury := 0, memberCount := 0,
    aclPolicy := "", createdAt := 0, chargeInternalTraffic := 0 }

/-- v2 session record. The big change vs v1.1 is the per-session
    `class` and `pricePerMb` fields: the price is stamped at open
    time from `circles[c].pricePerMb_{shared,internal}` depending
    on `class`. Subsequent `update_circle` calls do not affect a
    live session's stamped price. -/
structure Session where
  tailnetId       : TailnetId
  circle          : CircleId
  opener          : Addr
  deposit         : OctRaw
  openedAt        : Epoch
  class_          : SessionClass
  /-- Price-per-MiB stamped at open. Read by `settle_confirm`. -/
  pricePerMb      : Nat
  status          : SessionStatus
  operatorClaim   : Option (Nat × Nat)
  clientConfirm   : Option (Nat × Nat)
  deriving Repr

/-- In-flight unbonding record (carried over from v1.1). -/
structure Unbonding where
  stake       : OctRaw
  unlockEpoch : Epoch
  deriving Repr

def Unbonding.empty : Unbonding := { stake := 0, unlockEpoch := 0 }

abbrev Map (α : Type) (β : Type) := α → β

def Map.update {α} {β} [DecidableEq α]
    (m : Map α β) (k : α) (v : β) : Map α β :=
  fun x => if x = k then v else m x

structure Params where
  minSessionDeposit    : OctRaw
  minTailnetDeposit    : OctRaw
  sessionGraceEpochs   : Nat
  sweepGraceMultiplier : Nat
  sweepBountyBps       : Nat
  minCircleStake       : OctRaw
  unbondGraceEpochs    : Nat
  slashBurnBps         : Nat
  slashBountyBps       : Nat
  protocolFeeBps       : Nat
  deriving Repr

structure ProgramState where
  /-- Program owner (governance wallet). -/
  programOwner       : Addr
  /-- Pause switch; `true` blocks every USER entrypoint. Governance
      entrypoints (set_paused, transfer_ownership, set_params,
      withdraw_program_treasury) intentionally bypass pause. -/
  paused             : Bool
  /-- Circle registry. Keyed by `CircleId`. -/
  circles            : Map CircleId CircleRecord
  /-- Live circle stake (bonded). Mirrors AML `circle_stake[c]`. -/
  circleStake        : Map CircleId OctRaw
  /-- Unbonding requests, keyed by circle. -/
  circleUnbonding    : Map CircleId Unbonding
  /-- Permanently slashed circles. Mirrors AML `circle_slashed[c]`. -/
  circleSlashed      : Map CircleId Bool
  tailnets           : Map TailnetId Tailnet
  /-- Flat membership: `(tid, addr) ↦ true` iff in tailnet. -/
  members            : Map (TailnetId × Addr) Bool
  /-- Per-tailnet circle authorization: `(tid, circle) ↦ true` iff
      the tailnet owner has authorized that exit. Replaces v1.1
      `exits[tid]` (which was an unconditional configured list). -/
  authorizedCircles  : Map (TailnetId × CircleId) Bool
  sessions           : Map SessionId (Option Session)
  encEarn            : Map CircleId Nat
  programTreasury    : OctRaw
  burned             : OctRaw
  joinTokenCommits   : Map (TailnetId × Bytes) Bool
  joinTokenRedeemed  : Map Bytes Bool
  params             : Params
  currentEpoch       : Epoch

instance : DecidableEq (TailnetId × Addr) := by
  intro a b
  rcases a with ⟨t₁, a₁⟩
  rcases b with ⟨t₂, a₂⟩
  by_cases ht : t₁ = t₂
  · by_cases ha : a₁ = a₂
    · exact isTrue (by subst ht; subst ha; rfl)
    · exact isFalse (by intro he; cases he; exact ha rfl)
  · exact isFalse (by intro he; cases he; exact ht rfl)

instance : DecidableEq (TailnetId × CircleId) := by
  intro a b
  rcases a with ⟨t₁, c₁⟩
  rcases b with ⟨t₂, c₂⟩
  by_cases ht : t₁ = t₂
  · by_cases hc : c₁ = c₂
    · exact isTrue (by subst ht; subst hc; rfl)
    · exact isFalse (by intro he; cases he; exact hc rfl)
  · exact isFalse (by intro he; cases he; exact ht rfl)

instance : DecidableEq (TailnetId × Bytes) := by
  intro a b
  rcases a with ⟨t₁, h₁⟩
  rcases b with ⟨t₂, h₂⟩
  by_cases ht : t₁ = t₂
  · by_cases hh : h₁ = h₂
    · exact isTrue (by subst ht; subst hh; rfl)
    · exact isFalse (by intro he; cases he; exact hh rfl)
  · exact isFalse (by intro he; cases he; exact ht rfl)

end OctraVPN_V2
