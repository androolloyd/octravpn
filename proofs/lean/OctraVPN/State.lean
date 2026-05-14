/-!
# State of the OctraVPN program — Lean 4 model (v1).

Tracks the post-refactor state machine. Per `docs/aml-gap-analysis.md`:

- Operators stake OU in-program (`endpointStake`), unbond via grace
  (`endpointUnbonding`), and are permanently flagged when slashed
  by governance (`endpointSlashed`).
- Sessions are single-hop with a single exit operator (no route).
- Encrypted earnings (HFHE on real Octra) modeled as a plaintext
  `Nat` counter — the lemmas about additivity carry over to the
  ciphertext layer under the homomorphism axiom.
- Program treasury (Tier 2 protocol fee + burn share of slashed
  stakes) is plaintext-owner-controlled.
-/

namespace OctraVPN

abbrev Addr := Nat
abbrev Bytes := List UInt8
abbrev Epoch := Nat
abbrev OctRaw := Nat
/-- v1 AML uses int counters for tailnet and session IDs (matches
    `tailnet_count`, `session_count` in `program/main.aml`). -/
abbrev TailnetId := Nat
abbrev SessionId := Nat

inductive SessionStatus where
  | open      : SessionStatus
  | settled   : SessionStatus
  | refunded  : SessionStatus
  deriving Repr, DecidableEq

/-- On-chain endpoint record under `endpoints[addr]`. -/
structure EndpointRecord where
  active         : Bool
  endpoint       : String
  region         : String
  pricePerMb     : Nat
  registeredAt   : Epoch
  reputation     : Int
  deriving Repr

def EndpointRecord.empty : EndpointRecord :=
  { active := false, endpoint := "", region := "",
    pricePerMb := 0, registeredAt := 0, reputation := 0 }

/-- On-chain tailnet record under `tailnets[id]`. -/
structure Tailnet where
  owner       : Addr
  treasury    : OctRaw
  members     : List Addr
  exits       : List Addr
  createdAt   : Epoch
  deriving Repr

def Tailnet.empty : Tailnet :=
  { owner := 0, treasury := 0, members := [], exits := [], createdAt := 0 }

/-- A single-hop session record. v1 two-tx settlement adds the
    opener (only address allowed to confirm) plus per-side claim
    records. -/
structure Session where
  tailnetId       : TailnetId
  exit            : Addr
  /-- The account that called `open_session`. Only this address can
      submit `settle_confirm`. -/
  opener          : Addr
  deposit         : OctRaw
  openedAt        : Epoch
  status          : SessionStatus
  /-- Plaintext view of bytes paid for, for proof purposes only. -/
  paidBytes       : Nat
  /-- Operator's `settle_claim` record: `some (bytes_used, claimed_at)`
      after the operator submits. -/
  operatorClaim   : Option (Nat × Nat)
  /-- Client's `settle_confirm` record. Recorded on both match (final
      settlement) and mismatch (dispute). -/
  clientConfirm   : Option (Nat × Nat)
  deriving Repr

/-- In-flight unbonding record. `stake = 0` represents "no
    unbonding in progress". -/
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
  minEndpointStake     : OctRaw
  unbondGraceEpochs    : Nat
  slashBurnBps         : Nat
  slashBountyBps       : Nat
  protocolFeeBps       : Nat
  deriving Repr

structure ProgramState where
  /-- Program owner (governance wallet). -/
  programOwner     : Addr
  endpoints        : Map Addr EndpointRecord
  /-- Live operator stake. -/
  endpointStake    : Map Addr OctRaw
  /-- Unbonding requests. -/
  endpointUnbonding : Map Addr Unbonding
  /-- Permanently slashed addresses. -/
  endpointSlashed  : Map Addr Bool
  tailnets         : Map TailnetId Tailnet
  sessions         : Map SessionId (Option Session)
  /-- Encrypted earnings (modeled as plaintext for proof purposes;
      real Octra holds HFHE ciphertext). -/
  encEarn          : Map Addr Nat
  /-- Program treasury: Tier 2 fee + burn share of slashed stakes. -/
  programTreasury  : OctRaw
  burned           : OctRaw
  /-- Pre-auth join tokens: `(tailnet, sha256(preimage)) ↦ committed`. -/
  joinTokenCommits  : Map (TailnetId × Bytes) Bool
  /-- Spent join-token hashes: once redeemed, `true` forever. -/
  joinTokenRedeemed : Map Bytes Bool
  params           : Params
  currentEpoch     : Epoch

instance : DecidableEq (TailnetId × Bytes) := by
  intro a b
  rcases a with ⟨t₁, h₁⟩
  rcases b with ⟨t₂, h₂⟩
  by_cases ht : t₁ = t₂
  · by_cases hh : h₁ = h₂
    · exact isTrue (by subst ht; subst hh; rfl)
    · exact isFalse (by intro he; cases he; exact hh rfl)
  · exact isFalse (by intro he; cases he; exact ht rfl)

end OctraVPN
