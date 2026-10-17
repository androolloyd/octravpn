import Lean

/-!
Abstract accounting and deadline model for program/octranet-payments.aml.
The compiled-AML transaction tests exercise the implementation separately.
This file does not prove compiler/VM correctness, signatures, packet delivery,
network admission, or refinement of the entire AML state into this model.
Time is the canonical Program epoch_time in milliseconds, not epoch count.
-/
namespace OctranetPayments

def day : Nat := 86400000
def operatorDelay : Nat := 604800000

structure State where
  funds : Nat
  reserved : Nat
  earned : Nat
  stake : Nat
  other : Nat
  locked : Nat
  cap : Nat
  userActive : Bool
  userGeneration : Nat
  userDeadline : Nat
  operatorGeneration : Nat
  operatorUnlock : Nat
  deriving DecidableEq, Repr

def Invariant (s : State) : Prop :=
  s.reserved ≤ s.funds ∧
  s.locked = s.funds + s.earned + s.stake + s.other ∧ s.locked ≤ s.cap

def requestExit (s : State) (now : Nat) : Option State :=
  if s.userActive = false ∨ now = 0 then none
  else if s.userDeadline = 0 then some { s with userDeadline := now + day }
  else some s

def requestUnstake (s : State) (now : Nat) : Option State :=
  if s.stake = 0 ∨ now = 0 then none
  else if s.operatorUnlock = 0 then
    some { s with operatorUnlock := now + operatorDelay }
  else some s

-- planStop is read from the immutable operator_stopped[operator][generation]
-- map entry for this plan's offer. Rebonding does not clear that entry.
def claim (s : State) (now generation planStop amount : Nat)
    (authorized : Bool) : Option State :=
  if authorized = false ∨ s.userActive = false ∨ generation ≠ s.userGeneration then none
  else if s.userDeadline ≠ 0 ∧ now ≥ s.userDeadline then none
  else if planStop ≠ 0 ∧ now ≥ planStop + day then none
  else if amount > s.reserved ∨ amount > s.funds then none
  else some { s with funds := s.funds - amount, reserved := s.reserved - amount, earned := s.earned + amount }

def withdrawUser (s : State) (now : Nat) : Option State :=
  if s.userActive = false ∨ s.userDeadline = 0 ∨ now < s.userDeadline then none
  else some { s with funds := 0, reserved := 0, userActive := false, locked := s.locked - s.funds }

def withdrawOperator (s : State) (now : Nat) : Option State :=
  if s.stake = 0 ∨ s.operatorUnlock = 0 ∨ now < s.operatorUnlock then none
  else some { s with stake := 0, operatorUnlock := 0, locked := s.locked - s.stake }

def canForward (s : State) (payerGeneration providerGeneration minStake : Nat) : Bool :=
  s.userActive && decide (s.userDeadline = 0) &&
  decide (payerGeneration = s.userGeneration) && decide (s.reserved > 0) &&
  decide (s.stake ≥ minStake) && decide (s.operatorUnlock = 0) &&
  decide (providerGeneration = s.operatorGeneration)

theorem user_exit_exactly_one_day (s : State) (now : Nat)
    (ha : s.userActive = true) (hn : now ≠ 0) (hd : s.userDeadline = 0) :
    requestExit s now = some { s with userDeadline := now + day } := by
  simp [requestExit, ha, hn, hd]

theorem user_exit_retry_preserves_deadline (s : State) (now : Nat)
    (ha : s.userActive = true) (hn : now ≠ 0) (hd : s.userDeadline ≠ 0) :
    requestExit s now = some s := by
  simp [requestExit, ha, hn, hd]

theorem operator_unstake_exactly_seven_days (s : State) (now : Nat)
    (hs : s.stake ≠ 0) (hn : now ≠ 0) (hu : s.operatorUnlock = 0) :
    requestUnstake s now = some { s with operatorUnlock := now + operatorDelay } := by
  simp [requestUnstake, hs, hn, hu]

theorem operator_unstake_retry_preserves_deadline (s : State) (now : Nat)
    (hs : s.stake ≠ 0) (hn : now ≠ 0) (hu : s.operatorUnlock ≠ 0) :
    requestUnstake s now = some s := by
  simp [requestUnstake, hs, hn, hu]

theorem operator_stake_locked_before_deadline (s : State) (now : Nat)
    (h : now < s.operatorUnlock) : withdrawOperator s now = none := by
  simp [withdrawOperator, h]

theorem operator_stake_released_at_deadline (s : State)
    (hs : s.stake ≠ 0) (hu : s.operatorUnlock ≠ 0) :
    withdrawOperator s s.operatorUnlock =
      some { s with stake := 0, operatorUnlock := 0, locked := s.locked - s.stake } := by
  simp [withdrawOperator, hs, hu]

theorem user_claim_closed_at_deadline (s : State) (now gen stop amount : Nat)
    (auth : Bool) (hd : s.userDeadline ≠ 0) (hn : now ≥ s.userDeadline) :
    claim s now gen stop amount auth = none := by
  simp [claim, hd, hn]

theorem stopped_operator_claim_closed (s : State) (now gen stop amount : Nat)
    (auth : Bool) (hs : stop ≠ 0) (hn : now ≥ stop + day) :
    claim s now gen stop amount auth = none := by
  simp [claim, hs, hn]

theorem receipt_cannot_extend_user_deadline (s s' : State)
    (now gen stop amount : Nat) (auth : Bool)
    (h : claim s now gen stop amount auth = some s') :
    s'.userDeadline = s.userDeadline := by
  unfold claim at h
  split at h <;> simp_all
  split at h <;> simp_all
  split at h <;> simp_all
  split at h <;> simp_all
  subst s'
  rfl

theorem claim_preserves_accounting (s s' : State)
    (now gen stop amount : Nat) (auth : Bool)
    (hi : Invariant s) (h : claim s now gen stop amount auth = some s') :
    Invariant s' := by
  unfold claim at h
  split at h <;> simp_all
  split at h <;> simp_all
  split at h <;> simp_all
  split at h <;> simp_all
  subst s'
  simp only [Invariant] at *
  try dsimp
  omega

theorem withdrawal_returns_only_difference (s s' : State) (now : Nat)
    (hi : Invariant s) (h : withdrawUser s now = some s') :
    Invariant s' ∧ s'.earned = s.earned ∧ s'.stake = s.stake ∧
    s'.locked + s.funds = s.locked := by
  unfold withdrawUser at h
  split at h <;> simp_all
  subst s'
  simp only [Invariant] at *
  try dsimp
  refine ⟨⟨by omega, ?_, by omega⟩, True.intro, True.intro, ?_⟩ <;> omega

theorem unstake_preserves_payer_and_earnings (s s' : State) (now : Nat)
    (hi : Invariant s) (h : withdrawOperator s now = some s') :
    Invariant s' ∧ s'.funds = s.funds ∧ s'.reserved = s.reserved ∧
    s'.earned = s.earned ∧ s'.locked + s.stake = s.locked := by
  unfold withdrawOperator at h
  split at h <;> simp_all
  subst s'
  simp only [Invariant] at *
  try dsimp
  refine ⟨⟨by omega, ?_, by omega⟩, True.intro, True.intro, True.intro, ?_⟩ <;> omega

theorem stopped_provider_cannot_forward (s : State) (payer provider minimum : Nat)
    (h : s.operatorUnlock ≠ 0) : canForward s payer provider minimum = false := by
  simp [canForward, h]

theorem old_provider_generation_cannot_forward (s : State) (payer provider minimum : Nat)
    (h : provider ≠ s.operatorGeneration) : canForward s payer provider minimum = false := by
  simp [canForward, h]

theorem old_payer_generation_cannot_claim (s : State) (now gen stop amount : Nat)
    (auth : Bool) (h : gen ≠ s.userGeneration) : claim s now gen stop amount auth = none := by
  simp [claim, h]

theorem all_stopped_receipts_expire_before_unstake (stopped : Nat) :
    stopped + day < stopped + operatorDelay := by
  unfold day operatorDelay
  omega

theorem cumulative_increments_do_not_overcharge (previous middle latest : Nat)
    (h1 : previous ≤ middle) (h2 : middle ≤ latest) :
    (middle - previous) + (latest - middle) = latest - previous := by
  omega

structure Cumulative where
  bytes : Nat
  charge : Nat
  sequence : Nat
  deriving DecidableEq, Repr

-- The new charge is computed from the pinned tariff before this transition.
-- Sequence is authenticated metadata; its high-water mark cannot veto usage.
def redeem (s : Cumulative) (bytes charge sequence : Nat) (authorized : Bool) : Option Cumulative :=
  if authorized = false ∨ sequence = 0 ∨ bytes ≤ s.bytes ∨ charge < s.charge then none
  else some { bytes, charge, sequence := max s.sequence sequence }

theorem higher_sequence_cannot_cancel_larger_usage (s : Cumulative)
    (bytes charge sequence : Nat) (hb : s.bytes < bytes)
    (hc : s.charge ≤ charge) (hs : sequence ≠ 0) :
    redeem s bytes charge sequence true =
      some { bytes, charge, sequence := max s.sequence sequence } := by
  simp [redeem, hs, Nat.not_le_of_lt hb, Nat.not_lt_of_le hc]

theorem duplicate_usage_cannot_charge_again (s : Cumulative)
    (bytes charge sequence : Nat) (auth : Bool) (hb : bytes ≤ s.bytes) :
    redeem s bytes charge sequence auth = none := by
  simp [redeem, hb]

end OctranetPayments
