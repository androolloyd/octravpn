import Lean

/-!
Abstract prepaid accounting and deadline model for program/octranet-payments.aml.
The compiled-AML transaction tests exercise the implementation separately.
This file does not prove compiler/VM correctness, signatures, packet delivery,
network admission, or refinement of the entire AML state into this model.
Time is the canonical Program epoch_time in milliseconds, not epoch count.
Purchasing bytes is not a proof that an operator delivered Internet service.
The separate forwarding model below assumes authenticated purchased capacity;
its connection to the Rust meter is tested, not a proven refinement.
-/
namespace OctranetPayments

def day : Nat := 86400000
def operatorDelay : Nat := 604800000
def maxUint : Nat := 18446744073709551615

-- The source checks this bound before updating a plan reservation.
theorem guarded_reservation_fits_uint (reserved budget : Nat)
    (h_reserved : reserved ≤ maxUint)
    (h_guard : budget ≤ maxUint - reserved) :
    reserved + budget ≤ maxUint := by
  omega

-- The verifier-friendly subtraction form in open_plan is the same reservation
-- update as adding budget, provided the channel has enough free OCT.
theorem reservation_via_remaining_equals_add (funds reserved budget : Nat)
    (h_reserved : reserved ≤ funds)
    (h_budget : budget ≤ funds - reserved) :
    funds - ((funds - reserved) - budget) = reserved + budget := by
  omega

theorem reservation_via_remaining_fits_uint (funds reserved budget : Nat)
    (h_funds : funds ≤ maxUint)
    (h_reserved : reserved ≤ funds)
    (h_budget : budget ≤ funds - reserved) :
    funds - ((funds - reserved) - budget) ≤ maxUint := by
  have h_budget_uint : budget ≤ maxUint - reserved := by omega
  rw [reservation_via_remaining_equals_add funds reserved budget h_reserved h_budget]
  exact guarded_reservation_fits_uint reserved budget (by omega) h_budget_uint

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
  else if s.userDeadline = 0 then some { s with userDeadline := now }
  else some s

def requestUnstake (s : State) (now : Nat) : Option State :=
  if s.stake = 0 ∨ now = 0 then none
  else if s.operatorUnlock = 0 then
    some { s with operatorUnlock := now + operatorDelay }
  else some s

-- planStop is read from the immutable operator_stopped[operator][generation]
-- map entry for this plan's offer. Rebonding does not clear that entry.
def claim (s : State) (_now generation planStop amount : Nat)
    (authorized : Bool) : Option State :=
  if authorized = false ∨ s.userActive = false ∨ generation ≠ s.userGeneration then none
  else if s.userDeadline ≠ 0 then none
  else if planStop ≠ 0 then none
  else if amount > s.reserved ∨ amount > s.funds then none
  else some { s with funds := s.funds - amount, reserved := s.reserved - amount, earned := s.earned + amount }

-- Available channel OCT includes funds and earned traffic proceeds. Stake is
-- a separate liability. Reservations are allocations, not withdrawal holds.
def channelBalance (s : State) : Nat := s.funds + s.earned

def withdrawUser (s : State) (now : Nat) : Option State :=
  if now = 0 ∨ (s.userActive = false ∧ channelBalance s = 0) then none
  else some { s with funds := 0, earned := 0, reserved := 0, userActive := false, userDeadline := now, locked := s.locked - channelBalance s }

def withdrawPartial (s : State) (amount : Nat) : Option State :=
  if s.userActive = false ∨ amount = 0 ∨ amount > channelBalance s then none
  else some { s with funds := s.funds - amount, earned := s.earned - (amount - s.funds), reserved := 0, userGeneration := s.userGeneration + 1, locked := s.locked - amount }

def allocateEarnings (s : State) (amount : Nat) : Option State :=
  if amount > s.earned then none
  else some { s with funds := s.funds + amount, earned := s.earned - amount }

def withdrawEarnings (s : State) (amount : Nat) : Option State :=
  if amount = 0 ∨ amount > s.earned then none
  else some { s with earned := s.earned - amount, locked := s.locked - amount }

-- Other payees' earnings remain in custody but leave this channel's balance.
def payOther (s : State) (amount : Nat) : Option State :=
  if amount > s.reserved ∨ amount > s.funds then none
  else some { s with funds := s.funds - amount, reserved := s.reserved - amount, other := s.other + amount }

def withdrawOperator (s : State) (now : Nat) : Option State :=
  if s.stake = 0 ∨ s.operatorUnlock = 0 ∨ now < s.operatorUnlock then none
  else some { s with stake := 0, operatorUnlock := 0, locked := s.locked - s.stake }

-- Abstract only: `evidence` assumes both Ed25519 checks and exact slot
-- binding have already succeeded in the AML. The bond becomes a locked payer
-- award; this does not prove signatures, clocks or who controls the payer.
def slashBond (s : State) (evidence : Bool) : Option State :=
  if evidence = false ∨ s.stake = 0 then none
  else some { s with stake := 0, other := s.other + s.stake, operatorUnlock := 0 }

theorem slashBond_keeps_custody_accounting (s : State)
    (h : Invariant s) :
    Invariant { s with stake := 0, other := s.other + s.stake, operatorUnlock := 0 } := by
  rcases h with ⟨hr, hl, hc⟩
  simp only [Invariant] at *
  constructor
  · exact hr
  constructor
  · omega
  · omega

theorem slashBond_keeps_value_locked (s : State) (hp : s.stake > 0) :
    (slashBond s true).map State.locked = some s.locked := by
  simp [slashBond, Nat.ne_of_gt hp]

def withdrawAward (s : State) (amount : Nat) : Option State :=
  if amount = 0 ∨ amount > s.other then none
  else some { s with other := s.other - amount, locked := s.locked - amount }

theorem withdrawAward_keeps_custody_accounting (s : State) (amount : Nat)
    (h : Invariant s) (ha : amount ≤ s.other) :
    Invariant { s with other := s.other - amount, locked := s.locked - amount } := by
  rcases h with ⟨hr, hl, hc⟩
  simp only [Invariant] at *
  constructor
  · exact hr
  constructor
  · omega
  · omega

theorem slashBond_replay_without_rebond_fails (s : State)
    (hp : s.stake > 0) :
    (slashBond s true).bind (fun after => slashBond after true) = none := by
  simp [slashBond, Nat.ne_of_gt hp]

def canForward (s : State) (payerGeneration providerGeneration minStake : Nat) : Bool :=
  s.userActive && decide (s.userDeadline = 0) &&
  decide (payerGeneration = s.userGeneration) &&
  decide (s.stake ≥ minStake) && decide (s.operatorUnlock = 0) &&
  decide (providerGeneration = s.operatorGeneration)

theorem user_exit_stops_immediately (s : State) (now : Nat)
    (ha : s.userActive = true) (hn : now ≠ 0) (hd : s.userDeadline = 0) :
    requestExit s now = some { s with userDeadline := now } := by
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
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  have hs := Option.some.inj h
  subst s'
  rfl

theorem claim_preserves_accounting (s s' : State)
    (now gen stop amount : Nat) (auth : Bool)
    (hi : Invariant s) (h : claim s now gen stop amount auth = some s') :
    Invariant s' := by
  unfold claim at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  have hs := Option.some.inj h
  subst s'
  simp only [Invariant] at *
  try dsimp
  omega

theorem withdrawal_returns_available_channel_only (s s' : State) (now : Nat)
    (hi : Invariant s) (h : withdrawUser s now = some s') :
    Invariant s' ∧ s'.funds = 0 ∧ s'.earned = 0 ∧ s'.stake = s.stake ∧
    s'.locked + channelBalance s = s.locked := by
  unfold withdrawUser at h
  split at h <;> simp_all
  subst s'
  simp only [Invariant, channelBalance] at *
  try dsimp
  refine ⟨⟨by omega, ?_, by omega⟩, True.intro, True.intro, True.intro, ?_⟩ <;> omega

theorem withdrawal_requires_no_payer_delay (s : State) (now : Nat)
    (ha : s.userActive = true) (hn : now ≠ 0) :
    withdrawUser s now = some { s with funds := 0, earned := 0, reserved := 0, userActive := false, userDeadline := now, locked := s.locked - channelBalance s } := by
  simp [withdrawUser, ha, hn]

theorem partial_withdrawal_preserves_accounting (s s' : State) (amount : Nat)
    (hi : Invariant s) (h : withdrawPartial s amount = some s') :
    Invariant s' ∧ s'.reserved = 0 ∧ s'.userGeneration = s.userGeneration + 1 ∧
      s'.stake = s.stake ∧ s'.locked + amount = s.locked := by
  unfold withdrawPartial at h
  split at h <;> simp_all
  subst s'
  simp only [Invariant, channelBalance] at *
  try dsimp
  refine ⟨⟨by omega, ?_, by omega⟩, True.intro, True.intro, True.intro, ?_⟩ <;> omega

theorem earnings_allocation_preserves_custody (s s' : State) (amount : Nat)
    (hi : Invariant s) (h : allocateEarnings s amount = some s') :
    Invariant s' ∧ channelBalance s' = channelBalance s ∧ s'.locked = s.locked := by
  unfold allocateEarnings at h
  split at h <;> simp_all
  subst s'
  simp only [Invariant, channelBalance] at *
  try dsimp
  refine ⟨⟨by omega, ?_, by omega⟩, ?_, True.intro⟩ <;> omega

theorem earnings_withdrawal_preserves_accounting (s s' : State) (amount : Nat)
    (hi : Invariant s) (h : withdrawEarnings s amount = some s') :
    Invariant s' ∧ s'.funds = s.funds ∧ s'.stake = s.stake ∧
      s'.locked + amount = s.locked := by
  unfold withdrawEarnings at h
  split at h <;> simp_all
  subst s'
  simp only [Invariant] at *
  try dsimp
  refine ⟨⟨by omega, ?_, by omega⟩, True.intro, True.intro, ?_⟩ <;> omega

theorem earnings_withdrawal_requires_no_unstake (s : State) (amount : Nat)
    (hp : amount > 0) (he : amount ≤ s.earned) :
    withdrawEarnings s amount =
      some { s with earned := s.earned - amount, locked := s.locked - amount } := by
  simp [withdrawEarnings, Nat.ne_of_gt hp, Nat.not_lt.mpr he]

theorem partial_withdrawal_invalidates_old_generation (s s' : State)
    (amount now stop charge : Nat) (auth : Bool)
    (h : withdrawPartial s amount = some s') :
    claim s' now s.userGeneration stop charge auth = none := by
  unfold withdrawPartial at h
  split at h <;> simp_all
  subst s'
  have hg : s.userGeneration ≠ s.userGeneration + 1 := by omega
  simp [claim, hg]

theorem self_payment_preserves_channel_balance (s s' : State)
    (now gen stop amount : Nat) (auth : Bool)
    (h : claim s now gen stop amount auth = some s') :
    channelBalance s' = channelBalance s := by
  unfold claim at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  have hs := Option.some.inj h
  subst s'
  simp only [channelBalance]
  try dsimp
  omega

theorem cross_operator_payment_conserves_custody (s s' : State) (amount : Nat)
    (hi : Invariant s) (h : payOther s amount = some s') :
    Invariant s' ∧ channelBalance s' + amount = channelBalance s ∧
    s'.locked = s.locked ∧ s'.stake = s.stake := by
  unfold payOther at h
  split at h <;> simp_all
  subst s'
  simp only [Invariant, channelBalance] at *
  try dsimp
  refine ⟨⟨by omega, ?_, by omega⟩, ?_, True.intro, True.intro⟩ <;> omega

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

theorem eligibility_independent_of_remaining_escrow (s : State) (payer provider minimum : Nat) :
    canForward { s with reserved := 0 } payer provider minimum =
      canForward s payer provider minimum := by
  rfl

theorem old_payer_generation_cannot_claim (s : State) (now gen stop amount : Nat)
    (auth : Bool) (h : gen ≠ s.userGeneration) : claim s now gen stop amount auth = none := by
  simp [claim, h]

theorem instant_channel_release_precedes_unstake (stopped : Nat) :
    stopped < stopped + operatorDelay := by
  unfold operatorDelay
  omega

theorem stopped_payer_cannot_buy_more (s : State) (now gen stop amount : Nat)
    (auth : Bool) (hd : s.userDeadline ≠ 0) :
    claim s now gen stop amount auth = none := by
  simp [claim, hd]

theorem stopped_operator_cannot_sell_more (s : State) (now gen stop amount : Nat)
    (auth : Bool) (hs : stop ≠ 0) :
    claim s now gen stop amount auth = none := by
  simp [claim, hs]

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

-- Immutable successor quotes change NEW purchase eligibility only. Existing
-- purchased capacity retains its original tariff and is modeled below.
structure Quote where
  start : Nat
  finish : Nat
  cancelled : Bool
  sealed : Bool
  deriving DecidableEq, Repr

def quoteOpen (q : Quote) (now : Nat) : Bool :=
  q.sealed && !q.cancelled && decide (q.start ≤ now) &&
    decide (q.finish = 0 ∨ now < q.finish)

def scheduledParent (q : Quote) (now : Nat) : Quote := { q with finish := now + day }
def scheduledSuccessor (now : Nat) : Quote :=
  { start := now + day, finish := 0, cancelled := false, sealed := true }

theorem successor_requires_full_notice (now before : Nat) (h : before < now + day) :
    quoteOpen (scheduledSuccessor now) before = false := by
  simp [quoteOpen, scheduledSuccessor, Nat.not_le_of_lt h]

theorem successor_opens_at_exact_boundary (now : Nat) :
    quoteOpen (scheduledSuccessor now) (now + day) = true := by
  simp [quoteOpen, scheduledSuccessor]

theorem parent_retires_at_exact_boundary (q : Quote) (now : Nat) :
    quoteOpen (scheduledParent q now) (now + day) = false := by
  have h : now + day ≠ 0 := by unfold day; omega
  simp [quoteOpen, scheduledParent, h]

theorem cancelled_quote_never_opens (q : Quote) (now : Nat) :
    quoteOpen { q with cancelled := true } now = false := by
  simp [quoteOpen]

theorem rescheduling_restarts_full_notice (first second : Nat) (h : first ≤ second) :
    (scheduledSuccessor second).start = second + day ∧
      (scheduledSuccessor first).start ≤ (scheduledSuccessor second).start := by
  dsimp [scheduledSuccessor]
  exact ⟨rfl, Nat.add_le_add_right h day⟩

theorem parent_and_successor_quotes_are_exclusive (q : Quote) (scheduled now : Nat)
    (h : quoteOpen (scheduledParent q scheduled) now = true) :
    quoteOpen (scheduledSuccessor scheduled) now = false := by
  by_cases before : now < scheduled + day
  · exact successor_requires_full_notice scheduled now before
  · have nonzero : scheduled + day ≠ 0 := by unfold day; omega
    simp [quoteOpen, scheduledParent, nonzero, before] at h

-- A class's prepaid capacity is independent of actual packet handoffs.
structure Capacity where
  purchased : Nat
  consumed : Nat
  pending : Nat
  uncertain : Nat
  deriving DecidableEq, Repr

def held (s : Capacity) : Nat := s.consumed + s.pending + s.uncertain
def Prepaid (s : Capacity) : Prop := held s ≤ s.purchased

def reserveBytes (s : Capacity) (bytes : Nat) : Option Capacity :=
  if bytes = 0 ∨ held s + bytes > s.purchased then none
  else some { s with pending := s.pending + bytes }

def confirmBytes (s : Capacity) (bytes : Nat) : Option Capacity :=
  if bytes > s.pending then none
  else some { s with pending := s.pending - bytes, consumed := s.consumed + bytes }

theorem unpaid_class_cannot_reserve (s : Capacity) (bytes : Nat)
    (hp : s.purchased = 0) (hb : bytes > 0) : reserveBytes s bytes = none := by
  have h : held s + bytes > 0 := by omega
  simp [reserveBytes, hp, h]

theorem reservation_never_exceeds_prepaid (s s' : Capacity) (bytes : Nat)
    (h : reserveBytes s bytes = some s') : Prepaid s' := by
  unfold reserveBytes at h
  split at h <;> simp_all
  subst s'
  simp only [Prepaid, held] at *
  omega

theorem reservation_cannot_create_payment (s s' : Capacity) (bytes : Nat)
    (h : reserveBytes s bytes = some s') : s'.purchased = s.purchased := by
  unfold reserveBytes at h
  split at h <;> simp_all
  subst s'
  rfl

theorem confirmation_preserves_prepaid (s s' : Capacity) (bytes : Nat)
    (hi : Prepaid s) (h : confirmBytes s bytes = some s') : Prepaid s' := by
  unfold confirmBytes at h
  split at h <;> simp_all
  subst s'
  simp only [Prepaid, held] at *
  omega

theorem confirmation_cannot_create_payment (s s' : Capacity) (bytes : Nat)
    (h : confirmBytes s bytes = some s') : s'.purchased = s.purchased := by
  unfold confirmBytes at h
  split at h <;> simp_all
  subst s'
  rfl

end OctranetPayments
