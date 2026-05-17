import OctraVPN_V2.State
import OctraVPN_V2.Entrypoints

/-!
# Structural lemmas about the OctraVPN v2 spec.

Each lemma is one of the load-bearing safety properties of the v2
state machine. Together they form the formally-verified core that
backs the v2 program (`program/main-v2.aml`).

The theorems mirror v1.1's `OctraVPN/Lemmas.lean` shape with the
v2 deltas factored in:
  - `endpoints/operators` → `circles`
  - separate `register_endpoint` + `bond_endpoint` → atomic
    `registerCircleAtomic`
  - per-class pricing stamped at open
  - `chargeInternalTraffic` toggle on internal class
  - `authorize_circle` requires `circleIsActive`
  - HFHE earnings unchanged (still `proofOk : Prop`)

**PROOF GAPS** carried in `AmlLink.lean`:
  - HFHE soundness (FHE zero-proof verification)
  - `payable` / `nonreentrant` runtime modifiers
  - `CircleId` opaqueness vs sha256+base58 derivation
  - `ed25519_ok` signature verification (encoded as `verified` flag)
-/

namespace OctraVPN_V2

theorem Map.update_eq {α β} [DecidableEq α]
    (m : Map α β) (k : α) (v : β) : (m.update k v) k = v := by
  unfold Map.update; simp

theorem Map.update_ne {α β} [DecidableEq α]
    (m : Map α β) (k k' : α) (v : β) (h : k' ≠ k) :
    (m.update k v) k' = m k' := by
  unfold Map.update; simp [h]

-- ============================================================
-- Circle registry: register / update / retire
-- ============================================================

/-- ATOMIC REGISTRATION: a successful `registerCircleAtomic`
    simultaneously sets `circles[c].owner = caller`,
    `circles[c].active = true`, AND credits `circleStake[c]` by
    `value`. The post-state satisfies `value ≥ minCircleStake` for
    the just-bonded amount (when starting from zero stake).

    This is the v2 fix for v1.1's chicken-and-egg between
    `register_endpoint` and `bond_endpoint`. -/
theorem register_circle_atomic_sets_owner_active_stake
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (region : String) (priceShared priceInternal : Nat)
    (receiptPk : String) (value : OctRaw)
    (h : registerCircleAtomic s caller c region priceShared priceInternal
          receiptPk value = some s') :
    (s'.circles c).owner = caller ∧
    (s'.circles c).active = true ∧
    s'.circleStake c = s.circleStake c + value ∧
    s'.circleStake c ≥ s.params.minCircleStake := by
  unfold registerCircleAtomic at h
  by_cases h1 : (s.circles c).active
  · simp [h1] at h
  by_cases h2 : s.circleSlashed c
  · simp [h1, h2] at h
  by_cases h3 : receiptPk = ""
  · simp [h1, h2, h3] at h
  by_cases h4 : s.circleStake c + value < s.params.minCircleStake
  · simp [h1, h2, h3, h4] at h
  · simp [h1, h2, h3, h4] at h
    subst h
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold Map.update; simp
    · unfold Map.update; simp
    · unfold Map.update; simp
    · unfold Map.update; simp; exact Nat.le_of_not_lt h4

/-- NO CHICKEN-AND-EGG: `bondEndpoint(c)` requires the caller to
    be `circles[c].owner`. Therefore an unregistered circle (whose
    `circles[c].owner = 0`) can only be bonded via
    `registerCircleAtomic`, which establishes the owner atomically.

    In other words: there is no state where a non-zero caller can
    bond a circle whose owner is still the sentinel `0`. -/
theorem register_circle_atomic_no_chicken_and_egg
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (amount : OctRaw)
    (h : bondEndpoint s caller c amount = some s') :
    (s.circles c).owner = caller := by
  unfold bondEndpoint at h
  by_cases h1 : amount = 0
  · simp [h1] at h
  by_cases h2 : s.circleSlashed c
  · simp [h1, h2] at h
  by_cases h3 : (s.circleUnbonding c).stake ≠ 0
  · simp [h1, h2, h3] at h
  by_cases h4 : (s.circles c).owner ≠ caller
  · simp [h1, h2, h3, h4] at h
  · exact Decidable.of_not_not h4

/-- A successful `registerCircleAtomic` cannot register a
    previously slashed circle. -/
theorem register_circle_atomic_not_slashed
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (region : String) (priceShared priceInternal : Nat)
    (receiptPk : String) (value : OctRaw)
    (h : registerCircleAtomic s caller c region priceShared priceInternal
          receiptPk value = some s') :
    ¬ s.circleSlashed c := by
  unfold registerCircleAtomic at h
  by_cases h1 : (s.circles c).active
  · simp [h1] at h
  by_cases h2 : s.circleSlashed c
  · simp [h1, h2] at h
  · exact h2

/-- `bondEndpoint` requires the caller to own the circle. -/
theorem bond_endpoint_requires_owner
    (s s' : ProgramState) (caller : Addr) (c : CircleId) (amount : OctRaw)
    (h : bondEndpoint s caller c amount = some s') :
    (s.circles c).owner = caller := by
  exact register_circle_atomic_no_chicken_and_egg s s' caller c amount h

/-- `bondEndpoint` adds the bonded amount to the circle's live
    stake. -/
theorem bond_endpoint_increases_stake
    (s s' : ProgramState) (caller : Addr) (c : CircleId) (amount : OctRaw)
    (h : bondEndpoint s caller c amount = some s') :
    s'.circleStake c = s.circleStake c + amount := by
  unfold bondEndpoint at h
  by_cases h1 : amount = 0
  · simp [h1] at h
  by_cases h2 : s.circleSlashed c
  · simp [h1, h2] at h
  by_cases h3 : (s.circleUnbonding c).stake ≠ 0
  · simp [h1, h2, h3] at h
  by_cases h4 : (s.circles c).owner ≠ caller
  · simp [h1, h2, h3, h4] at h
  · simp [h1, h2, h3, h4] at h
    subst h
    unfold Map.update; simp

/-- IMMUTABILITY OF LIVE SESSIONS: a successful `updateCircle`
    call does NOT mutate the `sessions` map. In particular, the
    `pricePerMb` field of any open session stays exactly as it was
    stamped at open time, even if the operator updates their
    per-class prices afterward. -/
theorem update_circle_does_not_mutate_open_sessions
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (region : String) (priceShared priceInternal : Nat)
    (h : updateCircle s caller c region priceShared priceInternal = some s') :
    s'.sessions = s.sessions := by
  unfold updateCircle at h
  by_cases h1 : (s.circles c).owner ≠ caller
  · simp [h1] at h
  by_cases h2 : ¬ (s.circles c).active
  · simp [h1, h2] at h
  · simp [h1, h2] at h
    subst h
    rfl

/-- `updateCircle` is owner-gated. -/
theorem update_circle_owner_only
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (region : String) (priceShared priceInternal : Nat)
    (h : updateCircle s caller c region priceShared priceInternal = some s') :
    (s.circles c).owner = caller := by
  unfold updateCircle at h
  by_cases h1 : (s.circles c).owner ≠ caller
  · simp [h1] at h
  · exact Decidable.of_not_not h1

/-- `retireCircle` is owner-gated. -/
theorem retire_circle_owner_only
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (h : retireCircle s caller c = some s') :
    (s.circles c).owner = caller := by
  unfold retireCircle at h
  by_cases h1 : (s.circles c).owner ≠ caller
  · simp [h1] at h
  · exact Decidable.of_not_not h1

/-- After `retireCircle`, the circle's active flag is false. -/
theorem retire_clears_active
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (h : retireCircle s caller c = some s') :
    (s'.circles c).active = false := by
  unfold retireCircle at h
  by_cases h1 : (s.circles c).owner ≠ caller
  · simp [h1] at h
  by_cases h2 : ¬ (s.circles c).active
  · simp [h1, h2] at h
  · simp [h1, h2] at h
    subst h
    unfold Map.update; simp

-- ============================================================
-- Stake / slash
-- ============================================================

/-- After a successful `slashDoubleSign`, the circle's live stake
    is zero AND it's flagged slashed. Mirrors v1.1. -/
theorem slash_double_sign_slashes_stake
    (s s' : ProgramState) (caller : Addr) (c : CircleId) (verified : Bool)
    (bounty : OctRaw)
    (h : slashDoubleSign s caller c verified = some (s', bounty)) :
    s'.circleStake c = 0 ∧ s'.circleSlashed c = true := by
  unfold slashDoubleSign at h
  by_cases h1 : ¬ verified
  · simp [h1] at h
  by_cases h2 : s.circleSlashed c
  · simp [h1, h2] at h
  by_cases h3 : s.circleStake c + (s.circleUnbonding c).stake = 0
  · simp [h1, h2, h3] at h
  · simp [h1, h2, h3] at h
    by_cases h4 : (s.circles c).active
    · simp [h4] at h
      obtain ⟨hs, _⟩ := h
      subst hs
      refine ⟨?_, ?_⟩
      · unfold Map.update; simp
      · unfold Map.update; simp
    · simp [h4] at h
      obtain ⟨hs, _⟩ := h
      subst hs
      refine ⟨?_, ?_⟩
      · unfold Map.update; simp
      · unfold Map.update; simp

/-- `slashDoubleSign` returns the caller a bounty equal to
    `total - burn_amt`. -/
theorem slash_double_sign_pays_bounty
    (s s' : ProgramState) (caller : Addr) (c : CircleId) (verified : Bool)
    (bounty : OctRaw)
    (h : slashDoubleSign s caller c verified = some (s', bounty)) :
    let total := s.circleStake c + (s.circleUnbonding c).stake
    let burnAmt := total * s.params.slashBurnBps / 10000
    bounty = total - burnAmt := by
  unfold slashDoubleSign at h
  by_cases h1 : ¬ verified
  · simp [h1] at h
  by_cases h2 : s.circleSlashed c
  · simp [h1, h2] at h
  by_cases h3 : s.circleStake c + (s.circleUnbonding c).stake = 0
  · simp [h1, h2, h3] at h
  · simp [h1, h2, h3] at h
    by_cases h4 : (s.circles c).active
    · simp [h4] at h
      obtain ⟨_, hb⟩ := h
      exact hb.symm
    · simp [h4] at h
      obtain ⟨_, hb⟩ := h
      exact hb.symm

/-- `slashDoubleSign` on an already-slashed circle returns
    `none`. Mirrors AML revert. -/
theorem slash_double_sign_idempotent_when_already_slashed
    (s : ProgramState) (caller : Addr) (c : CircleId) (verified : Bool)
    (halr : s.circleSlashed c = true) :
    slashDoubleSign s caller c verified = none := by
  unfold slashDoubleSign
  by_cases h1 : ¬ verified
  · simp [h1]
  · simp [h1, halr]

/-- When `verified = false` (payloads identical OR sig invalid),
    `slashDoubleSign` returns `none`. -/
theorem slash_double_sign_distinct_payloads_required
    (s : ProgramState) (caller : Addr) (c : CircleId) :
    slashDoubleSign s caller c false = none := by
  unfold slashDoubleSign
  simp

/-- `govSlashOperator` burns the bonded stake (sets it to zero). -/
theorem gov_slash_operator_burns_stake
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (h : govSlashOperator s caller c = some s') :
    s'.circleStake c = 0 ∧ s'.circleSlashed c = true := by
  unfold govSlashOperator at h
  by_cases h1 : caller ≠ s.programOwner
  · simp [h1] at h
  by_cases h2 : s.circleSlashed c
  · simp [h1, h2] at h
  by_cases h3 : s.circleStake c + (s.circleUnbonding c).stake = 0
  · simp [h1, h2, h3] at h
  · simp [h1, h2, h3] at h
    by_cases h4 : (s.circles c).active
    · simp [h4] at h
      subst h
      refine ⟨?_, ?_⟩
      · unfold Map.update; simp
      · unfold Map.update; simp
    · simp [h4] at h
      subst h
      refine ⟨?_, ?_⟩
      · unfold Map.update; simp
      · unfold Map.update; simp

/-- `govSlashOperator` requires `caller = programOwner`. -/
theorem gov_slash_operator_requires_owner
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (h : govSlashOperator s caller c = some s') :
    caller = s.programOwner := by
  unfold govSlashOperator at h
  by_cases h1 : caller ≠ s.programOwner
  · simp [h1] at h
  · exact Decidable.of_not_not h1

/-- `unbondEndpoint` zeros the live stake and records the unbonding
    amount with the unlock epoch. Owner-gated. -/
theorem unbond_locks_stake
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (h : unbondEndpoint s caller c = some s') :
    (s.circles c).owner = caller ∧
    s'.circleStake c = 0 ∧
    (s'.circleUnbonding c).stake = s.circleStake c ∧
    (s'.circleUnbonding c).unlockEpoch =
      s.currentEpoch + s.params.unbondGraceEpochs := by
  unfold unbondEndpoint at h
  by_cases h0 : (s.circles c).owner ≠ caller
  · simp [h0] at h
  by_cases h1 : s.circleStake c = 0
  · simp [h0, h1] at h
  by_cases h2 : (s.circleUnbonding c).stake ≠ 0
  · simp [h0, h1, h2] at h
  · simp [h0, h1, h2] at h
    subst h
    refine ⟨Decidable.of_not_not h0, ?_, ?_, ?_⟩
    · unfold Map.update; simp
    · unfold Map.update; simp
    · unfold Map.update; simp

/-- `finalizeUnbond` clears the unbonding slot, returns the full
    staked amount, and is gated on the unlock epoch. -/
theorem finalize_unbond_clears_and_pays
    (s s' : ProgramState) (caller : Addr) (c : CircleId) (paid : OctRaw)
    (h : finalizeUnbond s caller c = some (s', paid)) :
    (s.circles c).owner = caller ∧
    paid = (s.circleUnbonding c).stake ∧
    paid > 0 ∧
    s.currentEpoch ≥ (s.circleUnbonding c).unlockEpoch ∧
    (s'.circleUnbonding c).stake = 0 := by
  unfold finalizeUnbond at h
  by_cases h0 : (s.circles c).owner ≠ caller
  · simp [h0] at h
  by_cases h1 : (s.circleUnbonding c).stake = 0
  · simp [h0, h1] at h
  by_cases h2 : s.currentEpoch < (s.circleUnbonding c).unlockEpoch
  · simp [h0, h1, h2] at h
  · simp [h0, h1, h2] at h
    obtain ⟨hs, hp⟩ := h
    refine ⟨Decidable.of_not_not h0, ?_, ?_, ?_, ?_⟩
    · exact hp.symm
    · subst hp; exact Nat.pos_of_ne_zero h1
    · exact Nat.le_of_not_lt h2
    · subst hs; subst hp; unfold Map.update; simp [Unbonding.empty]

-- ============================================================
-- Tailnet / authorization
-- ============================================================

/-- `createTailnet` puts the deposit into the tailnet treasury and
    adds the owner as the first member. -/
theorem create_tailnet_seeds_treasury
    (s s' : ProgramState) (owner : Addr) (tid : TailnetId)
    (acl : String) (deposit : Nat)
    (h : createTailnet s owner tid acl deposit = some s') :
    (s'.tailnets tid).treasury = deposit ∧
    (s'.tailnets tid).owner = owner ∧
    s'.members (tid, owner) = true ∧
    (s'.tailnets tid).memberCount = 1 := by
  unfold createTailnet at h
  by_cases h1 : (s.tailnets tid).owner ≠ 0
  · simp [h1] at h
  by_cases h2 : deposit < s.params.minTailnetDeposit
  · simp [h1, h2] at h
  · simp [h1, h2] at h
    subst h
    refine ⟨?_, ?_, ?_, ?_⟩
    all_goals (unfold Map.update; simp)

/-- AUTHORIZATION REQUIRES ACTIVE CIRCLE: `authorizeCircle` fails
    when the circle is slashed OR not active.

    Conversely: a successful `authorizeCircle` implies
    `circleIsActive s c = true`. -/
theorem authorize_circle_requires_active
    (s s' : ProgramState) (tid : TailnetId) (caller : Addr) (c : CircleId)
    (h : authorizeCircle s tid caller c = some s') :
    circleIsActive s c = true := by
  unfold authorizeCircle at h
  by_cases h1 : (s.tailnets tid).owner ≠ caller
  · simp [h1] at h
  by_cases h2 : ¬ circleIsActive s c
  · simp [h1, h2] at h
  · cases hca : circleIsActive s c with
    | false => exact (h2 (by simp [hca])).elim
    | true  => rfl

/-- `authorizeCircle` is owner-gated. -/
theorem authorize_circle_requires_owner
    (s s' : ProgramState) (tid : TailnetId) (caller : Addr) (c : CircleId)
    (h : authorizeCircle s tid caller c = some s') :
    (s.tailnets tid).owner = caller := by
  unfold authorizeCircle at h
  by_cases h1 : (s.tailnets tid).owner ≠ caller
  · simp [h1] at h
  · exact Decidable.of_not_not h1

/-- `revokeCircle` is owner-gated. -/
theorem revoke_circle_owner_only
    (s s' : ProgramState) (tid : TailnetId) (caller : Addr) (c : CircleId)
    (h : revokeCircle s tid caller c = some s') :
    (s.tailnets tid).owner = caller := by
  unfold revokeCircle at h
  by_cases h1 : (s.tailnets tid).owner ≠ caller
  · simp [h1] at h
  · exact Decidable.of_not_not h1

/-- `addMember` is owner-gated. After a successful call, the
    member is recorded in the membership map. -/
theorem add_member_grows_count
    (s s' : ProgramState) (tid : TailnetId) (caller member : Addr)
    (h : addMember s tid caller member = some s') :
    (s.tailnets tid).owner = caller ∧
    s'.members (tid, member) = true := by
  unfold addMember at h
  by_cases h1 : (s.tailnets tid).owner ≠ caller
  · simp [h1] at h
  have howner : (s.tailnets tid).owner = caller := Decidable.of_not_not h1
  by_cases h2 : s.members (tid, member) = true
  · -- Idempotent case: s' = s.
    simp [h1, h2] at h
    subst h
    exact ⟨howner, h2⟩
  · simp [h1, h2] at h
    subst h
    refine ⟨howner, ?_⟩
    unfold Map.update; simp

/-- `removeMember` is owner-gated and removes the member. -/
theorem remove_member_drops
    (s s' : ProgramState) (tid : TailnetId) (caller member : Addr)
    (h : removeMember s tid caller member = some s') :
    (s.tailnets tid).owner = caller ∧
    s'.members (tid, member) = false := by
  unfold removeMember at h
  by_cases h1 : (s.tailnets tid).owner ≠ caller
  · simp [h1] at h
  by_cases h2 : ¬ s.members (tid, member)
  · simp [h1, h2] at h
  · simp [h1, h2] at h
    subst h
    refine ⟨Decidable.of_not_not h1, ?_⟩
    unfold Map.update; simp

/-- `depositToTailnet` increases the treasury by `amount`. -/
theorem deposit_to_tailnet_grows_treasury
    (s s' : ProgramState) (caller : Addr) (tid : TailnetId) (amount : Nat)
    (h : depositToTailnet s caller tid amount = some s') :
    (s'.tailnets tid).treasury =
      (s.tailnets tid).treasury + amount ∧
    amount > 0 := by
  by_cases h1 : amount = 0
  · unfold depositToTailnet at h; simp [h1] at h
  have hpos : amount > 0 := Nat.pos_of_ne_zero h1
  by_cases h2 : (s.tailnets tid).owner = 0
  · unfold depositToTailnet at h; simp [h1, h2] at h
  by_cases h3 : (s.tailnets tid).owner ≠ caller ∧ ¬ s.members (tid, caller)
  · unfold depositToTailnet at h; simp [h1, h2, h3] at h
  · -- Success branch — pre-compute the resulting state.
    -- h3 says: ¬(owner ≠ caller ∧ ¬ member). Equivalently:
    -- owner = caller ∨ member, the AML "caller is owner or member"
    -- precondition.
    have hres : depositToTailnet s caller tid amount =
                some { s with
                        tailnets := s.tailnets.update tid
                          { (s.tailnets tid) with
                            treasury := (s.tailnets tid).treasury + amount } } := by
      unfold depositToTailnet
      simp [h1, h2]
      -- After simp, residual: `¬ owner = caller → members = true`.
      intro hneg
      apply Decidable.byContradiction
      intro hnm
      exact h3 ⟨hneg, hnm⟩
    rw [hres] at h
    -- h : some {body} = some s' ⇒ s' = body.
    have hs := (Option.some.inj h).symm
    -- hs : s' = {body}. Rewrite the goal.
    subst hs
    refine ⟨?_, hpos⟩
    unfold Map.update; simp

/-- `updateAcl` is owner-gated and writes the supplied policy. -/
theorem update_acl_owner_only
    (s s' : ProgramState) (tid : TailnetId) (caller : Addr) (policy : String)
    (h : updateAcl s tid caller policy = some s') :
    (s.tailnets tid).owner = caller ∧
    (s'.tailnets tid).aclPolicy = policy := by
  unfold updateAcl at h
  by_cases h1 : (s.tailnets tid).owner = 0
  · simp [h1] at h
  by_cases h2 : (s.tailnets tid).owner ≠ caller
  · simp [h1, h2] at h
  · simp [h1, h2] at h
    subst h
    refine ⟨Decidable.of_not_not h2, ?_⟩
    unfold Map.update; simp

/-- `setChargeInternalTraffic` is owner-gated and writes the
    supplied boolean (encoded as Nat 0|1). -/
theorem set_charge_internal_traffic_owner_only
    (s s' : ProgramState) (tid : TailnetId) (caller : Addr) (charge : Nat)
    (h : setChargeInternalTraffic s tid caller charge = some s') :
    (s.tailnets tid).owner = caller ∧
    (s'.tailnets tid).chargeInternalTraffic = charge ∧
    (charge = 0 ∨ charge = 1) := by
  unfold setChargeInternalTraffic at h
  by_cases h1 : (s.tailnets tid).owner ≠ caller
  · simp [h1] at h
  by_cases h2 : charge ≠ 0 ∧ charge ≠ 1
  · simp [h1, h2] at h
  · simp [h1, h2] at h
    subst h
    refine ⟨Decidable.of_not_not h1, ?_, ?_⟩
    · unfold Map.update; simp
    · -- h2 : ¬ (charge ≠ 0 ∧ charge ≠ 1)
      -- ⇒ charge = 0 ∨ charge = 1.
      by_cases hc0 : charge = 0
      · left; exact hc0
      · right
        -- ¬ (charge ≠ 0 ∧ charge ≠ 1), and we have charge ≠ 0.
        -- So we must have ¬ charge ≠ 1, i.e. charge = 1.
        apply Decidable.byContradiction
        intro hc1
        exact h2 ⟨hc0, hc1⟩

-- ============================================================
-- Sessions: open, settle, no-show, sweep
-- ============================================================

/-- `openSession` requires the circle to be active AND
    authorized. -/
theorem open_session_requires_active_circle
    (s s' : ProgramState) (caller : Addr) (tid : TailnetId)
    (sid : SessionId) (c : CircleId) (cls : SessionClass) (maxPay : Nat)
    (h : openSession s caller tid sid c cls maxPay = some s') :
    circleIsActive s c = true := by
  unfold openSession at h
  by_cases h1 : ¬ s.members (tid, caller)
  · simp [h1] at h
  by_cases h2 : ¬ s.authorizedCircles (tid, c)
  · simp [h1, h2] at h
  by_cases h3 : ¬ circleIsActive s c
  · simp [h1, h2, h3] at h
  · cases hca : circleIsActive s c with
    | false => exact (h3 (by simp [hca])).elim
    | true  => rfl

/-- `openSession` requires the circle to be authorized in the
    tailnet's `authorizedCircles` table. -/
theorem open_session_requires_authorization
    (s s' : ProgramState) (caller : Addr) (tid : TailnetId)
    (sid : SessionId) (c : CircleId) (cls : SessionClass) (maxPay : Nat)
    (h : openSession s caller tid sid c cls maxPay = some s') :
    s.authorizedCircles (tid, c) = true := by
  unfold openSession at h
  by_cases h1 : ¬ s.members (tid, caller)
  · simp [h1] at h
  by_cases h2 : ¬ s.authorizedCircles (tid, c)
  · simp [h1, h2] at h
  · cases hae : s.authorizedCircles (tid, c) with
    | false => exact (h2 (by simp [hae])).elim
    | true  => rfl

/-- PER-CLASS PRICING STAMPED AT OPEN: a session opened with
    `class = SHARED` has `pricePerMb = circles[c].pricePerMbShared`
    AT THE TIME OF OPEN; a session opened with `class = INTERNAL`
    has `pricePerMb = circles[c].pricePerMbInternal`. -/
theorem open_session_stamps_per_class_price_shared
    (s s' : ProgramState) (caller : Addr) (tid : TailnetId)
    (sid : SessionId) (c : CircleId) (maxPay : Nat)
    (h : openSession s caller tid sid c SessionClass.shared maxPay = some s') :
    ∃ sess, s'.sessions sid = some sess ∧
            sess.class_ = SessionClass.shared ∧
            sess.pricePerMb = (s.circles c).pricePerMbShared := by
  unfold openSession at h
  by_cases h1 : ¬ s.members (tid, caller)
  · simp [h1] at h
  by_cases h2 : ¬ s.authorizedCircles (tid, c)
  · simp [h1, h2] at h
  by_cases h3 : ¬ circleIsActive s c
  · simp [h1, h2, h3] at h
  by_cases h4 : maxPay < s.params.minSessionDeposit
  · simp [h1, h2, h3, h4] at h
  by_cases h5 : (s.tailnets tid).treasury < maxPay
  · simp [h1, h2, h3, h4, h5] at h
  · simp [h1, h2, h3, h4, h5] at h
    subst h
    -- Provide the session record explicitly so the match reduces.
    refine ⟨{ tailnetId := tid,
              circle := c,
              opener := caller,
              deposit := maxPay,
              openedAt := s.currentEpoch,
              class_ := SessionClass.shared,
              pricePerMb := (s.circles c).pricePerMbShared,
              status := SessionStatus.open,
              operatorClaim := none,
              clientConfirm := none }, ?_, rfl, rfl⟩
    unfold Map.update; simp

/-- Per-class pricing, internal arm. -/
theorem open_session_stamps_per_class_price_internal
    (s s' : ProgramState) (caller : Addr) (tid : TailnetId)
    (sid : SessionId) (c : CircleId) (maxPay : Nat)
    (h : openSession s caller tid sid c SessionClass.internal maxPay = some s') :
    ∃ sess, s'.sessions sid = some sess ∧
            sess.class_ = SessionClass.internal ∧
            sess.pricePerMb = (s.circles c).pricePerMbInternal := by
  unfold openSession at h
  by_cases h1 : ¬ s.members (tid, caller)
  · simp [h1] at h
  by_cases h2 : ¬ s.authorizedCircles (tid, c)
  · simp [h1, h2] at h
  by_cases h3 : ¬ circleIsActive s c
  · simp [h1, h2, h3] at h
  by_cases h4 : maxPay < s.params.minSessionDeposit
  · simp [h1, h2, h3, h4] at h
  by_cases h5 : (s.tailnets tid).treasury < maxPay
  · simp [h1, h2, h3, h4, h5] at h
  · simp [h1, h2, h3, h4, h5] at h
    subst h
    refine ⟨{ tailnetId := tid,
              circle := c,
              opener := caller,
              deposit := maxPay,
              openedAt := s.currentEpoch,
              class_ := SessionClass.internal,
              pricePerMb := (s.circles c).pricePerMbInternal,
              status := SessionStatus.open,
              operatorClaim := none,
              clientConfirm := none }, ?_, rfl, rfl⟩
    unfold Map.update; simp

/-- `settleClaim` requires the caller to own the session's circle. -/
theorem settle_claim_requires_circle_owner
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch : Nat)
    (h : settleClaim s sid bytes caller epoch = some s') :
    ∀ prev, s.sessions sid = some prev →
      (s.circles prev.circle).owner = caller := by
  intro prev hprev
  unfold settleClaim at h
  rw [hprev] at h
  by_cases h1 : prev.status ≠ SessionStatus.open
  · simp [h1] at h
  by_cases h2 : (s.circles prev.circle).owner ≠ caller
  · simp [h1, h2] at h
  · exact Decidable.of_not_not h2

/-- Re-claim with same bytes is a no-op. -/
theorem settle_claim_idempotent_on_same_bytes
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch claimedAt : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (howner : (s.circles prev.circle).owner = caller)
    (hactive : circleIsActive s prev.circle = true)
    (hprior : prev.operatorClaim = some (bytes, claimedAt))
    (h : settleClaim s sid bytes caller epoch = some s') :
    s' = s := by
  unfold settleClaim at h
  rw [hsess] at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have howner' : ¬ (s.circles prev.circle).owner ≠ caller := by simp [howner]
  have hactive' : ¬ ¬ circleIsActive s prev.circle := by simp [hactive]
  simp only at h
  rw [hprior] at h
  simp [hopen', howner', hactive'] at h
  exact h.symm

/-- Equivocation refunds the deposit to the tailnet treasury and
    marks the session refunded. The actual slash is left to a
    follow-up `slash_double_sign` (chain can't verify off-chain
    signatures here). -/
theorem settle_claim_equivocation_refunds
    (s s' : ProgramState) (sid : SessionId) (bytes prevBytes : Nat)
    (caller : Addr) (epoch claimedAt : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (howner : (s.circles prev.circle).owner = caller)
    (hactive : circleIsActive s prev.circle = true)
    (hprior : prev.operatorClaim = some (prevBytes, claimedAt))
    (hdiff : prevBytes ≠ bytes)
    (h : settleClaim s sid bytes caller epoch = some s') :
    (∃ upd, s'.sessions sid = some upd ∧
            upd.status = SessionStatus.refunded) ∧
    (s'.tailnets prev.tailnetId).treasury =
      (s.tailnets prev.tailnetId).treasury + prev.deposit := by
  unfold settleClaim at h
  rw [hsess] at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have howner' : ¬ (s.circles prev.circle).owner ≠ caller := by simp [howner]
  have hactive' : ¬ ¬ circleIsActive s prev.circle := by simp [hactive]
  simp only at h
  rw [hprior] at h
  simp [hopen', howner', hactive', hdiff] at h
  subst h
  refine ⟨?_, ?_⟩
  · refine ⟨{ prev with status := SessionStatus.refunded }, ?_, rfl⟩
    unfold Map.update; simp [hprior]
  · unfold Map.update; simp

/-- `settleConfirm` may only be submitted by the opener. -/
theorem settle_confirm_only_opener
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch : Nat)
    (h : settleConfirm s sid bytes caller epoch = some s') :
    ∀ prev, s.sessions sid = some prev → caller = prev.opener := by
  intro prev hprev
  unfold settleConfirm at h
  rw [hprev] at h
  by_cases h1 : prev.status ≠ SessionStatus.open
  · simp [h1] at h
  by_cases h2 : caller ≠ prev.opener
  · simp [h1, h2] at h
  · exact Decidable.of_not_not h2

/-- Match on `settleConfirm` settles the session. The stamped
    `pricePerMb` is what's used. -/
theorem settle_confirm_match_settles
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch claimedAt : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (hcaller : caller = prev.opener)
    (hclaim : prev.operatorClaim = some (bytes, claimedAt))
    (h : settleConfirm s sid bytes caller epoch = some s') :
    ∃ upd, s'.sessions sid = some upd ∧
           upd.status = SessionStatus.settled ∧
           upd.clientConfirm = some (bytes, epoch) := by
  unfold settleConfirm at h
  rw [hsess] at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have hcaller' : ¬ caller ≠ prev.opener := by simp [hcaller]
  have hbytes_eq : ¬ bytes ≠ bytes := by simp
  simp only at h
  rw [hclaim] at h
  simp [hopen', hcaller', hbytes_eq] at h
  subst h
  refine ⟨{ prev with
              status := SessionStatus.settled,
              clientConfirm := some (bytes, epoch) }, ?_, rfl, rfl⟩
  unfold Map.update; simp [hclaim]

/-- Mismatch on `settleConfirm` records the dispute and leaves
    the session open. -/
theorem settle_confirm_mismatch_disputes
    (s s' : ProgramState) (sid : SessionId) (bytes opBytes : Nat)
    (caller : Addr) (epoch claimedAt : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (hcaller : caller = prev.opener)
    (hclaim : prev.operatorClaim = some (opBytes, claimedAt))
    (hdiff : opBytes ≠ bytes)
    (h : settleConfirm s sid bytes caller epoch = some s') :
    (∃ upd, s'.sessions sid = some upd ∧
            upd.status = SessionStatus.open ∧
            upd.clientConfirm = some (bytes, epoch)) ∧
    s'.tailnets = s.tailnets ∧
    s'.encEarn = s.encEarn ∧
    s'.programTreasury = s.programTreasury := by
  unfold settleConfirm at h
  rw [hsess] at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have hcaller' : ¬ caller ≠ prev.opener := by simp [hcaller]
  simp only at h
  rw [hclaim] at h
  simp [hopen', hcaller', hdiff] at h
  subst h
  refine ⟨?_, rfl, rfl, rfl⟩
  refine ⟨{ prev with clientConfirm := some (bytes, epoch) }, ?_, ?_, rfl⟩
  · unfold Map.update; simp [hclaim]
  · simp [hopen]

/-- INTERNAL FREE WHEN TOGGLE OFF: when a session opened as
    `class = INTERNAL` is confirmed, AND the tailnet has
    `chargeInternalTraffic = 0` (the default), the effective
    price is forced to zero — `total_paid = 0`, `enc_earn` does
    NOT change, and the full deposit is refunded to the tailnet
    treasury, regardless of `bytes_used`. -/
theorem settle_confirm_internal_free_when_toggle_off
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch claimedAt : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (hcaller : caller = prev.opener)
    (hclass : prev.class_ = SessionClass.internal)
    (htoggle : (s.tailnets prev.tailnetId).chargeInternalTraffic = 0)
    (hclaim : prev.operatorClaim = some (bytes, claimedAt))
    (h : settleConfirm s sid bytes caller epoch = some s') :
    (s'.tailnets prev.tailnetId).treasury =
      (s.tailnets prev.tailnetId).treasury + prev.deposit ∧
    s'.encEarn prev.circle = s.encEarn prev.circle ∧
    s'.programTreasury = s.programTreasury := by
  unfold settleConfirm at h
  rw [hsess] at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have hcaller' : ¬ caller ≠ prev.opener := by simp [hcaller]
  have hbytes_eq : ¬ bytes ≠ bytes := by simp
  simp only at h
  rw [hclaim] at h
  simp [hopen', hcaller', hbytes_eq] at h
  -- The settlement path uses class_ to pick the effective price.
  -- With class=INTERNAL and chargeInternalTraffic=0, effPrice=0,
  -- so totalRaw=0, totalPaid=0, fee=0, net=0, refund=deposit.
  rw [hclass] at h
  simp [htoggle] at h
  subst h
  -- Three goals after subst. The residual contains
  -- `if prev.deposit < 0 then prev.deposit else 0`. On Nat this
  -- is always 0 because of `Nat.not_lt_zero`.
  have hdepnn : ¬ prev.deposit < 0 := Nat.not_lt_zero _
  refine ⟨?_, ?_, ?_⟩
  · unfold Map.update; simp [hdepnn]
  · unfold Map.update; simp [hdepnn]
  · simp [hdepnn]

/-- `claimNoShow` refunds the deposit. -/
theorem claim_no_show_refunds_to_tailnet
    (s s' : ProgramState) (sid : SessionId) (caller : Addr)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (h : claimNoShow s sid caller = some s') :
    (s'.tailnets prev.tailnetId).treasury =
      (s.tailnets prev.tailnetId).treasury + prev.deposit ∧
    (∃ upd, s'.sessions sid = some upd ∧
            upd.status = SessionStatus.refunded) := by
  unfold claimNoShow at h
  rw [hsess] at h
  by_cases h1 : prev.status ≠ SessionStatus.open
  · simp [h1] at h
  by_cases h2 : caller ≠ prev.opener
  · simp [h1, h2] at h
  by_cases h3 :
      s.currentEpoch < prev.openedAt + s.params.sessionGraceEpochs
  · simp [h1, h2, h3] at h
  by_cases h4 : prev.operatorClaim ≠ none
  · simp [h1, h2, h3, h4] at h
  · simp [h1, h2, h3, h4] at h
    subst h
    refine ⟨?_, ?_⟩
    · unfold Map.update; simp
    · refine ⟨{ prev with status := SessionStatus.refunded }, ?_, rfl⟩
      unfold Map.update; simp

/-- `sweepExpiredSession` refunds after the extended grace and
    pays a bounty. -/
theorem sweep_expired_session_refunds
    (s s' : ProgramState) (sid : SessionId) (caller : Addr)
    (bounty : OctRaw) (prev : Session)
    (hsess : s.sessions sid = some prev)
    (h : sweepExpiredSession s sid caller = some (s', bounty)) :
    s.currentEpoch ≥
      prev.openedAt + s.params.sessionGraceEpochs *
                       s.params.sweepGraceMultiplier ∧
    bounty = prev.deposit * s.params.sweepBountyBps / 10000 ∧
    (s'.tailnets prev.tailnetId).treasury =
      (s.tailnets prev.tailnetId).treasury + (prev.deposit - bounty) := by
  unfold sweepExpiredSession at h
  rw [hsess] at h
  by_cases h1 : prev.status ≠ SessionStatus.open
  · simp [h1] at h
  by_cases h2 :
      s.currentEpoch <
        prev.openedAt + s.params.sessionGraceEpochs *
                         s.params.sweepGraceMultiplier
  · simp [h1, h2] at h
  · simp [h1, h2] at h
    obtain ⟨hs, hb⟩ := h
    refine ⟨Nat.le_of_not_lt h2, hb.symm, ?_⟩
    subst hs; subst hb; unfold Map.update; simp

-- ============================================================
-- Join tokens
-- ============================================================

theorem precommit_records_commit
    (s s' : ProgramState) (tid : TailnetId) (h : Bytes) (caller : Addr)
    (hcall : precommitJoinToken s tid h caller = some s') :
    (s.tailnets tid).owner = caller ∧
    s'.joinTokenCommits (tid, h) = true := by
  unfold precommitJoinToken at hcall
  by_cases h1 : (s.tailnets tid).owner = 0
  · simp [h1] at hcall
  by_cases h2 : (s.tailnets tid).owner ≠ caller
  · simp [h1, h2] at hcall
  by_cases h3 : s.joinTokenCommits (tid, h) = true
  · simp [h1, h2, h3] at hcall
  by_cases h4 : s.joinTokenRedeemed h = true
  · simp [h1, h2, h3, h4] at hcall
  · simp [h1, h2, h3, h4] at hcall
    subst hcall
    refine ⟨Decidable.of_not_not h2, ?_⟩
    unfold Map.update; simp

theorem join_token_preimage_match
    (s s' : ProgramState) (tid : TailnetId) (preimage : Bytes)
    (caller : Addr)
    (h : redeemJoinToken s tid preimage caller = some s') :
    s.joinTokenCommits (tid, sha256 preimage) = true := by
  unfold redeemJoinToken at h
  by_cases h1 : (s.tailnets tid).owner = 0
  · simp [h1] at h
  by_cases h2 : ¬ s.joinTokenCommits (tid, sha256 preimage)
  · simp [h1, h2] at h
  · cases hcomm : s.joinTokenCommits (tid, sha256 preimage) with
    | false => exact (h2 (by simp [hcomm])).elim
    | true  => rfl

theorem join_token_uniqueness
    (s s' : ProgramState) (tid : TailnetId) (preimage : Bytes)
    (caller : Addr)
    (h : redeemJoinToken s tid preimage caller = some s') :
    s'.joinTokenRedeemed (sha256 preimage) = true := by
  unfold redeemJoinToken at h
  by_cases h1 : (s.tailnets tid).owner = 0
  · simp [h1] at h
  by_cases h2 : ¬ s.joinTokenCommits (tid, sha256 preimage)
  · simp [h1, h2] at h
  by_cases h3 : s.joinTokenRedeemed (sha256 preimage)
  · simp [h1, h2, h3] at h
  by_cases h4 : s.members (tid, caller)
  · simp [h1, h2, h3, h4] at h
  · simp [h1, h2, h3, h4] at h
    subst h
    unfold Map.update; simp

theorem join_token_no_double_redeem
    (s s' : ProgramState) (tid : TailnetId) (preimage : Bytes)
    (caller : Addr)
    (hred : s.joinTokenRedeemed (sha256 preimage) = true)
    (h : redeemJoinToken s tid preimage caller = some s') :
    False := by
  unfold redeemJoinToken at h
  by_cases h1 : (s.tailnets tid).owner = 0
  · simp [h1] at h
  by_cases h2 : ¬ s.joinTokenCommits (tid, sha256 preimage)
  · simp [h1, h2] at h
  · simp [h1, h2, hred] at h

-- ============================================================
-- Earnings claim (PROOF GAP: FHE soundness — see AmlLink)
-- ============================================================

/-- `claim_earnings` requires the caller to own the circle. -/
theorem claim_earnings_requires_owner
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (amount : Nat) (proofOk : Prop) [Decidable proofOk]
    (h : claimEarnings s caller c amount proofOk = some s') :
    (s.circles c).owner = caller := by
  unfold claimEarnings at h
  by_cases h1 : (s.circles c).owner ≠ caller
  · simp [h1] at h
  · exact Decidable.of_not_not h1

/-- A successful claim implies the on-chain ledger equals the
    claimed amount (FHE soundness assumption). -/
theorem claim_earnings_requires_exact_match
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (amount : Nat) (proofOk : Prop) [Decidable proofOk]
    (h : claimEarnings s caller c amount proofOk = some s') :
    s.encEarn c = amount := by
  unfold claimEarnings at h
  by_cases h1 : (s.circles c).owner ≠ caller
  · simp [h1] at h
  by_cases h2 : s.circleSlashed c
  · simp [h1, h2] at h
  by_cases h3 : amount = 0
  · simp [h1, h2, h3] at h
  by_cases h4 : ¬ proofOk
  · simp [h1, h2, h3, h4] at h
  by_cases h5 : s.encEarn c ≠ amount
  · simp [h1, h2, h3, h4, h5] at h
  · exact Decidable.of_not_not h5

/-- After a successful claim, the earnings ledger is reset. -/
theorem claim_earnings_resets_enc_earn
    (s s' : ProgramState) (caller : Addr) (c : CircleId)
    (amount : Nat) (proofOk : Prop) [Decidable proofOk]
    (h : claimEarnings s caller c amount proofOk = some s') :
    s'.encEarn c = 0 := by
  unfold claimEarnings at h
  by_cases h1 : (s.circles c).owner ≠ caller
  · simp [h1] at h
  by_cases h2 : s.circleSlashed c
  · simp [h1, h2] at h
  by_cases h3 : amount = 0
  · simp [h1, h2, h3] at h
  by_cases h4 : ¬ proofOk
  · simp [h1, h2, h3, h4] at h
  by_cases h5 : s.encEarn c ≠ amount
  · simp [h1, h2, h3, h4, h5] at h
  · simp [h1, h2, h3, h4, h5] at h
    subst h
    unfold Map.update; simp

-- ============================================================
-- Governance (owner-only, bypasses pause)
-- ============================================================

theorem set_paused_owner_only
    (s s' : ProgramState) (caller : Addr) (v : Bool)
    (h : setPaused s caller v = some s') :
    caller = s.programOwner ∧
    s'.paused = v ∧
    s'.programOwner = s.programOwner ∧
    s'.programTreasury = s.programTreasury := by
  unfold setPaused at h
  by_cases h1 : caller ≠ s.programOwner
  · simp [h1] at h
  · simp [h1] at h
    subst h
    refine ⟨Decidable.of_not_not h1, rfl, rfl, rfl⟩

theorem transfer_ownership_rotates
    (s s' : ProgramState) (caller newOwner : Addr)
    (h : transferOwnership s caller newOwner = some s') :
    caller = s.programOwner ∧
    s'.programOwner = newOwner := by
  unfold transferOwnership at h
  by_cases h1 : caller ≠ s.programOwner
  · simp [h1] at h
  · simp [h1] at h
    subst h
    exact ⟨Decidable.of_not_not h1, rfl⟩

theorem set_params_owner_only
    (s s' : ProgramState) (caller : Addr) (p : Params)
    (h : setParams s caller p = some s') :
    caller = s.programOwner ∧
    s'.params = p := by
  unfold setParams at h
  by_cases h1 : caller ≠ s.programOwner
  · simp [h1] at h
  by_cases h2 : p.minSessionDeposit = 0
  · simp [h1, h2] at h
  by_cases h3 : p.minTailnetDeposit = 0
  · simp [h1, h2, h3] at h
  by_cases h4 : p.sessionGraceEpochs = 0
  · simp [h1, h2, h3, h4] at h
  by_cases h5 : p.sweepGraceMultiplier = 0
  · simp [h1, h2, h3, h4, h5] at h
  by_cases h6 : p.sweepBountyBps > 1000
  · simp [h1, h2, h3, h4, h5, h6] at h
  by_cases h7 : p.minCircleStake < 100000000
  · simp [h1, h2, h3, h4, h5, h6, h7] at h
  by_cases h8 : p.unbondGraceEpochs < 1000
  · simp [h1, h2, h3, h4, h5, h6, h7, h8] at h
  by_cases h9 : p.slashBurnBps < 5000
  · simp [h1, h2, h3, h4, h5, h6, h7, h8, h9] at h
  by_cases h10 : p.slashBurnBps + p.slashBountyBps ≠ 10000
  · simp [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10] at h
  by_cases h11 : p.protocolFeeBps > 200
  · simp [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11] at h
  · simp [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11] at h
    subst h
    refine ⟨Decidable.of_not_not h1, rfl⟩

theorem withdraw_program_treasury_conserves
    (s s' : ProgramState) (caller to : Addr) (amount paid : OctRaw)
    (h : withdrawProgramTreasury s caller to amount = some (s', paid)) :
    caller = s.programOwner ∧
    paid = amount ∧
    s'.programTreasury + amount = s.programTreasury ∧
    s.programTreasury ≥ amount := by
  unfold withdrawProgramTreasury at h
  by_cases h1 : caller ≠ s.programOwner
  · simp [h1] at h
  by_cases h2 : amount = 0
  · simp [h1, h2] at h
  by_cases h3 : s.programTreasury < amount
  · simp [h1, h2, h3] at h
  · simp [h1, h2, h3] at h
    obtain ⟨hs, hp⟩ := h
    have hge : s.programTreasury ≥ amount := Nat.le_of_not_lt h3
    refine ⟨Decidable.of_not_not h1, hp.symm, ?_, hge⟩
    have hpt : s'.programTreasury = s.programTreasury - amount := by
      rw [← hs]
    rw [hpt]
    exact Nat.sub_add_cancel hge

end OctraVPN_V2
