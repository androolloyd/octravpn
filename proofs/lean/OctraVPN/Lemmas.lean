/-!
# Structural lemmas about the OctraVPN spec (tailnet edition).

These justify "this state machine is sound" — each lemma corresponds to a
property in the README / TLA+ spec but stated in Lean's logic so it
composes with future work (e.g. linking to a verified AML compiler).

The settle-related proofs use the `commitSettlement` decomposition in
`Entrypoints.lean`. The fold over `route` only touches `encEarn`, so the
session record post-settle is exactly what `commitSettlement` writes —
making the receipt-monotonicity and finalisation lemmas one-liners.
-/

import OctraVPN.State
import OctraVPN.Entrypoints

namespace OctraVPN

variable [DecidableEq Bytes]

/-- `Map.update_eq`: trivial helper, used pervasively. -/
theorem Map.update_eq {α β} [DecidableEq α]
    (m : Map α β) (k : α) (v : β) : (m.update k v) k = v := by
  unfold Map.update; simp

/-- `Map.update_ne`: untouched keys are unchanged. -/
theorem Map.update_ne {α β} [DecidableEq α]
    (m : Map α β) (k k' : α) (v : β) (h : k' ≠ k) :
    (m.update k v) k' = m k' := by
  unfold Map.update; simp [h]

/-- After `registerEndpoint` succeeds, the caller must have been an
    Octra protocol validator. This is the central security gate. -/
theorem register_requires_octra_validator
    (s s' : ProgramState) (caller : Addr)
    (ep r : String) (price : Nat)
    (h : registerEndpoint s caller ep r price = some s') :
    s.isOctraValidator caller := by
  unfold registerEndpoint at h
  by_cases h1 : (s.endpoints caller).active
  · simp [h1] at h
  · by_cases h2 : ¬ s.isOctraValidator caller
    · simp [h1, h2] at h
    · push_neg at h2
      exact h2

/-- After `registerEndpoint` succeeds, the endpoint is active. -/
theorem register_sets_active
    (s s' : ProgramState) (caller : Addr)
    (ep r : String) (price : Nat)
    (h : registerEndpoint s caller ep r price = some s') :
    (s'.endpoints caller).active = true := by
  unfold registerEndpoint at h
  by_cases h1 : (s.endpoints caller).active
  · simp [h1] at h
  · by_cases h2 : ¬ s.isOctraValidator caller
    · simp [h1, h2] at h
    · by_cases h3 : price = 0
      · simp [h1, h2, h3] at h
      · simp [h1, h2, h3] at h
        subst h
        unfold Map.update
        simp

/-- `retireEndpoint` deactivates the endpoint. -/
theorem retire_clears_active
    (s s' : ProgramState) (caller : Addr)
    (h : retireEndpoint s caller = some s') :
    (s'.endpoints caller).active = false := by
  unfold retireEndpoint at h
  by_cases h1 : ¬ (s.endpoints caller).active
  · simp [h1] at h
  · simp [h1] at h
    subst h
    unfold Map.update
    simp

/-- Creating a tailnet seeds the treasury exactly with the deposited
    amount and the owner is the first (and only) member. -/
theorem create_tailnet_seeds_treasury
    (s s' : ProgramState) (owner : Addr) (tid : Bytes) (deposit : Nat)
    (h : createTailnet s owner tid deposit = some s') :
    (s'.tailnets tid).treasury = deposit ∧
    (s'.tailnets tid).owner = owner ∧
    owner ∈ (s'.tailnets tid).members := by
  unfold createTailnet at h
  by_cases h1 : (s.tailnets tid).owner ≠ 0
  · simp [h1] at h
  · by_cases h2 : deposit < s.params.minTailnetDeposit
    · simp [h1, h2] at h
    · simp [h1, h2] at h
      subst h
      refine ⟨?_, ?_, ?_⟩
      all_goals (unfold Map.update; simp [List.mem_cons])

/-- The credit fold touches only `encEarn`; in particular, the session
    map and tailnet map are unchanged. -/
theorem creditEarnings_preserves_sessions
    (s : ProgramState) (route : List (Addr × Nat)) (bytesUsed : Nat) :
    (creditEarnings s route bytesUsed).sessions = s.sessions := by
  unfold creditEarnings
  induction route generalizing s with
  | nil => simp
  | cons hd tl ih =>
      simp [List.foldl, ih]

theorem creditEarnings_preserves_tailnets
    (s : ProgramState) (route : List (Addr × Nat)) (bytesUsed : Nat) :
    (creditEarnings s route bytesUsed).tailnets = s.tailnets := by
  unfold creditEarnings
  induction route generalizing s with
  | nil => simp
  | cons hd tl ih =>
      simp [List.foldl, ih]

/-- `commitSettlement` writes exactly the expected session record. -/
theorem commitSettlement_sets_session
    (s : ProgramState) (sid : Bytes) (prev : Session)
    (newSeq bytesUsed refund : Nat) :
    let s' := commitSettlement s sid prev newSeq bytesUsed refund
    s'.sessions sid =
      some { prev with
        status := SessionStatus.settled,
        receiptSeq := newSeq,
        paidBytes := bytesUsed } := by
  intro s'
  show (commitSettlement s sid prev newSeq bytesUsed refund).sessions sid = _
  unfold commitSettlement
  unfold Map.update
  simp

/-- Settling a session monotonically advances `receiptSeq`. -/
theorem settle_advances_seq
    (s s' : ProgramState) (sid : Bytes) (newSeq bytes : Nat)
    (ok : Prop) [Decidable ok]
    (h : settleSession s sid newSeq bytes ok = some s') :
    ∀ prev, s.sessions sid = some prev →
      newSeq > prev.receiptSeq ∧
      (∃ new, s'.sessions sid = some new ∧ new.receiptSeq = newSeq) := by
  intro prev hprev
  unfold settleSession at h
  rw [hprev] at h
  by_cases h1 : prev.status ≠ SessionStatus.open
  · simp [h1] at h
  by_cases h2 : newSeq ≤ prev.receiptSeq
  · simp [h1, h2] at h
  by_cases h3 : ¬ ok
  · simp [h1, h2, h3] at h
  -- Total-paid branch.
  by_cases h4 : computeTotalPaid s prev.route bytes > prev.deposit
  · simp [h1, h2, h3, h4] at h
  · simp [h1, h2, h3, h4] at h
    push_neg at h2
    refine ⟨h2, ?_⟩
    subst h
    refine ⟨_, ?_, rfl⟩
    -- s' = commitSettlement (creditEarnings s prev.route bytes) sid prev newSeq bytes refund
    -- s'.sessions sid = some upd by commitSettlement_sets_session.
    exact commitSettlement_sets_session _ _ _ _ _ _

/-- After settling, the session is in `settled` status. -/
theorem settle_finalizes
    (s s' : ProgramState) (sid : Bytes) (newSeq bytes : Nat)
    (ok : Prop) [Decidable ok]
    (h : settleSession s sid newSeq bytes ok = some s') :
    ∃ sess', s'.sessions sid = some sess' ∧ sess'.status = SessionStatus.settled := by
  unfold settleSession at h
  cases hprev : s.sessions sid with
  | none => rw [hprev] at h; simp at h
  | some prev =>
    rw [hprev] at h
    by_cases h1 : prev.status ≠ SessionStatus.open
    · simp [h1] at h
    by_cases h2 : newSeq ≤ prev.receiptSeq
    · simp [h1, h2] at h
    by_cases h3 : ¬ ok
    · simp [h1, h2, h3] at h
    by_cases h4 : computeTotalPaid s prev.route bytes > prev.deposit
    · simp [h1, h2, h3, h4] at h
    · simp [h1, h2, h3, h4] at h
      subst h
      refine ⟨_, commitSettlement_sets_session _ _ _ _ _ _, rfl⟩

/-- Tailnet treasury never decreases on settle: the deposit was locked
    at `openSession`; settlement returns the unspent portion. The
    invariant we prove here is structural: settling adds `refund =
    deposit - totalPaid` to the treasury. -/
theorem settle_returns_refund_to_treasury
    (s s' : ProgramState) (sid : Bytes) (newSeq bytes : Nat)
    (ok : Prop) [Decidable ok]
    (h : settleSession s sid newSeq bytes ok = some s') :
    ∀ prev, s.sessions sid = some prev →
      let total := computeTotalPaid s prev.route bytes
      total ≤ prev.deposit ∧
      (s'.tailnets prev.tailnetId).treasury =
        (s.tailnets prev.tailnetId).treasury + (prev.deposit - total) := by
  intro prev hprev
  unfold settleSession at h
  rw [hprev] at h
  by_cases h1 : prev.status ≠ SessionStatus.open
  · simp [h1] at h
  by_cases h2 : newSeq ≤ prev.receiptSeq
  · simp [h1, h2] at h
  by_cases h3 : ¬ ok
  · simp [h1, h2, h3] at h
  by_cases h4 : computeTotalPaid s prev.route bytes > prev.deposit
  · simp [h1, h2, h3, h4] at h
  · simp [h1, h2, h3, h4] at h
    push_neg at h4
    refine ⟨h4, ?_⟩
    subst h
    -- s' = commitSettlement (creditEarnings s prev.route bytes) sid prev newSeq bytes
    --                       (prev.deposit - computeTotalPaid s prev.route bytes)
    -- The tailnets map of the credit-fold result equals s.tailnets.
    show ((commitSettlement (creditEarnings s prev.route bytes) sid prev newSeq bytes
            (prev.deposit - computeTotalPaid s prev.route bytes)).tailnets
              prev.tailnetId).treasury = _
    unfold commitSettlement
    rw [creditEarnings_preserves_tailnets s prev.route bytes]
    unfold Map.update
    simp

end OctraVPN
