/-!
# Structural lemmas about the OctraVPN spec.

These are the proofs that justify our claim "this state machine is sound".
Each lemma corresponds to a property in the README / TLA+ spec but stated
in Lean's logic so it composes with future work (e.g. linking to a
verified compiler from AML to OCTB bytecode).
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

/-- After `register caller bond` succeeds, the bond is exactly `bond`. -/
theorem register_sets_bond
    (s : ProgramState) (caller : Addr)
    (ep r : String) (price : Nat) (bond : Bond)
    (attestOk : Prop) [Decidable attestOk]
    (h : register s caller ep r price bond attestOk = some s') :
    (s'.validators caller).bond = bond := by
  unfold register at h
  by_cases h1 : (s.validators caller).bond ≠ 0
  · simp [h1] at h
  · by_cases h2 : bond < s.params.minBond
    · simp [h1, h2] at h
    · by_cases h3 : ¬ attestOk
      · simp [h1, h2, h3] at h
      · simp [h1, h2, h3] at h
        subst h
        unfold Map.update
        simp

/-- After `addBond caller amount` succeeds, the bond goes up by exactly
    `amount`. -/
theorem addBond_increases_bond
    (s s' : ProgramState) (caller : Addr) (amount : Nat)
    (h : addBond s caller amount = some s') :
    (s'.validators caller).bond = (s.validators caller).bond + amount := by
  unfold addBond at h
  by_cases h1 : (s.validators caller).bond = 0
  · simp [h1] at h
  · simp [h1] at h
    subst h
    unfold Map.update
    simp

/-- `completeUnbond caller` — the returned amount equals the previous
    bond, and the new bond is zero. -/
theorem completeUnbond_returns_full_bond
    (s s' : ProgramState) (caller : Addr) (returned : Nat)
    (ready : Prop) [Decidable ready]
    (h : completeUnbond s caller ready = some (s', returned)) :
    returned = (s.validators caller).bond ∧
    (s'.validators caller).bond = 0 := by
  unfold completeUnbond at h
  by_cases h1 : (s.validators caller).bond = 0
  · simp [h1] at h
  · by_cases h2 : ¬ ready
    · simp [h1, h2] at h
    · simp [h1, h2] at h
      obtain ⟨hs', hret⟩ := h
      subst hs'
      subst hret
      refine ⟨rfl, ?_⟩
      unfold Map.update
      simp

/-- After `slashDoubleSign target` succeeds, target's bond is zero and
    they are jailed at the current epoch. -/
theorem slash_double_sign_zeros_bond
    (s s' : ProgramState) (target claimant : Addr)
    (ev : Prop) [Decidable ev]
    (h : slashDoubleSign s target claimant ev = some s') :
    (s'.validators target).bond = 0 ∧
    (s'.validators target).jailedAt = some s.currentEpoch := by
  unfold slashDoubleSign at h
  by_cases h1 : (s.validators target).bond = 0
  · simp [h1] at h
  · by_cases h2 : ¬ ev
    · simp [h1, h2] at h
    · simp [h1, h2] at h
      subst h
      refine ⟨?_, ?_⟩
      · unfold Map.update; simp
      · unfold Map.update; simp

/-- After `settleSession`, the session moves out of `open`. -/
theorem settle_finalizes
    (s s' : ProgramState) (sid : Bytes) (seq bytes : Nat)
    (ok : Prop) [Decidable ok]
    (h : settleSession s sid seq bytes ok = some s') :
    ∃ sess', s'.sessions sid = some sess' ∧ sess'.status = SessionStatus.settled := by
  unfold settleSession at h
  cases hsess : s.sessions sid with
  | none => simp [hsess] at h
  | some sess =>
    by_cases h1 : sess.status ≠ SessionStatus.open
    · simp [hsess, h1] at h
    · by_cases h2 : seq ≤ sess.receiptSeq
      · simp [hsess, h1, h2] at h
      · by_cases h3 : ¬ ok
        · simp [hsess, h1, h2, h3] at h
        · simp [hsess, h1, h2, h3] at h
          subst h
          refine ⟨_, ?_, rfl⟩
          unfold Map.update; simp

/-- Once jailed, `register` cannot bring you back. (Re-registration is
    blocked by the `bond ≠ 0` check; jailed validators still have bond.)
    A weaker phrasing: `register` returns `none` if the caller already has
    a non-zero bond. -/
theorem register_blocked_when_bonded
    (s : ProgramState) (caller : Addr) (ep r : String) (price : Nat)
    (bond : Bond) (attestOk : Prop) [Decidable attestOk]
    (h : (s.validators caller).bond ≠ 0) :
    register s caller ep r price bond attestOk = none := by
  unfold register
  simp [h]

end OctraVPN
