/-!
Safety model for the governed v4 candidate's stake/session lock.
This is an abstract transition model, not extraction or a proof of compiled AML.
Real-VM regression tests exercise the actual AML guards separately.
-/
namespace OctraVPN_V4
structure StakeState where
  active : Bool
  bond : Nat
  pending : Nat
  unlock : Nat
  outstanding : Nat
  earned : Nat
  deriving DecidableEq, Repr

def beginUnbond (s : StakeState) (now grace : Nat) : Option StakeState :=
  if s.active then none
  else if s.bond = 0 then none
  else if s.pending ≠ 0 then none
  else some { s with bond := 0, pending := s.bond, unlock := now + grace }

def finalizeUnbond (s : StakeState) (now : Nat) : Option (StakeState × Nat) :=
  if s.active then none
  else if s.outstanding ≠ 0 then none
  else if s.pending = 0 then none
  else if now < s.unlock then none
  else some ({ s with pending := 0, unlock := 0 }, s.pending)

def closeSession (s : StakeState) : Option StakeState :=
  if s.outstanding = 0 then none
  else some { s with outstanding := s.outstanding - 1 }

theorem active_cannot_unbond (s : StakeState) (now grace : Nat)
    (h : s.active = true) : beginUnbond s now grace = none := by
  simp [beginUnbond, h]

theorem active_cannot_finalize (s : StakeState) (now : Nat)
    (h : s.active = true) : finalizeUnbond s now = none := by
  simp [finalizeUnbond, h]

theorem funded_sessions_keep_stake_locked (s : StakeState) (now : Nat)
    (h : s.outstanding ≠ 0) : finalizeUnbond s now = none := by
  simp [finalizeUnbond, h]

theorem grace_keeps_stake_locked (s : StakeState) (now : Nat)
    (h : now < s.unlock) : finalizeUnbond s now = none := by
  simp [finalizeUnbond, h]

theorem unbond_conserves_stake (s s' : StakeState) (now grace : Nat)
    (h : beginUnbond s now grace = some s') :
    s'.bond + s'.pending = s.bond + s.pending := by
  unfold beginUnbond at h
  split at h <;> simp_all
  split at h <;> simp_all
  rcases h with ⟨_, rfl⟩
  simp_all

theorem closing_preserves_earned_funds (s s' : StakeState)
    (h : closeSession s = some s') : s'.earned = s.earned := by
  unfold closeSession at h
  split at h <;> simp_all
  subst s'
  rfl
end OctraVPN_V4
