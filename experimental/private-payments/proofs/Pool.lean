import Lean

/-!
Abstract value/deadline model for the experimental shielded pool.
`Conserves` and input membership/uniqueness are hypotheses supplied by a sound
proof verifier, not claims proved here about Poseidon, Groth16, AML or the VM.
The actual compiled Circle/value/proof implementation is tested separately.
-/
namespace ShieldedPool

structure State where
  custody : Nat
  unspent : Nat
  deriving DecidableEq

structure Transfer where
  consumed : Nat
  created : Nat
  deposit : Nat
  withdraw : Nat
  validFrom : Nat
  expires : Nat

def Conserves (t : Transfer) : Prop :=
  t.consumed + t.deposit = t.created + t.withdraw

instance (t : Transfer) : Decidable (Conserves t) :=
  inferInstanceAs (Decidable (t.consumed + t.deposit = t.created + t.withdraw))

def next (s : State) (t : Transfer) : State :=
  { custody := s.custody + t.deposit - t.withdraw,
    unspent := s.unspent - t.consumed + t.created }

def submit (s : State) (t : Transfer) (now : Nat) : Option State :=
  if t.validFrom ≤ now ∧ now < t.expires ∧
      t.consumed ≤ s.unspent ∧ Conserves t then some (next s t)
  else none

def commit (s : State) (result : Option State) : State := result.getD s

theorem preserves_backing (s : State) (t : Transfer)
    (backed : s.custody = s.unspent) (available : t.consumed ≤ s.unspent)
    (proof : Conserves t) :
    (next s t).custody = (next s t).unspent := by
  unfold next Conserves at *
  simp only at *
  omega

theorem withdrawal_fits_custody (s : State) (t : Transfer)
    (backed : s.custody = s.unspent) (available : t.consumed ≤ s.unspent)
    (proof : Conserves t) : t.withdraw ≤ s.custody + t.deposit := by
  unfold Conserves at proof
  omega

theorem expiry_rejects (s : State) (t : Transfer) (now : Nat)
    (expired : t.expires ≤ now) : submit s t now = none := by
  simp [submit, Nat.not_lt.mpr expired]

theorem expiry_preserves_funds (s : State) (t : Transfer) (now : Nat)
    (expired : t.expires ≤ now) : commit s (submit s t now) = s := by
  rw [expiry_rejects s t now expired]
  rfl

theorem no_protocol_commission (s : State) (t : Transfer)
    (backed : s.custody = s.unspent) (available : t.consumed ≤ s.unspent)
    (proof : Conserves t) :
    (next s t).custody + t.withdraw = s.custody + t.deposit := by
  have h := withdrawal_fits_custody s t backed available proof
  simp only [next]
  omega

-- Withdrawing all remaining available notes requires no new note capacity and
-- no delay. Earlier final purchases are already excluded from s.unspent.
theorem full_exit (s : State) (backed : s.custody = s.unspent) :
    let t : Transfer := {
      consumed := s.unspent
      created := 0
      deposit := 0
      withdraw := s.unspent
      validFrom := 7
      expires := 8 }
    submit s t 7 = some { custody := 0, unspent := 0 } := by
  simp [submit, Conserves, next, backed]

end ShieldedPool
