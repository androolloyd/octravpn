/-!
# Entrypoints, modeled as state-transition functions.

These are *spec*-level, not the AML source. Each function corresponds to
one entrypoint in `program/main.aml`. We model successful execution; the
revert paths are encoded as `Option ProgramState` returning `none`.
-/

import OctraVPN.State

namespace OctraVPN

variable [DecidableEq Bytes]

/-- Register a validator: only valid if not already registered, bond
    meets minimum, and (modeled as a hypothesis) the attestation
    signature verifies. -/
def register
    (s : ProgramState) (caller : Addr)
    (endpoint region : String) (price : Nat) (bond : Bond)
    (attestOk : Prop)
    [Decidable attestOk] : Option ProgramState :=
  if (s.validators caller).bond ≠ 0 then none
  else if bond < s.params.minBond then none
  else if ¬ attestOk then none
  else
    let rec : ValidatorRecord :=
      { ValidatorRecord.empty with
        bond := bond,
        endpoint := endpoint,
        region := region,
        pricePerMb := price,
        registeredAt := s.currentEpoch,
        lastAttestEpoch := s.currentEpoch }
    some { s with validators := s.validators.update caller rec }

/-- Add to existing bond. -/
def addBond (s : ProgramState) (caller : Addr) (amount : Nat) :
    Option ProgramState :=
  let rec := s.validators caller
  if rec.bond = 0 then none
  else
    let rec' := { rec with bond := rec.bond + amount }
    some { s with validators := s.validators.update caller rec' }

/-- Refresh attestation. -/
def refreshAttestation
    (s : ProgramState) (caller : Addr) (attestOk : Prop)
    [Decidable attestOk] : Option ProgramState :=
  let rec := s.validators caller
  if rec.bond = 0 then none
  else if ¬ attestOk then none
  else
    let unjailed :=
      if rec.bond ≥ s.params.minBond then none else rec.jailedAt
    let rec' := { rec with
      lastAttestEpoch := s.currentEpoch,
      jailedAt := unjailed }
    some { s with validators := s.validators.update caller rec' }

/-- Complete unbond — returns full remaining bond (we model the timer as
    a hypothesis `unbondReady`). -/
def completeUnbond
    (s : ProgramState) (caller : Addr) (unbondReady : Prop)
    [Decidable unbondReady] : Option (ProgramState × Nat) :=
  let rec := s.validators caller
  if rec.bond = 0 then none
  else if ¬ unbondReady then none
  else
    let returned := rec.bond
    let rec' := { rec with bond := 0, unbondRequest := none }
    some ({ s with validators := s.validators.update caller rec' }, returned)

/-- Settle a session. We assume signature/FHE host calls succeed
    (`receiptOk`). The settlement increases each route node's earnings
    by `(price × split_bps × bytes / 10000)`. -/
def settleSession
    (s : ProgramState) (sid : Bytes) (newSeq : Nat) (bytesUsed : Nat)
    (receiptOk : Prop) [Decidable receiptOk] : Option ProgramState :=
  match s.sessions sid with
  | none => none
  | some sess =>
    if sess.status ≠ SessionStatus.open then none
    else if newSeq ≤ sess.receiptSeq then none
    else if ¬ receiptOk then none
    else
      let s' := sess.route.foldl (fun acc (entry : Addr × Nat) =>
        let v := acc.validators entry.fst
        let weighted := v.pricePerMb * entry.snd / 10000
        let credit := weighted * bytesUsed
        let cur := acc.encEarn entry.fst
        { acc with encEarn := acc.encEarn.update entry.fst (cur + credit) }
      ) s
      let upd : Session := { sess with
        status := SessionStatus.settled,
        receiptSeq := newSeq,
        paidBytes := bytesUsed }
      some { s' with sessions := s'.sessions.update sid (some upd) }

/-- Slash a validator for double-signing receipts (modeled by the
    `evidence` hypothesis). Zeros bond, jails the validator, distributes
    the slashed amount per the params. -/
def slashDoubleSign
    (s : ProgramState) (target : Addr) (claimant : Addr)
    (evidence : Prop) [Decidable evidence] : Option ProgramState :=
  let rec := s.validators target
  if rec.bond = 0 then none
  else if ¬ evidence then none
  else
    let amount := rec.bond
    let bountyAmt := amount * s.params.slashBountyBps / 10000
    let burnAmt := amount * s.params.slashBurnBps / 10000
    let tresAmt := amount - bountyAmt - burnAmt
    let rec' := { rec with bond := 0, jailedAt := some s.currentEpoch }
    some { s with
      validators := s.validators.update target rec',
      treasury := s.treasury + tresAmt,
      burned := s.burned + burnAmt }

end OctraVPN
