/-!
# Entrypoints, modeled as state-transition functions (tailnet edition).

Each function corresponds to one entrypoint in `program/main.aml`.
Successful execution returns `some newState`; reverts are encoded as `none`.

`settleSession` is decomposed into a `creditFold` helper + a final
`commitSettlement` so the lemmas in `Lemmas.lean` can reason about each
piece in isolation. The fold body mutates `encEarn` only; the session
record is updated atomically in `commitSettlement`.
-/

import OctraVPN.State

namespace OctraVPN

variable [DecidableEq Bytes]

/-- Register an endpoint. Caller must be an Octra protocol validator
    (the chain-level gate); we model that via the oracle in state. -/
def registerEndpoint
    (s : ProgramState) (caller : Addr)
    (endpoint region : String) (price : Nat) : Option ProgramState :=
  if (s.endpoints caller).active then none
  else if ¬ s.isOctraValidator caller then none
  else if price = 0 then none
  else
    let rec : EndpointRecord :=
      { EndpointRecord.empty with
        active := true,
        endpoint := endpoint,
        region := region,
        pricePerMb := price,
        registeredAt := s.currentEpoch }
    some { s with endpoints := s.endpoints.update caller rec }

/-- Retire an endpoint. -/
def retireEndpoint (s : ProgramState) (caller : Addr) : Option ProgramState :=
  let rec := s.endpoints caller
  if ¬ rec.active then none
  else
    let rec' := { rec with active := false }
    some { s with endpoints := s.endpoints.update caller rec' }

/-- Create a tailnet with an initial treasury. -/
def createTailnet
    (s : ProgramState) (owner : Addr) (tailnetId : Bytes) (deposit : Nat) :
    Option ProgramState :=
  let existing := s.tailnets tailnetId
  if existing.owner ≠ 0 then none
  else if deposit < s.params.minTailnetDeposit then none
  else
    let t : Tailnet :=
      { Tailnet.empty with
        owner := owner,
        treasury := deposit,
        members := [owner],
        createdAt := s.currentEpoch }
    some { s with tailnets := s.tailnets.update tailnetId t }

/-- Add a member to a tailnet. Owner-gated. -/
def addMember
    (s : ProgramState) (tailnetId : Bytes) (caller member : Addr) :
    Option ProgramState :=
  let t := s.tailnets tailnetId
  if t.owner ≠ caller then none
  else if member ∈ t.members then none
  else
    let t' := { t with members := member :: t.members }
    some { s with tailnets := s.tailnets.update tailnetId t' }

/-- Deposit OU into a tailnet treasury. -/
def depositToTailnet
    (s : ProgramState) (tailnetId : Bytes) (amount : Nat) :
    Option ProgramState :=
  if amount = 0 then none
  else
    let t := s.tailnets tailnetId
    if t.owner = 0 then none
    else
      let t' := { t with treasury := t.treasury + amount }
      some { s with tailnets := s.tailnets.update tailnetId t' }

/-- Open a session against a tailnet. -/
def openSession
    (s : ProgramState) (caller : Addr) (tailnetId sid : Bytes)
    (route : List (Addr × Nat)) (deposit : Nat) : Option ProgramState :=
  let t := s.tailnets tailnetId
  if caller ∉ t.members then none
  else if deposit < s.params.minSessionDeposit then none
  else if t.treasury < deposit then none
  else
    let t' := { t with treasury := t.treasury - deposit }
    let sess : Session :=
      { tailnetId := tailnetId,
        deposit := deposit,
        openedAt := s.currentEpoch,
        receiptSeq := 0,
        status := SessionStatus.open,
        route := route,
        paidBytes := 0 }
    some { s with
      tailnets := s.tailnets.update tailnetId t',
      sessions := s.sessions.update sid (some sess) }

/-- Total payout for a settlement of `bytesUsed` along `route`. -/
def computeTotalPaid
    (s : ProgramState) (route : List (Addr × Nat)) (bytesUsed : Nat) : Nat :=
  route.foldl
    (fun acc entry =>
      let v := s.endpoints entry.fst
      let weighted := v.pricePerMb * entry.snd / 10000
      acc + weighted * bytesUsed)
    0

/-- Apply the per-hop Pedersen-earnings credit to `encEarn`. This is the
    only field the route fold touches. -/
def creditEarnings
    (s : ProgramState) (route : List (Addr × Nat)) (bytesUsed : Nat) :
    ProgramState :=
  route.foldl
    (fun acc entry =>
      let v := acc.endpoints entry.fst
      let weighted := v.pricePerMb * entry.snd / 10000
      let credit := weighted * bytesUsed
      let cur := acc.encEarn entry.fst
      { acc with encEarn := acc.encEarn.update entry.fst (cur + credit) })
    s

/-- Atomic commit step: mark the session settled, advance `receiptSeq`,
    return the deposit refund to the tailnet treasury. The session
    record at `sid` always becomes `(prev with status := settled,
    receiptSeq := newSeq, paidBytes := bytesUsed)`. -/
def commitSettlement
    (s : ProgramState) (sid : Bytes) (prev : Session) (newSeq bytesUsed refund : Nat) :
    ProgramState :=
  let upd : Session :=
    { prev with
      status := SessionStatus.settled,
      receiptSeq := newSeq,
      paidBytes := bytesUsed }
  let t := s.tailnets prev.tailnetId
  let t' := { t with treasury := t.treasury + refund }
  { s with
    tailnets := s.tailnets.update prev.tailnetId t',
    sessions := s.sessions.update sid (some upd) }

/-- Settle a session — composition of `creditEarnings` + `commitSettlement`. -/
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
      let totalPaid := computeTotalPaid s sess.route bytesUsed
      if totalPaid > sess.deposit then none
      else
        let refund := sess.deposit - totalPaid
        let s' := creditEarnings s sess.route bytesUsed
        some (commitSettlement s' sid sess newSeq bytesUsed refund)

end OctraVPN
