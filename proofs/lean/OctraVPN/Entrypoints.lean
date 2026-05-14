import OctraVPN.State

/-!
# Entrypoints, modeled as state-transition functions (v1).

Each function corresponds to one entrypoint in `program/main.aml`.
Successful execution returns `some newState`; reverts are encoded as
`none`.

The v1 model is single-hop with validator-only `settleSession`:
- `openSession` records the configured exit, not a route.
- `settleSession` requires `caller = sess.exit` and applies the
  payment ceiling `bytesUsed * pricePerMb ≤ deposit`.
- `claimEarnings` takes an abstract `proofOk : Prop` standing in for
  the on-chain `fhe_verify_zero(pk, delta, proof)` check.
- `govSlashOperator` is owner-gated (no in-AML signature
  verification).
-/

namespace OctraVPN

-- Nat has DecidableEq built-in; no auxiliary variable needed.

-- ============================================================
-- Operator stake lifecycle
-- ============================================================

/-- Bond `amount > 0` of stake for the caller. -/
def bondEndpoint (s : ProgramState) (caller : Addr) (amount : OctRaw) :
    Option ProgramState :=
  if amount = 0 then none
  else if s.endpointSlashed caller then none
  else if (s.endpointUnbonding caller).stake ≠ 0 then none
  else
    let cur := s.endpointStake caller
    some { s with endpointStake := s.endpointStake.update caller (cur + amount) }

/-- Begin unbonding the caller's entire stake. -/
def unbondEndpoint (s : ProgramState) (caller : Addr) : Option ProgramState :=
  let amt := s.endpointStake caller
  if amt = 0 then none
  else if (s.endpointUnbonding caller).stake ≠ 0 then none
  else
    let unlock := s.currentEpoch + s.params.unbondGraceEpochs
    let unb : Unbonding := { stake := amt, unlockEpoch := unlock }
    let epRec := s.endpoints caller
    let s1 := { s with
                endpointUnbonding := s.endpointUnbonding.update caller unb,
                endpointStake := s.endpointStake.update caller 0 }
    if epRec.active then
      let recPrime := { epRec with active := false }
      some { s1 with endpoints := s1.endpoints.update caller recPrime }
    else
      some s1

/-- Finalise unbonding after the grace window. The stake amount is
    returned (Lean abstracts the actual `transfer`). -/
def finalizeUnbond (s : ProgramState) (caller : Addr) :
    Option (ProgramState × OctRaw) :=
  let u := s.endpointUnbonding caller
  if u.stake = 0 then none
  else if s.currentEpoch < u.unlockEpoch then none
  else
    let s' := { s with
                endpointUnbonding := s.endpointUnbonding.update caller Unbonding.empty }
    some (s', u.stake)

/-- Governance slash. The owner gates this; off-chain evidence
    verification is the trust assumption. -/
def govSlashOperator (s : ProgramState) (caller op : Addr) :
    Option ProgramState :=
  if caller ≠ s.programOwner then none
  else if s.endpointSlashed op then none
  else
    let live := s.endpointStake op
    let unb := (s.endpointUnbonding op).stake
    let total := live + unb
    if total = 0 then none
    else
      let burnAmt := total * s.params.slashBurnBps / 10000
      let epRec := s.endpoints op
      let s1 := { s with
                  endpointStake := s.endpointStake.update op 0,
                  endpointUnbonding := s.endpointUnbonding.update op Unbonding.empty,
                  endpointSlashed := s.endpointSlashed.update op true,
                  programTreasury := s.programTreasury + burnAmt }
      if epRec.active then
        let recPrime := { epRec with active := false }
        some { s1 with endpoints := s1.endpoints.update op recPrime }
      else
        some s1

-- ============================================================
-- Endpoint lifecycle
-- ============================================================

/-- Register an endpoint. Caller must be bonded with
    `≥ minEndpointStake` and not previously slashed. -/
def registerEndpoint
    (s : ProgramState) (caller : Addr)
    (endpoint region : String) (price : Nat) : Option ProgramState :=
  if (s.endpoints caller).active then none
  else if s.endpointSlashed caller then none
  else if s.endpointStake caller < s.params.minEndpointStake then none
  else if price = 0 then none
  else
    let epRec : EndpointRecord :=
      { EndpointRecord.empty with
        active := true,
        endpoint := endpoint,
        region := region,
        pricePerMb := price,
        registeredAt := s.currentEpoch }
    some { s with endpoints := s.endpoints.update caller epRec }

/-- Retire an endpoint. -/
def retireEndpoint (s : ProgramState) (caller : Addr) : Option ProgramState :=
  let epRec := s.endpoints caller
  if ¬ epRec.active then none
  else
    let recPrime := { epRec with active := false }
    some { s with endpoints := s.endpoints.update caller recPrime }

-- ============================================================
-- Tailnet lifecycle
-- ============================================================

def createTailnet
    (s : ProgramState) (owner : Addr) (tailnetId : TailnetId) (deposit : Nat) :
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

def addMember
    (s : ProgramState) (tailnetId : TailnetId) (caller member : Addr) :
    Option ProgramState :=
  let t := s.tailnets tailnetId
  if t.owner ≠ caller then none
  else if member ∈ t.members then none
  else
    let t' := { t with members := member :: t.members }
    some { s with tailnets := s.tailnets.update tailnetId t' }

def depositToTailnet
    (s : ProgramState) (tailnetId : TailnetId) (amount : Nat) :
    Option ProgramState :=
  if amount = 0 then none
  else
    let t := s.tailnets tailnetId
    if t.owner = 0 then none
    else
      let t' := { t with treasury := t.treasury + amount }
      some { s with tailnets := s.tailnets.update tailnetId t' }

def configureTailnetExit
    (s : ProgramState) (tailnetId : TailnetId) (caller exit : Addr) :
    Option ProgramState :=
  let t := s.tailnets tailnetId
  if t.owner ≠ caller then none
  else if exit ∈ t.exits then none
  else
    let t' := { t with exits := exit :: t.exits }
    some { s with tailnets := s.tailnets.update tailnetId t' }

-- ============================================================
-- Session lifecycle (single-hop, v1)
-- ============================================================

/-- Open a single-hop session against a configured exit. -/
def openSession
    (s : ProgramState) (caller : Addr) (tailnetId : TailnetId) (sid : SessionId)
    (exit : Addr) (maxPay : Nat) : Option ProgramState :=
  let t := s.tailnets tailnetId
  if caller ∉ t.members then none
  else if exit ∉ t.exits then none
  else if maxPay < s.params.minSessionDeposit then none
  else if t.treasury < maxPay then none
  else
    let t' := { t with treasury := t.treasury - maxPay }
    let sess : Session :=
      { tailnetId := tailnetId,
        exit := exit,
        deposit := maxPay,
        openedAt := s.currentEpoch,
        status := SessionStatus.open,
        paidBytes := 0 }
    some { s with
      tailnets := s.tailnets.update tailnetId t',
      sessions := s.sessions.update sid (some sess) }

/-- Validator-only settle. The exit operator reports `bytesUsed`;
    AML caps the resulting payment at the deposit and refunds the
    rest. Earnings credit is plaintext-modeled here; the FHE
    homomorphism makes the chain operation equivalent. -/
def settleSession
    (s : ProgramState) (sid : SessionId) (caller : Addr) (bytesUsed : Nat) :
    Option ProgramState :=
  match s.sessions sid with
  | none => none
  | some sess =>
    if sess.status ≠ SessionStatus.open then none
    else if caller ≠ sess.exit then none
    else
      let epRec := s.endpoints caller
      let totalPaid := epRec.pricePerMb * bytesUsed
      if totalPaid > sess.deposit then none
      else
        let fee := totalPaid * s.params.protocolFeeBps / 10000
        let netPay := totalPaid - fee
        let refund := sess.deposit - totalPaid
        let t := s.tailnets sess.tailnetId
        let t' := { t with treasury := t.treasury + refund }
        let upd : Session :=
          { sess with
            status := SessionStatus.settled,
            paidBytes := bytesUsed }
        let curEarn := s.encEarn caller
        let recBumped := { epRec with reputation := epRec.reputation + 1 }
        some { s with
          sessions := s.sessions.update sid (some upd),
          tailnets := s.tailnets.update sess.tailnetId t',
          encEarn := s.encEarn.update caller (curEarn + netPay),
          programTreasury := s.programTreasury + fee,
          endpoints := s.endpoints.update caller recBumped }

/-- No-show refund: after grace, the deposit returns to the
    tailnet treasury. -/
def claimNoShow (s : ProgramState) (sid : SessionId) : Option ProgramState :=
  match s.sessions sid with
  | none => none
  | some sess =>
    if sess.status ≠ SessionStatus.open then none
    else if s.currentEpoch < sess.openedAt + s.params.sessionGraceEpochs then none
    else
      let upd := { sess with status := SessionStatus.refunded }
      let t := s.tailnets sess.tailnetId
      let t' := { t with treasury := t.treasury + sess.deposit }
      some { s with
        sessions := s.sessions.update sid (some upd),
        tailnets := s.tailnets.update sess.tailnetId t' }

-- ============================================================
-- Earnings claim (FHE zero-proof modeled as abstract Prop)
-- ============================================================

/-- Claim accumulated earnings. The `proofOk` proposition stands in
    for the on-chain `fhe_verify_zero(pk, encEarn - enc(amount), proof)`
    check — the proof returns the operator's bytes of opening, which
    the chain accepts iff the difference is encrypted zero. -/
def claimEarnings
    (s : ProgramState) (caller : Addr) (claimedAmount : Nat)
    (proofOk : Prop) [Decidable proofOk] : Option ProgramState :=
  if s.endpointSlashed caller then none
  else if claimedAmount = 0 then none
  else if ¬ proofOk then none
  -- Soundness gate: the proof can only succeed when claimed = actual,
  -- so the chain only sees a valid call when this equality holds.
  else if s.encEarn caller ≠ claimedAmount then none
  else
    some { s with encEarn := s.encEarn.update caller 0 }

end OctraVPN
