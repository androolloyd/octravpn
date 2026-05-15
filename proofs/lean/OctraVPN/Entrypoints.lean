import OctraVPN.State

/-!
# Entrypoints, modeled as state-transition functions (v1).

Each function corresponds to one entrypoint in `program/main.aml`.
Successful execution returns `some newState`; reverts are encoded as
`none`.

The v1 model is single-hop with a TWO-TX settlement flow:
- `openSession` records the configured exit, the opener (= caller),
  and starts both `operatorClaim` / `clientConfirm` as `none`.
- `settleClaim` is operator-only (`caller = sess.exit`). First call
  records the claim. Re-claim with the SAME bytes is idempotent;
  re-claim with DIFFERENT bytes is equivocation, slashes the
  operator and force-refunds the session.
- `settleConfirm` is client-only (`caller = sess.opener`). Matching
  bytes finalize settlement (FHE earnings credit, fee, refund of
  unused deposit). Mismatching bytes record the dispute; the session
  stays open.
- `precommitJoinToken` lets the tailnet owner publish a
  `sha256(preimage)` commitment.
- `redeemJoinToken` consumes a preimage and adds the caller to the
  tailnet members. Hashes are spent at most once.
- `claimEarnings` takes an abstract `proofOk : Prop` standing in for
  the on-chain `fhe_verify_zero(pk, delta, proof)` check.
- `govSlashOperator` is owner-gated (no in-AML signature
  verification).

For the join-token model `sha256 : Bytes → Bytes` is an opaque hash
function. We don't axiomatise collision resistance — the lemmas only
need pointwise determinism, which Lean gives us for free on any
function.
-/

namespace OctraVPN

/-- Abstract sha256 for proof purposes. Treated as an opaque,
    deterministic function `Bytes → Bytes`. Real Octra uses the
    chain's `sha256` host call; here we only need functional
    determinism, which any Lean function provides. -/
opaque sha256 : Bytes → Bytes

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

/-- Cryptographic equivocation slash via `slash_double_sign`.

The AML entrypoint takes `(payload_a, sig_a, payload_b, sig_b)` plus
the alleged operator and session id, and slashes iff the two payloads
are distinct AND both signatures verify under the operator's
receipt-signing pubkey. We don't model ed25519 verification — the
Lean state machine has no oracle for signature soundness — so we
parametrise the entrypoint by a boolean `verified` that downstream
clients always pass as `true` (the AML's `ed25519_ok` gate is what
makes that assumption sound in production).

`payloadA = payloadB` is captured by a separate `Decidable`
hypothesis `distinct : payloadA ≠ payloadB` flowed in by the caller;
in Lean we encode "both verified AND distinct" as the single boolean
flag `verified` for state-transition reasoning. The lemma
`slashDoubleSign_distinct_payloads_required` proves the entrypoint
returns the caller's state unchanged when the payloads coincide
(modeled by setting `verified := false`). -/
def slashDoubleSign
    (s : ProgramState) (_caller op : Addr)
    (verified : Bool) :
    Option (ProgramState × OctRaw) :=
  if ¬ verified then none
  else if s.endpointSlashed op then none
  else
    let live := s.endpointStake op
    let unb := (s.endpointUnbonding op).stake
    let total := live + unb
    if total = 0 then none
    else
      let burnAmt := total * s.params.slashBurnBps / 10000
      let bountyAmt := total - burnAmt
      let epRec := s.endpoints op
      let s1 := { s with
                  endpointStake := s.endpointStake.update op 0,
                  endpointUnbonding := s.endpointUnbonding.update op Unbonding.empty,
                  endpointSlashed := s.endpointSlashed.update op true,
                  programTreasury := s.programTreasury + burnAmt }
      if epRec.active then
        let recPrime := { epRec with active := false }
        some ({ s1 with endpoints := s1.endpoints.update op recPrime }, bountyAmt)
      else
        some (s1, bountyAmt)

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

/-- Update an endpoint's mutable fields (URI, region, price). Caller
    must own an `active` registration. Mirrors AML `update_endpoint`. -/
def updateEndpoint
    (s : ProgramState) (caller : Addr)
    (endpoint region : String) (price : Nat) : Option ProgramState :=
  let epRec := s.endpoints caller
  if ¬ epRec.active then none
  else if price = 0 then none
  else
    let recPrime := { epRec with
                      endpoint := endpoint,
                      region := region,
                      pricePerMb := price }
    some { s with endpoints := s.endpoints.update caller recPrime }

/-- Rotate WG and HFHE keys. AML requires `enc_earnings == enc_zero`,
    i.e. the operator's earnings ledger is currently zero. We model
    that precondition directly on `encEarn`. -/
def rotateKeys
    (s : ProgramState) (caller : Addr)
    (newWgPk newHfhePk : String) : Option ProgramState :=
  let epRec := s.endpoints caller
  if ¬ epRec.active then none
  else if s.encEarn caller ≠ 0 then none
  else
    let recPrime := { epRec with
                      wgPubkey := newWgPk,
                      hfhePubkey := newHfhePk }
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

/-- Remove a member from a tailnet. Owner-only and may never remove
    the owner themselves. Matches AML `remove_member`. -/
def removeMember
    (s : ProgramState) (tailnetId : TailnetId) (caller member : Addr) :
    Option ProgramState :=
  let t := s.tailnets tailnetId
  if t.owner ≠ caller then none
  else if member = t.owner then none
  else if member ∉ t.members then none
  else
    let t' := { t with members := t.members.filter (· ≠ member) }
    some { s with tailnets := s.tailnets.update tailnetId t' }

/-- Update the off-chain ACL doc hash on a tailnet. Owner-only. -/
def updateAcl
    (s : ProgramState) (tailnetId : TailnetId) (caller : Addr)
    (newPolicy : String) : Option ProgramState :=
  let t := s.tailnets tailnetId
  if t.owner = 0 then none
  else if t.owner ≠ caller then none
  else if newPolicy = "" then none
  else
    let t' := { t with aclPolicy := newPolicy }
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
        opener := caller,
        deposit := maxPay,
        openedAt := s.currentEpoch,
        status := SessionStatus.open,
        paidBytes := 0,
        operatorClaim := none,
        clientConfirm := none }
    some { s with
      tailnets := s.tailnets.update tailnetId t',
      sessions := s.sessions.update sid (some sess) }

-- ============================================================
-- Two-tx settlement: operator claims, client confirms.
-- ============================================================

/-- Operator-side `settle_claim` (v1 two-tx flow).

The caller must be the configured exit. If the operator has no
prior claim for this session, AML records the claim and returns.
If the operator already submitted the SAME bytes, the call is
idempotent. If the operator submits a DIFFERENT bytes value, this
is equivocation: AML atomically slashes the operator (burn share +
forfeited bounty go to the program treasury), marks them
permanently slashed, force-refunds the session deposit to the
tailnet treasury, and returns the new state. -/
def settleClaim
    (s : ProgramState) (sid : SessionId) (bytesUsed : Nat)
    (caller : Addr) (epoch : Nat) : Option ProgramState :=
  match s.sessions sid with
  | none => none
  | some sess =>
    if sess.status ≠ SessionStatus.open then none
    else if caller ≠ sess.exit then none
    else
      match sess.operatorClaim with
      | none =>
        -- First claim: record it.
        let upd : Session :=
          { sess with operatorClaim := some (bytesUsed, epoch) }
        some { s with sessions := s.sessions.update sid (some upd) }
      | some (prevBytes, _) =>
        if prevBytes = bytesUsed then
          -- Idempotent re-claim.
          some s
        else
          -- Equivocation: slash + force-refund.
          let live := s.endpointStake caller
          let unb := (s.endpointUnbonding caller).stake
          let total := live + unb
          let burnAmt := total * s.params.slashBurnBps / 10000
          let bountyAmt := total - burnAmt
          let epRec := s.endpoints caller
          let t := s.tailnets sess.tailnetId
          let t' := { t with treasury := t.treasury + sess.deposit }
          let updSess : Session :=
            { sess with status := SessionStatus.refunded }
          let s1 := { s with
            endpointStake := s.endpointStake.update caller 0,
            endpointUnbonding := s.endpointUnbonding.update caller Unbonding.empty,
            endpointSlashed := s.endpointSlashed.update caller true,
            programTreasury := s.programTreasury + burnAmt + bountyAmt,
            sessions := s.sessions.update sid (some updSess),
            tailnets := s.tailnets.update sess.tailnetId t' }
          if epRec.active then
            let recPrime := { epRec with active := false }
            some { s1 with endpoints := s1.endpoints.update caller recPrime }
          else
            some s1

/-- Client-side `settle_confirm` (v1 two-tx flow).

Only the session opener may submit. There must be a prior
`operatorClaim`. If the client's `bytesUsed` matches the operator's,
settlement applies: status → settled, FHE earnings credited by
`bytesUsed * pricePerMb − fee`, the unused deposit refunds to the
tailnet treasury, and reputation increments. If the bytes mismatch,
the client confirm is recorded as a dispute; the session stays
open. -/
def settleConfirm
    (s : ProgramState) (sid : SessionId) (bytesUsed : Nat)
    (caller : Addr) (epoch : Nat) : Option ProgramState :=
  match s.sessions sid with
  | none => none
  | some sess =>
    if sess.status ≠ SessionStatus.open then none
    else if caller ≠ sess.opener then none
    else
      match sess.operatorClaim with
      | none => none  -- operator has not claimed yet
      | some (opBytes, _) =>
        if opBytes ≠ bytesUsed then
          -- Dispute: record client's claim, no settlement.
          let upd : Session :=
            { sess with clientConfirm := some (bytesUsed, epoch) }
          some { s with sessions := s.sessions.update sid (some upd) }
        else
          -- Match: apply settlement.
          let epRec := s.endpoints sess.exit
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
                paidBytes := bytesUsed,
                clientConfirm := some (bytesUsed, epoch) }
            let curEarn := s.encEarn sess.exit
            let recBumped := { epRec with reputation := epRec.reputation + 1 }
            some { s with
              sessions := s.sessions.update sid (some upd),
              tailnets := s.tailnets.update sess.tailnetId t',
              encEarn := s.encEarn.update sess.exit (curEarn + netPay),
              programTreasury := s.programTreasury + fee,
              endpoints := s.endpoints.update sess.exit recBumped }

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

/-- Permissionless sweep after the extended grace
    (`sessionGraceEpochs * sweepGraceMultiplier`). Sends a
    `sweepBountyBps / BPS_DENOM` bounty to the caller and refunds
    the remainder to the tailnet treasury. The Lean model returns
    the bounty in the result tuple (AML's `transfer` is opaque). -/
def sweepExpiredSession
    (s : ProgramState) (sid : SessionId) (_caller : Addr) :
    Option (ProgramState × OctRaw) :=
  match s.sessions sid with
  | none => none
  | some sess =>
    if sess.status ≠ SessionStatus.open then none
    else
      let sweepGrace :=
        sess.openedAt + s.params.sessionGraceEpochs * s.params.sweepGraceMultiplier
      if s.currentEpoch < sweepGrace then none
      else
        let dep := sess.deposit
        let bounty := dep * s.params.sweepBountyBps / 10000
        let refund := dep - bounty
        let upd := { sess with status := SessionStatus.refunded }
        let t := s.tailnets sess.tailnetId
        let t' := { t with treasury := t.treasury + refund }
        some
          ({ s with
              sessions := s.sessions.update sid (some upd),
              tailnets := s.tailnets.update sess.tailnetId t' },
           bounty)

-- ============================================================
-- Pre-auth join tokens (hash-precommit pattern)
-- ============================================================

/-- Tailnet owner publishes `sha256(token_preimage)` for a future
    redeemer. Each `(tailnet, hash)` pair can be committed at most
    once and only if the hash has not yet been redeemed
    (anywhere). -/
def precommitJoinToken
    (s : ProgramState) (tid : TailnetId) (h : Bytes) (caller : Addr) :
    Option ProgramState :=
  let t := s.tailnets tid
  if t.owner = 0 then none
  else if t.owner ≠ caller then none
  else if s.joinTokenCommits (tid, h) then none
  else if s.joinTokenRedeemed h then none
  else
    some { s with
      joinTokenCommits := s.joinTokenCommits.update (tid, h) true }

/-- Anyone holding a `preimage` such that `sha256(preimage) = h` and
    `joinTokenCommits[(tid, h)] = true` joins the tailnet. The hash
    is marked spent so the same preimage can never be redeemed
    again. -/
def redeemJoinToken
    (s : ProgramState) (tid : TailnetId) (preimage : Bytes) (caller : Addr) :
    Option ProgramState :=
  let h := sha256 preimage
  let t := s.tailnets tid
  if t.owner = 0 then none
  else if ¬ s.joinTokenCommits (tid, h) then none
  else if s.joinTokenRedeemed h then none
  else if caller ∈ t.members then none
  else
    let t' := { t with members := caller :: t.members }
    some { s with
      tailnets := s.tailnets.update tid t',
      joinTokenRedeemed := s.joinTokenRedeemed.update h true }

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

-- ============================================================
-- Device registry
-- ============================================================

/-- Bind a device address to the caller's wallet. Idempotent on
    `existing = caller`. Fails if the device is bound to someone
    else. AML uses `0` as the sentinel for "no owner". -/
def registerDevice
    (s : ProgramState) (caller device : Addr) : Option ProgramState :=
  let existing := s.deviceOwner device
  if existing = caller then some s
  else if existing ≠ 0 then none
  else some { s with deviceOwner := s.deviceOwner.update device caller }

/-- Revoke a device the caller owns. -/
def revokeDevice
    (s : ProgramState) (caller device : Addr) : Option ProgramState :=
  if s.deviceOwner device ≠ caller then none
  else some { s with deviceOwner := s.deviceOwner.update device 0 }

-- ============================================================
-- Governance
-- ============================================================

/-- Pause / unpause the program. Owner-only. -/
def setPaused
    (s : ProgramState) (caller : Addr) (v : Bool) : Option ProgramState :=
  if caller ≠ s.programOwner then none
  else some { s with paused := v }

/-- Transfer program ownership. Owner-only. -/
def transferOwnership
    (s : ProgramState) (caller newOwner : Addr) : Option ProgramState :=
  if caller ≠ s.programOwner then none
  else some { s with programOwner := newOwner }

/-- Withdraw OU from the program treasury to a destination. Owner-
    only; capped at the available balance. Returns the new state
    and the amount transferred (AML's `transfer` is opaque).
    Intentionally not pause-gated: governance ops run during pause. -/
def withdrawProgramTreasury
    (s : ProgramState) (caller _to : Addr) (amount : OctRaw) :
    Option (ProgramState × OctRaw) :=
  if caller ≠ s.programOwner then none
  else if amount = 0 then none
  else if s.programTreasury < amount then none
  else
    some
      ({ s with programTreasury := s.programTreasury - amount },
       amount)

end OctraVPN
