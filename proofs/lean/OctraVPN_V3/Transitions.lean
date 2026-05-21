import OctraVPN_V3.State

/-!
# Entrypoints of v3, modeled as state-transition functions.

One function per entrypoint of `program/main-v3.aml`. A successful
transition returns `some newState` (or `some (newState, payout)`
when the entrypoint transfers OU to the caller); reverts are
`none`.

## v3 deltas captured here

  - Circle metadata is split across parallel maps; a successful
    `registerCircle` writes ALL of `circleOwner`, `circleReceiptPk`,
    `circleStateRoot`, `circleStateVersion`, `circleActive`, AND
    initialises the earnings ledger including the hash-chain
    genesis (`circleEarningsChain[c] = sha256(state_root)`,
    matching `main-v3.aml:302-303`).

  - `update_circle_state` is the ONLY entrypoint that bumps
    `circleStateVersion`. It accepts ANY 64-char hex `bytes` — the
    chain does no crypto check. Off-chain verifiers enforce
    integrity by fetching the canonical source and comparing
    `sha256_hex(source) == anchor`. We model the 64-char gate as a
    `len(...) = 64` predicate at the boundary, surfaced as
    `stateRootValid`.

  - `rotate_receipt_pubkey` ONLY mutates `circleReceiptPk`; it does
    NOT affect prior session settlements or any pre-rotation
    receipt. The slash path always reads the CURRENT
    `circleReceiptPk` — the anti-evasion property is that the
    rotation is forward-only.

  - `slash_double_sign` requires two DISTINCT signed payloads under
    the current `circleReceiptPk`. The Lean model encodes the
    "two-signature, distinct-payload" precondition as a single
    `verified : Bool` (the same approach as v2). See
    `AmlLink.lean` for the proof-gap on `ed25519_ok` decoding.

  - Tailnet membership is OFF-CHAIN. The `open_session` entrypoint
    DOES NOT take an inclusion proof on chain (`main-v3.aml:494-497`
    comments: "Membership = off-chain Merkle proof"). The
    operator's tailnet treasury must cover `max_pay`; if the
    operator misbehaves, the opener recovers via `claim_no_show`
    or `sweep_expired_session`.

  - `claim_no_show` is opener-only and requires the OPERATOR to
    not have claimed yet (`operator_claim_set == 0`).

  - `sweep_expired_session` is permissionless after the EXTENDED
    grace `session_grace_epochs * sweep_grace_multiplier`. The
    caller earns `sweep_bounty_bps` of the deposit as a bounty.

  - `claim_earnings` debits `circle_earnings_claimed`; it does NOT
    decrement `circle_earnings_total`, so the running total is
    monotonically non-decreasing across the circle's lifetime.

## Proof-of-correctness conventions

  - All entrypoints have a tagged `_` parameter where the AML
    silently drops the input (e.g. `gov_slash_operator`'s
    `caller` only matters for the owner check, the inner
    `apply_slash` uses `caller` again as the bounty recipient).

  - `transfer(caller, amount)` is modeled by returning a payout
    pair `(s', amount)` rather than threading wallet balances —
    we leave the OU bookkeeping to the chain runtime.
-/

namespace OctraVPN_V3

/-- Opaque sha256 primitive (matches `WireProtocol/V3Canonical.lean`
    + v2 pattern). The chain's `sha256()` returns a 64-char hex
    string; we model it as `Bytes → Bytes`. Cryptographic
    properties are axiomatized in `AmlLink.lean`. -/
opaque sha256 : Bytes → Bytes

/-- AML enforces `len(state_root) == 64`. We surface this as a
    Boolean precondition at the Lean boundary. The chain does NOT
    cryptographically check the hex, so neither do we. -/
def stateRootValid (b : Bytes) : Bool :=
  decide (b.length = 64)

-- ============================================================
-- Governance (owner-only; intentionally NOT pause-gated)
-- (AML: `main-v3.aml:221-269`)
-- ============================================================

/-- `transfer_ownership(new_owner)` — owner-only. -/
def transferOwnership (s : ProgramState) (caller newOwner : Addr) :
    Option ProgramState :=
  if caller ≠ s.programOwner then none
  else some { s with programOwner := newOwner }

/-- `set_paused(p)` — owner-only; `p ∈ {0,1}` so we type it `Bool`. -/
def setPaused (s : ProgramState) (caller : Addr) (v : Bool) :
    Option ProgramState :=
  if caller ≠ s.programOwner then none
  else some { s with paused := v }

/-- `set_params(...)` — owner-only with all AML sanity bounds
    (`main-v3.aml:235-258`). -/
def setParams (s : ProgramState) (caller : Addr) (p : Params) :
    Option ProgramState :=
  if caller ≠ s.programOwner then none
  else if p.minSessionDeposit = 0 then none
  else if p.minTailnetDeposit = 0 then none
  else if p.sessionGraceEpochs = 0 then none
  else if p.sweepGraceMultiplier = 0 then none
  else if p.sweepBountyBps > 1000 then none
  else if p.minCircleStake < 100000000 then none
  else if p.unbondGraceEpochs < 1000 then none
  else if p.slashBurnBps < 5000 then none
  else if p.slashBurnBps + p.slashBountyBps ≠ BPS_DENOM then none
  else if p.protocolFeeBps > 200 then none
  else if p.disputeGraceEpochs = 0 then none
  else if p.disputeGraceEpochs > p.sessionGraceEpochs * 2 then none
  else some { s with params := p }

/-- `withdraw_program_treasury(to, amount)` — owner-only. Returns
    `(state', amount)`; OU transfer is left to the runtime. -/
def withdrawProgramTreasury
    (s : ProgramState) (caller _to : Addr) (amount : OctRaw) :
    Option (ProgramState × OctRaw) :=
  if caller ≠ s.programOwner then none
  else if amount = 0 then none
  else if s.programTreasury < amount then none
  else
    some ({ s with programTreasury := s.programTreasury - amount }, amount)

-- ============================================================
-- Circle registry (AML: `main-v3.aml:277-346`)
-- ============================================================

/-- Atomic `register_circle(circle, state_root, receipt_pubkey)`
    with payable `value`. Sets owner+active+stake+state-root+
    receipt-pubkey AND initialises the earnings hash chain to
    `sha256(state_root)`. -/
def registerCircle
    (s : ProgramState) (caller : Addr) (c : CircleId)
    (stateRoot : Bytes) (receiptPk : String) (value : OctRaw) :
    Option ProgramState :=
  if s.paused then none
  else if s.circleActive c then none
  else if s.circleSlashed c then none
  else if ¬ stateRootValid stateRoot then none
  else if receiptPk = "" then none
  else if s.circleBond c + value < s.params.minCircleStake then none
  else
    let bond' := s.circleBond c + value
    some { s with
            circleBond           := s.circleBond.update c bond',
            circleOwner          := s.circleOwner.update c caller,
            circleReceiptPk      := s.circleReceiptPk.update c receiptPk,
            circleStateRoot      := s.circleStateRoot.update c stateRoot,
            circleStateVersion   := s.circleStateVersion.update c 1,
            circleActive         := s.circleActive.update c true,
            circleEarningsTotal  := s.circleEarningsTotal.update c 0,
            circleEarningsClaimed := s.circleEarningsClaimed.update c 0,
            circleEarningsChain  := s.circleEarningsChain.update c (sha256 stateRoot) }

/-- `update_circle_state(c, new_root)` — owner-gated, requires
    active + not slashed; bumps `circleStateVersion`. -/
def updateCircleState
    (s : ProgramState) (caller : Addr) (c : CircleId) (newRoot : Bytes) :
    Option ProgramState :=
  if s.paused then none
  else if s.circleOwner c ≠ caller then none
  else if ¬ s.circleActive c then none
  else if s.circleSlashed c then none
  else if ¬ stateRootValid newRoot then none
  else
    some { s with
            circleStateRoot    := s.circleStateRoot.update c newRoot,
            circleStateVersion := s.circleStateVersion.update c
                                   ((s.circleStateVersion c) + 1) }

/-- `rotate_receipt_pubkey(c, new_pk)` — owner-gated; only mutates
    `circleReceiptPk`. -/
def rotateReceiptPubkey
    (s : ProgramState) (caller : Addr) (c : CircleId) (newPk : String) :
    Option ProgramState :=
  if s.paused then none
  else if s.circleOwner c ≠ caller then none
  else if ¬ s.circleActive c then none
  else if s.circleSlashed c then none
  else if newPk = "" then none
  else
    some { s with circleReceiptPk := s.circleReceiptPk.update c newPk }

/-- `retire_circle(c)` — owner-gated; clears `circleActive`. -/
def retireCircle
    (s : ProgramState) (caller : Addr) (c : CircleId) :
    Option ProgramState :=
  if s.paused then none
  else if s.circleOwner c ≠ caller then none
  else if ¬ s.circleActive c then none
  else
    some { s with circleActive := s.circleActive.update c false }

-- ============================================================
-- Bond / unbond / finalize (AML: `main-v3.aml:352-388`)
-- ============================================================

/-- `bond_endpoint(c)` — payable; owner-gated; requires no
    pending unbonding and circle not slashed. -/
def bondEndpoint
    (s : ProgramState) (caller : Addr) (c : CircleId) (value : OctRaw) :
    Option ProgramState :=
  if s.paused then none
  else if value = 0 then none
  else if s.circleSlashed c then none
  else if (s.circleUnbonding c).stake ≠ 0 then none
  else if s.circleOwner c ≠ caller then none
  else
    some { s with circleBond := s.circleBond.update c (s.circleBond c + value) }

/-- `unbond_endpoint(c)` — owner-gated; starts the timer. -/
def unbondEndpoint
    (s : ProgramState) (caller : Addr) (c : CircleId) :
    Option ProgramState :=
  if s.paused then none
  else if s.circleOwner c ≠ caller then none
  else
    let amt := s.circleBond c
    if amt = 0 then none
    else if (s.circleUnbonding c).stake ≠ 0 then none
    else
      let unlock := s.currentEpoch + s.params.unbondGraceEpochs
      let unb : Unbonding := { stake := amt, unlockEpoch := unlock }
      some { s with
              circleBond      := s.circleBond.update c 0,
              circleUnbonding := s.circleUnbonding.update c unb }

/-- `finalize_unbond(c)` — owner-gated; pays back the unbonded
    amount after `unlockEpoch` is reached. Returns `(s', amt)`. -/
def finalizeUnbond
    (s : ProgramState) (caller : Addr) (c : CircleId) :
    Option (ProgramState × OctRaw) :=
  if s.paused then none
  else if s.circleOwner c ≠ caller then none
  else
    let u := s.circleUnbonding c
    if u.stake = 0 then none
    else if s.currentEpoch < u.unlockEpoch then none
    else
      let s' := { s with
                   circleUnbonding := s.circleUnbonding.update c Unbonding.empty }
      some (s', u.stake)

-- ============================================================
-- Slash (AML: `main-v3.aml:394-412` + `apply_slash` 197-215)
-- ============================================================

/-- `slash_double_sign(c, payload_a, sig_a, payload_b, sig_b)`.
    The `verified : Bool` parameter encodes
    `payload_a ≠ payload_b ∧ ed25519_ok(pk, payload_a, sig_a)
    ∧ ed25519_ok(pk, payload_b, sig_b)`. -/
def slashDoubleSign
    (s : ProgramState) (caller : Addr) (c : CircleId) (verified : Bool) :
    Option (ProgramState × OctRaw) :=
  if s.paused then none
  else if ¬ verified then none
  else if s.circleSlashed c then none
  else if s.circleReceiptPk c = "" then none
  else
    let live := s.circleBond c
    let unb := (s.circleUnbonding c).stake
    let total := live + unb
    if total = 0 then none
    else
      let burnAmt := total * s.params.slashBurnBps / BPS_DENOM
      let bountyAmt := total - burnAmt
      let _ := caller
      let s' : ProgramState :=
        { s with
            circleBond      := s.circleBond.update c 0,
            circleUnbonding := s.circleUnbonding.update c Unbonding.empty,
            circleSlashed   := s.circleSlashed.update c true,
            circleActive    := s.circleActive.update c false,
            programTreasury := s.programTreasury + burnAmt,
            burned          := s.burned + burnAmt }
      some (s', bountyAmt)

/-- `gov_slash_operator(c)` — owner-only. Same slash bookkeeping
    but the bounty goes to the program owner. -/
def govSlashOperator
    (s : ProgramState) (caller : Addr) (c : CircleId) :
    Option (ProgramState × OctRaw) :=
  if s.paused then none
  else if caller ≠ s.programOwner then none
  else if s.circleSlashed c then none
  else
    let live := s.circleBond c
    let unb := (s.circleUnbonding c).stake
    let total := live + unb
    if total = 0 then none
    else
      let burnAmt := total * s.params.slashBurnBps / BPS_DENOM
      let bountyAmt := total - burnAmt
      let s' : ProgramState :=
        { s with
            circleBond      := s.circleBond.update c 0,
            circleUnbonding := s.circleUnbonding.update c Unbonding.empty,
            circleSlashed   := s.circleSlashed.update c true,
            circleActive    := s.circleActive.update c false,
            programTreasury := s.programTreasury + burnAmt,
            burned          := s.burned + burnAmt }
      some (s', bountyAmt)

-- ============================================================
-- Tailnets (AML: `main-v3.aml:420-475`)
-- ============================================================

/-- `create_tailnet(members_root)` — payable. The caller is the
    initial owner; the deposit seeds `tailnet_treasury[tid]`. -/
def createTailnet
    (s : ProgramState) (caller : Addr) (membersRoot : Bytes) (value : OctRaw) :
    Option (ProgramState × TailnetId) :=
  if s.paused then none
  else if value < s.params.minTailnetDeposit then none
  else if ¬ stateRootValid membersRoot then none
  else
    let tid := s.tailnetCount
    let t : Tailnet :=
      { owner := caller, treasury := value, membersRoot := membersRoot,
        rootVersion := 1, retired := false }
    let s' : ProgramState :=
      { s with
          tailnetCount := tid + 1,
          tailnets := s.tailnets.update tid t }
    some (s', tid)

/-- `deposit_to_tailnet(tid)` — payable; permissionless (anyone
    can top up; membership is off-chain ACL). -/
def depositToTailnet
    (s : ProgramState) (_caller : Addr) (tid : TailnetId) (value : OctRaw) :
    Option ProgramState :=
  if s.paused then none
  else if value = 0 then none
  else if tid ≥ s.tailnetCount then none
  else
    let t := s.tailnets tid
    if t.retired then none
    else
      let t' := { t with treasury := t.treasury + value }
      some { s with tailnets := s.tailnets.update tid t' }

/-- `update_members_root(tid, new_root)` — owner-gated. -/
def updateMembersRoot
    (s : ProgramState) (caller : Addr) (tid : TailnetId) (newRoot : Bytes) :
    Option ProgramState :=
  if s.paused then none
  else if tid ≥ s.tailnetCount then none
  else
    let t := s.tailnets tid
    if t.owner ≠ caller then none
    else if ¬ stateRootValid newRoot then none
    else
      let t' := { t with membersRoot := newRoot, rootVersion := t.rootVersion + 1 }
      some { s with tailnets := s.tailnets.update tid t' }

/-- `retire_tailnet(tid)` — owner-gated. -/
def retireTailnet
    (s : ProgramState) (caller : Addr) (tid : TailnetId) :
    Option ProgramState :=
  if s.paused then none
  else
    let t := s.tailnets tid
    if t.owner ≠ caller then none
    else
      let t' := { t with retired := true }
      some { s with tailnets := s.tailnets.update tid t' }

/-- `withdraw_tailnet_treasury(tid, amount)` — owner-gated;
    requires `retired = true`. Returns `(s', amount)`. -/
def withdrawTailnetTreasury
    (s : ProgramState) (caller : Addr) (tid : TailnetId) (amount : OctRaw) :
    Option (ProgramState × OctRaw) :=
  if s.paused then none
  else
    let t := s.tailnets tid
    if t.owner ≠ caller then none
    else if ¬ t.retired then none
    else if amount = 0 then none
    else if t.treasury < amount then none
    else
      let t' := { t with treasury := t.treasury - amount }
      some ({ s with tailnets := s.tailnets.update tid t' }, amount)

-- ============================================================
-- Sessions (AML: `main-v3.aml:486-639`)
-- ============================================================

/-- `open_session(tailnet_id, circle, max_pay)`. Tailnet treasury
    is debited by `max_pay`; on misbehaviour the opener recovers
    via `claim_no_show` / `sweep_expired_session`. -/
def openSession
    (s : ProgramState) (caller : Addr) (tid : TailnetId) (c : CircleId)
    (maxPay : OctRaw) : Option (ProgramState × SessionId) :=
  if s.paused then none
  else if tid ≥ s.tailnetCount then none
  else
    let t := s.tailnets tid
    if t.retired then none
    else if ¬ circleIsActive s c then none
    else if maxPay < s.params.minSessionDeposit then none
    else if t.treasury < maxPay then none
    else
      let sid := s.sessionCount
      let sess : Session :=
        { tailnetId := tid, circle := c, opener := caller,
          deposit := maxPay, openedAt := s.currentEpoch,
          status := SessionStatus.open,
          operatorClaim := none, clientConfirm := none }
      let t' := { t with treasury := t.treasury - maxPay }
      let s' : ProgramState :=
        { s with
            sessionCount := sid + 1,
            tailnets := s.tailnets.update tid t',
            sessions := s.sessions.update sid (some sess) }
      some (s', sid)

/-- `settle_claim(session_id, bytes_used)`. Operator records
    bytes. Same-bytes repeats are idempotent; different-bytes is
    EQUIVOCATION, which refunds the deposit and marks the session
    refunded (slash itself is `slash_double_sign`'s job). -/
def settleClaim
    (s : ProgramState) (caller : Addr) (sid : SessionId) (bytesUsed : Nat) :
    Option ProgramState :=
  if s.paused then none
  else if sid ≥ s.sessionCount then none
  else
    match s.sessions sid with
    | none => none
    | some sess =>
      if sess.status ≠ SessionStatus.open then none
      else if s.circleOwner sess.circle ≠ caller then none
      else if ¬ circleIsActive s sess.circle then none
      else
        match sess.operatorClaim with
        | none =>
          let upd : Session := { sess with operatorClaim := some bytesUsed }
          some { s with sessions := s.sessions.update sid (some upd) }
        | some prevBytes =>
          if prevBytes = bytesUsed then
            some s
          else
            -- Equivocation refund.
            let t := s.tailnets sess.tailnetId
            let t' := { t with treasury := t.treasury + sess.deposit }
            let upd : Session := { sess with status := SessionStatus.refunded }
            some { s with
                    sessions := s.sessions.update sid (some upd),
                    tailnets := s.tailnets.update sess.tailnetId t' }

/-- `settle_confirm(session_id, bytes_used, net, blinding)`.
    Opener-only; requires the operator to have claimed first.
    Mismatched bytes records a dispute (`clientConfirm` set, status
    stays open). Match settles: caps net against deposit, takes
    protocol fee, refunds surplus to tailnet, credits the operator
    earnings ledger AND extends the hash chain. -/
def settleConfirm
    (s : ProgramState) (caller : Addr) (sid : SessionId)
    (bytesUsed : Nat) (net : Nat) (blinding : Bytes) :
    Option ProgramState :=
  if s.paused then none
  else if sid ≥ s.sessionCount then none
  else
    match s.sessions sid with
    | none => none
    | some sess =>
      if sess.status ≠ SessionStatus.open then none
      else if sess.opener ≠ caller then none
      else
        match sess.operatorClaim with
        | none => none
        | some opBytes =>
          if blinding = [] then none
          else if opBytes ≠ bytesUsed then
            -- Dispute path: just record the client side.
            let upd : Session := { sess with clientConfirm := some bytesUsed }
            some { s with sessions := s.sessions.update sid (some upd) }
          else
            -- Match: apply settlement.
            let dep := sess.deposit
            let totalPaid := if net > dep then dep else net
            let fee := totalPaid * s.params.protocolFeeBps / BPS_DENOM
            let netAfterFee := totalPaid - fee
            let refund := dep - totalPaid
            let upd : Session :=
              { sess with status := SessionStatus.settled,
                          clientConfirm := some bytesUsed }
            let t := s.tailnets sess.tailnetId
            let t' := { t with treasury := t.treasury + refund }
            let curTotal := s.circleEarningsTotal sess.circle
            let curHead  := s.circleEarningsChain sess.circle
            let newHead  := sha256 (curHead ++ sha256 blinding)
            let s' : ProgramState :=
              { s with
                  sessions := s.sessions.update sid (some upd),
                  tailnets := s.tailnets.update sess.tailnetId t',
                  programTreasury := s.programTreasury + fee,
                  circleEarningsTotal :=
                    if netAfterFee > 0 then
                      s.circleEarningsTotal.update sess.circle (curTotal + netAfterFee)
                    else s.circleEarningsTotal,
                  circleEarningsChain :=
                    if netAfterFee > 0 then
                      s.circleEarningsChain.update sess.circle newHead
                    else s.circleEarningsChain }
            some s'

/-- v3.2 (C-1 fix): `settle_resolve(session_id, accepted_bytes_used,
    blinding)` — either the operator's circle owner OR the tailnet
    owner picks one of the two recorded claims within the grace
    window. Half-slash on the losing party. Models
    `main-v3-c1-fix.aml:728-832`.

    The `verified : Bool` is the chain runtime's `circle_owner ==
    caller || tailnet_owner == caller` check; we surface it at the
    Lean boundary so the body assumes "caller is a dispute party".
    `pickOperator : Bool` says which claim was accepted. The losing
    side's half-slash amount is the function's second return value;
    on operator-loss the slash is from `circleBond`, on client-loss
    it is forfeited off the deposit. -/
def settleResolve
    (s : ProgramState) (caller : Addr) (sid : SessionId)
    (acceptedBytes : Nat) (blinding : Bytes) :
    Option (ProgramState × OctRaw) :=
  if s.paused then none
  else if sid ≥ s.sessionCount then none
  else
    match s.sessions sid with
    | none => none
    | some sess =>
      if sess.status ≠ SessionStatus.disputed then none
      else if s.currentEpoch ≥ s.sessionDisputeDeadline sid then none
      else
        match sess.operatorClaim, sess.clientConfirm with
        | none, _ => none
        | _, none => none
        | some opBytes, some clBytes =>
          if blinding = [] then none
          else
            let circleOwn := s.circleOwner sess.circle
            let tnOwn := (s.tailnets sess.tailnetId).owner
            if caller ≠ circleOwn ∧ caller ≠ tnOwn then none
            else if acceptedBytes ≠ opBytes ∧ acceptedBytes ≠ clBytes then none
            else
              let chosenOp : Bool := decide (acceptedBytes = opBytes)
              let halfBurnBps := s.params.slashBurnBps / 2
              let dep := sess.deposit
              -- Half-slash bookkeeping. Operator loses bond; client
              -- loses deposit fraction.
              let opSlashAmt :=
                if chosenOp then 0 else (s.circleBond sess.circle) * halfBurnBps / BPS_DENOM
              let clSlashAmt :=
                if chosenOp then dep * halfBurnBps / BPS_DENOM else 0
              let postSlashDep :=
                if chosenOp then dep - clSlashAmt else dep
              let totalPaid := if acceptedBytes > postSlashDep then postSlashDep else acceptedBytes
              let fee := totalPaid * s.params.protocolFeeBps / BPS_DENOM
              let netAfterFee := totalPaid - fee
              let refund := postSlashDep - totalPaid
              let curBond := s.circleBond sess.circle
              let curTotal := s.circleEarningsTotal sess.circle
              let curHead  := s.circleEarningsChain sess.circle
              let newHead  := sha256 (curHead ++ sha256 blinding)
              let upd : Session := { sess with status := SessionStatus.settled }
              let t := s.tailnets sess.tailnetId
              let t' := { t with treasury := t.treasury + refund }
              let s' : ProgramState :=
                { s with
                    sessions := s.sessions.update sid (some upd),
                    tailnets := s.tailnets.update sess.tailnetId t',
                    circleBond := s.circleBond.update sess.circle (curBond - opSlashAmt),
                    programTreasury :=
                      s.programTreasury + fee + opSlashAmt + clSlashAmt,
                    burned := s.burned + opSlashAmt + clSlashAmt,
                    circleEarningsTotal :=
                      if netAfterFee > 0 then
                        s.circleEarningsTotal.update sess.circle (curTotal + netAfterFee)
                      else s.circleEarningsTotal,
                    circleEarningsChain :=
                      if netAfterFee > 0 then
                        s.circleEarningsChain.update sess.circle newHead
                      else s.circleEarningsChain }
              some (s', opSlashAmt + clSlashAmt)

/-- v3.2 (C-1 fix): `claim_disputed_no_show(session_id)` — third-
    party fallback after the grace window expires. Defaults to the
    CLIENT's claimed value (operator-default cost), no slash, small
    sweep bounty to the caller. Models `main-v3-c1-fix.aml:843-902`.
-/
def claimDisputedNoShow
    (s : ProgramState) (_caller : Addr) (sid : SessionId) :
    Option (ProgramState × OctRaw) :=
  if s.paused then none
  else if sid ≥ s.sessionCount then none
  else
    match s.sessions sid with
    | none => none
    | some sess =>
      if sess.status ≠ SessionStatus.disputed then none
      else if s.currentEpoch < s.sessionDisputeDeadline sid then none
      else
        match sess.clientConfirm with
        | none => none
        | some clBytes =>
          let dep := sess.deposit
          let totalPaid := if clBytes > dep then dep else clBytes
          let fee := totalPaid * s.params.protocolFeeBps / BPS_DENOM
          let netAfterFee := totalPaid - fee
          let refund := dep - totalPaid
          let bounty := refund * s.params.sweepBountyBps / BPS_DENOM
          let refundAfterBounty := refund - bounty
          let upd : Session := { sess with status := SessionStatus.settled }
          let t := s.tailnets sess.tailnetId
          let t' := { t with treasury := t.treasury + refundAfterBounty }
          let curTotal := s.circleEarningsTotal sess.circle
          let s' : ProgramState :=
            { s with
                sessions := s.sessions.update sid (some upd),
                tailnets := s.tailnets.update sess.tailnetId t',
                programTreasury := s.programTreasury + fee,
                circleEarningsTotal :=
                  if netAfterFee > 0 then
                    s.circleEarningsTotal.update sess.circle (curTotal + netAfterFee)
                  else s.circleEarningsTotal }
          some (s', bounty)

/-- `claim_no_show(session_id)`. Opener-only; refunds the deposit
    to the tailnet after `session_grace_epochs` has elapsed AND
    operator has NOT claimed. -/
def claimNoShow
    (s : ProgramState) (caller : Addr) (sid : SessionId) :
    Option ProgramState :=
  if s.paused then none
  else if sid ≥ s.sessionCount then none
  else
    match s.sessions sid with
    | none => none
    | some sess =>
      if sess.status ≠ SessionStatus.open then none
      else if sess.opener ≠ caller then none
      else if s.currentEpoch < sess.openedAt + s.params.sessionGraceEpochs then none
      else if sess.operatorClaim ≠ none then none
      else
        let upd : Session := { sess with status := SessionStatus.refunded }
        let t := s.tailnets sess.tailnetId
        let t' := { t with treasury := t.treasury + sess.deposit }
        some { s with
                sessions := s.sessions.update sid (some upd),
                tailnets := s.tailnets.update sess.tailnetId t' }

/-- `sweep_expired_session(session_id)`. Permissionless after the
    extended grace; pays the caller `sweep_bounty_bps` of the
    deposit and refunds the remainder to the tailnet. -/
def sweepExpiredSession
    (s : ProgramState) (_caller : Addr) (sid : SessionId) :
    Option (ProgramState × OctRaw) :=
  if s.paused then none
  else if sid ≥ s.sessionCount then none
  else
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
          let bounty := dep * s.params.sweepBountyBps / BPS_DENOM
          let refund := dep - bounty
          let upd : Session := { sess with status := SessionStatus.refunded }
          let t := s.tailnets sess.tailnetId
          let t' := { t with treasury := t.treasury + refund }
          some
            ({ s with
                sessions := s.sessions.update sid (some upd),
                tailnets := s.tailnets.update sess.tailnetId t' },
             bounty)

-- ============================================================
-- Earnings claim (AML: `main-v3.aml:648-659`)
-- ============================================================

/-- `claim_earnings(circle, amount)` — owner-gated; not slashed;
    `amount ≤ availableEarnings`. Debits `claimed`, not `total`,
    so the running total is monotone. Returns `(s', amount)`. -/
def claimEarnings
    (s : ProgramState) (caller : Addr) (c : CircleId) (amount : Nat) :
    Option (ProgramState × OctRaw) :=
  if s.paused then none
  else if s.circleOwner c ≠ caller then none
  else if s.circleSlashed c then none
  else if amount = 0 then none
  else if amount > availableEarnings s c then none
  else
    let claimed' := s.circleEarningsClaimed c + amount
    some ({ s with circleEarningsClaimed := s.circleEarningsClaimed.update c claimed' },
          amount)

end OctraVPN_V3
