import OctraVPN_V2.State

/-!
# Entrypoints of v2, modeled as state-transition functions.

Each function corresponds to one entrypoint in `program/main-v2.aml`.
Successful execution returns `some newState`; reverts are encoded as
`none`.

Key v2 deltas vs v1.1:

- `registerCircleAtomic` is payable AND a single atomic transition
  that (1) sets `circles[c].owner`, (2) flips `circles[c].active`
  to `true`, AND (3) credits `circleStake[c]` by `value`. The
  chicken-and-egg in v1.1 (separate `register_endpoint` +
  `bond_endpoint`) is gone.

- `bondEndpoint(c)` requires `circles[c].owner = caller`, so the
  chicken-and-egg cannot recur: a circle must be registered first.

- `authorizeCircle(t, c)` requires `circles[c]` to be ACTIVE and
  NOT SLASHED at authorize-time. Replaces v1.1
  `configureTailnetExit`.

- `openSession` checks authorization AND `circleIsActive(c)`
  (active ∧ ¬slashed). The per-session price is stamped from the
  circle's per-class price at open time.

- `settleConfirm` reads the stamped `pricePerMb` from the session.
  If `class = INTERNAL` and the tailnet's `chargeInternalTraffic`
  toggle is OFF (= 0), the effective price is forced to zero
  regardless of `pricePerMb`.

- Slashes (`slashDoubleSign`, `govSlashOperator`) are keyed on
  `CircleId`. Same shape as v1.1.

- Governance entrypoints (`setPaused`, `transferOwnership`,
  `setParams`, `withdrawProgramTreasury`) intentionally BYPASS the
  pause gate. Mirrors AML.

`payable` and `nonreentrant` modifiers are not modeled explicitly;
they are runtime contracts enforced by the Octra AML interpreter.
**PROOF GAP**: re-entry rejection. The model treats each entrypoint
as one atomic, non-reentrant transition by construction.
-/

namespace OctraVPN_V2

opaque sha256 : Bytes → Bytes

-- ============================================================
-- Circle stake / slash lifecycle
-- ============================================================

/-- Top up an existing circle's stake. Requires the caller to be
    the circle's owner. Subsequent top-ups go through here; the
    first deposit goes through `registerCircleAtomic`. -/
def bondEndpoint (s : ProgramState) (caller : Addr) (c : CircleId)
    (amount : OctRaw) : Option ProgramState :=
  if amount = 0 then none
  else if s.circleSlashed c then none
  else if (s.circleUnbonding c).stake ≠ 0 then none
  else if (s.circles c).owner ≠ caller then none
  else
    let cur := s.circleStake c
    some { s with circleStake := s.circleStake.update c (cur + amount) }

/-- Begin unbonding the circle's entire stake. -/
def unbondEndpoint (s : ProgramState) (caller : Addr) (c : CircleId) :
    Option ProgramState :=
  if (s.circles c).owner ≠ caller then none
  else
    let amt := s.circleStake c
    if amt = 0 then none
    else if (s.circleUnbonding c).stake ≠ 0 then none
    else
      let unlock := s.currentEpoch + s.params.unbondGraceEpochs
      let unb : Unbonding := { stake := amt, unlockEpoch := unlock }
      some { s with
              circleUnbonding := s.circleUnbonding.update c unb,
              circleStake := s.circleStake.update c 0 }

/-- Finalize unbonding after the grace window. -/
def finalizeUnbond (s : ProgramState) (caller : Addr) (c : CircleId) :
    Option (ProgramState × OctRaw) :=
  if (s.circles c).owner ≠ caller then none
  else
    let u := s.circleUnbonding c
    if u.stake = 0 then none
    else if s.currentEpoch < u.unlockEpoch then none
    else
      let s' := { s with
                  circleUnbonding := s.circleUnbonding.update c Unbonding.empty }
      some (s', u.stake)

/-- Governance slash. Owner-gated. -/
def govSlashOperator (s : ProgramState) (caller : Addr) (c : CircleId) :
    Option ProgramState :=
  if caller ≠ s.programOwner then none
  else if s.circleSlashed c then none
  else
    let live := s.circleStake c
    let unb := (s.circleUnbonding c).stake
    let total := live + unb
    if total = 0 then none
    else
      let burnAmt := total * s.params.slashBurnBps / 10000
      let crec := s.circles c
      let s1 := { s with
                  circleStake := s.circleStake.update c 0,
                  circleUnbonding := s.circleUnbonding.update c Unbonding.empty,
                  circleSlashed := s.circleSlashed.update c true,
                  programTreasury := s.programTreasury + burnAmt }
      if crec.active then
        let recPrime := { crec with active := false }
        some { s1 with circles := s1.circles.update c recPrime }
      else
        some s1

/-- Cryptographic equivocation slash (`slash_double_sign`).
    The `verified : Bool` parameter encodes the off-chain
    requirement that BOTH signatures verify under the circle's
    `receiptPubkey` AND the two payloads are DISTINCT. -/
def slashDoubleSign
    (s : ProgramState) (_caller : Addr) (c : CircleId)
    (verified : Bool) :
    Option (ProgramState × OctRaw) :=
  if ¬ verified then none
  else if s.circleSlashed c then none
  else
    let live := s.circleStake c
    let unb := (s.circleUnbonding c).stake
    let total := live + unb
    if total = 0 then none
    else
      let burnAmt := total * s.params.slashBurnBps / 10000
      let bountyAmt := total - burnAmt
      let crec := s.circles c
      let s1 := { s with
                  circleStake := s.circleStake.update c 0,
                  circleUnbonding := s.circleUnbonding.update c Unbonding.empty,
                  circleSlashed := s.circleSlashed.update c true,
                  programTreasury := s.programTreasury + burnAmt }
      if crec.active then
        let recPrime := { crec with active := false }
        some ({ s1 with circles := s1.circles.update c recPrime }, bountyAmt)
      else
        some (s1, bountyAmt)

-- ============================================================
-- Circle registry (atomic register + update / retire)
-- ============================================================

/-- Atomic `register_circle`: payable + sets owner + active + bonds
    initial stake in a single transition.

    AML enforces:
      `require(self.circles[c].active == 0, "circle already active")`
      `require(self.circle_slashed[c] == 0, ...)`
      `require(self.circle_stake[c] + value >= self.min_circle_stake, ...)`

    `value` is the OctRaw passed to a payable call. -/
def registerCircleAtomic
    (s : ProgramState) (caller : Addr) (c : CircleId)
    (region : String) (priceShared priceInternal : Nat)
    (receiptPubkey : String) (value : OctRaw) :
    Option ProgramState :=
  if (s.circles c).active then none
  else if s.circleSlashed c then none
  else if receiptPubkey = "" then none
  else if s.circleStake c + value < s.params.minCircleStake then none
  else
    let stake' := s.circleStake c + value
    let rec' : CircleRecord :=
      { CircleRecord.empty with
          owner := caller,
          receiptPubkey := receiptPubkey,
          registeredAt := s.currentEpoch,
          reputation := 0,
          active := true,
          region := region,
          pricePerMbShared := priceShared,
          pricePerMbInternal := priceInternal }
    some { s with
            circleStake := s.circleStake.update c stake',
            circles := s.circles.update c rec' }

/-- Update mutable circle fields (region, prices). Owner-gated and
    requires the circle to be active. Does NOT touch live sessions
    — see `update_circle_does_not_mutate_open_sessions`. -/
def updateCircle
    (s : ProgramState) (caller : Addr) (c : CircleId)
    (newRegion : String) (newPriceShared newPriceInternal : Nat) :
    Option ProgramState :=
  let crec := s.circles c
  if crec.owner ≠ caller then none
  else if ¬ crec.active then none
  else
    let recPrime := { crec with
                      region := newRegion,
                      pricePerMbShared := newPriceShared,
                      pricePerMbInternal := newPriceInternal }
    some { s with circles := s.circles.update c recPrime }

/-- Retire a circle. Owner-gated. -/
def retireCircle
    (s : ProgramState) (caller : Addr) (c : CircleId) :
    Option ProgramState :=
  let crec := s.circles c
  if crec.owner ≠ caller then none
  else if ¬ crec.active then none
  else
    let recPrime := { crec with active := false }
    some { s with circles := s.circles.update c recPrime }

/-- Is a circle active AND not slashed? Used by `authorizeCircle`
    and `openSession`. Mirrors AML `circle_is_active(c)`. -/
def circleIsActive (s : ProgramState) (c : CircleId) : Bool :=
  if s.circleSlashed c then false
  else (s.circles c).active

-- ============================================================
-- Tailnet lifecycle
-- ============================================================

/-- `create_tailnet(acl_policy)`. Payable. The caller becomes
    owner + first member; the deposit seeds the tailnet treasury. -/
def createTailnet
    (s : ProgramState) (owner : Addr) (tid : TailnetId)
    (aclPolicy : String) (deposit : Nat) :
    Option ProgramState :=
  let existing := s.tailnets tid
  if existing.owner ≠ 0 then none
  else if deposit < s.params.minTailnetDeposit then none
  else
    let t : Tailnet :=
      { Tailnet.empty with
          owner := owner,
          treasury := deposit,
          memberCount := 1,
          aclPolicy := aclPolicy,
          createdAt := s.currentEpoch,
          chargeInternalTraffic := 0 }
    some { s with
            tailnets := s.tailnets.update tid t,
            members := s.members.update (tid, owner) true }

/-- `deposit_to_tailnet`. Payable; caller must be owner or member. -/
def depositToTailnet
    (s : ProgramState) (caller : Addr) (tid : TailnetId) (amount : Nat) :
    Option ProgramState :=
  if amount = 0 then none
  else
    let t := s.tailnets tid
    if t.owner = 0 then none
    else if t.owner ≠ caller ∧ ¬ s.members (tid, caller) then none
    else
      let t' := { t with treasury := t.treasury + amount }
      some { s with tailnets := s.tailnets.update tid t' }

/-- Owner-only `add_member`. Idempotent on already-member. -/
def addMember
    (s : ProgramState) (tid : TailnetId) (caller member : Addr) :
    Option ProgramState :=
  let t := s.tailnets tid
  if t.owner ≠ caller then none
  else if s.members (tid, member) then
    -- Idempotent.
    some s
  else
    let t' := { t with memberCount := t.memberCount + 1 }
    some { s with
            tailnets := s.tailnets.update tid t',
            members := s.members.update (tid, member) true }

/-- Owner-only `remove_member`. Requires the member to be present. -/
def removeMember
    (s : ProgramState) (tid : TailnetId) (caller member : Addr) :
    Option ProgramState :=
  let t := s.tailnets tid
  if t.owner ≠ caller then none
  else if ¬ s.members (tid, member) then none
  else
    let newCount := if t.memberCount > 0 then t.memberCount - 1 else 0
    let t' := { t with memberCount := newCount }
    some { s with
            tailnets := s.tailnets.update tid t',
            members := s.members.update (tid, member) false }

/-- Owner-only `update_acl`. -/
def updateAcl
    (s : ProgramState) (tid : TailnetId) (caller : Addr)
    (newPolicy : String) : Option ProgramState :=
  let t := s.tailnets tid
  if t.owner = 0 then none
  else if t.owner ≠ caller then none
  else
    let t' := { t with aclPolicy := newPolicy }
    some { s with tailnets := s.tailnets.update tid t' }

/-- Owner-only `set_charge_internal_traffic`. `charge ∈ {0,1}`. -/
def setChargeInternalTraffic
    (s : ProgramState) (tid : TailnetId) (caller : Addr) (charge : Nat) :
    Option ProgramState :=
  let t := s.tailnets tid
  if t.owner ≠ caller then none
  else if charge ≠ 0 ∧ charge ≠ 1 then none
  else
    let t' := { t with chargeInternalTraffic := charge }
    some { s with tailnets := s.tailnets.update tid t' }

/-- Owner-only `authorize_circle(tid, c)`. Requires the circle to
    currently be active AND not slashed. Replaces v1.1
    `configure_tailnet_exit`. -/
def authorizeCircle
    (s : ProgramState) (tid : TailnetId) (caller : Addr) (c : CircleId) :
    Option ProgramState :=
  let t := s.tailnets tid
  if t.owner ≠ caller then none
  else if ¬ circleIsActive s c then none
  else
    some { s with authorizedCircles := s.authorizedCircles.update (tid, c) true }

/-- Owner-only `revoke_circle(tid, c)`. -/
def revokeCircle
    (s : ProgramState) (tid : TailnetId) (caller : Addr) (c : CircleId) :
    Option ProgramState :=
  let t := s.tailnets tid
  if t.owner ≠ caller then none
  else
    some { s with authorizedCircles := s.authorizedCircles.update (tid, c) false }

-- ============================================================
-- Pre-auth join tokens (precommit + redeem, bytes-keyed)
-- ============================================================

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

def redeemJoinToken
    (s : ProgramState) (tid : TailnetId) (preimage : Bytes) (caller : Addr) :
    Option ProgramState :=
  let h := sha256 preimage
  let t := s.tailnets tid
  if t.owner = 0 then none
  else if ¬ s.joinTokenCommits (tid, h) then none
  else if s.joinTokenRedeemed h then none
  else if s.members (tid, caller) then none
  else
    let t' := { t with memberCount := t.memberCount + 1 }
    some { s with
            tailnets := s.tailnets.update tid t',
            members := s.members.update (tid, caller) true,
            joinTokenRedeemed := s.joinTokenRedeemed.update h true }

-- ============================================================
-- Session lifecycle (per-class pricing, stamped at open)
-- ============================================================

/-- `open_session(tid, c, class, max_pay)`.

    Preconditions (matching AML):
      - tailnet exists
      - caller is a member
      - circle is authorized for this tailnet
      - circle is active (active ∧ ¬slashed)
      - deposit ≥ min_session_deposit
      - tailnet treasury ≥ max_pay

    Mutation:
      - tailnet treasury debited by `max_pay`
      - new session record stored with the per-class price
        STAMPED from the circle's current price for that class. -/
def openSession
    (s : ProgramState) (caller : Addr) (tid : TailnetId)
    (sid : SessionId) (c : CircleId) (cls : SessionClass)
    (maxPay : Nat) : Option ProgramState :=
  let t := s.tailnets tid
  if ¬ s.members (tid, caller) then none
  else if ¬ s.authorizedCircles (tid, c) then none
  else if ¬ circleIsActive s c then none
  else if maxPay < s.params.minSessionDeposit then none
  else if t.treasury < maxPay then none
  else
    let crec := s.circles c
    let stampedPrice :=
      match cls with
      | SessionClass.shared   => crec.pricePerMbShared
      | SessionClass.internal => crec.pricePerMbInternal
    let t' := { t with treasury := t.treasury - maxPay }
    let sess : Session :=
      { tailnetId := tid,
        circle := c,
        opener := caller,
        deposit := maxPay,
        openedAt := s.currentEpoch,
        class_ := cls,
        pricePerMb := stampedPrice,
        status := SessionStatus.open,
        operatorClaim := none,
        clientConfirm := none }
    some { s with
            tailnets := s.tailnets.update tid t',
            sessions := s.sessions.update sid (some sess) }

/-- Operator-side `settle_claim`. The caller is the wallet that
    owns the circle. First call records; same-bytes is idempotent;
    different-bytes is equivocation (refunds + marks refunded;
    actual slash is left to `slash_double_sign`). -/
def settleClaim
    (s : ProgramState) (sid : SessionId) (bytesUsed : Nat)
    (caller : Addr) (epoch : Nat) : Option ProgramState :=
  match s.sessions sid with
  | none => none
  | some sess =>
    if sess.status ≠ SessionStatus.open then none
    else
      let crec := s.circles sess.circle
      if crec.owner ≠ caller then none
      else if ¬ circleIsActive s sess.circle then none
      else
        match sess.operatorClaim with
        | none =>
          let upd : Session :=
            { sess with operatorClaim := some (bytesUsed, epoch) }
          some { s with sessions := s.sessions.update sid (some upd) }
        | some (prevBytes, _) =>
          if prevBytes = bytesUsed then
            -- Idempotent.
            some s
          else
            -- Equivocation: refund deposit, mark session refunded.
            -- Slash is left for a follow-up `slash_double_sign`
            -- because chain can't verify signatures without seeing
            -- the off-chain `(payload, sig)` pair.
            let t := s.tailnets sess.tailnetId
            let t' := { t with treasury := t.treasury + sess.deposit }
            let updSess : Session :=
              { sess with status := SessionStatus.refunded }
            some { s with
                    sessions := s.sessions.update sid (some updSess),
                    tailnets := s.tailnets.update sess.tailnetId t' }

/-- Client-side `settle_confirm`.

    Reads the STAMPED `sess.pricePerMb` (not the current
    `circles[c].pricePerMb_*`!) so price changes mid-session do
    not retroactively apply.

    For `class = INTERNAL` AND `tailnet.chargeInternalTraffic = 0`,
    the effective price is forced to ZERO regardless of
    `sess.pricePerMb`, so `total_paid = 0` and the full deposit
    refunds. -/
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
      | none => none
      | some (opBytes, _) =>
        if opBytes ≠ bytesUsed then
          let upd : Session :=
            { sess with clientConfirm := some (bytesUsed, epoch) }
          some { s with sessions := s.sessions.update sid (some upd) }
        else
          -- Match: apply settlement with effective price.
          let t := s.tailnets sess.tailnetId
          let effPrice :=
            match sess.class_ with
            | SessionClass.internal =>
                if t.chargeInternalTraffic = 0 then 0 else sess.pricePerMb
            | SessionClass.shared   => sess.pricePerMb
          let totalRaw := effPrice * bytesUsed
          -- The AML clamps `total_paid` to the deposit. We mirror.
          let totalPaid := if totalRaw > sess.deposit then sess.deposit else totalRaw
          let fee := totalPaid * s.params.protocolFeeBps / 10000
          let net := totalPaid - fee
          let refund := sess.deposit - totalPaid
          let t' := { t with treasury := t.treasury + refund }
          let upd : Session :=
            { sess with
                status := SessionStatus.settled,
                clientConfirm := some (bytesUsed, epoch) }
          let curEarn := s.encEarn sess.circle
          some { s with
                  sessions := s.sessions.update sid (some upd),
                  tailnets := s.tailnets.update sess.tailnetId t',
                  encEarn := s.encEarn.update sess.circle (curEarn + net),
                  programTreasury := s.programTreasury + fee }

/-- `claim_no_show`. Caller must be the opener; grace must have
    elapsed; operator must not have claimed. -/
def claimNoShow (s : ProgramState) (sid : SessionId) (caller : Addr) :
    Option ProgramState :=
  match s.sessions sid with
  | none => none
  | some sess =>
    if sess.status ≠ SessionStatus.open then none
    else if caller ≠ sess.opener then none
    else if s.currentEpoch < sess.openedAt + s.params.sessionGraceEpochs then none
    else if sess.operatorClaim ≠ none then none
    else
      let upd := { sess with status := SessionStatus.refunded }
      let t := s.tailnets sess.tailnetId
      let t' := { t with treasury := t.treasury + sess.deposit }
      some { s with
              sessions := s.sessions.update sid (some upd),
              tailnets := s.tailnets.update sess.tailnetId t' }

/-- `sweep_expired_session`. Permissionless after extended grace. -/
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
-- Earnings claim (FHE zero-proof as abstract Prop)
-- ============================================================

/-- `claim_earnings(circle, amount, proof)`. The `proofOk` Prop
    abstracts AML's `fhe_verify_zero(pk, delta, proof)`.

    **PROOF GAP**: FHE soundness is asserted by axiom; the Lean
    model does not simulate HFHE arithmetic. The lemmas only
    assume that a passing proof witnesses `claimed_amount =
    encEarn[c]` (the soundness property of the zero-proof). -/
def claimEarnings
    (s : ProgramState) (caller : Addr) (c : CircleId)
    (claimedAmount : Nat) (proofOk : Prop) [Decidable proofOk] :
    Option ProgramState :=
  if (s.circles c).owner ≠ caller then none
  else if s.circleSlashed c then none
  else if claimedAmount = 0 then none
  else if ¬ proofOk then none
  else if s.encEarn c ≠ claimedAmount then none
  else
    some { s with encEarn := s.encEarn.update c 0 }

-- ============================================================
-- Governance (owner-only; bypasses pause)
-- ============================================================

def setPaused
    (s : ProgramState) (caller : Addr) (v : Bool) : Option ProgramState :=
  if caller ≠ s.programOwner then none
  else some { s with paused := v }

def transferOwnership
    (s : ProgramState) (caller newOwner : Addr) : Option ProgramState :=
  if caller ≠ s.programOwner then none
  else some { s with programOwner := newOwner }

/-- `set_params`. Owner-only. The Lean model preserves the AML's
    sanity bounds; if any bound fails we return `none`. -/
def setParams
    (s : ProgramState) (caller : Addr) (p : Params) :
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
  else if p.slashBurnBps + p.slashBountyBps ≠ 10000 then none
  else if p.protocolFeeBps > 200 then none
  else some { s with params := p }

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

end OctraVPN_V2
