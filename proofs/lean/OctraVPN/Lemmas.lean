import OctraVPN.State
import OctraVPN.Entrypoints

/-!
# Structural lemmas about the OctraVPN spec (v1).

Each lemma here is one of the load-bearing safety properties of the
v1 state machine. Together they form the formally-verified core that
backs `docs/whitepaper.md §3`.

Stake / slash lemmas:
- `register_requires_stake` — operators can only register with
  `endpointStake ≥ minEndpointStake`.
- `slash_burns_stake` — after a successful slash, stake = 0.
- `slash_marks_terminal` — after slash, the slashed flag is true.
- `slashDoubleSign_slashes_stake` — after a successful
  `slashDoubleSign`, `endpointStake[op] = 0` and
  `endpointSlashed[op] = true`.
- `slashDoubleSign_pays_bounty` — successful `slashDoubleSign`
  returns `total_stake - burn_amt` to the caller as bounty.
- `slashDoubleSign_idempotent_when_already_slashed` — a second
  `slashDoubleSign` on an already-slashed operator returns `none`
  (mirrors AML revert "already slashed").
- `slashDoubleSign_distinct_payloads_required` — when the alleged
  payloads coincide (`verified := false`), the entrypoint returns
  `none`, i.e. no state change.

Two-tx settlement lemmas (claim side):
- `settleClaim_requires_caller_is_exit` — only the configured exit
  operator can submit `settle_claim`.
- `settleClaim_records_claim` — first claim sets
  `operatorClaim = some (bytes, epoch)`.
- `settleClaim_idempotent_on_same_bytes` — re-claim with the same
  bytes is a no-op.
- `settleClaim_equivocation_refunds` — re-claim with DIFFERENT
  bytes slashes the operator and refunds the session deposit to
  the tailnet treasury; operator's earnings ledger is untouched.

Two-tx settlement lemmas (confirm side):
- `settleConfirm_only_opener` — only the session opener can
  confirm.
- `settleConfirm_match_settles` — matching bytes → status =
  settled, FHE earnings credited.
- `settleConfirm_mismatch_disputes` — mismatch → status stays
  open, `clientConfirm` recorded, no value flows.

Pre-auth join-token lemmas:
- `joinToken_preimage_match` — successful redeem requires the hash
  was previously committed.
- `joinToken_uniqueness` — after redeem,
  `joinTokenRedeemed[h] = true`.
- `joinToken_no_double_redeem` — once redeemed, the same hash can
  never be redeemed again.

Treasury / accounting lemmas:
- `create_tailnet_seeds_treasury` — `create_tailnet` puts the
  deposit into the treasury and adds the owner as the first member.
- `retire_clears_active` — retire flips active = false.

Claim lemmas:
- `claim_resets_encEarn` — successful claim zeros the ledger.
- `claim_requires_exact_match` — only an exact-match claim succeeds.
-/

namespace OctraVPN

-- Nat has DecidableEq built-in; no auxiliary variable needed.

theorem Map.update_eq {α β} [DecidableEq α]
    (m : Map α β) (k : α) (v : β) : (m.update k v) k = v := by
  unfold Map.update; simp

theorem Map.update_ne {α β} [DecidableEq α]
    (m : Map α β) (k k' : α) (v : β) (h : k' ≠ k) :
    (m.update k v) k' = m k' := by
  unfold Map.update; simp [h]

-- ============================================================
-- Stake / slash lemmas
-- ============================================================

/-- A successful `registerEndpoint` requires bonded stake. -/
theorem register_requires_stake
    (s s' : ProgramState) (caller : Addr)
    (ep r : String) (price : Nat)
    (h : registerEndpoint s caller ep r price = some s') :
    s.endpointStake caller ≥ s.params.minEndpointStake := by
  unfold registerEndpoint at h
  by_cases h1 : (s.endpoints caller).active
  · simp [h1] at h
  by_cases h2 : s.endpointSlashed caller
  · simp [h1, h2] at h
  by_cases h3 : s.endpointStake caller < s.params.minEndpointStake
  · simp [h1, h2, h3] at h
  · exact Nat.le_of_not_lt h3

/-- A successful `registerEndpoint` cannot come from a slashed addr. -/
theorem register_not_slashed
    (s s' : ProgramState) (caller : Addr)
    (ep r : String) (price : Nat)
    (h : registerEndpoint s caller ep r price = some s') :
    ¬ s.endpointSlashed caller := by
  unfold registerEndpoint at h
  by_cases h1 : (s.endpoints caller).active
  · simp [h1] at h
  by_cases h2 : s.endpointSlashed caller
  · simp [h1, h2] at h
  · exact h2

/-- After registerEndpoint, the endpoint is active. -/
theorem register_sets_active
    (s s' : ProgramState) (caller : Addr)
    (ep r : String) (price : Nat)
    (h : registerEndpoint s caller ep r price = some s') :
    (s'.endpoints caller).active = true := by
  unfold registerEndpoint at h
  by_cases h1 : (s.endpoints caller).active
  · simp [h1] at h
  by_cases h2 : s.endpointSlashed caller
  · simp [h1, h2] at h
  by_cases h3 : s.endpointStake caller < s.params.minEndpointStake
  · simp [h1, h2, h3] at h
  by_cases h4 : price = 0
  · simp [h1, h2, h3, h4] at h
  · simp [h1, h2, h3, h4] at h
    subst h
    unfold Map.update
    simp

/-- `bondEndpoint` increases the caller's stake by `amount`. -/
theorem bond_increases_stake
    (s s' : ProgramState) (caller : Addr) (amount : OctRaw)
    (h : bondEndpoint s caller amount = some s') :
    s'.endpointStake caller = s.endpointStake caller + amount := by
  unfold bondEndpoint at h
  by_cases h1 : amount = 0
  · simp [h1] at h
  by_cases h2 : s.endpointSlashed caller
  · simp [h1, h2] at h
  by_cases h3 : (s.endpointUnbonding caller).stake ≠ 0
  · simp [h1, h2, h3] at h
  · simp [h1, h2, h3] at h
    subst h
    unfold Map.update
    simp

/-- After a successful `govSlashOperator`, the operator's live stake
    is zero. -/
theorem slash_burns_stake
    (s s' : ProgramState) (caller op : Addr)
    (h : govSlashOperator s caller op = some s') :
    s'.endpointStake op = 0 := by
  unfold govSlashOperator at h
  by_cases h1 : caller ≠ s.programOwner
  · simp [h1] at h
  by_cases h2 : s.endpointSlashed op
  · simp [h1, h2] at h
  by_cases h3 : s.endpointStake op + (s.endpointUnbonding op).stake = 0
  · simp [h1, h2, h3] at h
  · simp [h1, h2, h3] at h
    by_cases h4 : (s.endpoints op).active
    · simp [h4] at h
      subst h
      unfold Map.update
      simp
    · simp [h4] at h
      subst h
      unfold Map.update
      simp

/-- After a successful `govSlashOperator`, the slashed flag is set. -/
theorem slash_marks_terminal
    (s s' : ProgramState) (caller op : Addr)
    (h : govSlashOperator s caller op = some s') :
    s'.endpointSlashed op = true := by
  unfold govSlashOperator at h
  by_cases h1 : caller ≠ s.programOwner
  · simp [h1] at h
  by_cases h2 : s.endpointSlashed op
  · simp [h1, h2] at h
  by_cases h3 : s.endpointStake op + (s.endpointUnbonding op).stake = 0
  · simp [h1, h2, h3] at h
  · simp [h1, h2, h3] at h
    by_cases h4 : (s.endpoints op).active
    · simp [h4] at h
      subst h
      unfold Map.update
      simp
    · simp [h4] at h
      subst h
      unfold Map.update
      simp

/-- `govSlashOperator` requires the caller to be the program owner. -/
theorem slash_requires_owner
    (s s' : ProgramState) (caller op : Addr)
    (h : govSlashOperator s caller op = some s') :
    caller = s.programOwner := by
  unfold govSlashOperator at h
  by_cases h1 : caller ≠ s.programOwner
  · simp [h1] at h
  · -- h1 : ¬ (a ≠ b) ⇒ a = b. Decidable equality on Addr (Nat).
    exact Decidable.of_not_not h1

-- ----- Cryptographic equivocation slash (`slashDoubleSign`) -----

/-- After a successful `slashDoubleSign`, the operator's live stake
    is zero AND the slashed flag is set. -/
theorem slashDoubleSign_slashes_stake
    (s s' : ProgramState) (caller op : Addr) (verified : Bool)
    (bounty : OctRaw)
    (h : slashDoubleSign s caller op verified = some (s', bounty)) :
    s'.endpointStake op = 0 ∧ s'.endpointSlashed op = true := by
  unfold slashDoubleSign at h
  by_cases h1 : ¬ verified
  · simp [h1] at h
  by_cases h2 : s.endpointSlashed op
  · simp [h1, h2] at h
  by_cases h3 : s.endpointStake op + (s.endpointUnbonding op).stake = 0
  · simp [h1, h2, h3] at h
  · simp [h1, h2, h3] at h
    by_cases h4 : (s.endpoints op).active
    · simp [h4] at h
      obtain ⟨hs, _⟩ := h
      subst hs
      refine ⟨?_, ?_⟩
      · unfold Map.update; simp
      · unfold Map.update; simp
    · simp [h4] at h
      obtain ⟨hs, _⟩ := h
      subst hs
      refine ⟨?_, ?_⟩
      · unfold Map.update; simp
      · unfold Map.update; simp

/-- After a successful `slashDoubleSign`, the caller's bounty is
    `total - burn_amt`, where `total = endpointStake[op] +
    endpointUnbonding[op].stake`. The Lean model returns the bounty
    explicitly in the entrypoint's tuple (AML's `transfer(caller,
    bounty_amt)` is opaque to the state machine). -/
theorem slashDoubleSign_pays_bounty
    (s s' : ProgramState) (caller op : Addr) (verified : Bool)
    (bounty : OctRaw)
    (h : slashDoubleSign s caller op verified = some (s', bounty)) :
    let total := s.endpointStake op + (s.endpointUnbonding op).stake
    let burnAmt := total * s.params.slashBurnBps / 10000
    bounty = total - burnAmt := by
  unfold slashDoubleSign at h
  by_cases h1 : ¬ verified
  · simp [h1] at h
  by_cases h2 : s.endpointSlashed op
  · simp [h1, h2] at h
  by_cases h3 : s.endpointStake op + (s.endpointUnbonding op).stake = 0
  · simp [h1, h2, h3] at h
  · simp [h1, h2, h3] at h
    by_cases h4 : (s.endpoints op).active
    · simp [h4] at h
      obtain ⟨_, hb⟩ := h
      exact hb.symm
    · simp [h4] at h
      obtain ⟨_, hb⟩ := h
      exact hb.symm

/-- `slashDoubleSign` on an already-slashed operator returns `none`
    (no state change). Mirrors the AML's `require(endpoint_slashed[op]
    == 0, "already slashed")`. -/
theorem slashDoubleSign_idempotent_when_already_slashed
    (s : ProgramState) (caller op : Addr) (verified : Bool)
    (halr : s.endpointSlashed op = true) :
    slashDoubleSign s caller op verified = none := by
  unfold slashDoubleSign
  by_cases h1 : ¬ verified
  · simp [h1]
  · simp [h1, halr]

/-- When the two payloads are identical (or any sig fails to verify
    — the AML's `require` aborts the call), the entrypoint returns
    `none`. In the Lean model that's the `verified := false` arm,
    standing for "either payloads collide or one of the sigs is bad".
    The lemma's content is: `verified = false ⇒ slashDoubleSign = none`,
    so no state mutates and no bounty is paid. -/
theorem slashDoubleSign_distinct_payloads_required
    (s : ProgramState) (caller op : Addr) :
    slashDoubleSign s caller op false = none := by
  unfold slashDoubleSign
  simp

-- ============================================================
-- Session lemmas
-- ============================================================

-- ----- Two-tx settlement: claim side -----

/-- A successful `settleClaim` requires the caller to match the
    session's recorded exit operator. (Generalisation of the old
    `settle_requires_caller_is_exit`.) -/
theorem settleClaim_requires_caller_is_exit
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch : Nat)
    (h : settleClaim s sid bytes caller epoch = some s') :
    ∀ prev, s.sessions sid = some prev → caller = prev.exit := by
  intro prev hprev
  unfold settleClaim at h
  rw [hprev] at h
  by_cases h1 : prev.status ≠ SessionStatus.open
  · simp [h1] at h
  by_cases h2 : caller ≠ prev.exit
  · simp [h1, h2] at h
  · exact Decidable.of_not_not h2

/-- First `settleClaim` records `operatorClaim = some (bytes, epoch)`
    on the session. -/
theorem settleClaim_records_claim
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (hcaller : caller = prev.exit)
    (hnoprior : prev.operatorClaim = none)
    (h : settleClaim s sid bytes caller epoch = some s') :
    ∃ upd, s'.sessions sid = some upd ∧
           upd.operatorClaim = some (bytes, epoch) := by
  unfold settleClaim at h
  rw [hsess] at h
  -- Outer `match some prev` reduces; the inner `match sess.operatorClaim`
  -- needs hnoprior to commit to the `none` branch.
  simp only at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have hcaller' : ¬ caller ≠ prev.exit := by simp [hcaller]
  simp [hopen', hcaller', hnoprior] at h
  subst h
  refine ⟨{ prev with operatorClaim := some (bytes, epoch) }, ?_, rfl⟩
  unfold Map.update; simp

/-- Re-claim with the *same* bytes is a no-op: returns the original
    state unchanged. -/
theorem settleClaim_idempotent_on_same_bytes
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch claimedAt : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (hcaller : caller = prev.exit)
    (hprior : prev.operatorClaim = some (bytes, claimedAt))
    (h : settleClaim s sid bytes caller epoch = some s') :
    s' = s := by
  unfold settleClaim at h
  rw [hsess] at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have hcaller' : ¬ caller ≠ prev.exit := by simp [hcaller]
  simp only at h  -- reduce `match some prev`
  -- Now the match on `prev.operatorClaim` can be rewritten.
  rw [hprior] at h
  simp [hopen', hcaller'] at h
  exact h.symm

/-- Equivocation: a second `settleClaim` with *different* bytes
    refunds the deposit to the tailnet treasury, marks the session
    refunded, slashes the operator (`endpointSlashed` becomes
    `true`, `endpointStake` becomes 0), and leaves the FHE earnings
    ledger of the operator untouched. -/
theorem settleClaim_equivocation_refunds
    (s s' : ProgramState) (sid : SessionId) (bytes prevBytes : Nat)
    (caller : Addr) (epoch claimedAt : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (hcaller : caller = prev.exit)
    (hprior : prev.operatorClaim = some (prevBytes, claimedAt))
    (hdiff : prevBytes ≠ bytes)
    (h : settleClaim s sid bytes caller epoch = some s') :
    (∃ upd, s'.sessions sid = some upd ∧
            upd.status = SessionStatus.refunded) ∧
    (s'.tailnets prev.tailnetId).treasury =
      (s.tailnets prev.tailnetId).treasury + prev.deposit ∧
    s'.endpointSlashed caller = true ∧
    s'.endpointStake caller = 0 ∧
    s'.encEarn caller = s.encEarn caller := by
  unfold settleClaim at h
  rw [hsess] at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have hcaller' : ¬ caller ≠ prev.exit := by simp [hcaller]
  have hdiff' : ¬ prevBytes = bytes := hdiff
  -- Reduce the outer `match some prev`, then rewrite the inner
  -- match on `prev.operatorClaim` with hprior.
  simp only at h
  rw [hprior] at h
  simp [hopen', hcaller', hdiff'] at h
  -- Split on whether the endpoint is currently active.
  by_cases hact : (s.endpoints caller).active
  · simp [hact] at h
    subst h
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · -- The stored session reuses `sess.operatorClaim` (the match-
      -- substituted value `some (prevBytes, claimedAt)`); the witness
      -- form `{ prev with status := refunded }` carries
      -- `prev.operatorClaim`, so we discharge the equality with hprior.
      refine ⟨{ prev with status := SessionStatus.refunded }, ?_, rfl⟩
      unfold Map.update; simp [hprior]
    · unfold Map.update; simp
    · unfold Map.update; simp
    · unfold Map.update; simp
    · rfl
  · simp [hact] at h
    subst h
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · refine ⟨{ prev with status := SessionStatus.refunded }, ?_, rfl⟩
      unfold Map.update; simp [hprior]
    · unfold Map.update; simp
    · unfold Map.update; simp
    · unfold Map.update; simp
    · rfl

-- ----- Two-tx settlement: confirm side -----

/-- `settleConfirm` may only be submitted by the session opener. If
    the caller is not the opener, the call returns `none`, so the
    state is unchanged (we phrase this as: every successful confirm
    has `caller = opener`). -/
theorem settleConfirm_only_opener
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch : Nat)
    (h : settleConfirm s sid bytes caller epoch = some s') :
    ∀ prev, s.sessions sid = some prev → caller = prev.opener := by
  intro prev hprev
  unfold settleConfirm at h
  rw [hprev] at h
  by_cases h1 : prev.status ≠ SessionStatus.open
  · simp [h1] at h
  by_cases h2 : caller ≠ prev.opener
  · simp [h1, h2] at h
  · exact Decidable.of_not_not h2

/-- When the client's bytes match the operator's claim, the session
    moves to `settled` and the FHE-earnings ledger gains
    `bytesUsed * pricePerMb − fee` for the exit operator. -/
theorem settleConfirm_match_settles
    (s s' : ProgramState) (sid : SessionId) (bytes : Nat)
    (caller : Addr) (epoch claimedAt : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (hcaller : caller = prev.opener)
    (hclaim : prev.operatorClaim = some (bytes, claimedAt))
    (h : settleConfirm s sid bytes caller epoch = some s') :
    let price := (s.endpoints prev.exit).pricePerMb
    let total := price * bytes
    total ≤ prev.deposit ∧
    (∃ upd, s'.sessions sid = some upd ∧
            upd.status = SessionStatus.settled ∧
            upd.paidBytes = bytes) ∧
    let fee := total * s.params.protocolFeeBps / 10000
    s'.encEarn prev.exit = s.encEarn prev.exit + (total - fee) := by
  unfold settleConfirm at h
  rw [hsess] at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have hcaller' : ¬ caller ≠ prev.opener := by simp [hcaller]
  have hbytes_eq : ¬ bytes ≠ bytes := by simp
  simp only at h
  rw [hclaim] at h
  simp [hopen', hcaller', hbytes_eq] at h
  by_cases h3 : (s.endpoints prev.exit).pricePerMb * bytes > prev.deposit
  · simp [h3] at h
  · simp [h3] at h
    refine ⟨by omega, ?_, ?_⟩
    · subst h
      refine ⟨{ prev with
                  status := SessionStatus.settled,
                  paidBytes := bytes,
                  clientConfirm := some (bytes, epoch) }, ?_, rfl, rfl⟩
      unfold Map.update; simp [hclaim]
    · subst h
      -- The encEarn update is at key `prev.exit`. We rewrite using
      -- update_eq.
      unfold Map.update; simp

/-- When the client's bytes mismatch the operator's claim, the
    session stays `open`, `clientConfirm` is recorded, and no
    settlement event fires (treasury, encEarn untouched). -/
theorem settleConfirm_mismatch_disputes
    (s s' : ProgramState) (sid : SessionId) (bytes opBytes : Nat)
    (caller : Addr) (epoch claimedAt : Nat)
    (prev : Session)
    (hsess : s.sessions sid = some prev)
    (hopen : prev.status = SessionStatus.open)
    (hcaller : caller = prev.opener)
    (hclaim : prev.operatorClaim = some (opBytes, claimedAt))
    (hdiff : opBytes ≠ bytes)
    (h : settleConfirm s sid bytes caller epoch = some s') :
    (∃ upd, s'.sessions sid = some upd ∧
            upd.status = SessionStatus.open ∧
            upd.clientConfirm = some (bytes, epoch)) ∧
    s'.tailnets = s.tailnets ∧
    s'.encEarn = s.encEarn ∧
    s'.programTreasury = s.programTreasury := by
  unfold settleConfirm at h
  rw [hsess] at h
  have hopen' : ¬ prev.status ≠ SessionStatus.open := by simp [hopen]
  have hcaller' : ¬ caller ≠ prev.opener := by simp [hcaller]
  simp only at h
  rw [hclaim] at h
  simp [hopen', hcaller', hdiff] at h
  subst h
  refine ⟨?_, rfl, rfl, rfl⟩
  refine ⟨{ prev with clientConfirm := some (bytes, epoch) }, ?_, ?_, rfl⟩
  · unfold Map.update; simp [hclaim]
  · -- status field of the record-update is `prev.status`, which is open.
    simp [hopen]

-- ============================================================
-- Pre-auth join token lemmas
-- ============================================================

/-- A hash `h` flagged as redeemed must have been a commitment for
    SOME tailnet. (`redeemJoinToken` is the only entrypoint that
    sets `joinTokenRedeemed[h] := true`, and it requires
    `joinTokenCommits[(tid, h)] = true`.) -/
theorem joinToken_preimage_match
    (s s' : ProgramState) (tid : TailnetId) (preimage : Bytes)
    (caller : Addr)
    (h : redeemJoinToken s tid preimage caller = some s') :
    s.joinTokenCommits (tid, sha256 preimage) = true := by
  unfold redeemJoinToken at h
  by_cases h1 : (s.tailnets tid).owner = 0
  · simp [h1] at h
  by_cases h2 : ¬ s.joinTokenCommits (tid, sha256 preimage)
  · simp [h1, h2] at h
  · -- h2 : ¬ ¬ commits ⇒ commits = true
    have := Decidable.of_not_not h2
    -- coerce Bool to "= true"
    cases hcomm : s.joinTokenCommits (tid, sha256 preimage) with
    | false => exact (h2 (by simp [hcomm])).elim
    | true  => rfl

/-- A redeemed hash can never be redeemed again: after a successful
    redeem, `joinTokenRedeemed[sha256 preimage] = true`, and the
    function's own guard rules out a second redeem of the same
    hash. -/
theorem joinToken_uniqueness
    (s s' : ProgramState) (tid : TailnetId) (preimage : Bytes)
    (caller : Addr)
    (h : redeemJoinToken s tid preimage caller = some s') :
    s'.joinTokenRedeemed (sha256 preimage) = true := by
  unfold redeemJoinToken at h
  by_cases h1 : (s.tailnets tid).owner = 0
  · simp [h1] at h
  by_cases h2 : ¬ s.joinTokenCommits (tid, sha256 preimage)
  · simp [h1, h2] at h
  by_cases h3 : s.joinTokenRedeemed (sha256 preimage)
  · simp [h1, h2, h3] at h
  by_cases h4 : caller ∈ (s.tailnets tid).members
  · simp [h1, h2, h3, h4] at h
  · simp [h1, h2, h3, h4] at h
    subst h
    unfold Map.update; simp

/-- Once `joinTokenRedeemed[h] = true`, no further call of
    `redeemJoinToken` with a preimage hashing to `h` can succeed
    (the second redeem hits the `already redeemed` guard). -/
theorem joinToken_no_double_redeem
    (s s' : ProgramState) (tid : TailnetId) (preimage : Bytes)
    (caller : Addr)
    (hred : s.joinTokenRedeemed (sha256 preimage) = true)
    (h : redeemJoinToken s tid preimage caller = some s') :
    False := by
  unfold redeemJoinToken at h
  by_cases h1 : (s.tailnets tid).owner = 0
  · simp [h1] at h
  by_cases h2 : ¬ s.joinTokenCommits (tid, sha256 preimage)
  · simp [h1, h2] at h
  · simp [h1, h2, hred] at h

-- ============================================================
-- Tailnet lemmas
-- ============================================================

theorem create_tailnet_seeds_treasury
    (s s' : ProgramState) (owner : Addr) (tid : TailnetId) (deposit : Nat)
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

-- ============================================================
-- Claim lemmas
-- ============================================================

/-- Successful claim implies the claimed amount equals the ledger
    balance: this is the soundness property of the on-chain
    `fhe_verify_zero` check. -/
theorem claim_requires_exact_match
    (s s' : ProgramState) (caller : Addr) (amount : Nat)
    (proofOk : Prop) [Decidable proofOk]
    (h : claimEarnings s caller amount proofOk = some s') :
    s.encEarn caller = amount := by
  unfold claimEarnings at h
  by_cases h1 : s.endpointSlashed caller
  · simp [h1] at h
  by_cases h2 : amount = 0
  · simp [h1, h2] at h
  by_cases h3 : ¬ proofOk
  · simp [h1, h2, h3] at h
  by_cases h4 : s.encEarn caller ≠ amount
  · simp [h1, h2, h3, h4] at h
  · -- `h4 : ¬ s.encEarn caller ≠ amount`. We don't have Mathlib's
    -- push_neg here; the explicit double-negation elimination via
    -- `Decidable.of_not_not` works on `Nat` equality (decidable).
    exact Decidable.of_not_not h4

/-- After a successful claim, the earnings ledger is reset to zero. -/
theorem claim_resets_encEarn
    (s s' : ProgramState) (caller : Addr) (amount : Nat)
    (proofOk : Prop) [Decidable proofOk]
    (h : claimEarnings s caller amount proofOk = some s') :
    s'.encEarn caller = 0 := by
  unfold claimEarnings at h
  by_cases h1 : s.endpointSlashed caller
  · simp [h1] at h
  by_cases h2 : amount = 0
  · simp [h1, h2] at h
  by_cases h3 : ¬ proofOk
  · simp [h1, h2, h3] at h
  by_cases h4 : s.encEarn caller ≠ amount
  · simp [h1, h2, h3, h4] at h
  · simp [h1, h2, h3, h4] at h
    subst h
    unfold Map.update
    simp

end OctraVPN
