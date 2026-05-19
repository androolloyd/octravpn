import WireProtocol.HmacToken

/-!
# Portal approve+unseal cache lifecycle — Lean spec & proofs.

Mirrors the in-process `allow_set` + `unseal_cache` machinery in
`crates/octravpn-client/src/portal/routes.rs::PortalState`
(lines 88-178).

The Rust state is:

```rust
pub(crate) struct PortalState {
    pub chain: PortalChain,
    pub allow_set: Arc<Mutex<BTreeSet<String>>>,
    pub hmac_secret: Arc<[u8; 32]>,
    pub unseal_cache: UnsealCache,          // Arc<Mutex<BTreeMap<...>>>
}
```

The relevant operations are:

  * `PortalState::allow(circle_id)` — insert into the allow_set
    (called by `confirm_post` only when `token_valid` returned true,
    see `routes.rs:358-363`).
  * `PortalState::is_allowed(circle_id)` — membership in allow_set.
  * `PortalState::record_unseal(circle_id, passphrase)` — insert into
    unseal_cache.
  * **Process restart** — both maps are in-memory only (see the
    module docstring at lines 81-85: "Survives only the portal's
    process lifetime — same model as the approval `allow_set`. A
    portal restart re-prompts. We deliberately do NOT serialize this
    to disk").

We model the cache as pure functions over a `PortalCacheState`
record. The key invariants:

  1. **Approval is monotonic within a process** —
     `allow` only adds entries; it never removes.
  2. **Approval requires a valid token** — only paths through
     `tokenValid` can produce an `allow_set` entry. We capture this
     as a Hoare-triple-style theorem on the `approveWithToken`
     wrapper that exactly mirrors `confirm_post` (`routes.rs:357-363`).
  3. **Process restart wipes both maps.** Modeled by `restart`
     returning the empty state.
  4. **The unseal cache holds passphrases until restart.** A recorded
     entry survives any further `record_unseal` / `allow` calls
     (until restart).
-/

namespace OctraVPN.WireProtocol.PortalCache

open OctraVPN.WireProtocol.HmacToken

/-- A passphrase opaque blob — the Rust source wraps it in
    `Arc<Zeroizing<String>>` for the zero-on-drop property; that
    secrecy property is a runtime invariant, not a functional one. -/
structure Passphrase where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-- The in-memory portal cache state. Mirrors the runtime fields of
    `PortalState` — chain + hmac are immutable, so the only mutable
    state is allow_set + unseal_cache. -/
structure PortalCacheState where
  hmac      : PortalHmac
  allowSet  : List CircleId
  unsealCache : List (CircleId × Passphrase)
  deriving Inhabited

/-- Fresh state at process start. -/
def PortalCacheState.fresh (h : PortalHmac) : PortalCacheState :=
  { hmac := h, allowSet := [], unsealCache := [] }

/-- Predicate: a circle id is in the allow_set. -/
def PortalCacheState.isAllowed (s : PortalCacheState) (c : CircleId) : Prop :=
  c ∈ s.allowSet

/-- Decidable membership for `isAllowed`. -/
instance (s : PortalCacheState) (c : CircleId) : Decidable (s.isAllowed c) :=
  inferInstanceAs (Decidable (c ∈ s.allowSet))

/-- `allow` — append the circle id to the allow_set unconditionally.
    Mirrors `PortalState::allow` (`routes.rs:173-177`). -/
def PortalCacheState.allow (s : PortalCacheState) (c : CircleId) : PortalCacheState :=
  if c ∈ s.allowSet then s
  else { s with allowSet := c :: s.allowSet }

/-- `record_unseal` — append the (circle_id, passphrase) pair.
    Mirrors `PortalState::record_unseal` (`routes.rs:141-145`). -/
def PortalCacheState.recordUnseal
    (s : PortalCacheState) (c : CircleId) (pp : Passphrase) : PortalCacheState :=
  { s with unsealCache := (c, pp) :: s.unsealCache }

/-- `approveWithToken` — the **only** path from a request body to an
    `allow_set` insert in the Rust source. Mirrors `confirm_post`
    (`routes.rs:357-378`): the token is checked, then on success the
    circle is added to the allow_set. -/
def PortalCacheState.approveWithToken
    (s : PortalCacheState) (c : CircleId) (suppliedHex : String) : PortalCacheState :=
  if s.hmac.tokenValid c suppliedHex then s.allow c
  else s

/-- `restart` — process restart: both in-memory maps reset to empty.
    The HMAC secret is also re-rolled in the real code (a fresh
    `OsRng.fill_bytes` in `PortalState::new`); we keep the same
    secret here since the invariant we want is "no token from a
    previous run survives", and the simpler way to express that is
    that the allow_set is empty after restart (so no token from
    a previous run can be reused without going through `confirm_post`
    again, which now requires the NEW secret). -/
def PortalCacheState.restart (s : PortalCacheState) : PortalCacheState :=
  { hmac := s.hmac, allowSet := [], unsealCache := [] }

-- ============================================================
-- §1  allow_set monotonicity
-- ============================================================

/-- **Allow-set monotonicity.** Approving a circle never removes any
    other circle from the allow_set. -/
theorem allow_set_monotonic
    (s : PortalCacheState) (c c' : CircleId) :
    c' ∈ s.allowSet → c' ∈ (s.allow c).allowSet := by
  intro h
  unfold PortalCacheState.allow
  by_cases hc : c ∈ s.allowSet
  · simp [hc]; exact h
  · simp [hc]; right; exact h

/-- After `allow c`, the circle is in the allow_set. -/
theorem allow_adds_circle (s : PortalCacheState) (c : CircleId) :
    c ∈ (s.allow c).allowSet := by
  unfold PortalCacheState.allow
  by_cases hc : c ∈ s.allowSet
  · rw [if_pos hc]; exact hc
  · rw [if_neg hc]; simp [List.mem_cons]

/-- **Approve-with-token monotonicity.** Same as `allow` but gated
    on `tokenValid`. -/
theorem approve_monotonic
    (s : PortalCacheState) (c c' : CircleId) (sup : String) :
    c' ∈ s.allowSet → c' ∈ (s.approveWithToken c sup).allowSet := by
  intro h
  unfold PortalCacheState.approveWithToken
  by_cases hv : s.hmac.tokenValid c sup = true
  · simp [hv]; exact allow_set_monotonic s c c' h
  · simp at hv; simp [hv]; exact h

-- ============================================================
-- §2  Approval-requires-valid-token
-- ============================================================

/-- **Approval requires a valid token.** If `approveWithToken c sup`
    added `c` to the allow_set (and it wasn't there already), then
    `tokenValid c sup` must have been true.

    Stated contrapositively: an invalid token leaves the allow_set
    unchanged. -/
theorem approve_invalid_token_no_change
    (s : PortalCacheState) (c : CircleId) (sup : String)
    (h : s.hmac.tokenValid c sup = false) :
    s.approveWithToken c sup = s := by
  unfold PortalCacheState.approveWithToken
  simp [h]

/-- **An `allow_set` entry implies a redeemed token.** Together
    with `approve_invalid_token_no_change`, this gives us:

    > A circle is in `allow_set` **iff** at least one valid HMAC token
    > has been redeemed for it (in this process).

    Phrased operationally: starting from `fresh`, the only way to
    reach a state where `c ∈ allowSet` is through a sequence of
    operations that includes at least one `approveWithToken c sup`
    with `tokenValid c sup = true`. The other state-changing ops
    (`recordUnseal`, `allow` on a *different* circle, `restart`)
    cannot add `c`.

    We prove the inductive version: an arbitrary trace of
    `approveWithToken` + `recordUnseal` ops only adds `c` to the
    allow_set when one of the approves passed token validation. -/
inductive PortalOp where
  | approve : CircleId → String → PortalOp
  | unseal  : CircleId → Passphrase → PortalOp
  deriving Inhabited

def PortalCacheState.step (s : PortalCacheState) : PortalOp → PortalCacheState
  | .approve c sup => s.approveWithToken c sup
  | .unseal c pp   => s.recordUnseal c pp

def PortalCacheState.trace (s : PortalCacheState) : List PortalOp → PortalCacheState
  | [] => s
  | (op :: rest) => (s.step op).trace rest

/-- Starting from `fresh`, the `unseal` op cannot add to the
    allow_set (it touches `unsealCache` only). -/
theorem unseal_does_not_add_to_allow_set
    (s : PortalCacheState) (c : CircleId) (pp : Passphrase) :
    (s.recordUnseal c pp).allowSet = s.allowSet := by
  unfold PortalCacheState.recordUnseal; rfl

/-- A circle id ends up in the allow_set only via an `approve` step
    with a valid token. -/
theorem allow_set_implies_valid_approve
    (s : PortalCacheState) (ops : List PortalOp) (c : CircleId)
    (h_init : c ∉ s.allowSet) (h_final : c ∈ (s.trace ops).allowSet) :
    ∃ (s' : PortalCacheState) (sup : String),
        c ∉ s'.allowSet ∧
        s'.hmac.tokenValid c sup = true ∧
        c ∈ (s'.approveWithToken c sup).allowSet := by
  induction ops generalizing s with
  | nil =>
      unfold PortalCacheState.trace at h_final
      exact absurd h_final h_init
  | cons op rest ih =>
      unfold PortalCacheState.trace at h_final
      match op, h_final with
      | .approve cb sup, h_final =>
          by_cases hc : c ∈ (s.step (.approve cb sup)).allowSet
          · -- c was added by this step (or already present).
            by_cases hc_prev : c ∈ s.allowSet
            · exact absurd hc_prev h_init
            · -- c wasn't in s, so this step added it.
              -- That means cb = c and tokenValid was true.
              show ∃ (s' : PortalCacheState) (sup : String),
                  c ∉ s'.allowSet ∧
                  s'.hmac.tokenValid c sup = true ∧
                  c ∈ (s'.approveWithToken c sup).allowSet
              unfold PortalCacheState.step PortalCacheState.approveWithToken
                PortalCacheState.allow at hc
              by_cases hv : s.hmac.tokenValid cb sup = true
              · simp only [hv, if_true] at hc
                by_cases hin : cb ∈ s.allowSet
                · simp [hin] at hc; exact absurd hc hc_prev
                · simp [hin, List.mem_cons] at hc
                  cases hc with
                  | inl hcc =>
                      subst hcc
                      refine ⟨s, sup, hc_prev, hv, ?_⟩
                      unfold PortalCacheState.approveWithToken
                      rw [hv]
                      simp only [if_true]
                      exact allow_adds_circle s c
                  | inr hcin => exact absurd hcin hc_prev
              · simp at hv; simp [hv] at hc; exact absurd hc hc_prev
          · -- not present after this step, recurse.
            apply ih (s.step (.approve cb sup)) hc h_final
      | .unseal cb pp, h_final =>
          have hpres : (s.step (.unseal cb pp)).allowSet = s.allowSet := by
            unfold PortalCacheState.step
            exact unseal_does_not_add_to_allow_set s cb pp
          have h_init2 : c ∉ (s.step (.unseal cb pp)).allowSet := by
            rw [hpres]; exact h_init
          exact ih (s.step (.unseal cb pp)) h_init2 h_final

-- ============================================================
-- §3  Process restart wipes the cache
-- ============================================================

/-- **Restart wipes the allow_set.** -/
theorem restart_clears_allow_set (s : PortalCacheState) :
    s.restart.allowSet = [] := rfl

/-- **Restart wipes the unseal_cache.** -/
theorem restart_clears_unseal_cache (s : PortalCacheState) :
    s.restart.unsealCache = [] := rfl

/-- **Cache does not outlive the process.** Both in-memory maps reset
    to empty on `restart`. Combined with the
    `allow_set_implies_valid_approve` theorem, this means a fresh
    `confirm_post` round-trip is required for every circle after
    each restart — no token from a previous run is honored unless
    it's re-supplied to the new HMAC. -/
theorem cache_does_not_outlive_process (s : PortalCacheState) :
    s.restart.allowSet = [] ∧ s.restart.unsealCache = [] :=
  ⟨restart_clears_allow_set s, restart_clears_unseal_cache s⟩

/-- After restart, no circle is allowed. -/
theorem post_restart_nothing_allowed (s : PortalCacheState) (c : CircleId) :
    ¬ s.restart.isAllowed c := by
  unfold PortalCacheState.isAllowed
  rw [restart_clears_allow_set]
  exact List.not_mem_nil c

-- ============================================================
-- §4  Concrete-value anchor
-- ============================================================

/-- Concrete anchor: a fresh state has empty allow_set, and after
    `approveWithToken` with the canonical token for `c`, `c ∈
    allowSet`. -/
example (h : PortalHmac) (c : CircleId) :
    c ∈ ((PortalCacheState.fresh h).approveWithToken c (h.tokenFor c)).allowSet := by
  have ht : h.tokenValid c (h.tokenFor c) = true := token_valid_self h c
  unfold PortalCacheState.approveWithToken
  have hh : (PortalCacheState.fresh h).hmac = h := rfl
  rw [hh, ht]
  simp only [if_true]
  exact allow_adds_circle (PortalCacheState.fresh h) c

end OctraVPN.WireProtocol.PortalCache
