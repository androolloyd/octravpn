/-!
# ACL evaluator — Lean spec & proofs.

Mirrors the ACL match function in
`crates/octravpn-mesh/src/acl.rs`. The Rust code walks `rules`
top-to-bottom; the **first** matching rule wins; no match means
deny. Each rule has an action (`accept` / `deny`), a list of
`src` matchers, and a list of `dst` matchers (port matching is
modelled abstractly here as part of the per-rule predicate).

Same modelling strategy as the existing `OctraVPN_Rust/Spec.lean`
ACL section (`acl.rs`) — we keep the structure pure-functional
and concrete. No new cryptographic axioms are needed: the
evaluator is total over a finite list of rules.
-/

namespace OctraVPN_Rust.ACL

/-- Decision returned by the ACL evaluator. -/
inductive Decision
  | accept
  | deny
  deriving DecidableEq, Repr, Inhabited

/-- A flow to evaluate. The exact field set isn't load-bearing —
    we just need *some* opaque payload that the rules' predicates
    can pattern-match against. Mirrors a `(src_addr, dst_addr,
    protocol, port)` tuple in `acl.rs`. -/
structure Flow where
  src   : List UInt8
  dst   : List UInt8
  proto : UInt8
  port  : UInt32
  deriving Inhabited, DecidableEq

/-- A single ACL rule.

    Mirrors `AclRule` in `crates/octravpn-mesh/src/acl.rs`. The
    rule has an action plus a predicate that, in Rust, is the
    conjunction of `src`-matchers, `dst`-matchers, and
    `port`-matchers. We collapse those into a single `pred`
    predicate so the algebraic properties don't depend on the
    matcher's internal layout. -/
structure Rule where
  action  : Decision
  pred : Flow → Bool

/-- A policy is an ordered list of rules. Mirrors `AclDoc::rules`
    in `acl.rs`. -/
abbrev Policy := List Rule

/-- The evaluator. Walks the policy top-to-bottom; first
    matching rule wins; no match ⇒ `Decision.deny`. Mirrors
    `AclDoc::match` in `acl.rs`. -/
def eval (pol : Policy) (f : Flow) : Decision :=
  match pol with
  | []      => Decision.deny
  | r :: rs => if r.pred f then r.action else eval rs f

/-- A flow is "allowed by" a policy iff `eval` returns `accept`. -/
def allowed (pol : Policy) (f : Flow) : Prop :=
  eval pol f = Decision.accept

/-- Convenience rule constructors used below. -/
def acceptAll : Rule := { action := Decision.accept, pred := fun _ => true }
def denyAll   : Rule := { action := Decision.deny,   pred := fun _ => true }

-- ============================================================
-- §1  Empty policy denies everything
-- ============================================================

/-- **Empty policy denies everything.** Matches the
    "no match ⇒ deny" rule in `acl.rs`. -/
theorem acl_deny_all_rejects_everything (f : Flow) :
    eval [] f = Decision.deny := rfl

/-- Corollary: nothing is allowed under the empty policy. -/
theorem acl_empty_policy_nothing_allowed (f : Flow) :
    ¬ allowed [] f := by
  unfold allowed
  rw [acl_deny_all_rejects_everything]
  intro h
  cases h

-- ============================================================
-- §2  Wildcard policy admits everything
-- ============================================================

/-- **Wildcard policy admits everything.** A policy whose first
    rule is `acceptAll` accepts every flow. -/
theorem acl_allow_all_admits_everything (f : Flow) :
    eval [acceptAll] f = Decision.accept := by
  unfold eval acceptAll
  simp

/-- Corollary: every flow is allowed under the single-wildcard
    policy. -/
theorem acl_wildcard_allows_all (f : Flow) :
    allowed [acceptAll] f := by
  unfold allowed
  exact acl_allow_all_admits_everything f

-- ============================================================
-- §3  Determinism
-- ============================================================

/-- **Determinism.** Same `(policy, flow)` ⇒ same decision —
    `eval` is a function. -/
theorem acl_match_deterministic (pol : Policy) (f : Flow) :
    eval pol f = eval pol f := rfl

-- ============================================================
-- §4  Monotonicity under more-permissive rules
-- ============================================================

/-- **Prepending an `accept` rule preserves prior `accept`
    decisions.** Specifically, if `eval pol f = accept` and `r`
    is an `accept` rule, then `eval (r :: pol) f = accept` (it
    either pred `r` — `accept` — or it doesn't, falling
    through to the unchanged tail which still says `accept`).

    This is the algebraic form of the "more-permissive rule"
    monotonicity property: adding a permissive rule never turns
    a previously-allowed flow into a denied one. -/
theorem acl_match_monotone
    (pol : Policy) (f : Flow)
    (h : eval pol f = Decision.accept)
    {r : Rule} (hr : r.action = Decision.accept) :
    eval (r :: pol) f = Decision.accept := by
  unfold eval
  by_cases hm : r.pred f = true
  · rw [if_pos hm, hr]
  · have : r.pred f = false := by
      cases hf : r.pred f
      · rfl
      · exact absurd hf hm
    rw [if_neg (by simp [this])]
    exact h

-- ============================================================
-- §5  First-match short-circuit
-- ============================================================

/-- **First-match short-circuit (positive case).** If the head
    rule pred, the head rule's action wins — `eval` never
    looks at the tail. -/
theorem acl_match_short_circuit
    (r : Rule) (rs : Policy) (f : Flow)
    (hm : r.pred f = true) :
    eval (r :: rs) f = r.action := by
  unfold eval
  rw [if_pos hm]

/-- **First-match short-circuit (negative case).** If the head
    rule does NOT match, evaluation falls through to the tail. -/
theorem acl_match_fallthrough
    (r : Rule) (rs : Policy) (f : Flow)
    (hm : r.pred f = false) :
    eval (r :: rs) f = eval rs f := by
  show (if r.pred f = true then r.action else eval rs f) = eval rs f
  rw [if_neg (by simp [hm])]

-- ============================================================
-- §6  Concrete anchors
-- ============================================================

/-- Concrete anchor: the empty policy denies a default flow. -/
example :
    eval [] (default : Flow) = Decision.deny := rfl

/-- Concrete anchor: the wildcard policy accepts a default flow. -/
example :
    eval [acceptAll] (default : Flow) = Decision.accept := by
  exact acl_allow_all_admits_everything _

end OctraVPN_Rust.ACL
