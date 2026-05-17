/-!
# AML ↔ Lean linkage scaffold for v2.

Placeholder API contract: every v2 spec entrypoint declares the AML
function name it claims to model, so a future linker can confirm
coverage. v2 surface is the slim registry shape in
`program/main-v2.aml`.

## PROOF GAP markers

The following v2 properties are NOT modeled inside Lean; the
chain runtime enforces them and we document them here:

1. **`payable`** — the runtime accepts a `value` parameter for
   tagged entrypoints. Lean treats `value` as a regular `OctRaw`
   parameter; the AML modifier is a syntactic gate.

2. **`nonreentrant`** — the runtime enforces an additional re-entry
   guard for tagged entrypoints (`finalize_unbond`, `settle_confirm`,
   `sweep_expired_session`, `claim_earnings`). The Lean state-
   machine model treats each entrypoint as a single atomic
   transition; re-entry rejection is therefore an invariant the
   chain runtime maintains, not one Lean must check.

3. **`CircleId` opaqueness** — `CircleId` is `Nat` in the model.
   On-chain, the circle id is `sha256+base58(deployer, nonce,
   deploy_payload)`, a 47-char `oct…` string. Collision resistance
   of sha256 is the chain's guarantee that the registry is
   functionally injective. Lean treats `CircleId` as abstract.

4. **HFHE soundness** — `claimEarnings` takes a `proofOk : Prop`
   parameter standing in for `fhe_verify_zero(pk, delta, proof)`.
   We assume in the model that the proof being accepted witnesses
   `claimedAmount = encEarn[c]`. The cryptographic soundness of
   the HFHE zero-proof is out of Lean's scope.

5. **`ed25519_ok` decoding** — `slash_double_sign` requires AML
   `ed25519_ok` to verify two distinct payloads under the circle's
   `receipt_pubkey`. The Lean model encodes the combined
   "verified AND distinct" condition as a single boolean
   `verified` parameter (mirroring how the AML's two
   `require(ed25519_ok(...))` calls plus a single
   `payload_a != payload_b` check compose).
-/

namespace OctraVPN_V2.AmlLink

/-- Hand-curated map: v2 spec function name → AML entrypoint name.
    Once the AML AST is exposed, this becomes a checked theorem. -/
def specToAml : List (String × String) :=
  [ ("registerCircleAtomic",      "register_circle"),
    ("updateCircle",              "update_circle"),
    ("retireCircle",              "retire_circle"),
    ("bondEndpoint",              "bond_endpoint"),
    ("unbondEndpoint",            "unbond_endpoint"),
    ("finalizeUnbond",            "finalize_unbond"),
    ("slashDoubleSign",           "slash_double_sign"),
    ("govSlashOperator",          "gov_slash_operator"),
    ("createTailnet",             "create_tailnet"),
    ("depositToTailnet",          "deposit_to_tailnet"),
    ("addMember",                 "add_member"),
    ("removeMember",              "remove_member"),
    ("updateAcl",                 "update_acl"),
    ("setChargeInternalTraffic",  "set_charge_internal_traffic"),
    ("authorizeCircle",           "authorize_circle"),
    ("revokeCircle",              "revoke_circle"),
    ("precommitJoinToken",        "precommit_join_token"),
    ("redeemJoinToken",           "redeem_join_token"),
    ("openSession",               "open_session"),
    ("settleClaim",               "settle_claim"),
    ("settleConfirm",             "settle_confirm"),
    ("claimNoShow",               "claim_no_show"),
    ("sweepExpiredSession",       "sweep_expired_session"),
    ("claimEarnings",             "claim_earnings"),
    ("setPaused",                 "set_paused"),
    ("transferOwnership",         "transfer_ownership"),
    ("setParams",                 "set_params"),
    ("withdrawProgramTreasury",   "withdraw_program_treasury") ]

/-- Returns `true` iff `xs` has no duplicate elements. Walks the
    list once with an accumulator of "already-seen" keys. -/
def listDistinct : List String → Bool
  | [] => true
  | x :: rest => if rest.contains x then false else listDistinct rest

/-- Trivial sanity check: every spec name appears at most once. -/
theorem specKeys_distinct :
    listDistinct (specToAml.map Prod.fst) = true := by
  decide

/-- Reverse direction: every AML entrypoint name in the map is
    unique on the v2 surface. -/
theorem amlKeys_distinct :
    listDistinct (specToAml.map Prod.snd) = true := by
  decide

end OctraVPN_V2.AmlLink
