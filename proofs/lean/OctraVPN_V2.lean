import OctraVPN_V2.State
import OctraVPN_V2.Entrypoints
import OctraVPN_V2.Lemmas
import OctraVPN_V2.AmlLink

/-!
# OctraVPN v2 — Lean 4 specification.

This module is a sibling to the v1.1 module (`OctraVPN.lean`).
v1.1 is preserved intact so its bulletproof proofs (46 theorems,
0 sorrys) remain valid.

The v2 program is a slim, circle-keyed registry. Key deltas
modeled here:

  - Circle-keyed registry instead of address-keyed operators.
    `CircleId` is treated as an opaque sort.
  - `registerCircleAtomic` is payable + atomic: owner + active +
    stake set in a single transition.
  - Slashes are keyed on `CircleId`.
  - `authorizeCircle` replaces `configureTailnetExit` and requires
    the circle to be active at authorize-time.
  - Per-class pricing stamped at open. `update_circle` does not
    mutate live sessions.
  - `chargeInternalTraffic` toggle makes class=INTERNAL traffic
    free when off.
  - HFHE remains an abstract `proofOk : Prop`.
  - Governance bypasses pause; user flows are pause-gated.

v2 theorem index (see `Lemmas.lean` for definitions):

Circle registry:
  - register_circle_atomic_sets_owner_active_stake
  - register_circle_atomic_no_chicken_and_egg
  - register_circle_atomic_not_slashed
  - bond_endpoint_requires_owner
  - bond_endpoint_increases_stake
  - update_circle_does_not_mutate_open_sessions
  - update_circle_owner_only
  - retire_circle_owner_only
  - retire_clears_active

Stake / slash:
  - slash_double_sign_slashes_stake
  - slash_double_sign_pays_bounty
  - slash_double_sign_idempotent_when_already_slashed
  - slash_double_sign_distinct_payloads_required
  - gov_slash_operator_burns_stake
  - gov_slash_operator_requires_owner
  - unbond_locks_stake
  - finalize_unbond_clears_and_pays

Tailnet / authorization:
  - create_tailnet_seeds_treasury
  - authorize_circle_requires_active
  - authorize_circle_requires_owner
  - revoke_circle_owner_only
  - add_member_grows_count
  - remove_member_drops
  - deposit_to_tailnet_grows_treasury
  - update_acl_owner_only
  - set_charge_internal_traffic_owner_only

Sessions:
  - open_session_requires_active_circle
  - open_session_requires_authorization
  - open_session_stamps_per_class_price_shared
  - open_session_stamps_per_class_price_internal
  - settle_claim_requires_circle_owner
  - settle_claim_idempotent_on_same_bytes
  - settle_claim_equivocation_refunds
  - settle_confirm_only_opener
  - settle_confirm_match_settles
  - settle_confirm_mismatch_disputes
  - settle_confirm_internal_free_when_toggle_off
  - claim_no_show_refunds_to_tailnet
  - sweep_expired_session_refunds

Join tokens:
  - precommit_records_commit
  - join_token_preimage_match
  - join_token_uniqueness
  - join_token_no_double_redeem

Earnings (PROOF GAP: FHE soundness):
  - claim_earnings_requires_owner
  - claim_earnings_requires_exact_match
  - claim_earnings_resets_enc_earn

Governance:
  - set_paused_owner_only
  - transfer_ownership_rotates
  - set_params_owner_only
  - withdraw_program_treasury_conserves
-/
