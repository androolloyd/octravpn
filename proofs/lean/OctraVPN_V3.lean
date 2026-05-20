import OctraVPN_V3.State
import OctraVPN_V3.Transitions
import OctraVPN_V3.AmlLink
import OctraVPN_V3.Invariants

/-!
# OctraVPN v3 — Lean 4 specification.

Sibling to `OctraVPN_V2.lean` (v2.x) and `OctraVPN.lean` (v1.1);
both are preserved intact. The v3 model covers the chain-minimal
state machine shipped in `program/main-v3.aml` (deployed on devnet
2026-05-18).

## v3 module shape (mirrors v2's structure)

  - `State.lean`        — On-chain state type. Circle metadata is
                          split across parallel maps to mirror the
                          AML's `map[address]X` shape directly.
  - `Transitions.lean`  — Every entrypoint as a state-transition
                          function `Option ProgramState` (or `Option
                          (ProgramState × OctRaw)` for paying calls).
  - `AmlLink.lean`      — Axiom set + chain-runtime proof-gap doc.
                          Introduces `Sha256.injective`,
                          `Ed25519.unforgeable`, and the finite-map
                          laws used downstream.
  - `Invariants.lean`   — ≥25 safety theorems with line-number
                          citations to `program/main-v3.aml`.

## v3 theorem index (see `Invariants.lean` for definitions and
`Theorems.md` for plain-English statements / AML line cites)

Circle registry:
  - register_circle_atomic
  - register_circle_initialises_earnings_chain
  - register_circle_not_paused
  - register_circle_not_slashed
  - update_circle_state_owner_only
  - update_circle_state_bumps_version
  - update_circle_state_active_required
  - rotate_receipt_pubkey_owner_only
  - rotate_receipt_pubkey_only_touches_pubkey
  - retire_circle_owner_only
  - retire_circle_clears_active

Bond / unbond / finalize:
  - bond_endpoint_increases_bond
  - bond_endpoint_owner_only
  - bond_endpoint_requires_no_unbonding
  - unbond_endpoint_zeroes_bond
  - finalize_unbond_grace_required
  - finalize_unbond_clears_unbonding
  - finalize_unbond_pays_full_amount

Slash:
  - slash_double_sign_burns_and_slashes
  - slash_double_sign_burn_plus_bounty_eq_total
  - slash_double_sign_requires_verified
  - slash_double_sign_already_slashed_rejected
  - slash_double_sign_burned_counter_increases
  - gov_slash_operator_owner_only

Tailnets:
  - create_tailnet_seeds_treasury
  - deposit_to_tailnet_grows_treasury
  - update_members_root_owner_only
  - update_members_root_bumps_version
  - withdraw_tailnet_treasury_owner_only
  - withdraw_tailnet_treasury_requires_retired

Sessions:
  - open_session_requires_active_circle
  - open_session_debits_tailnet_treasury
  - settle_claim_owner_only
  - settle_claim_idempotent_on_same_bytes
  - settle_claim_equivocation_refunds
  - settle_confirm_only_opener
  - settle_confirm_requires_operator_claim
  - settle_confirm_match_settles
  - settle_confirm_mismatch_dispute_stays_open
  - settle_confirm_fee_to_program_treasury
  - claim_no_show_only_opener
  - claim_no_show_grace_required
  - claim_no_show_rejects_after_operator_claim
  - sweep_expired_session_idempotent
  - sweep_grace_strictly_greater_than_claim_grace

Earnings:
  - claim_earnings_owner_only
  - claim_earnings_rejected_if_slashed
  - claim_earnings_bounded_by_available
  - claim_earnings_monotone_total

Governance:
  - transfer_ownership_owner_only
  - set_paused_owner_only
  - set_params_owner_only
  - withdraw_program_treasury_conserves

C-1 fix (dispute resolution; `main-v3-c1-fix.aml` sibling AML):
  - settle_resolve_grace_required
  - settle_resolve_loser_slashed
  - claim_disputed_no_show_after_grace
  - dispute_funds_never_stuck
-/
