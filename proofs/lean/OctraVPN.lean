import OctraVPN.State
import OctraVPN.Entrypoints
import OctraVPN.Lemmas
import OctraVPN.AmlLink

/-!
# OctraVPN — Lean 4 specification (v1)

This file gives a *functional* spec of the OctraVPN program's state
and entrypoints in Lean 4, then proves a handful of structural
invariants.

The model is deliberately abstract:
  - cryptography is uninterpreted (we model FHE zero-proofs as
    abstract `Prop` and let lemmas quantify over the outcome)
  - FHE earnings are modeled by their decrypted view (we don't
    simulate HFHE; we only need that homomorphic add corresponds to
    plaintext add)
  - storage is a finite map address → record

Lemmas proved here (see `Lemmas.lean` for the full list):
  - register_requires_stake, register_not_slashed, register_sets_active
  - bond_increases_stake, slash_burns_stake, slash_marks_terminal,
    slash_requires_owner
  - slashDoubleSign_slashes_stake, slashDoubleSign_pays_bounty,
    slashDoubleSign_idempotent_when_already_slashed,
    slashDoubleSign_distinct_payloads_required
  - settleClaim_requires_caller_is_exit, settleClaim_records_claim,
    settleClaim_idempotent_on_same_bytes,
    settleClaim_equivocation_refunds
  - settleConfirm_only_opener, settleConfirm_match_settles,
    settleConfirm_mismatch_disputes
  - joinToken_preimage_match, joinToken_uniqueness,
    joinToken_no_double_redeem
  - claim_requires_exact_match, claim_resets_encEarn
  - create_tailnet_seeds_treasury, retire_clears_active
  - v1.1 coverage additions:
    unbond_locks_stake, finalize_unbond_clears_and_pays,
    add_member_grows_roster, remove_member_drops_from_roster,
    deposit_to_tailnet_grows_treasury, configure_exit_appends,
    update_acl_owner_only,
    update_endpoint_active_only, rotate_keys_requires_zero_earnings,
    open_session_locks_deposit, claim_no_show_refunds_to_tailnet,
    sweep_expired_session_refunds, precommit_records_commit,
    register_device_no_steal, revoke_device_owner_only,
    set_paused_owner_only, transfer_ownership_rotates,
    withdraw_program_treasury_conserves
-/
