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
  - settle_requires_caller_is_exit, settle_finalizes,
    settle_bounded_by_deposit, settle_returns_refund_to_treasury
  - claim_requires_exact_match, claim_resets_encEarn
  - create_tailnet_seeds_treasury, retire_clears_active
-/
