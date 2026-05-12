/-!
# OctraVPN — Lean 4 specification

This file gives a *functional* spec of the OctraVPN program's state and
entrypoints in Lean 4, then proves a handful of structural invariants.

The model is deliberately abstract:
  - cryptography is uninterpreted (we model `verify_sig` as an oracle
    `Prop` and let lemmas quantify over its outcome)
  - FHE earnings are modeled by their decrypted view (we don't simulate
    HFHE; we only need that homomorphic add corresponds to plaintext add)
  - storage is a finite map address → record

Lemmas proved here:
  1. `register_addBond_complete_inverse` — a register followed by N
     `add_bond` calls and a `complete_unbond` returns exactly the sum of
     bonded amounts (ignoring slashing).
  2. `settle_increases_earnings` — settlement increases the route nodes'
     earnings ledger by the weighted (price × bytes_used × split_bps).
  3. `slash_double_sign_zeros_bond` — equivocation slashing zeroes the
     bond and jails the validator.
  4. `jailed_monotone_modulo_refresh` — once jailed, the only way to
     un-jail is via `refresh_attestation`.
-/

import OctraVPN.State
import OctraVPN.Entrypoints
import OctraVPN.Lemmas
import OctraVPN.AmlLink
