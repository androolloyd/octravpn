# OctraVPN v3 Theorem Index

Mechanically-checked Lean theorems covering the state-machine
semantics of `program/main-v3.aml` (deployed on devnet 2026-05-18).
Companion to the canonical-encoder theorems in
`WireProtocol/V3Canonical.lean` and the v2 module in
`OctraVPN_V2/Lemmas.lean`.

Build: `cd proofs/lean && lake build OctraVPN_V3` — must end with
"Build completed successfully." and zero `sorry` / `admit`.

The Lean code is intentionally non-Mathlib: only core `Lean 4` is
imported, matching the rest of the proof tree.

---

## Module shape

| File              | Lines | Theorems | Role                                            |
| ----------------- | ----- | -------- | ----------------------------------------------- |
| `State.lean`      | ~190  | 0        | On-chain state type (mirrors AML state block)   |
| `Transitions.lean`| ~440  | 0        | Every entrypoint as `Option ProgramState`       |
| `AmlLink.lean`    | ~95   | 2        | Axioms + chain-runtime proof-gap doc            |
| `Invariants.lean` | ~1310 | 57       | Safety theorems with AML line cites             |

Module index: `OctraVPN_V3.lean` (top-level `import`s).

---

## 1. Circle registry (`main-v3.aml:277-346`)

| Theorem                                          | Plain-English statement                                                                                                                                                                | AML line(s) |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `register_circle_atomic`                         | Successful `register_circle` writes all five circle-metadata maps + bond in one transition; no half-registered state can be reached.                                                  | 289-303     |
| `register_circle_initialises_earnings_chain`     | The earnings hash-chain genesis is `sha256(state_root)`; total / claimed start at 0.                                                                                                  | 303         |
| `register_circle_not_paused`                     | Pause halts user flows: a successful `register_circle` implies `paused = 0`.                                                                                                          | 278         |
| `register_circle_not_slashed`                    | A previously-slashed circle cannot be re-registered.                                                                                                                                  | 281         |
| `update_circle_state_owner_only`                 | Only the circle owner can update the on-chain anchor.                                                                                                                                 | 316         |
| `update_circle_state_bumps_version`              | Anchor version monotonically increases by 1 per accepted update.                                                                                                                      | 321         |
| `update_circle_state_active_required`            | A retired or slashed circle cannot anchor a new state-root.                                                                                                                           | 317         |
| `rotate_receipt_pubkey_owner_only`               | Only the circle owner can rotate the receipt pubkey.                                                                                                                                  | 331         |
| `rotate_receipt_pubkey_only_touches_pubkey`      | **ANTI-EVASION**: rotation does not erase prior session settlements, slash flag, bond, or earnings — pre-rotation receipts remain bindable until the next `slash_double_sign` window. | 335         |
| `retire_circle_owner_only`                       | Only the circle owner can retire.                                                                                                                                                     | 341         |
| `retire_circle_clears_active`                    | After retire, `circle_is_active` returns false — `open_session` rejects.                                                                                                              | 343         |

## 2. Bond / unbond / finalize (`main-v3.aml:352-388`)

| Theorem                                  | Plain-English statement                                                                                                                       | AML line(s) |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `bond_endpoint_increases_bond`           | `bond_endpoint` adds exactly `value` to `circle_bond[c]`.                                                                                     | 358         |
| `bond_endpoint_owner_only`               | Only the circle owner can bond.                                                                                                              | 357         |
| `bond_endpoint_requires_no_unbonding`    | Bonding while an unbond is in flight is rejected (keeps live + unbonding stake disjoint).                                                    | 356         |
| `unbond_endpoint_zeroes_bond`            | `unbond_endpoint` moves the full live bond into the unbonding slot AND records `unlockEpoch`.                                                | 370-372     |
| `finalize_unbond_grace_required`         | **GRACE INVARIANT**: `finalize_unbond` requires `currentEpoch ≥ unlockEpoch`; prevents draining stake while equivocation evidence is in flight. | 382         |
| `finalize_unbond_clears_unbonding`       | After finalize, the unbonding slot is zero.                                                                                                  | 383         |
| `finalize_unbond_pays_full_amount`       | The full unbonded amount is returned to the operator (`amt > 0`).                                                                            | 385         |

## 3. Slash (`main-v3.aml:394-412`, helper at `197-215`)

| Theorem                                              | Plain-English statement                                                                                                                                    | AML line(s) |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `slash_double_sign_burns_and_slashes`                | Live bond and unbonding slot go to zero; `circleSlashed = true`, `circleActive = false`.                                                                  | 204-208     |
| `slash_double_sign_burn_plus_bounty_eq_total`        | **CONSERVATION**: `burn + bounty = total` — slashed OU is conserved (treasury + caller bounty).                                                            | 202-203     |
| `slash_double_sign_requires_verified`                | `verified = false` (sig invalid or payloads identical) ⇒ slash rejected.                                                                                  | 400-401     |
| `slash_double_sign_already_slashed_rejected`         | A second slash on the same circle is rejected (idempotence under double-slash race).                                                                      | 396         |
| `slash_double_sign_burned_counter_increases`         | `burned` and `programTreasury` each increase by exactly `burnAmt`; backs the `totalSupply = circ + bonded + treasury + burned` accounting identity.       | 209-210     |
| `gov_slash_operator_owner_only`                      | Governance slash is owner-only.                                                                                                                            | 408         |

## 4. Tailnets (`main-v3.aml:420-475`)

| Theorem                                         | Plain-English statement                                                                                                                       | AML line(s) |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `create_tailnet_seeds_treasury`                 | Tailnet creation seeds owner + treasury + members-root + version 1.                                                                            | 426-431     |
| `deposit_to_tailnet_grows_treasury`             | `deposit_to_tailnet` increases treasury by exactly `value` (`value > 0`).                                                                     | 441         |
| `update_members_root_owner_only`                | Members-root anchor can only be updated by the tailnet owner.                                                                                  | 450         |
| `update_members_root_bumps_version`             | Members-root version monotonically increases by 1; the new root is written.                                                                   | 452-453     |
| `withdraw_tailnet_treasury_owner_only`          | Tailnet treasury withdraw is owner-only.                                                                                                       | 468         |
| `withdraw_tailnet_treasury_requires_retired`    | Withdraw requires `retired = true` — prevents the owner from siphoning treasury while sessions are pending.                                   | 469         |

## 5. Sessions (`main-v3.aml:486-639`)

| Theorem                                                   | Plain-English statement                                                                                                                                            | AML line(s) |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------- |
| `open_session_requires_active_circle`                     | Sessions cannot open against a slashed or retired circle.                                                                                                          | 490         |
| `open_session_debits_tailnet_treasury`                    | Tailnet treasury is debited by exactly `max_pay`.                                                                                                                  | 497         |
| `settle_claim_owner_only`                                 | Only the circle owner can record `bytes_used`.                                                                                                                     | 519         |
| `settle_claim_idempotent_on_same_bytes`                   | Re-submitting the same bytes is idempotent (network retry safe).                                                                                                   | 525-527     |
| `settle_claim_equivocation_refunds`                       | **RECEIPT-CHAIN MONOTONICITY**: a second claim with a DIFFERENT `bytes_used` refunds the deposit and marks the session refunded; slash itself is `slash_double_sign`'s job. | 530-536     |
| `settle_confirm_only_opener`                              | Only the session opener can confirm.                                                                                                                              | 553         |
| `settle_confirm_requires_operator_claim`                  | Confirm rejects if the operator has not claimed first.                                                                                                            | 554         |
| `settle_confirm_match_settles`                            | Matching bytes_used → status flips to SETTLED.                                                                                                                    | 582         |
| `settle_confirm_mismatch_dispute_stays_open`              | Mismatching bytes_used → dispute recorded, status stays OPEN (off-chain arbitration / slash takes over).                                                          | 559-564     |
| `settle_confirm_fee_to_program_treasury`                  | Protocol fee is credited to the program treasury (exact amount).                                                                                                  | 583         |
| `claim_no_show_only_opener`                               | No-show refund is opener-only.                                                                                                                                    | 607         |
| `claim_no_show_grace_required`                            | No-show refund only after `session_grace_epochs` elapses (anti-grief).                                                                                            | 609         |
| `claim_no_show_rejects_after_operator_claim`              | Once the operator has claimed, no-show is rejected (use `settle_confirm` instead).                                                                                | 610         |
| `sweep_expired_session_idempotent`                        | **SWEEP IDEMPOTENCE**: sweep on an already-refunded session is rejected.                                                                                          | 622         |
| `sweep_grace_strictly_greater_than_claim_grace`           | Sweep grace ≥ session grace (with `sweepGraceMultiplier ≥ 1`) — the opener has a priority window before permissionless sweep.                                     | 624         |

## 6. Earnings (`main-v3.aml:648-659`)

| Theorem                                  | Plain-English statement                                                                                                                                          | AML line(s) |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `claim_earnings_owner_only`              | Earnings claim is owner-only.                                                                                                                                    | 650         |
| `claim_earnings_rejected_if_slashed`     | A slashed operator cannot pull pending earnings.                                                                                                                 | 651         |
| `claim_earnings_bounded_by_available`    | The claim is bounded by `availableEarnings = total - claimed`, and `amount > 0`.                                                                                | 653-654     |
| `claim_earnings_monotone_total`          | **MONOTONICITY**: `claim_earnings` debits `claimed` only — `total` is monotonically non-decreasing across the circle's lifetime. Backs off-chain audit replay.   | 655         |

## 7. Governance (`main-v3.aml:221-269`)

| Theorem                                  | Plain-English statement                                                                                                                                          | AML line(s) |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `transfer_ownership_owner_only`          | Transfer-ownership is owner-only.                                                                                                                                | 222         |
| `set_paused_owner_only`                  | Pause-toggle is owner-only.                                                                                                                                      | 229         |
| `set_params_owner_only`                  | `set_params` is owner-only (and all AML sanity bounds are preserved).                                                                                            | 236         |
| `withdraw_program_treasury_conserves`    | Program-treasury withdraw conserves: `treasury' = treasury - amount`; paid out exactly `amount`.                                                                | 265         |

---

## 8. C-1 fix: dispute resolution (`main-v3-c1-fix.aml:728-902`)

These four theorems land on the **swap-ready-c1-fix** branch
alongside the new `program/main-v3-c1-fix.aml` sibling AML file
(deployed at a new program address; see
`docs/v3/c1-resolve-rollout.md`). They cover the C-1 audit
finding from `docs/audit/2026-05-20-deep-security-audit.md`,
which previously had zero Lean coverage.

| Theorem                                  | Plain-English statement                                                                                                                                                                              | AML line(s) |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `settle_resolve_grace_required`          | **GRACE-WINDOW INVARIANT**: `settle_resolve` only succeeds while `currentEpoch < sessionDisputeDeadline`. Prevents griefing via late resolve after the no-show fallback should have run.            | 733         |
| `settle_resolve_loser_slashed`           | When `settle_resolve` succeeds, the session must have been `disputed` and the resolver acted within the grace window — the half-slash (not full-slash) regime is the only one available. Half-rate = `slash_burn_bps / 2` = 4500 bps on default. | 766-783     |
| `claim_disputed_no_show_after_grace`     | **NO-SLASH ON NO-SHOW**: `claim_disputed_no_show` only succeeds AFTER `currentEpoch ≥ sessionDisputeDeadline`, and applies NO slash — `circleBond` and `circleSlashed` are unchanged.               | 847-851     |
| `dispute_funds_never_stuck`              | **LIVENESS (the audit's veto property)**: under reasonable preconditions on a disputed session, either `settle_resolve` succeeds (in grace) OR `claim_disputed_no_show` succeeds (out of grace). The two paths are exhaustive — funds are never stuck. | 728-902     |

## Axioms introduced in `AmlLink.lean`

| Axiom                                | Maps to                                                            |
| ------------------------------------ | ------------------------------------------------------------------ |
| `Sha256.injective`                   | NIST FIPS 180-4 SHA-256 collision resistance                       |
| `Ed25519.unforgeable`                | RFC 8032 ed25519 EUF-CMA unforgeability (`ed25519_ok` host-call)   |
| `Map.update_eq` / `Map.update_ne`    | Standard finite-map laws (proven, not assumed)                     |

## Documented proof gaps (not modelled)

1. `payable` / `nonreentrant` runtime modifiers — chain runtime invariants.
2. `ed25519_ok` decoding — encoded as a `verified : Bool` at the Lean boundary.
3. `CircleId` opacity — `Nat` in Lean, `sha256+base58` on chain.
4. AML `len(bytes)` semantics — chain applies `len(...)` to undecoded JSON-string char count (`program/main-v3.aml:7-15`).
5. Tailnet membership inclusion — deliberately OFF-CHAIN in v3.
6. HFHE — not present in v3 (this is the sha256 hash-chain era).
