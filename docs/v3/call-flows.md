# v3 call flows

End-to-end walk of every public entrypoint in
[`program/main-v3.aml`](../../program/main-v3.aml). Each section
documents: **caller** (auth), **prereqs**, **AML-side checks**,
**state changes on success**, **revert reasons**, **gas/value
implications**, and the **Rust client** that builds the call.

The 19 user-flow method-name constants live at
[`crates/octravpn-core/src/v3_calls.rs:34-73`](../../crates/octravpn-core/src/v3_calls.rs).
Both [`crates/octravpn-node/src/chain_v3.rs`](../../crates/octravpn-node/src/chain_v3.rs)
and [`crates/octravpn-client/src/chain_v3.rs`](../../crates/octravpn-client/src/chain_v3.rs)
delegate through `ContractCallBuilder` so the wire shape is owned by
one module. Adversarial cases (Rx, Bx, Sx, Tx, Ex, Cx, Fx, Px) refer
to [`docker/devnet/e2e-adversarial-v3.sh`](../../docker/devnet/e2e-adversarial-v3.sh).

Per-entrypoint **gas** notes describe the value parameter (the
`payable`-attached OU); chain compute fees are the standard
`--fee 1000` envelope ([`docker/devnet/v3-smoke.sh:48`](../../docker/devnet/v3-smoke.sh)).

---

## Circle registry

### 1. `register_circle(circle, state_root, receipt_pubkey)` — payable

**Source:** [`program/main-v3.aml:277-310`](../../program/main-v3.aml).
**Caller:** any wallet (becomes `circle_owner[circle]`).
**Rust:** node `build_register_circle_call` ([`chain_v3.rs:231`](../../crates/octravpn-node/src/chain_v3.rs)),
core method constant `REGISTER_CIRCLE` ([`v3_calls.rs:36`](../../crates/octravpn-core/src/v3_calls.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; circle inactive; circle not previously slashed                          |
| Checks          | `is_address(circle)`; `len(state_root) == 64`; `len(receipt_pubkey) > 0`; `bond + value >= min_circle_stake` |
| Value           | Initial bond top-up (atomic with registration); enforced ≥ `min_circle_stake`       |
| State changes   | `circle_bond += value`, `circle_owner = caller`, `circle_receipt_pk = pubkey`, `circle_state_root = state_root`, `circle_state_version = 1`, `circle_active = 1`, `circle_earnings_total = 0`, `circle_earnings_claimed = 0`, `circle_earnings_chain = sha256(state_root)` |
| Events          | `CircleRegistered`; `StakeBonded` (if value > 0)                                    |
| Revert reasons  | `"invalid circle id"`, `"circle already active"`, `"previously slashed"`, `"state_root must be 64-char hex sha256"`, `"receipt pubkey required"`, `"initial stake below minimum"` |
| Adversarial     | R1–R5                                                                               |

Earnings-chain genesis is `sha256(state_root)`, NOT the AML default
`"0"`. See [`data-model.md`](data-model.md) §determinism invariants.

### 2. `update_circle_state(circle, new_state_root)`

**Source:** [`program/main-v3.aml:314-324`](../../program/main-v3.aml).
**Caller:** `circle_owner[circle]`.
**Rust:** node `build_update_circle_state_call` ([`chain_v3.rs:249`](../../crates/octravpn-node/src/chain_v3.rs)).
**Atomic sidecar:**
[`crates/octravpn-node/src/circle_update.rs`](../../crates/octravpn-node/src/circle_update.rs)
+ CLI `octravpn-node circle update`.

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; circle active; circle not slashed                                       |
| Checks          | Caller is `circle_owner`; `len(new_state_root) == 64`                               |
| State changes   | `circle_state_root = new_state_root`; `circle_state_version += 1`                   |
| Events          | `CircleStateUpdated`                                                                |
| Revert reasons  | `"not circle owner"`, `"circle not active"`, `"previously slashed"`, `"state_root must be 64-char hex sha256"` |
| Adversarial     | R6, R7                                                                              |

Verifiers reject anchors whose canonical `epoch` field regresses
(off-chain; the chain does not enforce monotonic `epoch`).

**Atomic-update sidecar pattern.** Octra has no multi-tx atomicity,
so any policy/wg/attestation rotation that *also* changes the sealed
asset bytes must drive **two phases in strict order**:

1. **All blob writes via `circle_asset_put_encrypted`** (one tx per
   asset, e.g. `/policy.json`, `/wg.pub`, `/attestation.json`).
2. **One `update_circle_state` tx** binding the new
   [`StateRoot`](../../crates/octravpn-core/src/v3_state_root.rs) whose
   `*_hash` fields hash the freshly-uploaded bytes.

If step 2 fails the blobs are orphans — the OLD anchor still points at
the OLD bytes, so user-visible state is consistent. Recover via
`octravpn-node circle retry-anchor --circle <id> --anchor <hex>` (the
helper's `UpdateError::AnchorUpdateFailed` carries the right hex).

The reverse order (anchor first, blobs second) is **forbidden**: a
verifier polling between the anchor flip and the blob write would see
a new anchor pointing at hashes the chain can't serve. The
`circle_update::apply` helper enforces the correct order; operators
should never hand-roll `update_circle_state` against a circle whose
sealed bytes also change.

### 3. `rotate_receipt_pubkey(circle, new_pubkey)`

**Source:** [`program/main-v3.aml:329-337`](../../program/main-v3.aml).
**Caller:** `circle_owner[circle]`.
**Rust:** node `build_rotate_receipt_pubkey_call` ([`chain_v3.rs:268`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; circle active; circle not slashed                                       |
| Checks          | Caller is `circle_owner`; `len(new_pubkey) > 0`                                     |
| State changes   | `circle_receipt_pk = new_pubkey`                                                    |
| Revert reasons  | `"not circle owner"`, `"circle not active"`, `"previously slashed"`, `"pubkey required"` |
| Adversarial     | R8                                                                                  |

**Forensic note.** Old pubkey is dropped — future `slash_double_sign`
verifies against the new key. Off-chain attestation history bots are
expected to flag rotations (see
[`../security/threat-model-v3.md`](../security/threat-model-v3.md) §4.3 walk-through).

### 4. `retire_circle(circle)`

**Source:** [`program/main-v3.aml:339-346`](../../program/main-v3.aml).
**Caller:** `circle_owner[circle]`.
**Rust:** node `build_retire_circle_call` ([`chain_v3.rs:286`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; circle currently active                                                 |
| Checks          | Caller is `circle_owner`                                                            |
| State changes   | `circle_active = 0` (does NOT touch bond or earnings)                               |
| Events          | `CircleRetired`                                                                     |
| Revert reasons  | `"not circle owner"`, `"circle not active"`                                         |
| Adversarial     | R9                                                                                  |

Retirement is reversible only via a fresh `register_circle` —
permitted because `circle_slashed == 0`.

---

## Bond / unbond / finalize

### 5. `bond_endpoint(circle)` — payable

**Source:** [`program/main-v3.aml:352-361`](../../program/main-v3.aml).
**Caller:** `circle_owner[circle]`.
**Rust:** node `build_bond_endpoint_call` ([`chain_v3.rs:304`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; circle not slashed; circle not currently unbonding                      |
| Checks          | `value > 0`; caller is owner                                                        |
| Value           | Bond top-up; no minimum (the floor only gates initial registration)                 |
| State changes   | `circle_bond += value`                                                              |
| Events          | `StakeBonded`                                                                       |
| Revert reasons  | `"no value"`, `"previously slashed"`, `"unbonding in progress"`, `"not circle owner"` |
| Adversarial     | B1, B2                                                                              |

### 6. `unbond_endpoint(circle)`

**Source:** [`program/main-v3.aml:363-375`](../../program/main-v3.aml).
**Caller:** `circle_owner[circle]`.
**Rust:** node `build_unbond_endpoint_call` ([`chain_v3.rs:319`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; some live bond; no concurrent unbonding                                 |
| Checks          | Caller is owner; `circle_bond > 0`; `circle_unbonding == 0`                         |
| State changes   | `circle_unbonding = circle_bond`; `circle_bond = 0`; `circle_unbond_unlock_epoch = epoch + unbond_grace_epochs` |
| Events          | `StakeUnbonded`                                                                     |
| Revert reasons  | `"not circle owner"`, `"no stake"`, `"already unbonding"`                            |
| Adversarial     | B3                                                                                  |

Unbonding bond is **still slashable** until `finalize_unbond` —
`apply_slash` ([`program/main-v3.aml:197-215`](../../program/main-v3.aml))
zeroes both buckets and burns/bounties the sum.

### 7. `finalize_unbond(circle)` — nonreentrant

**Source:** [`program/main-v3.aml:377-388`](../../program/main-v3.aml).
**Caller:** `circle_owner[circle]`.
**Rust:** node `build_finalize_unbond_call` ([`chain_v3.rs:331`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; some unbonding amount; grace elapsed                                    |
| Checks          | Caller is owner; `circle_unbonding > 0`; `epoch >= circle_unbond_unlock_epoch`     |
| State changes   | `circle_unbonding = 0`; `circle_unbond_unlock_epoch = 0`; `transfer(caller, amt)`  |
| Events          | `StakeFinalized`                                                                    |
| Revert reasons  | `"not circle owner"`, `"nothing unbonding"`, `"unbond grace not elapsed"`, `"transfer failed"` |
| Adversarial     | B4                                                                                  |

The `nonreentrant` attribute on the entrypoint prevents reentrant
withdrawals via the `transfer` callback.

---

## Slash

### 8. `slash_double_sign(circle, payload_a, sig_a, payload_b, sig_b)`

**Source:** [`program/main-v3.aml:394-404`](../../program/main-v3.aml).
**Caller:** anyone; the caller receives the bounty.
**Rust:** node `build_slash_double_sign_call` ([`chain_v3.rs:350`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; circle not already slashed                                              |
| Checks          | `payload_a != payload_b`; `len(circle_receipt_pk) > 0`; `ed25519_ok(pk, payload_a, sig_a)`; `ed25519_ok(pk, payload_b, sig_b)` |
| State changes   | `apply_slash`: zero `circle_bond` + `circle_unbonding`; `circle_slashed = 1`; `circle_active = 0`; burn 90% to `treasury`/`burned`; transfer 10% bounty to caller |
| Events          | `OperatorSlashed`                                                                   |
| Revert reasons  | `"already slashed"`, `"payloads identical"`, `"circle has no receipt pubkey"`, `"sig_a invalid"`, `"sig_b invalid"`, `"no stake to slash"`, `"bounty transfer failed"` |
| Adversarial     | S1, S2, S3, S5 (POSITIVE), S6                                                       |

**Wire-format note.** `ed25519_ok` expects **base64** for the public
key + signature, NOT hex (memory: `octra_aml_wire_format.md`). The
positive S5 case in
[`docker/devnet/e2e-adversarial-v3.sh:326-336`](../../docker/devnet/e2e-adversarial-v3.sh)
is the on-chain witness this path actually fires.

### `gov_slash_operator(circle)` (owner-only)

**Source:** [`program/main-v3.aml:406-412`](../../program/main-v3.aml).
NOT in `v3_calls.rs` — operator/client daemons never call it.
Adversarial: S4 (non-owner reject); the positive path is governance-
only and validated by the broader ceremony runbook
[`../mainnet-ceremony.md`](../mainnet-ceremony.md).

---

## Tailnets

### 9. `create_tailnet(members_root) -> int` — payable

**Source:** [`program/main-v3.aml:420-433`](../../program/main-v3.aml).
**Caller:** any wallet (becomes `tailnet_owner[tid]`).
**Rust:** node `build_create_tailnet_call` ([`chain_v3.rs:378`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused                                                                          |
| Checks          | `value >= min_tailnet_deposit`; `len(members_root) == 64`                           |
| Value           | Initial treasury (drained by `open_session`, topped up by refunds)                  |
| State changes   | `tid = tailnet_count++`; `tailnet_owner = caller`; `tailnet_treasury = value`; `tailnet_members_root = root`; `tailnet_root_version = 1`; `tailnet_retired = 0` |
| Returns         | The new `tid`                                                                       |
| Events          | `TailnetCreated`                                                                    |
| Revert reasons  | `"deposit below minimum"`, `"members_root must be 64-char hex sha256"`              |
| Adversarial     | T1, T2                                                                              |

### 10. `update_members_root(tailnet_id, new_members_root)`

**Source:** [`program/main-v3.aml:447-456`](../../program/main-v3.aml).
**Caller:** `tailnet_owner[tid]`.
**Rust:** node `build_update_members_root_call` ([`chain_v3.rs:391`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; tailnet exists                                                          |
| Checks          | Caller is owner; `len(new_members_root) == 64`                                      |
| State changes   | `tailnet_members_root = new`; `tailnet_root_version += 1`                           |
| Events          | `TailnetMembersRootUpdated`                                                         |
| Revert reasons  | `"tailnet not found"`, `"not tailnet owner"`, `"members_root must be 64-char hex sha256"` |
| Adversarial     | T3                                                                                  |

### 11. `retire_tailnet(tailnet_id)`

**Source:** [`program/main-v3.aml:458-463`](../../program/main-v3.aml).
**Caller:** `tailnet_owner[tid]`.
**Rust:** node `build_retire_tailnet_call` ([`chain_v3.rs:407`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; caller owns tailnet                                                     |
| State changes   | `tailnet_retired = 1` (does NOT touch treasury)                                     |
| Revert reasons  | `"not tailnet owner"`                                                               |
| Adversarial     | T4                                                                                  |

After retirement, `open_session` rejects; `withdraw_tailnet_treasury`
becomes legal.

### 12. `deposit_to_tailnet(tailnet_id)` — payable

**Source:** [`program/main-v3.aml:435-444`](../../program/main-v3.aml).
**Caller:** anyone (membership is off-chain).
**Rust:** node `build_deposit_to_tailnet_call` ([`chain_v3.rs:419`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; tailnet exists; tailnet not retired                                     |
| Checks          | `value > 0`                                                                         |
| State changes   | `tailnet_treasury += value`                                                         |
| Events          | `TailnetDeposit`                                                                    |
| Revert reasons  | `"no deposit"`, `"tailnet not found"`, `"tailnet retired"`                          |
| Adversarial     | T6, T7                                                                              |

### 13. `withdraw_tailnet_treasury(tailnet_id, amount)` — nonreentrant

**Source:** [`program/main-v3.aml:466-475`](../../program/main-v3.aml).
**Caller:** `tailnet_owner[tid]`.
**Rust:** node `build_withdraw_tailnet_treasury_call` ([`chain_v3.rs:433`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; caller owns; tailnet retired; treasury sufficient                       |
| Checks          | `amount > 0`; `tailnet_retired == 1`; `tailnet_treasury >= amount`                  |
| State changes   | `tailnet_treasury -= amount`; `transfer(caller, amount)`                            |
| Revert reasons  | `"not tailnet owner"`, `"tailnet not retired"`, `"amount > 0"`, `"treasury insufficient"`, `"transfer failed"` |
| Adversarial     | T5                                                                                  |

---

## Session lifecycle

### 14. `open_session(tailnet_id, circle, max_pay) -> int`

**Source:** [`program/main-v3.aml:486-508`](../../program/main-v3.aml).
**Caller:** anyone (the opener).
**Rust:** client `build_open_session_call` ([`chain_v3.rs:249`](../../crates/octravpn-client/src/chain_v3.rs)),
also exposed on the node side ([`chain_v3.rs:455`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; tailnet exists, not retired; circle active and not slashed; tailnet treasury sufficient |
| Checks          | `circle_is_active(circle)`; `max_pay >= min_session_deposit`; `tailnet_treasury[tid] >= max_pay` |
| Value           | Zero — escrow is moved from tailnet treasury, not from the opener's wallet           |
| State changes   | `tailnet_treasury -= max_pay`; `sid = session_count++`; populate session_*           |
| Returns         | New `sid`                                                                           |
| Events          | `SessionOpened`                                                                     |
| Revert reasons  | `"tailnet not found"`, `"tailnet retired"`, `"circle inactive or slashed"`, `"deposit below min"`, `"tailnet treasury insufficient"` |
| Adversarial     | E1, E2, E3, E4; positive in smoke L77 + adversarial preflight L404                  |

Membership is enforced **off-chain** via Merkle proof against
`tailnet_members_root`. If the operator co-signs a session for a
non-member the chain has no way to detect it; the slash path is the
defense (forge two contradictory receipts → `slash_double_sign`).

### 15. `settle_claim(session_id, bytes_used)`

**Source:** [`program/main-v3.aml:513-543`](../../program/main-v3.aml).
**Caller:** `circle_owner[session_exit]`.
**Rust:** node `build_settle_claim_call` ([`chain_v3.rs:476`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; session exists; session OPEN; caller owns exit circle; circle still active |
| Checks          | `bytes_used >= 0`                                                                   |
| State (first claim) | `operator_claim_set = 1`; `operator_claim_bytes = bytes_used`                   |
| State (re-claim same value) | No-op (idempotent)                                                      |
| State (re-claim different value) | Equivocation: session → REFUNDED; deposit returned to tailnet; `SettleDispute` + `SessionRefunded` emitted. Bond is NOT auto-slashed here — equivocator MUST be slashed via a separate `slash_double_sign` tx |
| Events          | `SettleClaimed` (first claim) or `SettleDispute` + `SessionRefunded` (mismatch)     |
| Revert reasons  | `"session not found"`, `"session not open"`, `"bytes >= 0"`, `"not circle owner"`, `"operator inactive"` |
| Adversarial     | E5, E6                                                                              |

### 16. `settle_confirm(session_id, bytes_used, net, settle_blinding)` — nonreentrant

**Source:** [`program/main-v3.aml:549-601`](../../program/main-v3.aml).
**Caller:** `session_opener[sid]`.
**Rust:** client `build_settle_confirm_call` ([`chain_v3.rs:270`](../../crates/octravpn-client/src/chain_v3.rs)),
also on the node side.

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; session OPEN; caller is opener; operator has claimed                    |
| Checks          | `net >= 0`; `len(settle_blinding) > 0`                                              |
| State (bytes mismatch)  | `client_confirm_set = 1`; emit `SettleDispute`; session stays OPEN          |
| State (bytes agree)     | `client_confirm_set = 1`; cap `net <= deposit`; deduct `fee = net * protocol_fee_bps / BPS_DENOM` to `treasury`; refund `deposit - net` to tailnet; if `net_after_fee > 0` then bump `circle_earnings_total` and extend hash chain `head' = sha256(head ‖ sha256(blinding))`; status → SETTLED |
| Events          | `SettleConfirmed`; `SessionSettled`; `SettleDispute` (mismatch) or `EarningsCommitted` (agree, net > 0) |
| Revert reasons  | `"session not found"`, `"session not open"`, `"only opener can confirm"`, `"no operator claim yet"`, `"net >= 0"`, `"blinding required"` |
| Adversarial     | E7, E8, E9, E11; positive in smoke L84                                              |

The hash-chain update is the swap-ready earnings-privacy primitive
(see [`fee-model.md`](fee-model.md) §3 and
[`canonical-encoders.md`](canonical-encoders.md) §earnings-chain).
Verified byte-for-byte by [`docker/devnet/v3-smoke.sh:87-98`](../../docker/devnet/v3-smoke.sh).

### 17. `claim_no_show(session_id)`

**Source:** [`program/main-v3.aml:603-617`](../../program/main-v3.aml).
**Caller:** `session_opener[sid]`.
**Rust:** client `build_claim_no_show_call` ([`chain_v3.rs:288`](../../crates/octravpn-client/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; session OPEN; opener is caller; `epoch >= opened_at + session_grace_epochs`; operator never claimed |
| Checks          | `operator_claim_set == 0`                                                           |
| State changes   | `session_status = REFUNDED`; `tailnet_treasury += deposit`                          |
| Events          | `SessionRefunded` (`"no-show"`)                                                     |
| Revert reasons  | `"session not found"`, `"session not open"`, `"only opener"`, `"grace not elapsed"`, `"operator claimed"` |
| Adversarial     | E10                                                                                 |

### 18. `sweep_expired_session(session_id)` — nonreentrant

**Source:** [`program/main-v3.aml:619-639`](../../program/main-v3.aml).
**Caller:** anyone (the bounty hunter).
**Rust:** client `build_sweep_expired_session_call` ([`chain_v3.rs:303`](../../crates/octravpn-client/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; session OPEN; `epoch >= opened_at + session_grace_epochs * sweep_grace_multiplier` |
| State changes   | `session_status = REFUNDED`; `bounty = deposit * sweep_bounty_bps / BPS_DENOM`; transfer bounty to caller; remainder → tailnet treasury |
| Events          | `SessionSwept`                                                                      |
| Revert reasons  | `"session not found"`, `"session not open"`, `"sweep grace not elapsed"`, `"bounty transfer failed"` |
| Adversarial     | E12                                                                                 |

This is the long-tail garbage collector: an opener who vanished
without confirming or no-show-claiming. Anyone can sweep for the
1% bounty after 10× grace.

---

## Earnings

### 19. `claim_earnings(circle, amount)` — nonreentrant

**Source:** [`program/main-v3.aml:648-659`](../../program/main-v3.aml).
**Caller:** `circle_owner[circle]`.
**Rust:** node `build_claim_earnings_call` ([`chain_v3.rs:551`](../../crates/octravpn-node/src/chain_v3.rs)).

| Stage           | Detail                                                                              |
| --------------- | ----------------------------------------------------------------------------------- |
| Prereqs         | Not paused; caller owns circle; circle not slashed; `amount > 0`; `amount <= total - claimed` |
| State changes   | `circle_earnings_claimed += amount`; `transfer(caller, amount)`                     |
| Events          | `EarningsClaimed`                                                                   |
| Revert reasons  | `"not circle owner"`, `"operator slashed"`, `"amount > 0"`, `"amount exceeds available earnings"`, `"transfer failed"` |
| Adversarial     | C1, C2, C3, C4; smoke step 7 positive + step 8 overclaim guard                      |

The chain does NOT consult the hash chain on claim — `total` is the
authoritative gate. Hash chain is for off-chain tamper detection
(see [`security-model.md`](security-model.md) §earnings-chain).

---

## Governance (owner-only — not in `v3_calls.rs`)

These entrypoints intentionally bypass `require_not_paused` so a
paused contract can still be administered. Adversarial P3 in
[`docker/devnet/e2e-adversarial-v3.sh:510-512`](../../docker/devnet/e2e-adversarial-v3.sh)
is a regression guard.

| Entrypoint                                              | Source                                       | Adversarial   |
| ------------------------------------------------------- | -------------------------------------------- | ------------- |
| `transfer_ownership(new_owner)`                         | [`program/main-v3.aml:221-226`](../../program/main-v3.aml) | F2, P3        |
| `set_paused(p)`                                         | [`program/main-v3.aml:228-233`](../../program/main-v3.aml) | F1            |
| `set_params(...)` (10 ints)                              | [`program/main-v3.aml:235-258`](../../program/main-v3.aml) | F3            |
| `withdraw_program_treasury(to, amount)`                  | [`program/main-v3.aml:260-269`](../../program/main-v3.aml) | F4, F5        |
| `gov_slash_operator(circle)`                             | [`program/main-v3.aml:406-412`](../../program/main-v3.aml) | S4            |

`set_params` enforces invariants on the *new* values:
`min_circle_stake >= 100_000_000`, `unbond_grace_epochs >= 1000`,
`slash_burn_bps + slash_bounty_bps == BPS_DENOM`,
`protocol_fee_bps <= 200`, `sweep_bounty_bps <= 1000`. Source:
[`program/main-v3.aml:235-258`](../../program/main-v3.aml).

---

## View functions

Read-only RPC entrypoints used by clients + auditors. Source:
[`program/main-v3.aml:665-711`](../../program/main-v3.aml).

| View                                       | Returns                                              |
| ------------------------------------------ | ---------------------------------------------------- |
| `get_circle_active(circle)`                | `bool`                                               |
| `is_circle_slashed(circle)`                | `bool`                                               |
| `get_circle_state_root(circle)`            | `bytes` (64-char hex)                                |
| `get_circle_state_version(circle)`         | `int`                                                |
| `get_circle_owner(circle)`                 | `address`                                            |
| `endpoint_stake_of(circle)`                | `int` (live bond only — does NOT include unbonding) |
| `get_tailnet_members_root(tailnet_id)`     | `bytes`                                              |
| `get_tailnet_treasury(tailnet_id)`         | `int`                                                |
| `get_earnings_total(circle)`               | `int`                                                |
| `get_earnings_claimed(circle)`             | `int`                                                |
| `get_earnings_chain(circle)`               | `bytes` (64-char hex)                                |
| `get_session_status(session_id)`           | `int` (0/1/2)                                        |

There is no `view` for `circle_bond + circle_unbonding` together —
auditors checking total slashable stake call both queries and sum.
There is also no view for `treasury` / `burned`; the smoke script
relies on event emission to track them.
