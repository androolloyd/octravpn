# v3 vs v2 migration delta

A side-by-side reference for operators who shipped against v2
([`program/main-v2.aml`](../../program/main-v2.aml)) and are moving
to v3 ([`program/main-v3.aml`](../../program/main-v3.aml)). For the
empirical *why*, see [`overview.md`](overview.md) §"Why we moved on".

## Per-entrypoint delta

| v2 entrypoint                          | v3 entrypoint                        | Status     | Note                                                                                  |
| -------------------------------------- | ------------------------------------ | ---------- | ------------------------------------------------------------------------------------- |
| `register_circle(circle, receipt_pk, region, p_shared, p_internal)` | `register_circle(circle, state_root, receipt_pk)` | **Renamed args** | region + prices moved into sealed `policy.json` inside the circle; chain holds only `state_root` |
| `update_circle(circle, …)` (price / region)      | `update_circle_state(circle, new_state_root)` | **Replaced**     | Single anchor update instead of multi-field; price changes live in `policy.json`                  |
| —                                      | `rotate_receipt_pubkey(circle, new_pk)` | **New**         | v2 had no on-chain pubkey rotation; v3 explicitly allows + tracks (off-chain audit-bot territory) |
| `retire_circle(circle)`                | `retire_circle(circle)`              | Same       |                                                                                                   |
| `bond_endpoint(circle)`                | `bond_endpoint(circle)`              | Same       |                                                                                                   |
| `unbond_endpoint(circle)`              | `unbond_endpoint(circle)`            | Same       |                                                                                                   |
| `finalize_unbond(circle)`              | `finalize_unbond(circle)`            | Same       |                                                                                                   |
| `slash_double_sign(circle, …)`         | `slash_double_sign(circle, …)`       | Same       | v2 + v3 both verify against `circle_receipt_pk` (base64 ed25519)                                  |
| `gov_slash_operator(circle)`           | `gov_slash_operator(circle)`         | Same       |                                                                                                   |
| `add_authorized_circle(tid, circle)`   | —                                    | **Removed**     | ACL moved into sealed `members.json`; chain only holds `members_root` hash                       |
| `remove_authorized_circle(tid, circle)` | —                                   | **Removed**     | same                                                                                              |
| `create_tailnet(name, …)`              | `create_tailnet(members_root)`       | **Renamed args** | tailnet display name lives in `tailnet-{id}/config.json` sealed asset                            |
| —                                      | `update_members_root(tid, new_root)` | **New**         | rotate the members anchor                                                                         |
| `retire_tailnet(tid)`                  | `retire_tailnet(tid)`                | Same       |                                                                                                   |
| `deposit_to_tailnet(tid)`              | `deposit_to_tailnet(tid)`            | Same       |                                                                                                   |
| `withdraw_tailnet_treasury(tid, amt)`  | `withdraw_tailnet_treasury(tid, amt)` | Same      |                                                                                                   |
| `open_session(tid, circle, class, max_pay)` | `open_session(tid, circle, max_pay)` | **Class removed** | Class lives in operator-signed off-chain receipt; chain agnostic                                 |
| `settle_claim(sid, bytes, …)`          | `settle_claim(sid, bytes)`           | **Args trimmed** | No class param; equivocation logic identical                                                     |
| `settle_confirm(sid, bytes, net, blinding)` | `settle_confirm(sid, bytes, net, settle_blinding)` | **Same shape, hash chain replaces HFHE** | v3 commits `head' = sha256(head ‖ sha256(blinding))`; v2 added to encrypted ciphertext       |
| `claim_no_show(sid)`                   | `claim_no_show(sid)`                 | Same       |                                                                                                   |
| `sweep_expired_session(sid)`           | `sweep_expired_session(sid)`         | Same       |                                                                                                   |
| `claim_earnings(circle, amount, fhe_proof)` | `claim_earnings(circle, amount)`  | **Args trimmed** | No FHE zero-proof; v3 gates against plaintext `total - claimed`                                   |
| `transfer_ownership`, `set_paused`, `set_params`, `withdraw_program_treasury` | same | Same  | Governance surface preserved; `set_params` signature has 10 ints in v3                            |

## Per-data-type delta

| v2 on-chain field                                    | v3 equivalent                                | Status            |
| ---------------------------------------------------- | -------------------------------------------- | ----------------- |
| `circle_record: map[address]CircleRecord` (struct)   | flat maps: `circle_owner`, `circle_receipt_pk`, `circle_state_root`, `circle_state_version`, `circle_active` | **Restructured**  |
| `circle_record.region: string`                       | inside sealed `state-root.json`              | **Moved off-chain** |
| `circle_record.price_per_mb` / per-class             | inside sealed `policy.json`                  | **Moved off-chain** |
| `circle_record.hfhe_pk: bytes`                       | —                                            | **Removed**       |
| `circle_record.enc_zero: bytes`                      | —                                            | **Removed**       |
| `enc_earnings: map[address]bytes` (HFHE ciphertext)  | `circle_earnings_total: map[address]int` + `circle_earnings_chain: map[address]bytes` | **Replaced** |
| `authorized_circles: map[(tid,cid)]bool`             | `tailnet_members_root: map[int]bytes`        | **Replaced**      |
| `tailnet_record: map[int]TailnetRecord`              | flat maps: `tailnet_owner`, `tailnet_treasury`, `tailnet_members_root`, `tailnet_root_version`, `tailnet_retired` | **Restructured** |
| `session_record: map[int]Session`                    | flat maps: `session_deposit`, `session_status`, `session_opener`, `session_exit`, `session_tailnet`, `session_opened_at`, `operator_claim_*`, `client_confirm_*` | **Restructured** |
| —                                                    | `circle_state_version`, `tailnet_root_version` | **New**           |

The shape change is structural: v3 stores no `struct`s. Every value
is `int`, `address`, or short `string` / `bytes`. This is a
deliberate response to the 4 KiB string-cap quirk (memory:
`octra_aml_string_cap_4kb.md`) which silently truncated v2's inline
multi-field records once `region` strings grew.

## What stayed the same

- **Two-tx settle.** Operator claims → opener confirms → settle or
  dispute. Equivocation on the second claim refunds the session.
- **Slash mechanics.** `apply_slash` is essentially identical:
  zero the buckets, set the permanent flag, burn 90% + bounty 10%.
- **Pause semantics.** Pause halts user flows; governance bypasses.
- **`circle_id` derivation.** Octra-circle addresses are stable
  across main-contract redeploys (open question #5 in
  [`../octra-dev-questions.md`](../octra-dev-questions.md)).
- **Hash-precommit join tokens** were removed in v2 already; v3
  doesn't bring them back. Membership is purely off-chain Merkle
  proof against `tailnet_members_root`.
- **Data plane.** WireGuard / noise IK / per-session receipt JSON
  unchanged.

## What's new

- **3 SHA-256 anchors instead of inline fields**:
  `circle_state_root` (operator commitment),
  `tailnet_members_root` (tailnet ACL),
  `circle_earnings_chain` (per-circle tamper-evident settle log).
- **`rotate_receipt_pubkey`** — explicit on-chain key rotation.
- **`update_circle_state`** + **`update_members_root`** with
  monotonic version counters.
- **`circle_state_version`** + **`tailnet_root_version`** monotonic
  counters, available via view functions.

## What's removed (relative to v2)

- HFHE earnings ledger (`fhe_load_pk`, `fhe_*` host calls). Blocked
  by Octra chain runtime (memory:
  `octra_aml_fhe_load_pk_blocked.md`). Swap path documented at
  [`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md) §5.2.
- Inline policy storage (`region`, prices, endpoint URL on chain).
- Inline `authorized_circles` ACL.
- Per-class settle math on chain. Class lives in the operator's
  signed receipt; chain only sees `bytes_used` + agreed `net`.
- The `claim_earnings`-time FHE zero-proof. Replaced by the
  plaintext `total - claimed` gate.

## Operator migration path

No in-place upgrade. v3 is a new contract at a new address.

1. **Day −7**: operator builds the v3 sealed-asset bundle
   (`policy.json`, `attestation.json`) inside their existing
   Octra Circle. The `circle_id` does NOT change across v2 → v3 (it
   depends on deployer wallet + nonce + deploy payload, not on the
   main contract; see open question #5).
2. **Day −7**: operator builds `state-root.json` v1, computes
   `sha256_hex(canonical_bytes(state_root))`. Schema in
   [`canonical-encoders.md`](canonical-encoders.md).
3. **Day −7**: operator generates a new ed25519 receipt keypair
   (base64-encoded for the chain). Recommended: a fresh key per
   v3 deploy.
4. **Day 0** (mainnet ceremony, see
   [`../mainnet-ceremony.md`](../mainnet-ceremony.md)): v3 deploys
   at a fresh address `R'`.
5. **Day 0+ε**: operator calls
   `register_circle(circle_id, state_root_hex, receipt_pk_b64)`
   with `value >= min_circle_stake` on `R'`. This is atomic —
   registration + bond happen in a single tx.
6. **Day 0+δ**: tailnet owner re-anchors via
   `create_tailnet(members_root_hex)` — note the tid will be NEW
   (chain-local counter); operators referencing the old tid in
   pre-existing client config must update.
7. **Day 0+δ**: clients update wallet config to point at `R'`.
   `octravpn-client` reads `[chain].program_addr`.
8. **Sessions on v2 (`R`) continue to be settle-able** until
   governance pauses `R` or operators voluntarily retire on `R`.
   Open sessions on `R` continue to consume v2's flow (`R.tailnet_treasury` → `R.session_deposit` → settle or refund). No
   data migration is possible — OU on `R` stays on `R`.
9. **Day 0+30**: governance may eventually `set_paused(1)` on `R`
   after a grace window.

The v3-circle-resident architecture doc spells out the redeploy
mechanics + race conditions at [`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md) §4.

## Comparison to v1.1

For completeness — v1.1 (`program/main.aml` at
`oct2YehVLezCi2RCcSkURc3nyyYtzxmspwGHHALm6pjkUvJ`) used a fully
public endpoint registry keyed by wallet address, with on-chain HFHE
earnings. v3's deltas vs v1.1 are a strict superset of v2's deltas:
all v2 changes apply, plus the circle-keyed shift v2 introduced. The
v1.1 → v2 walk is in [`../architecture.md`](../architecture.md) §2;
v2 → v3 is the present document.
