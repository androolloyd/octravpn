# v3 data model

Every map, scalar, and constant in
[`program/main-v3.aml`](../../program/main-v3.aml). Line numbers
in brackets reference that file at head.

## Types in play

| Type      | RPC encoding                                            | AML quirks                                                                                 |
| --------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `int`     | JSON number                                             | 64-bit signed in AML's interpreter; tx values fit u64                                      |
| `address` | JSON string, `oct…` display                             | validated by `is_address()` ([`program/main-v3.aml:223,279`](../../program/main-v3.aml))   |
| `bytes`   | JSON string (NOT decoded by chain) — see note           | `len()` returns char count; unset reads back as the literal `"0"` (memory: `octra_aml_bytes_encoding.md`) |
| `string`  | JSON string, ≤ ~4096 chars                              | silently truncates above 4 KiB (memory: `octra_aml_string_cap_4kb.md`)                     |

**Note on `bytes`:** v3 stores every "32-byte SHA-256 anchor" as a
**64-char lowercase hex digest**, not a raw 32-byte buffer. The chain
enforces `len(anchor) == 64` at the entrypoint
([`program/main-v3.aml:282,319,423,451`](../../program/main-v3.aml)).
Integrity is enforced off-chain by verifiers fetching the canonical
JSON and comparing `sha256_hex(json) == anchor` — see
[`canonical-encoders.md`](canonical-encoders.md).

## Constants

Defined at [`program/main-v3.aml:35-44`](../../program/main-v3.aml).

| Constant                       | Value | Used by                                                                |
| ------------------------------ | ----- | ---------------------------------------------------------------------- |
| `BPS_DENOM`                    | 10000 | Slash + sweep + protocol-fee bps math                                  |
| `SLASH_BURN_DEFAULT_BPS`       | 9000  | Initial 90/10 burn/bounty split (`apply_slash`)                        |
| `PROTOCOL_FEE_DEFAULT_BPS`     | 50    | 0.5% of `net` on settle                                                |
| `SWEEP_GRACE_MULT_DEFAULT`     | 10    | `sweep_grace = session_grace_epochs * 10`                              |
| `SWEEP_BOUNTY_DEFAULT_BPS`     | 100   | 1% of swept deposit to caller                                          |
| `SESSION_OPEN` / `_SETTLED` / `_REFUNDED` | 0 / 1 / 2 | Session FSM (see [`state-machine.md`](state-machine.md))    |

## Top-level scalars

Declared at [`program/main-v3.aml:79-142`](../../program/main-v3.aml).

| Field                                                                | Type      | Purpose                                                                 |
| -------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------- |
| `owner`                                                              | `address` | Governance principal; settable via `transfer_ownership`                 |
| `paused`                                                             | `int`     | 0 or 1; gates user flows only ([`program/main-v3.aml:183-185`](../../program/main-v3.aml)) |
| `tailnet_count`                                                      | `int`     | Monotonic ID source for `create_tailnet`                                |
| `session_count`                                                      | `int`     | Monotonic ID source for `open_session`                                  |
| `treasury`                                                           | `int`     | Protocol-fee + slash-burn accumulator                                   |
| `burned`                                                             | `int`     | Cumulative burn counter (subset of `treasury`); audit-only             |
| `min_session_deposit`, `min_tailnet_deposit`, `min_circle_stake`     | `int`     | Governance floors                                                       |
| `session_grace_epochs`, `unbond_grace_epochs`                        | `int`     | Grace windows                                                           |
| `sweep_grace_multiplier`, `sweep_bounty_bps`                         | `int`     | Sweep economics                                                         |
| `slash_burn_bps`, `slash_bounty_bps`                                 | `int`     | Slash split; `set_params` invariant: must sum to `BPS_DENOM` ([`program/main-v3.aml:245`](../../program/main-v3.aml)) |
| `protocol_fee_bps`                                                   | `int`     | Cap: 200 (2%) via `set_params` ([`program/main-v3.aml:246`](../../program/main-v3.aml)) |

## Circle registry

The "circle" here is an Octra Circle address acting as an opaque
namespace for sealed assets. The chain treats it as a primary key;
the circle is NOT required to be executable (v3 explicitly works
around the fact that circles store but don't run `code_b64` —
memory `octra_circles_not_executable.md`).

Maps declared at [`program/main-v3.aml:83-96`](../../program/main-v3.aml).

| Map                          | Key       | Value     | Invariant                                                                  | Source            |
| ---------------------------- | --------- | --------- | -------------------------------------------------------------------------- | ----------------- |
| `circle_owner`               | `address` | `address` | Set once at `register_circle` ([:290](../../program/main-v3.aml)); never reset | L84 |
| `circle_receipt_pk`          | `address` | `string`  | Base64 ed25519 pubkey (≈ 44 chars); rotatable via `rotate_receipt_pubkey`  | L86               |
| `circle_state_root`          | `address` | `bytes`   | 64-char lowercase hex SHA-256 of canonical `state-root.json`               | L88               |
| `circle_state_version`       | `address` | `int`     | Monotonic per circle; bumps in `update_circle_state`                       | L89               |
| `circle_active`              | `address` | `int`     | 1 after `register_circle`; 0 after `retire_circle` or slash                | L90               |
| `circle_bond`                | `address` | `int`     | OU currently bonded (live, slashable, not yet unbonding)                   | L93               |
| `circle_unbonding`           | `address` | `int`     | OU in grace; still slashable                                               | L94               |
| `circle_unbond_unlock_epoch` | `address` | `int`     | Epoch at which `finalize_unbond` may succeed                               | L95               |
| `circle_slashed`             | `address` | `int`     | Permanent ban flag; 1 = circle can never re-register                       | L96               |

## Tailnet registry

Maps declared at [`program/main-v3.aml:99-105`](../../program/main-v3.aml).

| Map                       | Key   | Value     | Invariant                                                                   | Source |
| ------------------------- | ----- | --------- | --------------------------------------------------------------------------- | ------ |
| `tailnet_owner`           | `int` | `address` | Set at `create_tailnet`; auth for `update_members_root` / `retire_tailnet` | L100   |
| `tailnet_treasury`        | `int` | `int`     | OU custody; drained on `open_session`, topped up on settle refund          | L101   |
| `tailnet_members_root`    | `int` | `bytes`   | 64-char hex SHA-256 of `members.json`; rotatable via `update_members_root` | L103   |
| `tailnet_root_version`    | `int` | `int`     | Monotonic per tailnet; bumps in `update_members_root`                       | L104   |
| `tailnet_retired`         | `int` | `int`     | 1 disables further deposits + opens; required for `withdraw_tailnet_treasury` | L105 |

Tailnet ACL is **off-chain**: the chain only holds the
`members_root` hash. Membership is proved by a Merkle path against
the root, verified by the operator. See
[`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md) §3.2
for the per-member sealed-key envelope shape.

## Session escrow + adjudication

Maps declared at [`program/main-v3.aml:108-120`](../../program/main-v3.aml).

| Map                       | Key   | Value     | Invariant                                                                   | Source |
| ------------------------- | ----- | --------- | --------------------------------------------------------------------------- | ------ |
| `session_deposit`         | `int` | `int`     | Max-pay locked from tailnet treasury at open                                | L109   |
| `session_status`          | `int` | `int`     | 0=OPEN, 1=SETTLED, 2=REFUNDED. Monotonic forward                            | L110   |
| `session_opener`          | `int` | `address` | Only opener may `settle_confirm` / `claim_no_show`                          | L111   |
| `session_exit`            | `int` | `address` | The operator's `circle_id`; auth for `settle_claim`                          | L112   |
| `session_tailnet`         | `int` | `int`     | tailnet the deposit came from + must be refunded to                         | L113   |
| `session_opened_at`       | `int` | `int`     | Epoch; gates `claim_no_show` + `sweep_expired_session`                       | L114   |
| `operator_claim_bytes`    | `int` | `int`     | Operator's `bytes_used`. Equivocation = mismatch on second claim            | L117   |
| `operator_claim_set`      | `int` | `int`     | 0/1 flag; first claim wins, second mismatched claim triggers refund + dispute | L118 |
| `client_confirm_bytes`    | `int` | `int`     | Opener's `bytes_used`; mismatch with operator's = dispute                   | L119   |
| `client_confirm_set`      | `int` | `int`     | 0/1 flag                                                                    | L120   |

## Earnings ledger

Maps declared at [`program/main-v3.aml:123-126`](../../program/main-v3.aml).

| Map                       | Key       | Value     | Invariant                                                                  | Source |
| ------------------------- | --------- | --------- | -------------------------------------------------------------------------- | ------ |
| `circle_earnings_total`   | `address` | `int`     | Plaintext running gross (post-fee) credit to the operator                  | L123   |
| `circle_earnings_claimed` | `address` | `int`     | Cumulative claimed; `claim_earnings` enforces `claimed ≤ total`           | L124   |
| `circle_earnings_chain`   | `address` | `bytes`   | SHA-256 hash chain: `head' = sha256(head ‖ sha256(settle_blinding))`      | L126   |

Hash-chain genesis is initialized at `register_circle` to
`sha256(state_root)` so audit replay doesn't depend on the AML
default-value quirk (unset `bytes` reads as the literal `"0"` —
memory `octra_aml_bytes_encoding.md`). See
[`program/main-v3.aml:295-303`](../../program/main-v3.aml).

## Determinism invariants

These are not enforced by the chain — verifiers enforce them off-chain.

1. **`circle_id` is deployer-derived.** Octra's circle-address
   derivation depends on the deployer wallet + nonce + deploy
   payload, NOT on the main contract address. So `circle_id` is
   stable across v3 redeploys. (Open question #5 in
   [`../octra-dev-questions.md`](../octra-dev-questions.md).)
2. **`circle_state_version` is monotonic per circle.** Bumped at
   [`program/main-v3.aml:321`](../../program/main-v3.aml); never
   resets. Verifiers reject `update_circle_state` whose `epoch`
   field inside the JSON regresses (see
   [`canonical-encoders.md`](canonical-encoders.md)).
3. **`session_count` / `tailnet_count` are append-only.** No
   delete; retired entities keep their slot.
4. **`session_status` is forward-only.** OPEN → SETTLED or
   OPEN → REFUNDED; never resets.
5. **`circle_slashed[c] == 1` is sticky.** No entrypoint resets
   it. `register_circle` rejects previously-slashed circles
   ([`program/main-v3.aml:281`](../../program/main-v3.aml)).

## Lifecycle state diagram

ASCII overview; the formal per-entity FSMs are in
[`state-machine.md`](state-machine.md).

```text
                       deploy main-v3 (constructor)
                                  │
                                  ▼
       ┌─────────────────────── owner ──────────────────────────┐
       │                                                        │
       │  register_circle ── circle (active, bonded)            │
       │       │                                                │
       │       │ update_circle_state / rotate_receipt_pubkey   │
       │       │ bond_endpoint                                  │
       │       ▼                                                │
       │  ┌──────────────┐  unbond_endpoint  ┌──────────────┐  │
       │  │ Circle ACTIVE│───────────────────►│  UNBONDING   │  │
       │  │              │                    │              │  │
       │  │              │   finalize_unbond (after grace)   │  │
       │  │              │                    │              │  │
       │  └──────┬───────┘                    └──────┬───────┘  │
       │         │ slash_double_sign /                │          │
       │         │ gov_slash_operator                 │ slash    │
       │         ▼                                    ▼          │
       │  ┌──────────────────── SLASHED (permanent) ──────────┐ │
       │  └────────────────────────────────────────────────────┘ │
       │                                                          │
       │  create_tailnet                                          │
       │       │                                                  │
       │       ▼                                                  │
       │  ┌──────────────┐                                        │
       │  │ Tailnet OPEN │   open_session                         │
       │  │              │──────────────────► Session OPEN        │
       │  └──────┬───────┘                          │              │
       │         │ retire_tailnet                   │ settle_claim │
       │         ▼                                  ▼              │
       │  ┌──────────────┐                  ┌──────────────┐       │
       │  │   RETIRED    │                  │  CLAIM_SET   │       │
       │  │ (withdraw OK)│                  └──────┬───────┘       │
       │  └──────────────┘                         │ settle_confirm│
       │                                           ▼               │
       │                                  ┌──────────────────┐    │
       │                                  │  SETTLED         │    │
       │                                  │  earnings_total++│    │
       │                                  │  hash_chain ext  │    │
       │                                  └──────────────────┘    │
       │                                           │               │
       │                                           ▼               │
       │                                    claim_earnings         │
       │                                                           │
       └───────────────────────────────────────────────────────────┘

    REFUND paths (parallel to SETTLED):
      - settle_claim equivocation         → REFUNDED + SettleDispute
      - settle_confirm bytes mismatch      → SettleDispute (session stays open)
      - claim_no_show after grace          → REFUNDED
      - sweep_expired_session after 10× grace → REFUNDED minus 1% bounty
```

For per-entity transition tables see [`state-machine.md`](state-machine.md).
