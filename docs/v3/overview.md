# v3 overview

## What v3 is

OctraVPN v3 is the chain-minimal successor to v2. The on-chain
program ([`program/main-v3.aml`](../../program/main-v3.aml), 712 lines)
holds only what cannot be enforced off-chain:

- OU custody for operator bonds, session escrow, tailnet treasuries,
  and a protocol fee treasury;
- monotonic state-version + permanent slash flags;
- ed25519 verification of equivocating receipt signatures;
- a 32-byte (64-char hex) SHA-256 anchor per role pointing at a
  canonical JSON document sealed inside an Octra Circle.

Everything that *can* live in a circle does — operator policy
(`oct://<circle>/policy.json`), tailnet membership
(`oct://<owner>/tailnet-{id}/members.json`), per-session receipts,
attestation bundles, governance audit logs. The chain holds the
hash, not the document. See
[`canonical-encoders.md`](canonical-encoders.md) for the byte-exact
JSON format used to derive each anchor.

This pivot was empirically forced. Three Octra-devnet constraints,
each verified at head-of-tree, made the v2 design unsatisfiable:

1. `map[address]string` truncates silently at ~4096 bytes
   (memory: `octra_aml_string_cap_4kb.md`). v2 stored operator
   policy + ciphertext inline; v3 cannot.
2. AML `fhe_*` host calls revert on devnet
   (memory: `octra_aml_fhe_load_pk_blocked.md`). v2 settled
   into an HFHE-encrypted earnings ledger; v3 falls back to a
   SHA-256 hash chain.
3. Circles store `code_b64` but `contract_call` against the circle
   returns `"bytecode not found"`
   (memory: `octra_circles_not_executable.md`). Bonds + slash
   cannot move into a `BondEscrow` circle yet, so they stay on the
   main contract.

The full empirical case is in
[`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md) §1.

## What v3 adds over v2

| Surface                       | v2                                                  | v3                                                              |
| ----------------------------- | --------------------------------------------------- | --------------------------------------------------------------- |
| Per-class routing             | tariff stored on-chain per circle (`prices.shared`, `prices.internal`) | tariff lives in sealed `/policy.json`; chain only sees `bytes_used` + `net` |
| Operator policy storage       | inline on the main contract (`region`, prices)      | sealed asset in operator circle; chain holds `policy_hash` anchor (see [`canonical-encoders.md`](canonical-encoders.md)) |
| Tailnet ACL                   | `authorized_circles: map[(tid, cid)]bool`           | sealed `/members.json` per tailnet; chain holds `tailnet_members_root` anchor |
| Earnings                      | HFHE ciphertext via `fhe_*` host calls              | plaintext running total + SHA-256 hash chain (HFHE-swap-ready)  |
| Chain anchors                 | none — full struct stored                           | `circle_state_root`, `tailnet_members_root`, `circle_earnings_chain` (32B SHA-256 each) |
| Equivocation slash            | `slash_double_sign` against operator wallet         | `slash_double_sign` against `circle_receipt_pk` (44-char base64 ed25519) |
| Adversarial coverage          | 45-case drill (`e2e-adversarial-v2.sh`)             | 40-case drill (`e2e-adversarial-v3.sh`) + 1 positive slash      |

The chain-side per-circle footprint dropped from a ~4 KB struct
(`CircleRecord` + HFHE pubkey + ciphertexts) to a deterministic
~60 bytes (2 short scalars + 32-byte hash + 2 ints). Source:
[`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md) §2.

## What v3 does NOT change

- **Data plane.** WireGuard / boringtun / noise IK tunnel is
  untouched. Per-session receipt JSON is the same shape.
- **Two-tx settle.** Operator submits `settle_claim`, opener
  submits `settle_confirm`; equivocation triggers refund
  ([`program/main-v3.aml:513-543`](../../program/main-v3.aml)).
- **Pause semantics.** Pause halts user flows only (memory:
  `octra_v1_pause_bypass.md`). Governance entrypoints
  (`transfer_ownership`, `set_paused`, `set_params`,
  `withdraw_program_treasury`, `gov_slash_operator`) intentionally
  bypass pause for incident response. See
  [`program/main-v3.aml:217-269`](../../program/main-v3.aml) and the
  P3 regression-guard case in
  [`docker/devnet/e2e-adversarial-v3.sh:510-512`](../../docker/devnet/e2e-adversarial-v3.sh).
- **HFHE roadmap.** v3's `settle_confirm` keeps the hash-chain head
  in `circle_earnings_chain`; when Octra ships working `fhe_*`
  against new deploys the upgrade is additive (a parallel ciphertext
  field next to the plaintext total). See
  [`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md) §5.2.

## Why we moved on from v2

Three reasons, in order of operational severity:

1. **The 4 KB string cap silently truncated production data.**
   v2's `register_circle` accepted a multi-KB sealed-policy
   ciphertext as a `string` param; the chain returned 200, the
   tx confirmed, and the value came back at exactly 4096 bytes.
   No revert, no warning. v3 stores zero inline blobs — every
   field is either an int, an address, or a 64-char hex digest
   ([`program/main-v3.aml:79-142`](../../program/main-v3.aml)).
2. **`fhe_load_pk` reverts.** v2's earnings ledger called
   `fhe_load_pk(circles[c].owner)` on every settle, and the host
   call reverts on every deployed program (including Octra's own
   `program-examples/private_ml`). The fix isn't on our side;
   we engineered around it with a hash chain that's strictly
   weaker than HFHE but strictly stronger than per-settle
   plaintext (see [`fee-model.md`](fee-model.md) §3).
3. **The chain doesn't run circle code.** v2 was designed
   anticipating `BondEscrow` circles holding stake. The chain
   accepts the bytecode but `contract_call` against the circle
   reverts. Bonds stay on the main contract until that ships.

Migration path for operators: v3 is a **new deploy**, not an
in-place upgrade. Stake on v2's contract stays on v2's contract.
See [`v3-vs-v2.md`](v3-vs-v2.md) §6 for the per-operator walk-through.

## Where to read next

- The on-chain state shape and invariants: [`data-model.md`](data-model.md).
- Every entrypoint walked end-to-end: [`call-flows.md`](call-flows.md).
- The adversary model: [`security-model.md`](security-model.md).
- Side-by-side v2/v3 delta: [`v3-vs-v2.md`](v3-vs-v2.md).
