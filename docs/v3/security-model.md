# v3 security model

This document scopes the on-chain enforcement layer of v3. The
end-to-end operator-daemon + client adversary model (control-plane,
DERP, key compromise, audit log) lives in
[`../security/threat-model-v3.md`](../security/threat-model-v3.md) —
this document focuses on what the v3 AML enforces and what off-chain
code must enforce alongside it.

## Trust assumptions

| Assumption                                                         | Why we accept it                                                                                              |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Wallet ownership = identity                                        | The chain runtime ed25519-verifies the tx envelope; we don't carry inline sigs in the call payload             |
| Validator honest-majority for ordering + liveness                  | Chain-level assumption; out of scope (`../security/threat-model-v3.md §3`)                                     |
| RPC endpoint is the chain (pinned roots)                           | `[chain].pinned_root_paths` in node config; mitigation lives in the daemon, not in v3                          |
| Off-chain canonical JSON encoders are deterministic across implementers | Enforced by the Lean theorems in [`canonical-encoders.md`](canonical-encoders.md) §Lean references             |
| Octra-circle `circle_id` derivation is main-contract-independent   | Open question #5 in [`../octra-dev-questions.md`](../octra-dev-questions.md); empirically true today          |
| AML `bytes` params are NOT decoded at the RPC boundary             | Memory: `octra_aml_bytes_encoding.md`. v3 stores 64-char hex strings; the chain enforces `len() == 64`         |

## Adversary capabilities

We enumerate by capability tier; full attack-tree in
[`../security/threat-model-v3.md`](../security/threat-model-v3.md).

### Tier A — unauthenticated network reach

Can: submit RPC calls, observe events + view results.
Defeated by: chain auth on every state mutation (`caller` is
ed25519-verified); event emission is by-design public; views return
only what the FSM exposes.

### Tier B — controls an opener wallet (client)

Can: open sessions against an honest operator's circle; refuse to
confirm; equivocate during confirm.
Defeats:

- **Refuse to confirm**: deposit stays escrowed; operator eats grace
  delay; OU returns to tailnet via `claim_no_show` or `sweep_expired_session`. Operator's
  loss is bounded by 10× `session_grace_epochs`.
- **Confirm with mismatched bytes**: emits `SettleDispute`; session
  stays OPEN; OU still locked. Operator can submit
  `slash_double_sign` if the opener signed a contradictory receipt
  off-chain. The pure on-chain dispute does not slash anyone — only
  signed equivocation does.

### Tier C — controls an operator wallet + receipt key

Can: register circles; sign receipts; rotate keys; equivocate.
Defeats:

- **Equivocation**: a second `settle_claim` with different
  `bytes_used` triggers `SETTLED → REFUNDED` and `SettleDispute`
  emission ([`program/main-v3.aml:528-536`](../../program/main-v3.aml)).
  The bond is NOT auto-slashed — anyone holding the two
  contradictorily-signed off-chain receipts MUST submit
  `slash_double_sign` to actually burn the bond. The on-chain
  equivocation only refunds.
- **Sign two different receipts with the same key**: detected by
  `slash_double_sign` (`ed25519_ok` × 2); bond is burned 90% + 10%
  bounty.
- **Rotate receipt key to escape slashing**: detected post-hoc by
  off-chain attestation history bots. The chain does not retain
  pubkey history; the off-chain audit log does.
- **Withhold settle_claim**: opener's `claim_no_show` after grace
  refunds the deposit. Operator earns nothing — symmetric to the
  Tier-B refuse-to-confirm.

### Tier D — controls multiple operator wallets (collusion)

Can: spin up arbitrary circles; cross-sign receipts.
Defeats: no chain enforcement beyond per-circle slashing. Reputation
+ off-chain tailnet ACL (validated against `tailnet_members_root`)
are the defense — chain has no notion of operator-cluster identity.

### Tier E — controls a tailnet-owner wallet

Can: rotate `members_root` to lock members out; retire and drain
treasury.
Defeats:

- **Treasury drain after retire**: legal. Members are expected to
  notice retirement (chain event) and stop opening sessions. Open
  sessions still settle into the treasury via refund — but a
  hostile owner can drain mid-flight (see `state-machine.md
  §tailnet edge cases`). This is documented as a runbook
  responsibility, not a chain check.
- **Rotate `members_root` to an attacker-controlled member set**:
  legal. Off-chain Merkle proof verification is what gates session
  membership; the chain has no notion of "valid" members. Defense:
  members monitor `TailnetMembersRootUpdated` events and validate
  the new `members.json` against their expectations.

### Tier F — chain governance keys

Can: `transfer_ownership`, `set_paused`, `set_params`,
`gov_slash_operator`, `withdraw_program_treasury`.
Defeats: governance is the trust root for the contract. Mitigation
is m-of-n cold-storage multisig per
[`../mainnet-ceremony.md`](../mainnet-ceremony.md). Once devnet
moves to mainnet the owner key is multisig-only.

## Invariants

These are the on-chain properties the AML enforces. Each cites the
file:line of the enforcement + a cross-reference to the Lean theorem
(if one exists) and/or the adversarial drill that exercises it.

| #   | Invariant                                                                    | Enforced at                                                       | Verified by                                                                 |
| --- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------- |
| I1  | Anchor length = 64                                                           | [`main-v3.aml:282,319,423,451`](../../program/main-v3.aml)         | `check_hash_length_required` ([`proofs/lean/WireProtocol/V3Canonical.lean:279`](../../proofs/lean/WireProtocol/V3Canonical.lean)); R1, R2, T2 |
| I2  | Anchors are deterministic per JSON input                                     | n/a (off-chain encoder)                                           | `canonical_determinism` ([`V3Canonical.lean:242`](../../proofs/lean/WireProtocol/V3Canonical.lean)); `canonical_idempotent` (:249); `canonical_string_injective` (:264) |
| I3  | Anchor key order is sorted                                                   | n/a                                                               | `canonical_keys_sorted` ([`V3Canonical.lean:218`](../../proofs/lean/WireProtocol/V3Canonical.lean)); `canonical_reorder_invariant` (:228) |
| I4  | `policy_anchor` is deterministic + reorder-invariant + epoch-collision-resistant | n/a                                                            | `policy_anchor_deterministic` ([`V3Policy.lean:84`](../../proofs/lean/WireProtocol/V3Policy.lean)); `policy_anchor_field_reorder_invariant` (:97); `policy_anchor_collision_resistant_on_epoch` (:111); `policy_anchor_includes_acl_hash` (:129); `policy_anchor_size` (:145) |
| I5  | `members_anchor` is deterministic + reorder-invariant (incl. member order) + collision-resistant + size-bounded | n/a                                                            | `members_anchor_deterministic` ([`V3Members.lean:167`](../../proofs/lean/WireProtocol/V3Members.lean)); `members_anchor_field_reorder_invariant` (:182); `members_anchor_member_reorder_invariant` (:199); `members_anchor_collision_resistant` (:217); `members_anchor_size_bounded` (:235) |
| I6  | Slashed circles cannot re-register or re-bond                                | [`main-v3.aml:281,355`](../../program/main-v3.aml)                 | Adversarial drill: S6; FSM transition table (Slashed → _any_ = no-op)        |
| I7  | Slashed circles cannot claim earnings                                        | [`main-v3.aml:651`](../../program/main-v3.aml)                     | C3                                                                          |
| I8  | `circle_earnings_claimed ≤ circle_earnings_total`                            | [`main-v3.aml:653-654`](../../program/main-v3.aml)                 | C4; smoke step 8 (overclaim)                                                |
| I9  | `slash_burn_bps + slash_bounty_bps == BPS_DENOM`                             | [`main-v3.aml:245`](../../program/main-v3.aml) (set_params guard)  | Implicit by construction; F3 (non-owner reject)                              |
| I10 | `protocol_fee_bps ≤ 200` (2%)                                                | [`main-v3.aml:246`](../../program/main-v3.aml)                     | Implicit                                                                    |
| I11 | Bond can't be withdrawn before unbond grace                                  | [`main-v3.aml:382`](../../program/main-v3.aml)                     | B4 (finalize-without-unbond reject)                                          |
| I12 | Session deposit caps operator earnings                                       | [`main-v3.aml:574-577`](../../program/main-v3.aml) (net ≤ deposit) | E5–E11; structural — net is `min(net, deposit)`                              |
| I13 | Equivocating settle_claim refunds deposit (chain-only; slash needs sigs)     | [`main-v3.aml:528-536`](../../program/main-v3.aml)                 | E5, E6 (negative); equivocation positive is currently only exercised by `slash_double_sign` S5 |
| I14 | `session_status` is forward-only (OPEN → SETTLED/REFUNDED, no regression)    | [`main-v3.aml:516,552,606,622`](../../program/main-v3.aml)         | E11 (settle_confirm on settled rejects)                                      |
| I15 | Pause halts user flows; governance bypasses                                  | [`main-v3.aml:183-185`](../../program/main-v3.aml); governance fns omit `require_not_paused` | P1, P2, P3 (regression guard)                                                |
| I16 | Tailnet treasury sufficiency check before session open                       | [`main-v3.aml:492`](../../program/main-v3.aml)                     | Implicit; not directly drilled                                              |
| I17 | Hash-chain commit is deterministic from `(prev_head, settle_blinding)`       | [`main-v3.aml:591-593`](../../program/main-v3.aml)                 | Smoke step 6 (local replay matches on-chain byte-for-byte)                   |
| I18 | `circle_state_version` is monotonic per circle                               | [`main-v3.aml:321`](../../program/main-v3.aml) (only `+= 1` mutation) | Implicit                                                                    |

Theorems referenced are part of the WireProtocol Lean tree. Compile
via `lake build` from `proofs/lean/`; the v3 modules total 24
theorems (`V3Canonical.lean` 14, `V3Policy.lean` 5, `V3Members.lean` 5).

## Slash conditions

There are exactly two paths into the `Slashed` terminal state.

### `slash_double_sign(circle, payload_a, sig_a, payload_b, sig_b)`

Source: [`program/main-v3.aml:394-404`](../../program/main-v3.aml).

**Proof shape required:** two ed25519 signatures by the same
`circle_receipt_pk` over two DIFFERENT payloads. The chain
crypto-verifies both sigs via `ed25519_ok`. The payload format is
operator-application-defined (typically
`receipt-v1|sid=<n>|bytes=<m>` per the adversarial drill
[`docker/devnet/e2e-adversarial-v3.sh:314-315`](../../docker/devnet/e2e-adversarial-v3.sh)).
The chain does NOT parse payloads; mere distinctness suffices.

**What this catches:**

- Operator signs two different `bytes_used` claims for the same
  session at different epochs.
- Operator signs receipts for two different sessions with the same
  `(sid, seq)` (Sybil-resistant).
- Operator equivocates across forked binaries against the same
  receipt key (the residual gap discussed at
  [`../security/threat-model-v3.md §2.a`](../security/threat-model-v3.md)).

**What this does NOT catch:**

- Operator signs ONE receipt with a key, then rotates the on-chain
  pubkey, then signs a contradictory receipt with the new key. The
  payload pair would verify under different `receipt_pk` values, so
  `ed25519_ok` against the current on-chain pubkey fails one of the
  pair. Defence: off-chain rotation-history audit.
- Operator under-counts bytes deterministically (signs `bytes=0`
  every time). There's no contradictory signature, so no slash.
  Defence: opener disputes via mismatched `settle_confirm`; OU
  remains escrowed; operator earns nothing.

**Slash split:** controlled by `slash_burn_bps` (default 9000, min
5000). Burn share goes to `treasury` + `burned`
([`main-v3.aml:209-210`](../../program/main-v3.aml)); bounty
(`BPS_DENOM - burn`) transfers to the slash submitter. Defaults:
90% burn, 10% bounty.

### `gov_slash_operator(circle)` — owner-only

Source: [`program/main-v3.aml:406-412`](../../program/main-v3.aml).

Skips the ed25519 check; otherwise identical mechanics. Reserved
for governance response to off-chain misbehavior the chain can't
witness (e.g. coordinated denial-of-service, attestation fraud).
Caller is restricted to `self.owner`, so the bounty effectively
funds the protocol treasury (the caller is the owner — same key as
governs `withdraw_program_treasury`). Adversarial: S4 (non-owner
reject); the positive case is ceremony-only.

## Earnings hash chain

The `circle_earnings_chain` is **tamper detection, not tamper
prevention**. Its job:

- Chain observers see the head (32-byte digest) but cannot derive
  per-session amounts or recipients without the off-chain receipt.
- Off-chain auditors holding the signed receipt sequence
  reconstruct `head_n = sha256(head_{n-1} ‖ sha256(blinding_n))`
  and verify the on-chain head matches.

**Threat surfaces and defenses:**

1. **Operator omits a settle from their off-chain receipt log**:
   replay diverges immediately from `head_1` onward. Auditor
   detects.
2. **Operator inserts a fictitious settle**: same — replay diverges.
3. **Operator reorders settles**: same — order matters in the hash
   chain.
4. **Operator presents two different chains to two different
   auditors**: detectable by comparing audit reports (the on-chain
   head is canonical).
5. **Operator burns the entire receipt log**: head is opaque, but
   without receipts the operator cannot prove they earned the
   plaintext `circle_earnings_total` — which is the gate
   `claim_earnings` enforces. So the receipts are economically
   self-preserving for the operator.

The hash chain is **swap-ready for HFHE**: when Octra ships working
`fhe_*` host calls, `settle_confirm` gains a parallel ciphertext
branch and `claim_earnings` gains an optional zero-knowledge proof
arg. The plaintext total stays as the authoritative gate so a
ciphertext-only failure can't lock funds. See
[`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md) §5.2.

## Out-of-scope surfaces

- Operator binary integrity (host compromise, kernel attacks). See
  [`../security/threat-model-v3.md`](../security/threat-model-v3.md) §7.
- Validator-level censorship of slash submissions. Mitigation is
  multi-RPC failover, tracked in
  [`../security-roadmap.md`](../security-roadmap.md).
- Front-running of `claim_earnings` or `withdraw_program_treasury`.
  Both are scoped to `caller`; an attacker can't redirect the
  transfer target.
- Side-channel leakage from event timing
  (`SettleConfirmed`/`EarningsClaimed` timestamps reveal session
  activity to chain observers — this is inherent to a public chain;
  v3's `circle_earnings_chain` blinds the amounts but not the
  cadence).

## Auditor checklist

When reviewing a v3 deploy, verify on-chain:

- [ ] `owner` is the documented multisig (`get_circle_owner` substitute:
  chain RPC `octra_program_owner`).
- [ ] `paused == 0` for normal operation.
- [ ] `min_circle_stake >= 100_000_000` (the floor `set_params` enforces).
- [ ] `slash_burn_bps >= 5000`; `slash_burn_bps + slash_bounty_bps == 10000`.
- [ ] `protocol_fee_bps <= 200`.
- [ ] `unbond_grace_epochs >= 1000`.

And off-chain:

- [ ] Every operator's circle hosts `state-root.json` whose
  canonical sha256 hex matches `get_circle_state_root(circle)`.
- [ ] Every tailnet's owner-circle hosts `tailnet-{id}/members.json`
  whose canonical sha256 hex matches
  `get_tailnet_members_root(tid)`.
- [ ] Replaying each operator's receipt sequence reconstructs
  `get_earnings_chain(circle)`.
- [ ] All `OperatorSlashed` events have a matching off-chain
  governance attestation under `oct://<gov_circle>/slashed/...`
  (see
  [`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md) §3.3).
