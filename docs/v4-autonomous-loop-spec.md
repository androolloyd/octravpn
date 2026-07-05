# v4 Autonomous Money Loop — Unified Implementation Spec

> Produced by a 5-way design fan-out (client state machine · ChainTxQueue ·
> claim scheduler · refund watcher · vault lifecycle) + synthesis, grounded
> against the current tree. This is the build-ordered plan to make v4 relay
> settlement the settlement-of-record (`[v3.relay]` default-on).

Grounded against current tree: `settler.rs::settle_active` already arms when
`receipt_posted && client.relay_config().enabled` (in-memory, non-durable);
`relay_settlement.rs::submit_relay_claim_from_vault` does
`get`→status-check→`ctx.nonce()`→`submit_signed_tx` inline; `receipt_vault.rs` is
single-record `OCRV1`, `by_session: BTreeMap<SessionId, SignedReceipt>`, no
enumeration/lifecycle; `hub/spawn.rs:369` spawns `run_sweeper`.

---

## PART A — END STATE TO SHIP FIRST (the milestone)

**Target milestone = P0-1 "real client arm on devnet," standing on the two
foundations it needs to be crash-safe.** Bundles steps 1, 2, 5 (ChainTxQueue +
vault-terminal-states minimally + client state machine). It is the smallest
slice that lets `docker/devnet/v4-relay-e2e.sh` reach `RELAY_CLAIMED` **without a
`cast arm_relay` fallback**, driven by the real Rust client, and survive a client
kill between POST-ACK and arm.

"Done" for the first milestone:
1. **Client arms durably.** `settle_active` and `connect_v3` disconnect route
   through one driver `settle_state::arm_if_countersigned`. The arm is broadcast
   **iff** the durable `settle_state.bin` floor for that session `==
   Countersigned(2)`, written only on `post_countersigned_receipt` → `Ok`. No arm
   without a prior operator vault-ACK.
2. **Crash recovery works.** Kill the client after POST-ACK, before arm → boot
   replay (`replay_pending` in `Client::new`) re-arms idempotently; the session
   still reaches `RELAY_CLAIMED`. Kill before ACK → floor ≤ `Proposed(1)` →
   falls back to `settle_confirm`, never arms.
3. **Nonce is single-owner.** The client arm submission goes through the shared
   `ChainTxQueue`; re-arm after crash is nonce-deduped.
4. **The e2e proves it** — drop the cast-arm fallback; a real client arm + a
   kill/restart interleave produce `RELAY_ARMED`, then the operator claim tail
   reaches `RELAY_CLAIMED`. A second variant reaches it via the explicit
   `octravpn-client settle arm <sid>` CLI on a Countersigned-not-armed session.

---

## PART B — STRICT BUILD ORDER

1. **`ChainTxQueue` core actor** (foundation) — `crates/octravpn-core/src/chain_tx_queue.rs`. Single nonce-owner; `submit(unsigned_call)` overwrites the placeholder nonce, signs, submits; `+1` on Ok, `next=None` reconcile on nonce error, same-nonce retry on transient. Reuses `rpc::next_nonce`. Tests: 100 concurrent submits → contiguous nonces; nonce-err→refetch; transient→same nonce; cold `{68}`→`69`.
2. **Vault v2: terminal states + enumeration + tagged codec** (foundation) — `receipt_vault.rs` `OCRV2` framing, `LifecycleState{Proposed,Armed{deadline,settlement_hash},ClaimSubmitted{tx},Claimed{tx},Refunded{tx},Expired}`, `by_session: BTreeMap<SessionId,SessionEntry>`, `mark_*`/`armed_unclaimed`/`entries`, compaction, OCRV1→V2 migration, ARMED-freeze + seq-floor fold rules. New errors `ReceiptFrozen/IllegalTransition/ArmedHashMismatch`. 12th fuzz target `fuzz_vault_record_decode`.
3. **Reroute node operator submitters through `ChainTxQueue`** — `chain_v3.rs` `submit_call` shim + `tx_queue: Option<Handle>`; build the queue once at boot from the sealed operator keypair; reroute v3_boot/circle_update/v3_cli. Closes the nonce race before any long-lived submitter.
4. **Reroute client submitters through the shared queue** — client `chain_v3.rs` `submit_call`; `Client` builds one handle, clones into every ctx. Makes step 5's re-arm idempotency real.
5. **P0-1 client settlement state machine** (**milestone commit**) — `settle_state.rs` durable ladder `Proposed(1)→Countersigned(2)→ArmSubmitted(3)→ArmConfirmed(4)`; three entry points (tunnel-shutdown hook, `octravpn-client settle arm <sid>`, boot replay); receipt-ACK→arm happens-before. Split `submit_arm_relay` into `build_arm_params` + thin `submit_arm`. Route `connect_v3` disconnect through the driver when relay enabled. `[v3.relay].state_dir` config. **Devnet e2e = the Part A diff.**
6. **P0-2 autonomous claim scheduler** — `relay_claimer.rs` boot-spawned actor (mirrors `run_sweeper`); scans vault for armed-unclaimed, claims when quiescent and `epoch ≤ deadline-margin`; write-ahead `mark_claim_submitted` before submit; idempotent on restart. `ControlRelayCfg` gains `auto_claim/claim_scan_period_secs/claim_margin_epochs/quiescent_ticks/...` clamped at load.
7. **Vault-lifecycle wiring into the claim path** — write-ahead-before-broadcast fully realized; `ArmedHashMismatch` aborts a claim rather than revealing a wrong preimage; discovery sub-pass promotes `Proposed` entries by polling chain status.
8. **P0-3 client refund watcher + node relay_sweep** (default-on gate) — client auto-refund at `D+k_r`; node `relay_sweep` at `D+G+k_s`. `relay_sweep_call` + wire test. Non-overlap margins clamped. Devnet: operator-no-show→refund; client-offline→sweep; claim-at-`D-1`→watcher never refunds.
9. **Formal models + flip default-on** — `RelaySettlement.tla` (claim-XOR-refund, window non-overlap), `relay_receipt_ack.spthy` (ACK-precedes-arm), Kani on the epoch-gate. Flip defaults **only after** step 6+8 e2e + the models are green.

---

## PART C — SHARED INVARIANTS

| # | Invariant | Enforced at | Proven by |
|---|---|---|---|
| I1 | **Receipt-ACK → arm happens-before.** No `arm_relay` unless durable floor `== Countersigned(2)`, written only on POST→Ok (node returns `accepted:true` only after `receipt_vault.put` fsyncs). | `settle_state::arm_if_countersigned`; `post_receipt` handler. | Step 5 unit + crash e2e + Tamarin. |
| I2 | **Claim XOR refund.** `relay_claim` needs `epoch < D`, `relay_refund` needs `epoch ≥ D` (AML). Both off-chain submitters re-read fresh `RELAY_ARMED` pre-submit. | main-v4.aml; relay_settlement + refund_watcher. | Step 8 non-overlap e2e + TLA+. |
| I3 | **Claim/refund/sweep window non-overlap.** `(-∞,D-k_c] / [D+k_r,∞) / [D+G+k_s,∞)`, quiet zone `(D-k_c, D+k_r)`; margins clamped `[1,5]`, `RELAY_EXPIRY_MIN=10`. | config `resolve()`/`clamped()` at load. | clamp tables + TLA+. |
| I4 | **Nonce single-owner.** One `ChainTxQueue` per wallet; `+1` only on Ok; nonce-err→reconcile. All submissions via `submit_call`. | `chain_tx_queue::process`. | Step 1 concurrency unit + proptest. |
| I5 | **Vault seq-monotonicity + ARMED-freeze.** Stale lower-seq never becomes the money receipt; once `Armed`, higher-seq `put` rejected so the revealed preimage always hashes to on-chain `H`. | `receipt_vault` fold rules. | Step 2 unit + proptest + crash-injection. |
| I6 | **Write-ahead-before-broadcast.** Every durable record fsyncs before the dependent chain broadcast. | settle_state; relay_settlement; refund_watcher. | Steps 5/7/8 crash-injection. |

---

## PART D — RECONCILED CONFLICTS & OPEN DECISIONS

**Resolved:** (1) ChainTxQueue lives in **core**, not node (both crates need
byte-identical mock-testable logic; per-crate ctx keeps only `build_*_call` +
a thin `submit_call`). (2) `net` durability: `arm_net.bin` now, fold into vault
`Armed{}` later. (3) One `submit(unsigned_call: Value)` interface (queue
overwrites the placeholder nonce). (4) `ControlRelayCfg` field ownership split
across steps 6/8; `resolve()`/clamp lives once. (5) `connect_v3` is the real v4
path — step 5 routes its disconnect through the driver (milestone-blocking).

**Open — need a human call:**
- **D1 — shadow-mode / escrow double-encumbrance.** Run any dual-path (arm *and*
  settle_confirm) before default-on, or straight arm-xor-confirm? *Recommend
  straight xor; if shadow, arm-only-observe (no second on-chain effect).*
- **D2 — `force_claim_at_margin` default** at default-on (capture revenue vs
  paranoid). *Human call.*
- **D3 — `is_nonce_error` string set.** Devnet's confirmed reject is
  `octra_submit error 102: invalid nonce`; broaden with more captured strings
  before relying on reconcile in prod.
- **D4 — `state_dir` cross-identity collision.** *Recommend keying the durable
  files by wallet address, or require explicit `state_dir` for multi-identity
  hosts.*

---

## PART E — PROOF PLAN

- **Unit:** queue nonce sequencing (1); vault fold/ARMED-freeze/migration (2);
  state ladder + reconstruction (5); claim gate + idempotency (6); margin clamps
  + refund gate + `relay_sweep_call` wire shape (8).
- **Proptest:** queue random interleavings → contiguous nonces (1); vault
  rank-monotonic replay → identical `(receipt,state)` (2); intent-journal random
  crash → exactly-once refund (8).
- **Crash-injection** (CrashPoint-style from `compact.rs`): vault mid-compaction
  (2); write-ahead reorder in claim/refund (7,8).
- **Fuzz:** `fuzz_vault_record_decode` total, `payload_len` bounded (2).
- **Kani:** claimer epoch-gate arithmetic never claims at/after `D` (9).
- **TLA+ `RelaySettlement.tla`:** claim-XOR-refund + window non-overlap
  exhaustive over margin/epoch (9).
- **Tamarin `relay_receipt_ack.spthy`:** operator cannot be asked to claim
  without a prior durable receipt ACK — no arm without ACK (9).
- **Devnet e2e:** milestone arm-with-crash-recovery (5); autonomous claim, no CLI
  (6); refund + sweep + non-overlap (8); full default-on smoke (9).

Foundations (1–2) unblock everything; the first shippable milestone is **step 5
with the cast-arm fallback deleted from the e2e**. Default-on (9) flips only
after the refund/sweep e2e and the TLA+/Tamarin models are green.
