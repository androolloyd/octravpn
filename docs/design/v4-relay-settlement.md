# v4 Relay-Settlement — the AML fallback that pays operators when the client goes dark

**Status:** DESIGN DRAFT (P0.3). Nothing here is wired. Companion AML
draft: [`program/main-v4-relay.draft.aml`](../../program/main-v4-relay.draft.aml).

**Scope:** close the single biggest v3 settlement hole using only
chain-side primitives that are already PROVEN on devnet (`sha256()`,
`map[uint]uint`, `transfer()`, `payable`/`value`, `nonreentrant`). This
is deliberately the **AML fallback rail** — it needs **no native
`circle_call` / `circle_outbox` execution**, which is unconfirmed on
devnet (see [§9](#9-relationship-to-the-native-circle_outbox-rail-p21)).

---

## 1. The hole

v3 settles a session in two txs (`program/main-v3.aml`):

1. `settle_claim(session_id, bytes_used)` — the **operator** records the
   metered byte count (`program/main-v3.aml:513`).
2. `settle_confirm(session_id, bytes_used, net, settle_blinding)` — the
   **client** finalises payment (`program/main-v3.aml:549`).

Step 2 is gated at **`program/main-v3.aml:553`**:

```
require(self.session_opener[session_id] == caller, "only opener can confirm")
```

Settlement is therefore **client-driven and terminal only when the
client submits it.** The failure mode:

- The client crashes / drops its link / is killed / griefs after the
  session and never submits `settle_confirm`.
- A fully valid, **dual-signed** receipt already exists — the client's
  settler builds it and self-verifies it
  (`crates/octravpn-client/src/settler.rs:80-90`) — but it is **stashed
  locally** and the chain never sees the client's countersignature.
- After `session_grace_epochs * sweep_grace_multiplier`, anyone calls
  `sweep_expired_session` (`program/main-v3.aml:618`) and the deposit is
  refunded to the **tailnet treasury**. The operator, who served the
  traffic, is paid **0**.

The countersignature exists; the chain just never learns it. That is the
gap this rail closes.

---

## 2. Design in one line

Add an **operator-driven, unilateral** settlement path gated by a
**sha256 preimage reveal** (an HTLC-shaped hashlock). The client commits
`H = sha256(preimage)` on chain while it is still online; the operator
later reveals `preimage` to pull payment with **no further client tx**.
The `preimage` is the canonical serialization of the dual-signed
receipt, so revealing it is self-authorising (the client's signature is
inside it).

`sha256()` is the only new chain primitive, and it is already proven on
devnet at **`program/main-v3.aml:590`** (`let bh = sha256(settle_blinding)`).

---

## 3. State machine

Session status extends the v3 enum (`program/main-v3.aml:42-44`). The new
values live in a **distinct numeric range (3-5)** so every v3
settle/sweep path — each of which `require(status == SESSION_OPEN)` —
locks out automatically once a session is armed. No double-spend between
the two rails is possible.

```
                      arm_relay / open_relay_session
   SESSION_OPEN (0)  ───────────────────────────────►  SESSION_RELAY_ARMED (3)
        │                                                   │        │
        │ v3 settle_confirm / claim_no_show / sweep         │        │
        ▼                                                   │        │
   SETTLED(1) / REFUNDED(2)          relay_claim(preimage)  │        │ relay_refund  (epoch >= deadline)
   (v3 paths, now mutually exclusive │  (epoch < deadline)  │        │ relay_sweep   (epoch >= deadline + grace)
    with the relay lane)             ▼                      ▼        ▼
                            RELAY_CLAIMED(4)         RELAY_REFUNDED(5)
```

| Transition | Caller | Guard | Effect |
|---|---|---|---|
| `arm_relay` | opener (client) | `status==OPEN`, operator active | commit `(H, net, deadline)`, `status→ARMED` |
| `open_relay_session` | opener (client) | tailnet solvent, operator active | escrow deposit + commit in one tx, `status→ARMED` |
| `relay_claim` | operator (circle owner) | `status==ARMED`, `epoch<deadline`, `sha256(preimage)==H` | credit operator `net`, refund surplus, `status→CLAIMED` |
| `relay_refund` | opener (client) | `status==ARMED`, `epoch>=deadline` | refund deposit to tailnet, `status→REFUNDED` |
| `relay_sweep` | anyone | `status==ARMED`, `epoch>=deadline+grace` | bounty to caller, rest to tailnet, `status→REFUNDED` |

Two arm entry points, by design:

- **`arm_relay`** (general / metered): promote an existing v3
  `SESSION_OPEN` session into the relay lane once the final dual-signed
  receipt is agreed. The arm can fire the instant that receipt exists —
  **decoupled from tunnel teardown**. This is the recommended primary
  path.
- **`open_relay_session`** (pre-quoted): open straight into `ARMED`,
  pulling the deposit from the tailnet treasury like `open_session`
  (`program/main-v3.aml:486`). Collapses the client's **entire** on-chain
  liveness requirement to a single tx at session start.

---

## 4. The preimage and `SignedReceipt::settlement_hash()`

### 4.1 What to add in `crates/octravpn-core/src/receipt.rs`

`SignedReceipt` already has `signing_payload()`
(`receipt.rs:218-233`) — a 32-byte sha256 over the **metering fields
only** (`context`, `session_id`, `seq`, `bytes_used`, `blind`). It
deliberately **excludes the signatures** (`receipt.rs:168` — the shadow
blob is likewise excluded).

The hashlock needs the opposite property: the preimage must be
**unforgeable without both signatures**, so that possessing it proves
the client actually countersigned. Add two methods (draft, not wired):

```rust
impl SignedReceipt {
    /// Canonical settlement PREIMAGE — a deterministic, domain-tagged
    /// STRING that binds the metering payload AND both signatures. This
    /// is the exact string the operator reveals to the AML
    /// `relay_claim` gate; the client commits its sha256 at arm time.
    ///
    /// Distinct from `signing_payload()` (metering only, no sigs). The
    /// signatures MUST be inside the preimage: that is what makes
    /// holding the preimage equivalent to holding a client-countersigned
    /// receipt.
    ///
    /// Encoding (length-prefixed so no field-boundary ambiguity):
    ///   b"octravpn-settle-v1|"                       (domain tag)
    ///   || signing_payload()            (32 B)       (folds metering + context)
    ///   || client_pubkey.0              (32 B)
    ///   || client_sig.0                 (64 B)
    ///   || node_pubkey.0                (32 B)
    ///   || node_sig.0                   (64 B)
    /// then base64 (std, padded) the whole buffer to a printable ASCII
    /// string. Total ~ 300 B raw -> ~400 chars b64 (well under the AML
    /// 4 KiB string cap; and relay_claim only HASHES it, never stores it
    /// in a map).
    pub fn settlement_preimage(&self) -> String { /* ... */ }

    /// 64-char lowercase-hex sha256 of `settlement_preimage()` — the
    /// on-chain commitment `H`. MUST equal the AML's
    /// `sha256(preimage)` char-for-char:
    ///   settlement_hash() == hex(sha256(settlement_preimage().as_bytes()))
    pub fn settlement_hash(&self) -> String { /* ... */ }
}
```

### 4.2 Why the AML equality holds

Per the AML `bytes`/string semantics (verified; see the wire-format
memory note and `program/main-v3.aml:7-15`):

- A `string`/`bytes` param is an **undecoded JSON string**; `len()` is
  its char count.
- `sha256(s)` hashes the **raw UTF-8 bytes of the string `s`** and
  returns a **64-char lowercase-hex** digest.

So if the operator passes `settlement_preimage()` (a base64 ASCII
string) verbatim as the `preimage` param, then in-AML
`sha256(preimage)` == `hex(sha256(preimage_ascii_bytes))` ==
`settlement_hash()`. The client commits `settlement_hash()`; the gate is
a plain string equality. **This byte-for-byte agreement is the load-
bearing correctness property** and must be pinned by a cross-impl test
(a Rust `settlement_hash()` vs a reference AML-side sha256 of the same
bytes, mirroring `receipt.rs` `canonical_payload_helper_matches_...`).

### 4.3 Threat notes on the preimage

- **Binds both sigs** → the operator cannot fabricate the preimage from
  the single-signed `ProposedReceipt` it already holds
  (`crates/octravpn-node/src/control/handlers/receipt.rs:188` builds
  `ProposedReceipt` with only `node_sig`). It needs the client's
  countersignature, which only arrives via the handback route (§6).
- **`context` is folded in** (via `signing_payload()`), so a preimage
  from program/chain/circle A cannot be replayed to settle B — inherits
  the v1.2 cross-domain rejection already tested in
  `receipt.rs:452-530`.
- The AML does **not** verify ed25519 or parse the receipt. It checks
  only `sha256(preimage) == H`. Metering integrity is enforced
  **off-chain** (§8).

---

## 5. Receipt-vault store (NEW; NOT a `receipt_journal` extension)

The operator must persist the client-posted dual-signed receipt so it
can `relay_claim` even across a restart. This needs a **new store** —
**not** an extension of `receipt_journal`.

**Why not `receipt_journal`:** that journal is a **fixed-width 44-byte
record** — `[session_id:32][seq:u64 BE][crc32:u32 BE]`
(`crates/octravpn-core/src/receipt_journal/codec.rs:17-27`). It stores a
single monotonic `u64` floor per session and nothing else. A
`SignedReceipt` is **variable-length JSON** (receipt + 2 pubkeys + 2
sigs + optional shadow blob). Stuffing it into the journal is a format
change, not a field add — it would break the append-only replay
(`codec.rs:35-71`) and the compaction/eviction machinery
(`receipt_journal/{compact,eviction}.rs`). Keep the journal exactly as
is (it still governs receipt-seq monotonicity per P1-8/9).

**New module: `crates/octravpn-core/src/receipt_vault.rs`** (draft).
Append-only, length-prefixed, one entry per posted receipt:

```
magic:  b"OCRV1\0\0\0"                       (8 B, distinct from OCRJ2)
record: [session_id:32]
        [len:u32 BE]                          (byte length of the JSON)
        [json bytes: serde_json(SignedReceipt)]
        [crc32:u32 BE over session_id||len||json]
```

- **fsync before ACK** — same durability discipline the journal uses
  (`receipt.rs` handler comment at `handlers/receipt.rs:76-83`): only
  ACK the POST once the receipt is on disk, so a crash never loses a
  receipt the client believes was accepted.
- **Replay:** on open, fold to the latest well-formed record per
  `session_id` (highest `receipt.seq` wins — receipts are monotonic,
  `receipt.rs:322`). Torn tail dropped silently; bad CRC surfaces as a
  corruption error (mirror `codec.rs:35-71`).
- **Lookup:** `get(session_id) -> Option<SignedReceipt>` gives
  `relay_claim`'s caller the exact preimage source.
- **Bounded growth:** cap/rotate by count or age; a claimed or
  refunded session's entry can be pruned once the on-chain status is
  terminal (`RELAY_CLAIMED`/`RELAY_REFUNDED`).

The vault lives on the **operator** side (it is what lets the operator
settle unilaterally). The client keeps its own copy too (it already
stashes `signed` in `settler.rs`); the vault is the operator's durable
mirror.

---

## 6. New control route: `POST /session/:id/receipt`

The client must hand the countersigned receipt back to the operator.
Today the control plane is read-only for receipts: the client GETs the
proposal from `GET /session/:id`
(`crates/octravpn-node/src/control/handlers/receipt.rs::get_state`) and
never sends anything back.

### 6.1 Route (in `crates/octravpn-node/src/control/router.rs`)

Add one line to `limited_routes`
(`router.rs:39-55`), next to the existing `.route("/session/:id", get(...))`:

```rust
.route("/session/:id/receipt", post(handlers::receipt::post_receipt))
```

Path shape matches `octravpn_core::control::path_state`
(`control.rs:23-24` → `/session/{hex}`); the new sub-path is
`/session/{hex}/receipt`. Add a `path_receipt()` + `receipt_url()`
helper next to `session_state_url` (`control.rs:37-40`).

### 6.2 Handler (new `post_receipt` in `handlers/receipt.rs`)

```
POST /session/:id/receipt
body: SignedReceipt (JSON)

1. Parse :id (hex) -> SessionId; 400 on bad id (mirror get_state:66).
2. Deserialize SignedReceipt; 400 on malformed body.
3. sr.verify()            -> reject 401 on BadClientSig / BadNodeSig
   (receipt.rs:313-320). Confirms BOTH sigs.
4. Context match: sr.receipt.context == *s.receipt_context, else 409
   (same binder guard the client applies in settler.rs:46-59).
5. Session-id match: sr.receipt.session_id == :id, else 400.
6. node_sig is OURS: sr.node_pubkey == s.node_kp.public, else 401
   (we only vault receipts we actually co-signed).
7. Monotonicity: sr.receipt.seq must be >= the vault's current seq for
   this session; accept the highest. (Ties to receipt_journal floor for
   sanity, but the vault is the source of truth for the blob.)
8. Persist to receipt_vault (fsync), THEN 200 { accepted: true,
   settlement_hash: sr.settlement_hash() } so the client can assert the
   operator's H matches what it is about to commit on chain.
9. Optional: publish a `receipt_countersigned` SSE event + audit row,
   mirroring the get_state emission (handlers/receipt.rs:199-222).
```

The response echoing `settlement_hash()` lets the client do a
final **pre-arm cross-check**: it only submits `arm_relay(H, …)` if the
operator agrees on `H`. If they disagree, neither party is bound and the
client falls back to plain v3 settle.

---

## 7. Client change: `settler.rs` posts the countersigned receipt + arms

Reference: `crates/octravpn-client/src/settler.rs::settle_active`
(`settler.rs:34-93`). Today it builds `signed` (dual-signed,
`settler.rs:80-89`), self-verifies (`settler.rs:90`), then calls
`submit_settle_confirm` (v3 path, `settler.rs:92`).

The v4 fallback inserts two steps between build and finalize:

```rust
// after: signed.verify().context("dual-sig self-verify")?;   (settler.rs:90)

// 1. Hand the countersigned receipt back to the operator so it can
//    settle unilaterally if we go dark. Idempotent + retryable.
post_countersigned_receipt(client, &exit.validator.endpoint, &active.session_id, &signed)
    .await
    .context("POST /session/:id/receipt")?;

// 2. Commit the hashlock on chain (the LAST client-liveness point).
let h = signed.settlement_hash();          // 64-hex
let net = /* pre-agreed credit for signed.receipt.bytes_used */;
submit_arm_relay(client, &active, &h, net, RELAY_EXPIRY_EPOCHS).await?;
```

`submit_arm_relay` mirrors `submit_settle_confirm`
(`settler.rs:126-156`): build the `contract_call` envelope for
`arm_relay(session_id, settlement_hash, net, relay_expiry_epochs)` via
the shared builder, sign with `sign_call`, submit. Wire shape belongs in
`octravpn_core::v3_calls` (add `ARM_RELAY` / `RELAY_CLAIM` /
`RELAY_REFUND` to `v3_calls.rs::method`, `v3_calls.rs:34-73`, plus
`*_call` methods) and delegated from both
`chain_v3.rs::ChainCtxV3` (node, `crates/octravpn-node/src/chain_v3.rs`)
and the client's `chain_v3.rs` — exactly the pattern the existing
`build_settle_confirm_call` follows (`chain_v3.rs:551-563`).

**Order matters:** POST the receipt **before** arming. If the arm lands
but the operator never got the receipt, the deposit just sits until
`relay_refund` — no loss, but no settlement either. Posting first
guarantees the operator can claim the moment the arm confirms. The POST
is idempotent (vault keeps the highest-seq receipt), so retry on
transient failure is safe.

### 7.1 Operator claim path (node side)

A small operator loop (or a manual `relay claim` CLI subcommand) watches
`RelaySessionArmed` events for its circle, loads the matching receipt
from the vault (`receipt_vault.get(session_id)`), and submits
`relay_claim(session_id, sr.settlement_preimage())`. Reuse the
`ChainCtxV3` submit plumbing (`chain_v3.rs:705-722`). Claim before
`relay_deadline`; the operator's local clock plus the on-chain `epoch`
give ample margin (default 200 epochs, §RELAY_EXPIRY_DEFAULT_EPOCHS).

---

## 8. Security model — what each layer enforces

| Property | Enforced by | Where |
|---|---|---|
| Operator can pull **at most** `net` | AML `require(net <= dep)` at arm; cap in claim | `main-v4-relay.draft.aml` `write_relay_arm` / `relay_claim` |
| Operator can pull **only** by revealing the client-agreed receipt | AML `sha256(preimage) == H` | `relay_claim` gate |
| Preimage unforgeable without the client's countersignature | preimage binds `client_sig` | `receipt.rs::settlement_preimage` (§4) |
| `net` matches metered bytes | **off-chain**: operator refuses to vault/claim a receipt whose embedded `net` disagrees with its meter; client only commits `H` for a receipt it countersigned | `post_receipt` handler + settler |
| Operator's exposure bounded mid-session | incremental receipts; operator stops routing when the client stops countersigning (unchanged from v3) | `handlers/receipt.rs::get_state` streaming |
| No double-settlement across rails | status leaves `SESSION_OPEN` on arm; v3 paths `require(status==OPEN)` | status enum ranges (§3) |
| Client recovers on operator no-show | `relay_refund` after deadline | `relay_refund` |
| Funds never permanently stuck | `relay_sweep` after deadline + grace | `relay_sweep` |
| Cross-program/chain/circle replay rejected | `context` folded into preimage | `signing_payload()` binders (`receipt.rs:218-233`) |

**Honest limitation.** The chain verifies only the sha256 equality; it
does **not** parse the receipt or check ed25519. If a client commits `H`
for a low-`net` receipt, the operator's defense is the same streaming
discipline v3 already relies on: it does not deliver the final service
increment / does not treat the session as settled until it holds a
receipt whose `net` it agrees with. The rail converts "client must
submit the paying tx" (v3, unrecoverable if skipped) into "client must
authorize once, operator collects" — a strictly better incentive
alignment, not a trustless meter.

---

## 9. Relationship to the native `circle_outbox` rail (P2.1)

Octra's webcli exposes `circle_outbox_open`, `ingress_commit`,
`relay_claim`, `relay_cancel`, and `circle_call` sub-methods
(`bind_object_native`, `apply_object_transition_native`, …). A future
**native** relay-settlement rail would run settlement *inside* the
operator circle as a circle-call, with the outbox carrying the payout —
richer and more private than this AML escrow.

**That rail is UNCONFIRMED on devnet.** Native `circle_call` + relay-op
execution has never been observed to settle; deploy_circle persists
`code_b64` but `contract_call` into a circle returns "bytecode not
found" (circles are passive storage today, per the circles-not-yet-
executable finding). Probes to determine whether these ops execute are
separate work and must fail loudly rather than assume success.

**This v4 AML fallback deliberately depends on none of it.** It uses
only `sha256()` + `map[uint]uint` + `transfer()` + `payable`/`value` +
`nonreentrant`, all proven live in `program/main-v3.aml`. It is the
ship-now rail; the native `circle_outbox` rail is the later, unproven
upgrade. When the native path is confirmed, `relay_claim`'s payout can
be re-homed onto the outbox with the off-chain handback (§6) and vault
(§5) unchanged.

---

## 10. Open questions for review

1. **`net` at arm time vs. cap-only.** The draft commits an exact `net`
   at arm and caps it against the deposit. Alternative: commit only `H`
   and let `relay_claim` pay the full deposit (simplest, but no partial
   refund). The draft chooses committed-`net` to preserve v3's
   surplus-refund-to-tailnet behavior.
2. **`open_relay_session` tailnet bounds check** is stubbed (the
   `tailnet_count` field is elided from the additive fragment). The
   merge into `main-v3.aml` must restore
   `require(tailnet_id < self.tailnet_count, ...)`. Called out in the
   draft's trailing comment rather than silently faked.
3. **Preimage size vs. AML 4 KiB string cap.** A `SignedReceipt`
   base64 preimage is ~400 chars — comfortably under the 4096-char map
   cap. `relay_claim` only hashes it (never stores it in a map), so the
   cap is not on the hot path; still worth a proptest bound if the
   shadow-blob fields are ever folded in.
4. **Deadline units.** Draft uses `epoch` deltas (consistent with v3
   grace fields). Confirm epoch granularity gives the operator a
   comfortable claim window in wall-clock terms on devnet/mainnet.
5. **SSE/audit surface** for `receipt_countersigned` and
   `relay_claim` — mirror the existing `receipt_signed` emission
   (`handlers/receipt.rs:199-222`) so the operator's forensics path sees
   the full lifecycle.
