# AML Gap Analysis: OctraVPN vs. Confirmed Octra Primitives

**Date**: 2026-05-12, refreshed 2026-05-14. **Octra status**: live
mainnet, v3.0.0-irmin, ~10s epochs, $44.5M mcap. **OctraVPN status**:
AML compiles against `octra_compileAml` and the cryptographic
equivocation slash now lives in-program (see §3 and `program/main.aml`).

This document audits every host call our `program/main.aml` makes
against the confirmed Octra AML surface (from
`docs/octra-research.md §6`) and specifies the migration path for
each gap. The goal is a fully-audited, formally-verifiable AML that
uses only primitives Octra actually exposes today.

## 0. 2026-05-14 dev-team announcement (status update)

The Octra dev team announced that the AML compiler exposes:

- `ed25519_ok(pk, msg, sig) -> bool` — **confirmed**. Replaces our
  previously-deferred `verify_ed25519`. Used in
  `program/main.aml::slash_double_sign` and (logically) anywhere else
  we previously had to defer cryptographic checks.
- `digest_sha256(bytes) -> bytes` — **confirmed** as the canonical
  spelling. `sha256` is presumably an alias since the v1 AML still
  compiles using the bare `sha256(token_preimage)` form.
- `digest_keccak256(bytes) -> bytes` — **confirmed**. Not used by v1
  yet; available for Ethereum-bridge-style features.
- `current_tx_hash() -> bytes` — **confirmed**. Not used by v1 yet;
  potentially useful for replay-bounding nested calls.
- Native `bool` type — **confirmed** (entrypoint return types in
  `program/main.aml` already use it).

Reference deployment: `octBDvZSiTqdEBAyFSp79CHeoLMR9MzHugX9YkHtuQ57MRB`
(its AML is readable via `vm_contract` / `contract_source`).

This resolves the headline gap in this document (§2.2's
`verify_ed25519` row, §7's "stays off-chain for v1" decision, and
the deferred items in §10's table). The cryptographic equivocation
slash branch is now `program/main.aml::slash_double_sign`. The
`settle_claim`-internal equivocation slash (which detects two
on-chain claims) and the new off-chain dual-sig slash now run side
by side; both Lean and TLA proofs exercise both branches.

---

## 1. The headline

**Our AML cannot deploy to Octra mainnet as-is.** It calls 10+ host
helpers that are not present in the only public AML example
(`octra-labs/contract-examples/example_1.aml`) and not documented as
host functions. We've been compiling against our own mock — the real
Octra AML compiler will reject our program.

The good news: every functional requirement can be met with the
confirmed primitives, with two honest trade-offs (cryptographic
non-repudiation of receipts → economic ceiling enforcement;
cryptographic slashing → off-chain evidence + Octra-team escalation).

---

## 2. Host-call inventory

### 2.1 ✅ Confirmed in AML (use freely)

| Call                                             | Where we use it                                 |
| ------------------------------------------------ | ----------------------------------------------- |
| `require`, `assert`, `revert`                    | Throughout                                       |
| `transfer(addr, amount)`                         | `sweep_expired_session`, `submit_equivocation`, `finalize_unbond` |
| Builtins: `caller`, `origin`, `value`, `epoch`, `self_addr` | Throughout                              |
| `checkpoint() / commit() / rollback()`           | Not currently used — should adopt for CEI       |
| `concat`, `to_string`, `parse_ints`, `mget`      | Building blocks for our helper funcs (concat_receipt_v1, etc.) |
| `emit Event(...)`                                | All event emissions                              |
| **`fhe_load_pk(addr)`**                          | Need to adopt — load operator's HFHE pubkey      |
| **`fhe_deser(b64) / fhe_ser(ct)`**               | Need to adopt — for storing ciphertexts          |
| **`fhe_add(pk, a, b) / fhe_sub(pk, a, b)`**      | Need to adopt — replace Pedersen earnings ops    |
| **`fhe_add_const(pk, ct, k)`**                   | Need to adopt — for partial-known additions       |
| **`fhe_scale(pk, ct, k)`**                       | Need to adopt — replace `pedersen_mul_scalar_g`  |
| **`fhe_verify_zero(pk, ct, proof)`**             | Need to adopt — replace `pedersen_verify_eq`     |

### 2.2 ❌ NOT in confirmed AML surface — must replace

| Call                                                       | Where we use it                                        | Replacement                                                                                                                       |
| ---------------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `verify_ed25519(pk, msg, sig)`                             | `settle_session` (dual-sig); `submit_equivocation` (2x) | **Resolved 2026-05-14**: confirmed as `ed25519_ok(pk, msg, sig) -> bool`. Mainnet reference `octBDvZSiTqdEBAyFSp79CHeoLMR9MzHugX9YkHtuQ57MRB`. Cryptographic equivocation slash is live in `program/main.aml::slash_double_sign`. |
| `verify_ed25519_acct(addr, msg, sig)`                      | `redeem_join_token`                                    | Drop. Pre-auth tokens replaced by direct owner `add_member` calls (and hash-precommit `precommit_join_token` / `redeem_join_token`). The newly-confirmed `ed25519_ok` could revive a signed-token variant in v1.2 if a real product use surfaces. See §4. |
| `pedersen_add(a, b)`                                       | `settle_session` earnings credit                       | `fhe_add(pk_op, cur, new)` where `pk_op = fhe_load_pk(op_addr)`.                                                                  |
| `pedersen_mul_scalar_g(k)`                                 | `settle_session` earnings credit                       | `fhe_scale(pk_op, enc_one, k)` — or pre-stored `enc(1)` per pk.                                                                   |
| `pedersen_mul_scalar_h(k)`                                 | `settle_session` blind component                       | Not needed — HFHE doesn't use blinding factors the same way; ciphertext-randomness is baked in by fhe-encrypt.                    |
| `pedersen_zero()`                                          | `register_endpoint` ledger init                        | Use `fhe_deser(b64_zero_ct_per_pk)` — operator provides `enc_pk(0)` at register time.                                             |
| `pedersen_verify_eq(commit, val, blind)`                   | `claim_earnings`                                       | `fhe_verify_zero(pk, fhe_sub(earnings, fhe_encrypt(val)), proof)` — operator provides plaintext + zero-proof of the difference.   |
| `pedersen_verify_open(commit, val_bytes, blind)`           | `settle_session` route opening                         | Route commitments need a different scheme. See §5.                                                                                |
| `emit_private_transfer(stealth_output, amount)`            | `claim_earnings`                                       | Replace with two-step: AML `transfer(caller, amt)` → caller submits follow-up native `op_type="stealth"` tx for privacy. See §6.  |

### 2.3 ⚠ Probably AML-internal, verify with Octra team

| Call                  | Where                                  | Status (2026-05-14)                                                                   |
| --------------------- | -------------------------------------- | ------------------------------------------------------------------------------------- |
| `sha256(bytes)`       | id derivation; receipt msg              | **Confirmed** as `digest_sha256(bytes) -> bytes` (canonical name); the bare `sha256(...)` form in v1 still compiles via the live `octra_compileAml` RPC, so it's presumably an alias. |
| `digest_keccak256(b)` | (new) Ethereum-bridge / EVM compat     | **Confirmed 2026-05-14**. Not used by v1 yet.                                          |
| `current_tx_hash()`   | (new) replay-bounding nested calls     | **Confirmed 2026-05-14**. Not used by v1 yet.                                          |
| `addr_bytes(addr)`    | `pedersen_verify_open` route opening   | Likely AML-internal type conversion. Verify.                                          |
| `is_address(v)`       | `register_device`, `transfer_ownership` | Likely AML-internal. Verify.                                                          |
| `address_zero()`      | Null checks                            | Likely AML-internal. Verify.                                                          |
| `len(bytes_or_str)`   | Length checks throughout                | Standard. Verify.                                                                     |

### 2.4 🛠 Helper functions we call but never define

These are not host calls — they're helpers we expected the AML
standard library to provide. None of them are defined in `main.aml`.
We must either define them ourselves (using confirmed primitives) or
remove the call.

| Call                              | Defined? | Plan                                                                |
| --------------------------------- | -------- | ------------------------------------------------------------------- |
| `concat3_addr_int_int(a, b, c)`   | No       | Define inline using `concat` + `to_string`                          |
| `concat4_addr_int_int_bytes`      | No       | Same                                                                |
| `concat_join_token_v1(...)`       | No       | Same — but token verification removed (see §4), so this dies        |
| `concat_receipt_v1(...)`          | No       | Same — receipt verification removed (see §3), so this dies          |
| `set_member`, `get_member`        | No       | Replace with direct map access: `members[concat(tid, addr)] = 1`    |
| `set_tailnet_exit`, `get_tailnet_exit` | No   | Same                                                                |
| `blind_to_scalar(blind)`          | No       | Pedersen-specific; dies with the Pedersen rewrite                   |

---

## 3. Receipt verification: cryptographic → economic

**Current design**: `settle_session(..., client_sig, node_sig, route_open)`
verifies a dual-signed receipt. The Tamarin proof
`proofs/tamarin/octravpn.spthy` establishes receipt unforgeability
based on `verify_ed25519` in AML.

**Problem**: AML cannot verify Ed25519 signatures. The Tamarin claim
is meaningful but the AML implementation never could enforce it.

**Replacement**: **Validator-only settlement with economic ceiling.**

```aml
fn settle_session(
  session_id: bytes,
  bytes_used: int,
  blind: bytes,
  // dropped: seq, client_sig, node_sig, route_open
) {
  require(self.endpoints[caller].active != 0, "caller not active operator")
  let s = self.sessions[session_id]
  require(s.status == 0, "session not open")
  require(s.advertised_exit == caller, "not the session's exit operator")
  
  let pay = mul_div_safe(bytes_used, self.endpoints[caller].price_per_mb, 1)
  require(pay <= s.deposit, "claim exceeds escrow")
  // ... fee + earnings + refund as before, but now using fhe_add
}
```

**The trade-off, stated honestly**:
- Validator can claim ANY `bytes_used <= max_pay / price`. They can
  inflate but not exceed the client's deposit ceiling.
- Client's recourse: stop using a validator who routinely claims the
  full deposit regardless of service.
- Reputation system + free market on validator selection enforces honesty.
- This is the **same** integrity the existing Tailscale-DERP model
  has: clients trust DERP relays to report bandwidth honestly; market
  exit is the recourse.

**What gets formally verified**:
- ✓ Treasury non-negativity.
- ✓ `total_paid ≤ session.deposit` (state machine).
- ✓ Refund completeness.
- ✓ FHE earnings ledger invariants.
- ✗ "Bytes_used corresponds to actual service" — drops out of the
  AML threat model; documented as economic-trust.

**Multi-hop routing**: dropped from v1. Route commits (`route_commit`,
`route_open`, splits) all depended on `pedersen_verify_open` which
isn't in AML. Single-hop sessions only for v1.

---

## 4. Join tokens: removed

**Current design**: Owner mints a signed token; anyone with the token
calls `redeem_join_token(...)` which verifies `verify_ed25519_acct`.

**Problem**: AML can't verify signatures.

**Replacement**: Drop `redeem_join_token`. Owner adds members via
`add_member(tailnet_id, member)`, which is owner-signed at the
tx-validation layer (the tx's `from` field is the owner's address,
verified by Octra's native tx-signing). No in-AML signature check
needed.

**Trade-off**: Loses the off-chain "give my friend a token" UX. They
have to send their address; owner submits one tx.

Pre-auth tokens can return in v1.1 if Octra adds `verify_ed25519` to
AML.

---

## 5. Multi-hop route privacy: deferred

**Current design**: Pedersen-committed route, revealed at settle.
Hides which validators a client used until settlement, then becomes
public.

**Problem**: Pedersen ops aren't in AML.

**Replacement options for v1.1+**:

**5a. Encrypted route in `op_type="stealth"` blob**: Client wraps the
route in a native stealth tx; Octra runtime processes the encrypted
data; AML only sees the resolved (operator, payment) tuples post-
stealth. Requires Octra to extend `op_type` semantics for VPN routes.

**5b. Per-hop client-validator session with separate settle_session
calls**: Single-hop primitive, client opens N sessions for N hops,
each settled independently. Loses unlinkability (chain observers see
all the hops) but works today.

**5c. FHE-encrypted route**: Route as a vector of encrypted ints.
Settle decodes via fhe_verify_zero proofs. Feasible but complex.

**v1 decision**: Defer multi-hop entirely. Single-hop only. v1.1
revisits via 5a + Octra-team engagement.

---

## 6. Stealth payouts: two-step

**Current design**: `claim_earnings(amount, blind, stealth_output)`
verifies Pedersen + emits private transfer.

**Problem**: Pedersen + `emit_private_transfer` not in AML.

**Replacement**: **Two-step claim.**

```aml
fn claim_earnings(claimed_amount: int, proof: bytes) {
  let pk = fhe_load_pk(caller)
  let earnings = self.enc_earnings[caller]
  let claim_ct = fhe_encrypt(pk, claimed_amount)
  let delta = fhe_sub(pk, earnings, claim_ct)
  require(fhe_verify_zero(pk, delta, proof), "bad opening")
  self.enc_earnings[caller] = fhe_encrypt(pk, 0)
  transfer(caller, claimed_amount)
  emit EarningsClaimed(caller, claimed_amount)
}
```

The plaintext OU lands in the validator's wallet. **For stealth
privacy**, the validator immediately submits a native
`op_type="stealth"` tx paying themselves at a fresh address. That tx
uses Octra's native stealth-tx layer (range proofs, Pedersen,
zero-proofs), all of which work at native-tx level.

**Trade-off**: Two txs per claim instead of one. Marginal extra gas.
Privacy story is intact — the on-chain trail shows the validator's
public claim amount but the funds disappear into a stealth output in
the very next block.

---

## 7. Equivocation slashing: now on-chain (cryptographic)

**Resolved 2026-05-14.** AML's `ed25519_ok(pk, msg, sig) -> bool` is
confirmed, and the corresponding entrypoint
`slash_double_sign(operator_addr, session_id, payload_a, sig_a,
payload_b, sig_b)` is live in `program/main.aml`. The Lean and TLA
proofs cover the post-state shape (`endpointStake = 0`,
`endpointSlashed = true`, 90 % burn / 10 % bounty to the slasher).

### 7.1 Two complementary slash paths

| Path                                | Trigger                                                          | Catches                                                                                          |
| ----------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `settle_claim` in-AML equivocation | Two `settle_claim(sid, bytes_used)` calls from the same operator with different `bytes_used`. | Operator who tries to bill different amounts on chain.                                          |
| `slash_double_sign`                 | Two distinct signed payloads under the operator's `receipt_pubkey`. | Operator who signs two contradictory off-chain receipts (e.g. for the same `(session_id, seq)`). |

Both paths share the 90 / 10 split and mark `endpoint_slashed[op] = 1`
permanently (the `require(endpoint_slashed[op] == 0, "already
slashed")` gate makes the entrypoint idempotent post-slash).

### 7.2 Historical alternatives (no longer needed)

The pre-2026-05-14 plan had three options:

**7a. Off-chain slash escalation**: Anyone with evidence verifies it
locally (`octravpn slash-evidence verify` already works), publishes
the verified bundle, and escalates to the Octra team for
protocol-level action. **Superseded** by `slash_double_sign`.

**7b. Native-tx wrapper for slash evidence**: Octra adds an
`op_type="vpn_slash_evidence"` that the runtime verifies. AML sees a
boolean "slash succeeded" and burns the stake. **Superseded**.

**7c. Governance-only slash**: `gov_slash_operator(addr,
evidence_url)` is still in place as a backstop for cases without
cryptographic evidence (e.g. an operator refuses to serve traffic or
censors specific clients).

---

## 8. FHE earnings ledger: the new core

**State change**:

```aml
state {
  // ...
  enc_earnings: map[address]bytes        // FHE ciphertext bytes (was Pedersen point)
  op_pk: map[address]bytes               // operator's HFHE pubkey
}
```

**On `register_endpoint`**: operator provides their HFHE pubkey + a
ciphertext encoding `enc_pk(0)`.

```aml
fn register_endpoint(
  endpoint: string,
  ..., // existing params
  hfhe_pubkey: bytes,
  initial_enc_zero: bytes
) {
  // existing checks
  self.op_pk[caller] = hfhe_pubkey
  self.enc_earnings[caller] = initial_enc_zero  // operator pre-computes fhe_encrypt(pk, 0)
}
```

**On `settle_session`**: credit operator via FHE.

```aml
fn settle_session(session_id: bytes, bytes_used: int, blind_unused: bytes) {
  // ... validation
  let pk = self.op_pk[caller]
  let cur = fhe_deser(self.enc_earnings[caller])
  // Encode the pay as a constant ciphertext (cheap)
  let credit = fhe_add_const(pk, fhe_deser(self.zero_ct[pk_id]), pay)
  let new_earnings = fhe_add(pk, cur, credit)
  self.enc_earnings[caller] = fhe_ser(new_earnings)
}
```

**On `claim_earnings`**: open via `fhe_verify_zero`. See §6.

---

## 9. Migration plan

In order, each step independently testable:

1. **Audit confirmed list with Octra team**. Send them this doc;
   confirm `sha256`, `addr_bytes`, `is_address`, `address_zero`,
   `len`, and verify the FHE primitive signatures match.

2. **Rewrite `program/main.aml` against confirmed primitives only**.
   - Drop multi-hop routes from v1.
   - Drop dual-sig receipt verification; move to validator-only settle.
   - Drop pre-auth join tokens; use direct `add_member`.
   - Drop in-AML equivocation slashing; use governance-driven slash.
   - Migrate earnings ledger to FHE.
   - Migrate claim_earnings to two-step (FHE verify + plain transfer +
     client-side stealth follow-up).

3. **Update `program/interfaces/IOctraVPN.aml`** to match.

4. **Update mock-chain (`tests/mocks/src/lib.rs`)** to implement the
   new entrypoints faithfully.

5. **Replace property tests + AML fuzz** to cover the new state machine.

6. **Update formal proofs**:
   - TLA+: drop receipt-related invariants; add FHE-ledger
     invariants (additivity, zero-claim soundness).
   - Lean: drop `commitSettlement_sets_session`; add FHE-equivalent
     lemmas.
   - Tamarin: this is the big loss. Receipt unforgeability moves out
     of scope (lives at native-tx layer, not AML). Replace with
     "client-deposit ceiling is binding" theorem.

7. **Update docs**: `whitepaper.md` §1 threat model, §3 formal
   claims, §4 economic design; `economics.md` §10 adversarial
   scenarios; `security-roadmap.md` §2.4.

8. **Engage Octra team** with the concrete asks from §2.2 + §5 + §7:
   - `verify_ed25519` host call in AML.
   - Custom `op_type="vpn_*"` extensions for receipts + slash evidence.
   - Pre-stored ciphertext zero for cheap `fhe_encrypt(pk, 0)`.

9. **Compile + deploy against testnet** for the first time.

---

## 10. What this preserves of the original design

| Property                            | v1 keeps? | Verified by                                     |
| ----------------------------------- | --------- | ----------------------------------------------- |
| Encrypted operator earnings         | ✓         | FHE (Pedersen-equivalent, more expressive)      |
| Encrypted treasury aggregates       | ✓ (v1.1)  | FHE                                              |
| Stealth payouts                     | ✓         | Native-tx stealth (two-step from AML view)      |
| Operator bonding + governance slash | ✓         | AML state machine + governance gate             |
| Tailnet membership + ACL            | ✓         | AML state + off-chain ACL doc                   |
| Treasury accounting                 | ✓         | AML state, TLA+/Lean verified                   |
| **Single-hop sessions**             | ✓         | Validator-only settle, economic ceiling          |
| **Multi-hop privacy routing**       | ✗ → v1.1  | Needs Octra extension (§5)                       |
| **Dual-sig receipt integrity**      | ✓         | Off-chain dual-sig + on-chain `slash_double_sign` via `ed25519_ok` (confirmed 2026-05-14, see §0 / §7). |
| **In-AML equivocation slash**       | ✓         | `settle_claim` (on-chain dup) AND `slash_double_sign` (off-chain dup). See §7. |
| **Pre-auth join tokens**            | ✓ (hash)  | Hash-precommit pattern; signed-token variant possible in v1.2 via `ed25519_ok`. See §4. |
| **HMAC-chained audit log**          | ✓         | Off-chain operator log; on-chain ACL hash       |

---

## 11. Honest assessment of "formally verified"

What we can prove with the new design:

| Property                                                       | Tool      |
| -------------------------------------------------------------- | --------- |
| Treasury non-negativity                                        | TLA+      |
| Session settles or refunds (no stuck OU)                       | TLA+      |
| `total_paid ≤ session.deposit` (economic ceiling enforcement) | Lean      |
| Slashed operators cannot earn                                  | TLA+      |
| FHE earnings ledger is additive under settle                   | Lean (with FHE axioms) |
| `claim_earnings` requires valid `fhe_verify_zero` proof        | Lean      |
| Governance-slash is single-shot terminal                       | TLA+      |
| Cryptographic equivocation slash is single-shot terminal       | Lean (`slashDoubleSign_slashes_stake`, `slashDoubleSign_idempotent_when_already_slashed`), TLA+ (`Inv_SlashedOpHasZeroStake`) |
| `slash_double_sign` is enabled iff operator has two distinct signed payloads | TLA+ (`Inv_DoubleSignSlashable`) |
| No path exists where an unbonded address registers             | TLA+      |

What we CAN'T prove without Octra cooperation:

- "Bandwidth receipts are unforgeable" — moves to native-tx layer,
  not formally verified by Octra (no public formal proofs of their
  runtime). The off-chain dual-sig protocol's EUF-CMA reduction is
  in `proofs/tamarin/octravpn.spthy` but the AML layer's reduction
  hinges on the `ed25519_ok` host call (confirmed 2026-05-14, so the
  reduction is now sound; the formal AML model still treats
  `ed25519_ok` as an oracle).
- "Stealth payouts are unlinkable" — same (native-tx layer).

---

## 12. Sources

- `docs/octra-research.md` (this repo, 2026-05-10) — primary source.
- `octra-labs/contract-examples/example_1.aml` (GitHub) — only public AML.
- Octra litepaper §3, §3.6 — consensus/economic backdrop.
- `docs/octra.org/tech-docs/hfhe` — HFHE primitives.
- `octra-labs/pvac_hfhe_cpp` — PoC HFHE implementation.

For internal cross-references:
- `docs/whitepaper.md §3` (formal-claims table) — needs update after
  the rewrite.
- `docs/economics.md §10` (adversarial scenarios) — needs honesty
  pass for receipt integrity.
- `docs/security-roadmap.md` — adds "AML primitive asks for Octra
  team" as a new section.
