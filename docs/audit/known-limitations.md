# Known Limitations / Open TODOs

Every `TODO`, `FIXME`, `XXX`, `HACK`, `punted`, `Punted`, "not yet
wired", or "not yet implemented" comment in the in-scope tree
(crates/, fuzz/fuzz_targets/, docs/operators/) at the commit
recorded in `manifest.json`.

> Reproduce this list:
>
> ```sh
> grep -rn "TODO\|FIXME\|XXX\|HACK\|punted\|Punted\|not yet wired\|not yet implemented\|stub today" \
>   crates/ fuzz/fuzz_targets/ docs/operators/ \
>   | grep -v "/target/" | grep -v ".proptest-regressions"
> ```
>
> The vendored `aws-lc-sys` build artifacts under
> `fuzz/target/.../aws-lc-sys-*/out/include/openssl/*.h` are NOT
> first-party code and are excluded (they ship a few hundred upstream
> BoringSSL TODOs).

Each entry is classified:
- **S** — Security-relevant. Must be addressed before audit can
  certify the corresponding property.
- **P** — Performance / observability only. No security impact.
- **D** — Documentation only.

---

## crates/

### `crates/octravpn-core/src/v3_canonical.rs:181`

> `// serde_json::to_string emits raw UTF-8 (no \uXXXX escapes) for
> //   BMP chars >= 0x80. Match that.`

**Class: D (documentation comment, not a TODO).** Grep matched the
literal word "TODO" inside a normal-prose explanation of how the
canonical encoder matches `serde_json` behaviour. No outstanding
work.

---

### `crates/octra-circle-sim/src/lib.rs:29`

> `//!     CircleSim via the (TODO) HTTP control plane.`

**Class: P.** `octra-circle-sim` is an in-process simulator used by
tests only; it is not built into any production binary. The "HTTP
control plane" alluded to is for richer test ergonomics, not
correctness. Excluding it from scope (also called out in
`file-index.md` §9). No security exposure.

---

### `crates/octravpn-client/src/operator_backend.rs:20`

> `//! The v2 impl is a stub today — wire-up follows once Octra ships
> //! the Circle DSL (see docs/v2-circles-design.md §9).`

**Class: S, but cleanly fail-closed.** The v2 `CircleOperator`
settlement backend is unimplemented. The stub at line 102 returns
`anyhow::anyhow!("CircleOperator settlement not yet implemented …")`,
so any caller that tries to settle through the v2-circle backend
errors loudly rather than silently dropping receipts. v3 is the
production path; v2-circle is reachable only with
`v3_runner=false` + a v2-circle-configured operator backend.

**Action for auditor:** confirm there is no code path that catches
this error and treats it as success. Grep:

```sh
grep -rn "operator_backend\|CircleOperator" crates/
```

---

### `crates/octravpn-client/src/operator_backend.rs:103`

> `"CircleOperator settlement not yet implemented — pending Octra
> Circle DSL (see docs/v2-circles-design.md §9)"`

**Class: S (same item as above).** The error-message companion to
the stub comment. Same disposition.

---

### `crates/octravpn-node/src/tunnel.rs:131`

> `// TODO: instrument exact handshake completion when
> //   boringtun surfaces it.`

**Class: P.** Today the node bumps `wg_handshake_success_total` on
any `TunnResult::WriteToNetwork`, which is a conservative proxy that
over-counts keepalives. This is a Prometheus-metric accuracy issue,
not a security property. boringtun does not surface a "handshake
complete" event; until it does, the conservative bump is what we have.
No effect on AEAD safety, on receipt signing, or on the slash path.

---

### `crates/octravpn-node/src/control.rs:189`

> `// dashboard panel \`settled-vs-no-show ratio\` for the TODO.`

**Class: P.** Talks about a dashboard panel for a
`session_no_shows_total` counter that the settlement-side cross-
check has not yet started populating. The counter exists; the
cross-check that would bump it is the v3 settler integration. The
no-show condition is still detected by the on-chain `sweep_session`
path (drill: `e2e-adversarial-v3.sh` category E), so the absence of
the daemon-side counter is observability, not security.

---

## docs/operators/

### `docs/operators/mainnet-deployment.md:245`

> *TODO (production-readiness P0 item #3, task #216).* A future
> `octravpn-node v3 deploy-circle` subcommand will fold this into
> the daemon CLI. Until it lands, the manual `octra cast` step
> above is the path.

**Class: P (operator-ergonomic).** Folding `deploy_circle` into the
daemon does not change the on-chain semantics; the existing manual
flow signs exactly the same tx. The mainnet-deployment doc is the
canonical procedure today.

---

### `docs/operators/mainnet-deployment.md:359`

> *TODO (gap).* The `octravpn-node attest` one-shot verb the unit
> invokes is not wired yet (`Cmd::Attest` is absent in
> `crates/octravpn-node/src/main.rs`). The long-running daemon
> handles attestation refresh via the `[attestation]` poll loop;
> the timer is harmless but currently a no-op.

**Class: S (low-severity).** The systemd `octravpn-attest.timer`
unit references a CLI subcommand that does not exist. Until the
subcommand is added, the timer is a no-op. The daemon's in-process
attestation refresh runs unconditionally, so the security property
("the node periodically re-attests") is held — but an operator who
relies *only* on the timer (e.g. with the daemon disabled in
attestation mode) will see no attestations refresh. The
documentation calls this out; the timer should either be removed
from the systemd bundle or the `Cmd::Attest` verb added.

---

### `docs/operators/mainnet-deployment.md:423`

> There is no graceful-drain CLI today (TODO, task #216). The
> practical equivalent is to firewall-drop :443 for new
> connections while leaving :51820/udp open until in-flight
> sessions close (~`SESSION_GRACE` s).

**Class: P.** Decommissioning ergonomics. The lack of a one-shot
drain verb does not affect the slash, settle, or unbond invariants.
The documented `iptables` recipe achieves the same effect.

---

## fuzz/

No `TODO`/`FIXME` entries in `fuzz/fuzz_targets/` itself. The
generated `fuzz/target/` build artifacts contain many BoringSSL
upstream TODOs and are explicitly excluded.

---

## Punted items from release / threat-model docs

These are outside the `crates/ fuzz/ docs/operators/` grep but are
referenced from threat-model docs and are tracked here for the
auditor's awareness:

- **`docs/release.md` §7 "Punted (deferred follow-ups)"** —
  Windows + macOS release builds, OCI image publishing, Homebrew
  tap, SBOM publishing. **Class: D / supply-chain hygiene**, no
  runtime exposure.

- **PVAC / HFHE bridge not yet enabled on devnet.** Per memory
  `octra_aml_fhe_load_pk_blocked.md`, the chain does not currently
  execute `fhe_*` host calls for our deploys, so the HFHE-private
  earnings ledger is anchored as a sha256 hash chain
  (`crates/octravpn-core/src/earnings.rs`) rather than via Pedersen
  commitments under HFHE. **Class: S (residual privacy degradation
  vs the design target).** The current scheme provides
  tamper-evidence; it does not hide amounts from the chain. The
  threat-model summary marks this as a known privacy limitation.

- **Circles not yet executable on devnet.** Per memory
  `octra_circles_not_executable.md`, `deploy_circle` accepts +
  persists `code_b64` and computes a real `code_hash`, but
  `contract_call` returns `bytecode not found` on devnet. The v3
  architecture (`docs/v3-circle-resident-architecture.md`) is the
  workaround. **Class: D / design**, with a path forward marked
  forward-compatible.

- **JSON-RPC body cap 1 MiB on devnet.** Per memory
  `octra_devnet_rpc_body_cap.md`, the devnet nginx terminator
  rejects POST bodies > 1 MiB, which blocks PVAC pubkey
  registration (~4 MB). Mainnet accepts. **Class: D
  (configuration)**, no exposure on the audit surface.

- **AML map[address]string truncates at 4 KiB.** Per memory
  `octra_aml_string_cap_4kb.md`. We do not store anything larger
  than 4 KiB in a map value (only sha256 anchors); off-chain
  blob storage lives in circle sealed assets. **Class: D / design
  constraint** baked into the v3 schemas.

---

## Formal-proof model ↔ chain gaps (2026-08-17 upstream-source audit)

The Octra node source is now public (octra-labs/lite_node, pinned at
commit `75d9ed1d73a0e3731f7d7a4262d29b672ad3c24e` for the citations
below). Auditing our Lean claim set against it found two places where
a proof's *model* encodes chain behavior the chain does not have. In
both cases the Lean theorem is sound about its model and the model
faithfully mirrors **our own Rust client** — the gap is between the
model and the chain, not inside the proof. Nothing here involves a
`sorry`; the proofs build clean.

### `proofs/lean/WireProtocol/RpcEnvelope.lean:222` — `chain_id_binding_rejects_replay`

> A tx signed for `chain_id = X` cannot be replayed against a
> different chain.

**Class: S (assurance overstatement — the property is real but not
chain-enforced).**

What it IS: a genuine Lean `theorem` (the 2026-05-20 note about it
being "earlier axiomatised" is historical — today it is derived from
the modeling axiom `txCanonical_chainId_injective`,
`RpcEnvelope.lean:138`, plus `Sha256.injective` and
`verify_rejects_tampered_message`). The axiom faithfully mirrors the
v2 canonical-bytes encoder in
`octra-foundry/crates/octra-core/src/tx.rs::to_canonical_json`, and
the Rust proptests exercise it.

What it is NOT: a property of the Octra chain. Verified against the
node source:

- The chain's signing preimage has **no `chain_id` field**:
  `serialize_for_signing` emits exactly `from, to_, amount, nonce,
  ou, timestamp, op_type` (+ optional `encrypted_data`, `message`)
  — `lib/core/transaction.ml:309-326`.
- The envelope parser (`of_yojson`, `transaction.ml:273-306`) reads
  known keys via `List.assoc_opt` and **silently drops** a
  `chain_id` key. The chain then re-derives the preimage from the
  parsed record — without `chain_id` — so a v2-signed tx fails
  signature admission outright (`transaction.ml:335-341`, reached
  from `signature_admission` in `node_runtime/tx_view.ml`). The v2
  format is not merely un-enforced; it is **unusable** against the
  real chain.
- No production caller sets `OctraTx.chain_id` — the only
  `chain_id: Some(..)` constructions are inside `mod tests`
  (`tx.rs:773`, `tx.rs:827`). All real traffic is v1.

What the chain actually enforces (same-chain replay resistance
only): nonce must equal `balance.nonce + 1` and is tracked in a
spent-nonce set (`lib/core/ledger.ml:241-247`), and the signed
timestamp must be within ±300s of the node's clock
(`node_runtime/tx_view.ml:1125-1129`). **There is no cross-chain
binding of any kind in the chain's tx envelope.** A v1 tx valid on
chain A is, at the envelope layer, also valid on a chain B that
shares the sender's account state, within the timestamp window.

What still holds: cross-chain binding for the *settle path* is
enforced in-program at the receipt layer — the client-signed receipt
payload binds `ReceiptContext::chain_id`
(`crates/octravpn-core/src/receipt.rs:226`) and our AML program
checks it (`OctraVPN_Rust.Lemmas.receipt_cross_chain_rejected`).
The tx-envelope-layer theorem additionally holds for any verifier
that implements the v2 rules (our `verify_envelope_signature`,
`octra-mock-rpc`).

Verdict: **(a) spec ↔ implementation mismatch** — the theorem is
sound about its model, and the model matches our client's v2 format;
the chain ignores-and-rejects that format. It is not vacuous, not
false over its own domain, and not an axiom-in-disguise. The theorem
site now carries a scope caveat (`RpcEnvelope.lean`, THM 26
docstring), as do `WireProtocol/Theorems.md` §11 and the module
docstring. The theorem is retained: it documents a defence we want
the chain to adopt and that our own verifiers already enforce.

Downstream citations that inherit the caveat:
`proofs/lean/OctraVPN_Rust/EndToEnd.lean:49` (layer-4 listing) and
`EndToEnd.lean:369` (THM 31 `cross_chain_replay_detected` cites the
RpcEnvelope theorem as compositional support — THM 31 itself is a
receipt-layer statement and stands on
`receipt_cross_chain_rejected` alone).

---

### `proofs/lean/OctraVPN/Entrypoints.lean:521` + `proofs/lean/OctraVPN_V2/Entrypoints.lean:553` — `claimEarnings` gates a mutation on `fhe_verify_zero`

> The `proofOk` proposition stands in for the on-chain
> `fhe_verify_zero(pk, encEarn - enc(amount), proof)` check.

**Class: S for any v1/v2 certification; no impact on the deployed
v3 path.**

The v1 and v2 program models (and the lemmas built on them, e.g.
`OctraVPN/Lemmas.lean:613` `claim_requires_exact_match`) model the
chain accepting a **mutating** `claim_earnings` call gated by
`fhe_verify_zero`. The chain cannot execute that program: the VM's
`FHE_VERIFY_ZERO` opcode **reverts unless `st.is_view`**
(`lib/vm/runtime/contract_vm.ml:2667-2671`; likewise
`FHE_VERIFY_RANGE` at 2694-2698 and `GROTH16_VERIFY_BN254` at
~2721-2723). fhe-verification is a view-only capability — it cannot
gate a state change inside a transaction. The v2 "PROOF GAP" list
(`OctraVPN_V2/AmlLink.lean:32`, item 4) declares the *cryptographic
soundness* of the zero-proof as out of scope but does not mention
the view-only restriction; the modeled entrypoint shape is
unimplementable on today's chain, not merely unproven.

The production path is unaffected: the v3 model claims earnings
against a plaintext `availableEarnings` bound with no FHE gate
(`OctraVPN_V3/Invariants.lean:1008-1029`), and v3's AmlLink states
HFHE is not present in v3 (`OctraVPN_V3/AmlLink.lean:57`). The
HFHE modules themselves are honestly framed as a future swap-in
("currently inert", `WireProtocol/HFHE.lean:497`;
`OctraVPN_Rust/ShadowBlob.lean:21`).

**Action for auditor:** treat v1/v2 `claimEarnings` theorems as
verifying a *target* design contingent on Octra allowing
fhe-verification in mutating context; do not certify them as
properties of any deployable program.

---

### Swept and clean (same error class, no findings)

- **Chain events.** The chain emits no tx events
  (`octra_transaction` returns status objects only,
  `node_runtime/tx_view.ml:93-136`; execution results live in
  receipts). No proof models a chain event log: the TLA+
  `settled_sids` "SessionSettled event" variable
  (`proofs/tla/OctraVPN.tla:93`) is a ghost history variable of the
  model's own state machine, and the "settlement event fires" prose
  in `OctraVPN/Lemmas.lean:480` describes a state transition, not
  an emitted log.
- **Confirmation timing.** `octra_submit` only stages
  (confirmation at epoch apply). No Lean/TLA theorem assumes
  submit ⇒ confirmed; all program models are per-execution state
  transitions, which is compatible with staged-then-applied
  semantics. (The `EndToEnd.lean` prose "no third outcome" is about
  an *executed* call being accepted-or-rejected; a dropped/pending
  tx executes nothing and changes no state.)
- **Circles holding value.** Circle execution disables transfers;
  custody stays in the AML program. All models place custody in the
  AML program treasury; no proof asserts a circle holds or moves
  value.
- **Tamarin.** `proofs/tamarin/octravpn.spthy:14-40` explicitly
  labels its properties "TARGET, not v1" — honest framing, no
  change needed.
- **README theorem count.** The README claims "373 Lean 4
  theorems"; the tree contains 377 top-level `theorem` declarations
  and zero `sorry`/`admit`. The count is not overstated. Note that
  118 `axiom` declarations underpin the set (hash/signature
  primitives and encoder-injectivity modeling axioms) — standard
  practice, and disclosed per-module in the Theorems.md files.

---

## Three items to flag first for the auditor

These are the items the OctraVPN team would want the auditor to
look at on day one, ranked by realistic blast radius:

1. **`crates/octravpn-client/src/operator_backend.rs` v2-circle
   stub.** The error message is the right shape, but the cleanness
   of fail-closed depends on every caller propagating the error.
   Specifically check that no caller in `settler.rs` or the v2
   runner downgrades the error to a warning that lets a session
   close "successfully" without a real settled receipt. If such a
   path exists, it lets a malicious operator + complicit client
   close a session without burning the bond evidence.

2. **`docs/operators/mainnet-deployment.md:359` —
   `octravpn-attest.timer` is a no-op.** A defense-in-depth check
   for the operator's on-disk attestation freshness is silently
   not running. The daemon's in-process loop is the load-bearing
   path; if a misconfiguration disables the daemon's attestation
   poll while the operator is relying on the timer, attestations
   go stale and a chain verifier could (rightly) refuse to slash
   or settle. Either remove the timer file from the systemd
   bundle or add `Cmd::Attest`.

3. **HFHE bridge unwired → earnings amounts visible on chain.**
   The hash-chain commit is tamper-evident but NOT hiding. Any
   on-chain observer who tracks a circle's per-epoch
   `claim_earnings` calls learns the per-epoch earnings amounts.
   This is a privacy degradation relative to the v2 threat model's
   design target. The audit-prep `threat-model-summary.md` flags
   this as a known privacy limitation, not a confidentiality
   defect, but auditors evaluating the privacy claims should be
   handed this constraint up front.
