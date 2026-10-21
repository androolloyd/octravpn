# Lean 4 spec & proofs

`OctraVPN.lean` collects state, entrypoint definitions, and proofs of
structural lemmas about the program's state-transition system.

## Lemmas (mechanically checked by Lean)

- **register_sets_bond** — registration sets bond to the requested value.
- **addBond_increases_bond** — bond top-up sums correctly.
- **completeUnbond_returns_full_bond** — unbond returns all of the
  remaining bond and zeros the validator's bond.
- **slash_double_sign_zeros_bond** — equivocation zeroes bond + jails.
- **settle_finalizes** — successful settlement moves the session out of
  `open`.
- **register_blocked_when_bonded** — registration is rejected when the
  caller already has bond.

## Running

```
cd proofs/lean
lake build
```

`lean-toolchain` pins the Lean version. The build is hermetic — no
external Mathlib dependency for the v1 proofs above (we only use core
Lean 4).

## Wire-protocol primitive proofs

`WireProtocol/` adds 36 deductive theorems (+ 5 concrete-value
anchors) covering the wire-protocol primitives that landed during the
Tailscale interop work (Walls 1-5): controlbase framing
(`Controlbase.lean`), BE-nonce composition and replay-window
correctness (`BeNonce.lean`), per-circle HMAC approval tokens
(`HmacToken.lean`), and the portal approve+unseal cache lifecycle
(`PortalCache.lean`). Combined with the 54 Rust security-primitive
theorems in `OctraVPN_Rust/` (PR #181), the deductive proof surface
now stands at 90 mechanically-checked theorems. See
`WireProtocol/Theorems.md` for the plain-English index and
Rust-signature mapping; `lake build` from this directory builds the
full set.

## Relationship to AML source

The spec here is *abstract*. The next milestone is to mechanically link
this spec to the compiled OCTB bytecode (or, easier, to the AML source's
operational semantics). Octra's Applied compiler exposes ABI + disassembly
on every compile, which gives us the surface we'd need to relate AML to a
formal semantics.

## Current v4 scope (2026-10-11)

`OctraVPN_V4.lean` proves six abstract stake lifecycle properties, including
retirement before unbonding and funded sessions blocking finalization. Historical
v1-v3 models now use full traffic payments with zero commission. Their other
historical abstractions do not establish correctness of the revised AML slashing
or onboarding paths. Crypto/protocol models contain
explicit axioms and opaque definitions. There is no compiler/bytecode refinement
proof, and a successful `lake build` does not certify deployment safety. Real AML
regressions and native host money tests are separate checks.

## Octranet payment candidate (2026-10-17)

`OctranetPayments.lean` models the staged `program/octranet-payments.aml`:
instant full or partial payer withdrawal, immediate operator earnings withdrawal,
seven-day operator unstake, separate payer/earnings/stake accounting,
stopped-generation admission, cumulative
receipt redemption, 24-hour rate-change notice, bounded prepaid capacity and
an abstract equivocation award. Its 48 theorems have no application axioms or
`sorry`. Canonical clock input, authentic signatures, tariff calculation,
service evidence and the immutable per-generation stop record remain
assumptions at the model boundary. This is not compiler/bytecode refinement
or a proof of network admission or packet delivery.

`crates/octra-node-runtime/tests/octranet_payments.rs` compiles the actual AML
and factory and runs the production Program transaction adapter with real
ledger transfers. It checks deadline boundaries, accounting, receipt attacks,
rebond/rejoin, failed-transfer rollback and native upgrade authorization.
Those finite tests complement the model; neither establishes Mainnet readiness.
