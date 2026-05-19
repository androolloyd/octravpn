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
