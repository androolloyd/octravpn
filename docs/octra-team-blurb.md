# OctraVPN — "what we need fixed" (blurb for the Octra team)

*Fact-checked against primary sources; the two load-bearing claims (`fhe_load_pk`/`private_ml` revert,
and `register-pvac` works) are verified.*

---

**What we need fixed:** On devnet, `fhe_load_pk` — and every AML `fhe_*` host call — reverts with
`execution reverted` on newly-deployed contracts, **including `program-examples/private_ml` deployed
verbatim** (`octHCQv6URtBXKjvAUo4AtDuDAgNjPhfazGiLPJXHwB3gDt`; `private_predict` reverts at the first
`fhe_load_pk`). Pubkey registration itself works end-to-end — `octra_registerPvacPubkey` round-trips a
~4.1 MB PVAC pubkey and the AES-KAT gate clears — so the AML→HFHE bridge just doesn't seem wired for
newly-deployed contracts. **Is there a chain-side enablement we're missing (a flag / version gate /
deployer allowlist), or a known-good reference deploy we can diff against?** We have a full repro plus
a local mock of the `fhe_*` host calls, and can validate a fix the moment it's on devnet.

*(Optional add-on — "please confirm these execute + enforce on devnet": executable circles via a
`runtime`/`build` manifest (`program.call`); the native `circle_call` object ops (does a non-permitted
`attach` revert?); and `relay_claim`'s on-chain `sha256(preimage)` check.)*
