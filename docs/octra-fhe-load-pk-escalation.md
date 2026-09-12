# Escalation — AML `fhe_*` host calls revert on devnet (`fhe_load_pk`)

**Status:** ready to file with Octra Labs (chain-side blocker; octravpn cannot fix from Rust or the sidecar).
**Source of truth:** `docs/audit/fhe-load-pk-status.json` (daily probe), `pvac-sidecar/`, `program/main-v2.aml`.

---

**TITLE:** AML `fhe_*` host calls revert on all newly-deployed contracts on devnet (`fhe_load_pk`) despite `octra_registerPvacPubkey` succeeding — `private_ml` reverts verbatim

## Summary
`octra_registerPvacPubkey` works end-to-end for us (a ~4.1 MB PVAC pubkey registers and round-trips via
`octra_pvacPubkey`; the AES-KAT gate clears). But every AML `fhe_*` host call — starting at `fhe_load_pk` —
reverts with the generic `execution reverted` on newly-deployed contracts on devnet, **including
`octra-labs/program-examples/private_ml` cloned and deployed verbatim**. This blocks the on-chain HFHE
settle/claim path; we ship a sha256 hash-chain + plaintext-total fallback in the meantime, but per-settle
amounts remain chain-observable.

## What works (rules out our key material / AES impl)
- Wallet `oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm` has a 4.1 MB PVAC pubkey registered via
  `octra_registerPvacPubkey`, verified by `octra_pvacPubkey` returning it byte-for-byte.
- The AES known-answer-test the RPC requires (5th param) passes — no "AES implementation incompatible — KAT
  mismatch" rejection. Our sidecar's `pvac_aes_kat()` matches the chain's expected vector.

## What reverts
- `private_ml` (VERBATIM clone) deployed at `octHCQv6URtBXKjvAUo4AtDuDAgNjPhfazGiLPJXHwB3gDt`: calling
  `private_predict(0, pk_addr, ct0, ct1)` reverts with `execution reverted` at the first `fhe_load_pk`.
- Minimal probe contract `octaUNQtHpsmGrd4m4pftsjhE7zYwK4fVEgsDTKQ4BsXDRB`: 8 probe shapes (view vs
  state-change × caller-self vs explicit-address × string-typed vs address-typed pubkey arg) all revert
  identically at `fhe_load_pk`.
- Machine-readable status artifact: `docs/audit/fhe-load-pk-status.json` →
  `{"bridge_status":"blocked","probes":{"baseline":"true","private_predict":"false","probe_load_pk":"false"},`
  `"errors":{"private_predict":"execution reverted","probe_load_pk":"execution reverted"}}`.

## Questions
1. When are `fhe_*` AML host calls expected to execute against newly-deployed contracts on devnet? Is there a
   chain-side opt-in flag, deployer allowlist, or version gate we should pass at deploy or call time?
2. Is `program-examples/private_ml` known-working from a specific historical deploy address we can diff against?
3. Does `fhe_load_pk` resolve the caller's registered pubkey, the contract address's, or an explicit arg?
   (Our probes cover all three; all revert.)

## Impact
This is the sole remaining blocker for on-chain HFHE-hidden settlement in OctraVPN v3. Our storage shape is
designed to swap HFHE in additively the moment the bridge runs (running_total→ciphertext commitment,
settle→`fhe_add_const`, claim→`fhe_verify_zero`; schema unchanged). We have an honest mock
(`octra-foundry crates/octra-mock-rpc/src/aml/host_fhe.rs`, 23 tests, full
encrypt→add→add_const→make_zero_proof→verify_zero→decrypt smoke passing) that confirms the contract shape is
correct on our side — we just need the devnet bridge live. Repro: `docker/devnet/v3-smoke-hfhe.sh`
(`OCTRAVPN_E2E_USE_HFHE_MOCK=1`) and the fhe-load-pk-probe workflow.
