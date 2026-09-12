# Octra upstream delta — 2026-08-22 → 2026-09-12

> What `octra-labs/lite_node` shipped between our sequence-4 pin and the
> current sequence-12 marker, and what it changes for OctraVPN / octra-foundry.
>
> Compared `f3b6d580` (sequence 4, accepted 2026-08-22) against
> `d01d4123` (HEAD, 2026-09-11). Live marker: sequence **12**,
> `public_commit 9e7ee19a`, `source_commit e984d401` — and devnet's
> `octra_runtimeVersion.source_commit` matches it, so devnet runs sequence 12.

---

## 0. One paragraph

Sequence 12 is a **required** release built around a compiler/VM overhaul
("AML Program core", 322 files, 53K insertions) that names the compiler
**`1.0 Rehovot`**. It does **not** change the client money path: the signing
preimage is untouched, the error-code table is unchanged (one new admission
cap added), the JSON-RPC surface is 156 = 156 names with nothing added or
removed, and `consensus_rules_id` / `runtime_profile_hash` are identical.
`main-v4.aml` compiles clean on the new compiler (0 errors, 7 pre-existing
FV warnings) at **7,248 instructions, up from 6,024** — new codegen — and the
already-deployed v4 still executes. Two things need our attention: the
release marker gained `action`/`notice_code` (our canary already handles
them) and **the state/receipt retention window is now `keep_epochs = 8192`
≈ 22.75h**, which any audit tooling must respect. Separately, **devnet
consensus was halted at epoch 1,500,060 on 2026-09-12** — staging accepted
txs, nothing applied, and the marker had expired without reissue.

## 1. What shipped (client-visible)

| Surface | Change | Evidence |
|---|---|---|
| Signing preimage | **none** | `lib/core/transaction.ml` diff has no signing-relevant lines |
| Error codes | +`max_admits = 100` per request (`octra_submit` counts 1, `octra_submitBatch` counts N) | `lib/core/rpc.ml` |
| JSON-RPC names | 156 → 156, ∅ added, ∅ removed | `node_runtime/rpc_dispatch.ml` |
| gRPC (new) | read-only `Node` service: `Status`, `Account`, `Transaction`, `Epoch`, replies are JSON-in-bytes | `proto/octra/node/v1/node.proto` |
| Storage caps | untouched — `view_storage_value_limit = 4096` (display slice), `max_storage_value_len = 4_194_304` | `contract_rpc.ml:641,1140`, `contract_vm.ml:309` |
| Compiler | `1.0 Rehovot`; artifact keys `{abi, bytecode, certificate, disasm, instructions, size, verification, version}`; certificate now `{bytecode_hash, compiler, compiler_version, declaration, schema, source_hash, source_mode, verification_hash, verification_schema}` | live `octra_compileAml` |
| Deploy admission | certificate is stored with the record; `contract_verify` reworked (source-mode admission, single-flight) — no evidence deploy *requires* the certificate | `contract_rpc.ml` diff |
| `network.env` | +`OCTRA_JOIN_RPC` (state-sync sources, validated); −`OCTRA_VALIDATOR_READY_*`; new sha `db87b332…` | `config/network.env`, `validator_common.py:44,372` |
| Release marker | schema `octra-devnet-release-v2`; `ACTIONS = {current, recommended, required, hold}`, `NOTICES = {consensus_recovery, routine_update, release_hold, release_current}` | `controls/lib/release.py:42-48` |
| Retention | `keep_epochs = 8192`; snapshots `retained_limit = 8` | `octra_epochTags`, `sync_lease.ml:13` |
| Epoch gates | none new; 1,299,000 / 1,330,000 / 1,334,000 / 1,380,000 all passed (devnet ≥ 1.5M) | `lib/core/rule_graph.ml`, `c_relief.ml:20` |
| Validator set | 16 → 36, `f = 11`, `quorum = 25`, weighted | live `octra_validatorSetProof` (shape unchanged) |

## 2. Verified against real nodes

- **Local sequence-12 node** (`octra-node:9e7ee19a`, Single mode): epochs
  advance; `forge create` deployed `main-v4` with `confirmed: true`, a real
  `tx_hash`, and predicted == receipt address; `get_sweep_grace → 1000`.
  **Rehovot-compiled v4 executes on the sequence-12 VM.**
- **Devnet**: reachable, `v3.0.0-irmin`, our v4 at `octEX1mU…` still answers
  (`get_session_count = 1`), the seq-2 probe program still answers
  (`pokes = 2`) — old deploys survived the storage migration. But
  **consensus was halted** (epoch pinned at 1,500,060 across ~40 minutes,
  `head_epoch 1,500,059`), so today's devnet deploys sit in staging.

## 3. What changed in our tooling because of this

- **forge create** now prints the real `tx_hash` (`octra_submit` returns
  `{tx_hash, status, nonce, ou_cost}` — there never was a `hash` key), waits
  for the epoch, and takes the address from the **execution receipt** rather
  than trusting its pre-submit prediction. `--no-wait` / `--wait-secs` added.
- **Canary baseline** advanced to the full sequence-12 marker. The canary
  correctly refuses the currently-expired live marker (issued 09-08, expired
  09-11, not reissued as of 09-12).
- **Local node image** pinned to `9e7ee19a` (the marker's `public_commit`);
  `docker/octra-node/docker-compose.yml` points at it.

## 4. What this means for testing

Receipts and epoch history live for ~22.75h. Any test or audit path that
reads a receipt must do so inside that window; the operator audit CLI (P0 #4)
must be designed around it. And with devnet capable of halting for hours, the
local sequence-12 node is now the primary integration target — devnet is a
spot-check, not the harness.
