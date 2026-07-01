# devnet experiments — decisive go/no-go probes

Three **probes** the roadmap hinges on. Each one asks a single yes/no
question of the live Octra chain (devnet or the local mock), prints a
clear `VERDICT:` line, and **never assumes success**. They are diagnostic
experiments, not demos — a probe that says "FALLBACK" or "FAIL" is doing
its job.

These scripts model their tx-build + RPC style on the existing
`docker/devnet/v3-smoke.sh` and `e2e-adversarial-v3.sh`, and on how the
foundry builds/submits txs (`octra-foundry` `crates/octra-cli/src/cast`
and `.../octra-core/src/tx.rs`).

## What each probe decides

| Script | Roadmap gate | Question | PASS means | FALLBACK/FAIL means |
|---|---|---|---|---|
| `relay-outbox-probe.sh` | **P2.1** native relay rail | Does the chain EXECUTE `circle_outbox_open` + `relay_claim`, verifying `sha256(preimage)==committed_hash` on-chain? | Both ops confirm → build the native relay rail | `UNKNOWN_OP`/`BYTECODE_NOT_FOUND` → relay is an AML `contract_call` method, not a native op |
| `circle-call-object-probe.sh` | **P2.2** chain-enforced enrollment | Does attaching a **non-allowlisted** wallet (step 4) REVERT on-chain? | Step 4 reverts → enrollment is enforced by the chain | Step 4 confirms → no enforcement (security hole); `UNKNOWN_OP` → enforce in the AML layer |
| `credit-token-redeploy-smoke.sh` | **P1.2** enlarged AML | Does a bigger main-v3-class AML compile AND execute `mint → transfer → balance`? | Balances move exactly as the AML says → GO | Compile fails / exec doesn't settle → NO-GO |

`_oplib.sh` is a shared, **non-executable** helper (sourced by probes 1
and 2). It builds, signs, and submits arbitrary Octra `op_type` txs — see
its header for why hand-signing is necessary and how it stays honest
(real ed25519 via `cast wallet sign` over the exact `to_canonical_json`
bytes; integer timestamp to avoid Rust/Python float-format divergence).

## Prerequisites (same contract as `v3-smoke.sh`)

- A **pre-built** foundry `octra` binary. The probes do **not** build it.
  Default path: `../octra-foundry/target/release/octra`. Build once:
  ```
  (cd ../octra-foundry && cargo build --release -p octra-cli)
  ```
  or set `OCTRA_BIN=/path/to/octra`.
- `curl` and `python3` on PATH.
- A reachable RPC. Default `OCTRA_RPC_URL=https://devnet.octrascan.io/rpc`.
  Point it at the local mock (`octra-mock-rpc`) to dry-run the wire shapes.
- A funded signer key. Default `docker/devnet/state/deployer.key`.

## How to run + verify each

All commands are run from the repo root.

### 1) P2.1 — native relay rail
```
docker/devnet/experiments/relay-outbox-probe.sh
```
Reads the final `VERDICT:` line:
- `PASS` — `circle_outbox_open` **and** `relay_claim` both `CONFIRMED`;
  the chain verified the sha256 preimage. Build P2.1 native.
- `FAIL/FALLBACK` — an op came back `UNKNOWN_OP` / `BYTECODE_NOT_FOUND`;
  implement relay as an AML `contract_call` method on `main-v3`.
- `REVERTED` — op recognized but refused (likely our best-effort message
  field names are wrong): the rail *exists*; follow up with the exact
  webcli schema.
- `INCONCLUSIVE` — tooling/bad-sig/timeout; **not** a chain answer.

Overrides: `OPCIRCLE=<circle id>`, `RELAY_KEY=<key file>`. Exit `0` on a
decisive answer (PASS *or* FALLBACK), `2` if inconclusive.

### 2) P2.2 — chain-enforced enrollment
```
docker/devnet/experiments/circle-call-object-probe.sh
```
The decisive line is `step4 attach-outsider=…`:
- `REVERTED` → **PASS** (chain enforces the allowlist).
- `CONFIRMED` → **FAIL** (chain accepted a non-allowlisted member).
- `UNKNOWN_OP`/`BYTECODE_NOT_FOUND` → **FALLBACK** (enforce in AML).

Step 6 reads `circle_object_members` back; a PASS that still lists the
outsider is downgraded to PARTIAL. Overrides: `OPCIRCLE`, `OWNER_KEY`,
`OBJ_ID`. Exit `0` decisive, `1` FAIL(no enforcement), `2` inconclusive.

### 3) P1.2 — enlarged AML compiles + executes
```
docker/devnet/experiments/credit-token-redeploy-smoke.sh
```
Deploys `program/main-v3-credit.draft.aml` (override with `CREDIT_AML`),
then `mint_credit → transfer_credit → balance_of` and asserts the
balances. `VERDICT: PASS` requires every balance to match exactly.
Overrides: `DEPLOYER_KEY`, `MINT_OU` (default 5000), `XFER_OU`
(default 2000). Exit `0` PASS · `1` FAIL (compile/exec) · `2`
INCONCLUSIVE (env or AML source missing — the AML-dependent steps are
stubbed with a printed TODO, never a false PASS).

## Honesty notes (what is UNPROVEN)

- **Native `circle_call` + relay op EXECUTION on devnet is UNCONFIRMED.**
  Probes 1 and 2 exist to *determine* that. Prior evidence
  (`MEMORY octra_circles_not_executable`) is that circles are passive
  storage and `contract_call` on a circle returns `bytecode not found` —
  so `FALLBACK` is the expected outcome until proven otherwise.
- The **op_type strings** (`circle_outbox_open`, `relay_claim`,
  `circle_call`) are the documented Octra webcli op_types, but the
  **`message` field names** these probes send are BEST-EFFORT and
  **UNVERIFIED against the webcli reference**. A param-shape `REVERTED`
  still proves the op is *recognized*; only `UNKNOWN_OP` /
  `BYTECODE_NOT_FOUND` is the negative signal. Cross-check the exact
  schema in `octra-labs/webcli` before finalizing a native design.
- No probe touches `fhe_*` host calls — those revert on devnet
  (`MEMORY octra_aml_fhe_load_pk_blocked`). Probe 3 stays inside the
  proven AML feature set (`map[address]uint`, `payable`/`value`,
  `transfer()`, `nonreentrant`, `require`/`emit`).
- A `TOOLING_BADSIG` verdict means our locally-built signature/nonce was
  rejected *before* op dispatch — the probe flags this as INCONCLUSIVE so
  a signing bug can never masquerade as "op unsupported."
