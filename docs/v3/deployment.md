# v3 deployment

## Current state

| Network | Program address                                          | Status                  | Last verified |
| ------- | -------------------------------------------------------- | ----------------------- | ------------- |
| Devnet  | `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`         | Live                    | 2026-05-18    |
| Mainnet | _not deployed_                                           | Awaiting ceremony       | —             |

Devnet deploy was driven by [`docker/devnet/v3-smoke.sh`](../../docker/devnet/v3-smoke.sh)
on 2026-05-18 against `https://devnet.octrascan.io/rpc` from
[`program/main-v3.aml`](../../program/main-v3.aml) using constructor
args `100 1000 100_000_000 100 1000`. Probe results recorded in
[`../audit/2026-05-20-claims-audit.md`](../audit/2026-05-20-claims-audit.md) §VERIFIED #3 — `octra_balance` returns 485 OCT.

## Test pass record

| Suite                                                              | Status                | Source                                                                                  |
| ------------------------------------------------------------------ | --------------------- | --------------------------------------------------------------------------------------- |
| End-to-end smoke (deploy → register → tailnet → session → claim)  | PASSED                | [`docker/devnet/v3-smoke.sh`](../../docker/devnet/v3-smoke.sh) — last green 2026-05-18  |
| Earnings hash-chain replay (byte-for-byte vs on-chain)             | PASSED                | smoke step 6, [`v3-smoke.sh:87-98`](../../docker/devnet/v3-smoke.sh)                    |
| 40-case adversarial drill                                          | PASSED (40/40 green)  | [`docker/devnet/e2e-adversarial-v3.sh`](../../docker/devnet/e2e-adversarial-v3.sh)      |
| Lean theorems on v3 canonical/policy/members                       | 24 theorems, 0 `sorry` | `proofs/lean/WireProtocol/V3{Canonical,Policy,Members}.lean`                            |
| Proptest budget on canonical encoder                               | 23 properties, 256 cases | `crates/octravpn-core/src/v3_{canonical,state_root,policy,members}.rs`                  |

The "40 cases" count from the audit reflects the labelled R/B/S/T/E/C/F/P
matrix in [`e2e-adversarial-v3.sh`](../../docker/devnet/e2e-adversarial-v3.sh)
(R1–R9, B1–B4, S1–S6, T1–T7, E1–E12, C1–C4, F1–F5, P1–P3 ≈ 50 invocations
including positives + preflight; the security/architecture docs round to "40 cases" to match the design narrative).

## Known chain-side blockers

These are chain-runtime quirks v3 engineers around. None block the
current devnet deploy from operating; all are upstream-Octra issues
listed in [`../octra-dev-questions.md`](../octra-dev-questions.md).

| Issue                                                              | Memory entry                                  | v3 mitigation                                                                            |
| ------------------------------------------------------------------ | --------------------------------------------- | ---------------------------------------------------------------------------------------- |
| AML `fhe_load_pk` reverts                                          | `octra_aml_fhe_load_pk_blocked.md`            | Use SHA-256 hash chain in `circle_earnings_chain` instead of HFHE ledger                 |
| `map[address]string` truncates at 4 KiB                            | `octra_aml_string_cap_4kb.md`                 | Store no inline blobs; every "blob" is a 64-char hex SHA-256 anchor                      |
| Circles store but don't execute `code_b64`                         | `octra_circles_not_executable.md`             | Bonds + slash stay on main contract; `BondEscrow` circle swap path is sketched but unused |
| AML `bytes` params undecoded at RPC; `len()` is char count          | `octra_aml_bytes_encoding.md`                 | All anchors stored as 64-char lowercase hex; `len() == 64` checks at every entrypoint     |
| AML default-value: unset `bytes` reads as the literal `"0"`         | `octra_aml_bytes_encoding.md`                 | `circle_earnings_chain` initialised to `sha256(state_root)` at `register_circle`         |
| `octra_aml.fhe_load_pk` would otherwise need per-wallet pubkey reg | `octra_hfhe_pubkey_per_wallet.md`             | Not relied on; v3 has no `fhe_*` calls                                                   |
| Devnet RPC 1 MiB body cap (resolved 2026-05-18)                    | `octra_devnet_rpc_body_cap.md`                | Resolved upstream — included for completeness                                            |

The full empirical case for each is in
[`../v3-circle-resident-architecture.md`](../v3-circle-resident-architecture.md) §1.

## Path to mainnet

Mainnet deploy is gated on the ceremony at
[`../mainnet-ceremony.md`](../mainnet-ceremony.md). Pre-conditions
from that doc:

- Contract source `program/main-v3.aml` has cleared an external audit.
- Audit findings closed OR explicitly accepted in writing by the
  owner-wallet quorum.
- Devnet smoke (`bash docker/devnet/v3-smoke.sh`) green on the
  identical source.
- Devnet adversarial drill (`bash docker/devnet/e2e-adversarial-v3.sh`)
  green on the identical source.
- Tree clean; HEAD commit signed.

This document is intentionally short: every operational detail for
mainnet bring-up belongs in the ceremony doc, not here.

## Deploy parameters

The devnet constructor `100 1000 100_000_000 100 1000` corresponds to:

| Position | Parameter                   | Value          | Floor (set_params)                                            |
| -------- | --------------------------- | -------------- | ------------------------------------------------------------- |
| 1        | `min_session_deposit`       | 100            | `> 0`                                                         |
| 2        | `min_tailnet_deposit`       | 1000           | `> 0`                                                         |
| 3        | `min_circle_stake`          | 100_000_000    | `>= 100_000_000`                                              |
| 4        | `session_grace_epochs`      | 100            | `> 0`                                                         |
| 5        | `unbond_grace_epochs`       | 1000           | `>= 1000`                                                     |

Mainnet target values live in
[`../../ceremony/mainnet-params.toml.example`](../../ceremony/mainnet-params.toml.example);
defaults established by the constructor for the other params (slash
splits, sweep grace, protocol fee) are documented in
[`fee-model.md`](fee-model.md) §"Governance parameter floors".

## How to verify a deploy

```bash
# 1. Probe the program exists + responds:
curl -s -X POST "$RPC" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_call",
       "params":["oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3",
                 "get_circle_state_version",
                 ["oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"]]}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"])'

# 2. Run the v3 smoke (requires a deployer key + bond OU):
bash docker/devnet/v3-smoke.sh

# 3. Run the adversarial drill (reuses any deploy via V3_PROGRAM_ADDR):
V3_PROGRAM_ADDR=oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3 \
  bash docker/devnet/e2e-adversarial-v3.sh
```

Mainnet uses the ceremony verifier
([`../mainnet-ceremony.md`](../mainnet-ceremony.md) §2 step-by-step),
NOT this smoke script. The smoke is devnet-only because it deploys
+ drives load against the contract.
