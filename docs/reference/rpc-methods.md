<!-- captured from source at SHA 2ffead7 (2026-05-20) -->

# Octra JSON-RPC methods

Every Octra chain JSON-RPC method the `octravpn-node` and `octravpn`
binaries consume, plus every AML program method name they emit inside
a `contract_call` envelope.

## Transport

* Every RPC is JSON-RPC 2.0 over HTTPS POST to `[chain].rpc_url`.
* The transport client lives in
  `crates/octravpn-core/src/rpc.rs::RpcClient`. The single
  `RpcClient::call(method, params) -> Result<Value>` shape underpins
  the typed helpers below.
* TLS trust roots: system store by default, pinned with
  `[chain].pinned_root_paths` (PEM bundles).
* Mock surface for tests: `target/debug/octravpn-mock-rpc` and
  `crates/octra-circle-sim/src/rpc_chain.rs`. The mock matches the
  same method strings.

## Method categories

| Category | Layer | Endpoint pattern |
|---|---|---|
| Native Octra | chain | `octra_<verb>` (`octra_balance`, `octra_isValidator`, …) |
| Native lookup | chain | `node_status`, `transaction`, `contract_call` (no `octra_` prefix) |
| AML contract method | program (via `contract_call`) | `register_circle`, `open_session`, `settle_claim`, … |

The AML methods are emitted as the `"method"` field inside a
`contract_call` JSON envelope (see
`crates/octravpn-core/src/v3_calls.rs:6-200` for the canonical shape).

---

## Native Octra RPCs

All defined in `crates/octravpn-core/src/rpc.rs`. The typed helpers
return `serde_json::Value`; callers downcast to the expected shape.

### `node_status`

* **Builder.** `RpcClient::node_status()` at `rpc.rs:175`.
* **Params.** `[]`.
* **Response.** `{ "epoch": u64, "latest_block_height": u64, … }`.
* **Mock handler.** `crates/octravpn-client/tests/v3_client_integration.rs:93`
  and `crates/octravpn-node/tests/v3_boot_integration.rs:97`.
* **Used by.** Boot health probe, `config validate`, `health`.

### `octra_balance`

* **Builder.** `RpcClient::balance(addr)` at `rpc.rs:179`.
* **Params.** `[ "<oct… display>" ]`.
* **Response.** `{ "balance": u64 }` (raw OU).

### `octra_recommendedFee`

* **Builder.** `RpcClient::recommended_fee(params)` at `rpc.rs:187`.
* **Params.** Op-type-dependent fee hint shape.
* **Response.** `{ "fee": u64 }`.

### `octra_submit`

* **Builder.** `RpcClient::submit(signed_tx)` at `rpc.rs:233`.
* **Params.** `[ <signed tx JSON> ]`.
* **Response.** `{ "tx_hash": "<hex64>" }` or error `{code, message}`.
* **Error codes.** `-32001` insufficient funds, `-32002` invalid
  signature, `-32003` nonce mismatch, `-32099` revert. (Chain-side; see
  the AML runtime for the canonical list.)

### `octra_transaction`

* **Builder.** `RpcClient::transaction(hash)` at `rpc.rs:237`.
* **Params.** `[ "<tx_hash>" ]`.
* **Response.** `{ "status": "applied"|"pending"|"reverted", "events": […], "ret": … }`.
* **Used by.** Every `*_post-submit` flow that needs the
  `chain-assigned session_id` or `tailnet_id` returned by the program.

### `octra_listContracts`

* **Builder.** `RpcClient::list_contracts()` at `rpc.rs:241`.
* **Params.** `[]`.
* **Response.** Array of `{ addr, program_addr, owner, … }` records.
* **Used by.** `octravpn nodes` to enumerate operator endpoints.

### `octra_viewPubkey`

* **Builder.** `RpcClient::view_pubkey(addr)` at `rpc.rs:245`.
* **Params.** `[ "<addr>" ]`.
* **Response.** `{ "pubkey_b64": "…" }`.

### `octra_privateTransfer`

* **Builder.** `RpcClient::private_transfer(tx)` at `rpc.rs:249`.
* **Params.** `[ <stealth tx JSON> ]`.
* **Used by.** `claim-earnings` second leg — the stealth wrap.

### `octra_stealthOutputs`

* **Builder.** `RpcClient::stealth_outputs(params)` at `rpc.rs:257`.
* **Used by.** Stealth-tx scanning for incoming earnings.

### `octra_isValidator`

* **Builder.** `RpcClient::is_validator(addr)` at `rpc.rs:270`.
* **Params.** `[ "<addr>" ]`.
* **Response.** `{ "is_validator": bool, "stake": u64 }`.
* **Constant.** `RPC_DIRECT = "octra_isValidator"` in
  `crates/octravpn-core/src/validator_oracle.rs:35`.
* **Used by.** The attestation poll loop in `hub/attestation.rs`.

### `octra_listValidators`

* **Use.** Pagination fallback when `octra_isValidator` is unavailable.
  `crates/octravpn-core/src/validator_oracle.rs:37` declares the
  `(method, [offset, limit])` shape.
* **Params.** `[offset:u64, limit:u64]` — paged with `[0, 5000]`.

### `contract_call`

* **Builder.** `RpcClient::contract_call(payload)` at `rpc.rs:229`.
* **Use.** The transport for every AML method below. Encodes
  `{ kind: "contract_call", from, to, method, params, value }` and
  signs it before `octra_submit` in production paths; or sends it as a
  raw view-call for read-only methods.

---

## AML contract methods (via `contract_call`)

These are the `"method"` strings inside the JSON envelope. Builders in
`crates/octravpn-core/src/v3_calls.rs` and per-version files in
`crates/octravpn-node/src/chain*.rs`. The mock surface that handles
each is noted where it exists.

### v1.1 / `program/main.aml`

Built in `crates/octravpn-node/src/chain.rs`.

| Method | Builder | Notes |
|---|---|---|
| `register_endpoint` | `chain.rs:138` | Operator endpoint registration. |
| `register_validator` | (validator path) `crates/octravpn-core/benches/core.rs:110` | Validator-registration helper. |
| `bond_endpoint` | `chain.rs:161` | Top-up bond. Payable. |
| `unbond_endpoint` | `chain.rs:175` | Start grace timer. |
| `finalize_unbond` | `chain.rs:189` | Claim stake back. |
| `claim_earnings` | `chain.rs:210` | Two-step earnings claim. |
| `settle_claim` | `chain.rs:235` | Operator-side settle. |

### v2 / `program/main-v2.aml`

Built in `crates/octravpn-node/src/chain_v2.rs`.

| Method | Builder | Notes |
|---|---|---|
| `register_circle` | `chain_v2.rs:250` | Atomic register+bond. Payable. |
| `bond_endpoint` | `chain_v2.rs:282` | Bond a circle. |
| `settle_claim` | `chain_v2.rs:304` | Circle-scoped settle. |
| `deploy_circle` (op_type) | `chain_v2.rs:197` | Raw deploy-circle op via `op_type` channel. |
| `settle_claim_v2` (mock) | `crates/octra-circle-sim/src/rpc_chain.rs:122` | Mock helper for sim tests. |

### v3 / `program/main-v3.aml`

Builders in `crates/octravpn-core/src/v3_calls.rs`. Every line below
maps 1:1 to a Rust fn returning the canonical envelope.

| Method | Builder | Tx semantics |
|---|---|---|
| `register_circle` | `v3_calls.rs:454` | Anchor + receipt pubkey. Boot-only. |
| `update_circle_state` | `v3_calls.rs:471` | Bump anchor. |
| `rotate_receipt_pubkey` | `v3_calls.rs:496` | Swap on-chain receipt pubkey. |
| `retire_circle` | `v3_calls.rs:513` | `circle_active[c] = 0`. |
| `bond_endpoint` | `v3_calls.rs:530` | Payable top-up. |
| `unbond_endpoint` | `v3_calls.rs:547` | Grace timer. |
| `finalize_unbond` | `v3_calls.rs:564` | Pull stake back. |
| `slash_double_sign` | `v3_calls.rs:592` | Burn bond on equivocation; 10% bounty. |
| `create_tailnet` | `v3_calls.rs:609` | Payable; assigns tailnet_id. |
| `update_members_root` | `v3_calls.rs:626` | Anchor bump. |
| `retire_tailnet` | `v3_calls.rs:643` | Mark retired. |
| `deposit_to_tailnet` | `v3_calls.rs:660` | Payable top-up. |
| `withdraw_tailnet_treasury` | `v3_calls.rs:677` | Owner-only post-retire. Built inline (no builder yet). |
| `open_session` | `v3_calls.rs:694` | Returns session id. |
| `settle_claim` | `v3_calls.rs:711` | Operator-side. |
| `settle_confirm` | `v3_calls.rs:738` | Opener-side. Returns bool. |
| `claim_no_show` | `v3_calls.rs:755` | Opener abort. |
| `sweep_expired_session` | `v3_calls.rs:772` | Public sweep with bounty. |
| `claim_earnings` | `v3_calls.rs:789` | Pull from circle's earnings ledger. |

### Tailnet / membership (client-driven)

Built in `crates/octravpn-client/src/tailnet.rs`.

| Method | Builder | Notes |
|---|---|---|
| `redeem_join_token` | `tailnet.rs:299` | Add caller to tailnet via preauth token. |
| `register_device` | `tailnet.rs:331` | Attach device address to wallet. |
| `revoke_device` | `tailnet.rs:350` | Detach. |
| `create_tailnet` | `tailnet.rs:397` | Wallet becomes owner. |
| `add_member` | `tailnet.rs:435` | Owner-only. |
| `remove_member` | `tailnet.rs:460` | Owner-only. |
| `deposit_to_tailnet` | `tailnet.rs:480` | Open to anyone. |
| `update_acl` | `tailnet.rs:506` | New ACL hash on chain. |
| `configure_tailnet_exit` | `tailnet.rs:535` | Owner sets exit validator. |

---

## Request / response shapes

### Generic `contract_call` envelope

```jsonc
{
  "kind":   "contract_call",
  "from":   "<oct…>",          // signer address
  "to":     "<oct…>",          // program address
  "method": "<aml_method>",
  "params": [ … ],              // method-specific positional args
  "value":  <u64 OU>,           // 0 unless the method is payable
  "fee":    <u64 OU>,
  "nonce":  <u64>
}
```

Signed via `octra_core::tx::sign_call` before `octra_submit`. The view
form (no signing) is sent directly to `contract_call`.

### Generic JSON-RPC error envelope

```json
{ "jsonrpc": "2.0", "id": 1, "error": { "code": <i32>, "message": "<str>", "data": …optional } }
```

Common chain-side codes:

| Code | Meaning |
|---|---|
| `-32000` | Generic server error |
| `-32001` | Insufficient funds |
| `-32002` | Bad signature |
| `-32003` | Bad nonce |
| `-32099` | Revert (the AML program rejected the call); `data` is the revert message |
| `-32600` | Malformed request |
| `-32601` | Unknown method |
| `-32602` | Invalid params |

---

## Mock RPC

The `target/debug/octravpn-mock-rpc` binary (built from
`crates/octravpn-mesh` and friends) provides a deterministic stand-in
for integration tests. Handler matches the same method strings; the
exhaustive switch is in `crates/octra-circle-sim/src/rpc_chain.rs`.
Notable mock paths:

* `node_status` → returns a fixed `{epoch: 1234}` for v3 boot
  integration (`tests/v3_boot_integration.rs:97`).
* `settle_claim_v2` → mock-only method used by the circle simulator
  (`rpc_chain.rs:122`).

---

## Adding a new RPC

1. Add a builder in `crates/octravpn-core/src/v3_calls.rs` (or
   per-version chain file) returning a `serde_json::Value` envelope
   with `{ kind: "contract_call", method: "<new>", … }`.
2. Wire a CLI surface (top-level subcommand in
   `crates/octravpn-node/src/cli/v3.rs`).
3. Add a row to the table above and a request/response example.
4. Update the mock RPC's match arm in `crates/octra-circle-sim/src/rpc_chain.rs`
   so integration tests can exercise the path.

---

## Cross-references

* `RpcClient` source: `crates/octravpn-core/src/rpc.rs`.
* `contract_call` envelope spec: top of `crates/octravpn-core/src/v3_calls.rs`.
* v1.1 program: `program/main.aml`.
* v2 program: `program/main-v2.aml`.
* v3 program: `program/main-v3.aml`.
* Mainnet vs devnet chain ids:
  `crates/octravpn-core/src/receipt.rs::CHAIN_ID_*`.
