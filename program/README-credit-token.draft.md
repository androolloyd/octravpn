# VPN credit token — Rust builder wiring (DRAFT / signatures only)

Companion to `program/main-v3-credit.draft.aml`. This sketches the
`ContractCallBuilder` methods that would emit `contract_call` envelopes
for the new credit entrypoints, mirroring the existing
`deposit_to_tailnet_call` / `withdraw_tailnet_treasury_call` pair in
`crates/octravpn-core/src/v3_calls.rs`.

**Nothing here is implemented.** These are signatures + wiring notes so a
reviewer can see the shape before code lands. The AML side is unproven
until a devnet redeploy (see the draft's PROVENANCE block), so do not
implement these against a live program yet.

## Where it goes

`crates/octravpn-core/src/v3_calls.rs` is the single source of truth for
the wire shape (both `octravpn-node::chain_v3` and
`octravpn-client::chain_v3` delegate to it). Every method delegates to
the generic `ContractCallBuilder::call(method, params, value, fee, nonce)`
after substituting a `method::` constant — the method name never appears
as a stringly-typed literal at the call site.

## 1. Method-name constants

Add to the `pub mod method { ... }` block, matching the existing doc-comment
style (AML signature in the doc comment):

```rust
/// `payable mint_credit()` — buys credit 1:1 with attached OCT.
pub const MINT_CREDIT: &str = "mint_credit";
/// `transfer_credit(to, amount)`.
pub const TRANSFER_CREDIT: &str = "transfer_credit";
/// `nonreentrant redeem_credit_to_native(amount)`.
pub const REDEEM_CREDIT_TO_NATIVE: &str = "redeem_credit_to_native";
/// `deposit_credit_to_tailnet(tailnet_id, amount)`.
pub const DEPOSIT_CREDIT_TO_TAILNET: &str = "deposit_credit_to_tailnet";
```

## 2. Builder methods

Add to `impl ContractCallBuilder`, alongside the tailnet-treasury pair.
The signatures follow the crate convention exactly:
`(&self, params: &[Value], value: u64, fee: u64, nonce: u64) -> Value`.

```rust
/// Build a `mint_credit` call. Payable: no params; `value` is the OCT
/// attached to buy credit 1:1 (it becomes the caller's credit balance
/// AND grows credit_reserve). `params` is `&[]`.
pub fn mint_credit_call(&self, value: u64, fee: u64, nonce: u64) -> Value {
    self.call(method::MINT_CREDIT, &[], value, fee, nonce)
}

/// Build a `transfer_credit` call.
/// `params` order: `[to_addr, amount]`. `value` is 0.
pub fn transfer_credit_call(
    &self,
    params: &[Value],
    value: u64,
    fee: u64,
    nonce: u64,
) -> Value {
    self.call(method::TRANSFER_CREDIT, params, value, fee, nonce)
}

/// Build a `redeem_credit_to_native` call. Burns credit, pays the
/// caller native OCT out of credit_reserve.
/// `params` order: `[amount]`. `value` is 0.
pub fn redeem_credit_to_native_call(
    &self,
    params: &[Value],
    value: u64,
    fee: u64,
    nonce: u64,
) -> Value {
    self.call(method::REDEEM_CREDIT_TO_NATIVE, params, value, fee, nonce)
}

/// Build a `deposit_credit_to_tailnet` call. Burns the caller's credit
/// and re-earmarks the backing OCT into the tailnet treasury.
/// `params` order: `[tailnet_id, amount]`. `value` is 0.
pub fn deposit_credit_to_tailnet_call(
    &self,
    params: &[Value],
    value: u64,
    fee: u64,
    nonce: u64,
) -> Value {
    self.call(method::DEPOSIT_CREDIT_TO_TAILNET, params, value, fee, nonce)
}
```

### Signature note: `mint_credit_call` drops `params`

`mint_credit()` takes no AML args (the payment rides in `value`), so the
builder wrapper omits `params` and passes `&[]`. This is the only credit
wrapper that deviates from the `params: &[Value]` convention. If you'd
rather keep every wrapper uniform for macro/codegen reasons, keep the
`params: &[Value]` arg and `debug_assert!(params.is_empty())` instead.

## 3. Consumer wiring (both crates)

Each consumer holds a private `ContractCallBuilder` and exposes a thin
`build_<method>_call` that forwards to it. Add matching forwarders in
both:

- `crates/octravpn-node/src/chain_v3.rs`   (operator daemon)
- `crates/octravpn-client/src/chain_v3.rs` (client CLI)

e.g. `build_mint_credit_call(&self, value, fee, nonce)` -> delegates to
`self.builder.mint_credit_call(value, fee, nonce)`, and likewise for the
other three. Only add a forwarder to a crate that actually needs the op:

- Client CLI needs: `mint_credit`, `transfer_credit`,
  `redeem_credit_to_native`, `deposit_credit_to_tailnet` (all user flows).
- Operator daemon needs: none for MVP — the operator RECEIVES credit via
  the earn-in-credit branch of `settle_confirm` (server-side AML), not via
  a client-built call. It would only need `redeem_credit_to_native` /
  `transfer_credit` if operators cash out programmatically.

## 4. CLI surface (`crates/octravpn-node/src/v3_cli.rs`)

Add subcommands mirroring the existing `deposit-to-tailnet` /
`withdraw-tailnet-treasury` handlers:

- `credit mint --amount <OCT>`            (amount -> `value`, params `[]`)
- `credit transfer --to <addr> --amount <n>`
- `credit redeem --amount <n>`
- `credit deposit-tailnet --tailnet-id <id> --amount <n>`
- `credit balance --holder <addr>`  (read-only view -> `balance_of`)

## 5. Tests to pin the wire shape

Mirror the per-method unit tests at the bottom of `v3_calls.rs` — assert
exact JSON for each new method, e.g. `mint_credit_call` produces
`{"kind":"contract_call","method":"mint_credit","params":[],"value":<n>,...}`,
then add the consumers' delegation tests (node + client) asserting their
`build_*_call` yields byte-identical output. Also add a devnet smoke step
(new script, do NOT edit `v3-smoke.sh`) that runs
mint -> transfer -> redeem and mint -> deposit_credit_to_tailnet and
asserts `is_solvent()` stays true and `reserve_surplus() == 0` throughout.

## Wiring order / blockers

1. AML redeploy + confirm first (draft is unproven on devnet).
2. Add `method::` consts + builder methods (this file).
3. Wire both consumers' `build_*_call` forwarders + CLI subcommands.
4. Unit tests (JSON pin) + delegation tests + devnet solvency smoke.
5. Governance: multisig/quorum BEFORE mainnet — the token holds real
   backing OCT, so single-owner-key blast radius is the gating risk (see
   the WARNING in the AML draft header).
