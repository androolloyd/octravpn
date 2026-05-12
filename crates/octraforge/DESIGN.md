# octraforge — a Foundry-style test framework for Octra programs

`octraforge` brings the ergonomics of `forge` (Solidity) to Octra programs. The
first user is `OctraVPN`. Tests are plain Rust functions; cheatcodes are method
calls on a `ForgeCtx` handle that wraps a Rust-modeled program runtime — the
in-process `octravpn_mock_rpc::ChainState`. We treat the mock as ground truth
because there is no AML interpreter in this repo.

## API shape

```rust
#[octra_test]
fn test_register_then_attest(forge: &mut ForgeCtx) {
    let v = forge.deploy_octravpn(/* min_bond */ 100, /* min_deposit */ 10);
    forge.prank("octV1...");
    forge.deal("octV1...", 1_000);
    let r = forge.register_validator("1.2.3.4:51820", "eu", 100);
    forge.expect_emit("ValidatorRegistered");
    r.assert_ok();
    forge.warp_epoch(3);
    forge.refresh_attestation().assert_ok();
}
```

`#[octra_test]` is a wrapper macro (declarative — `octra_test!`) that builds
a fresh `ForgeCtx`, runs the body, and lets `?` propagate. Each test gets an
isolated context: a brand-new `ChainState` with `epoch: 1`, no validators, no
sessions, an empty snapshot stack, and a fresh "expectations" buffer. Nothing
crosses test boundaries.

`ForgeCtx` is the equivalent of Foundry's `Vm` cheatcode contract plus the
test base class fused together. It owns:

- `state: ChainState` — the world.
- `program_addr: String` — the deployed program's address.
- `pranked_caller: Option<String>` — if set, used as `from` for the next
  submitted call (cleared after one use, like Foundry's `prank`).
- `expectations: Vec<Expectation>` — pending `expect_emit`/`expect_revert`
  asserted at end of next `submit`.
- `recorded_logs: Option<Vec<Value>>` — opt-in event capture buffer.
- `snapshots: Vec<ChainState>` — vector of full state clones. `snapshot()`
  returns an index; `revert_to(id)` truncates and restores.

## Cheatcodes

| Cheatcode | Foundry analogue |
|---|---|
| `forge.warp_epoch(n: u64)` | `vm.warp` / `vm.roll` |
| `forge.roll_epoch(delta: u64)` | `vm.roll(block.number + delta)` |
| `forge.prank(addr: &str)` | `vm.prank(addr)` (single-call) |
| `forge.start_prank(addr)` / `stop_prank()` | `vm.startPrank` / `stopPrank` |
| `forge.deal(addr, amount: u64)` | `vm.deal` |
| `forge.balance(addr) -> u64` | balance read |
| `forge.expect_emit(event_name)` | `vm.expectEmit` |
| `forge.expect_revert(substring)` | `vm.expectRevert("...")` |
| `forge.record_logs()` / `take_logs()` | `vm.recordLogs` / `getRecordedLogs` |
| `forge.snapshot() -> SnapshotId` | `vm.snapshot()` |
| `forge.revert_to(SnapshotId)` | `vm.revertTo(id)` |
| `forge.current_epoch() -> u64` | `block.number` |

`expect_revert` works because `submit` returns `Result<SubmitResult, String>`
and the harness asserts the substring on `Err`. `expect_emit` queues a check
that fires inside `submit`'s success path.

## Testing the actual `OctraVPN` program

Domain helpers in `octraforge::octravpn` build canonical JSON envelopes
matching the AML method signatures, sign them with `octravpn_core::tx::sign_call`
where appropriate, and call `forge.submit(call)`. The chain state lives in
`ChainState` and is mutated by `octravpn_mock_rpc::submit_tx` — the same code
path the HTTP mock router uses, but invoked in-process. No threads, no ports,
no async runtime needed.

```rust
forge.deploy_octravpn(min_bond, min_deposit);
forge.call_register_validator(endpoint, wg_pk, view_pk, region, price);
forge.call_open_session(route_commit, csp, stealth, deposit);
forge.call_settle_session(sid, seq, bytes_used, blind, openings);
forge.call_claim_earnings(amount, blind, stealth);
forge.call_slash_double_sign(...);  // future
forge.call_slash_offline(...);      // future
```

Every `call_*` returns `SubmitResult { hash, events, gas_used }` — Foundry-ish
but borrows `Vec<Event>` directly so callers can `result.events.iter().find(...)`.

## Fuzzing

`proptest` integrates as a free function: tests written with `#[octra_test]`
just open a `proptest!` block inside the body and re-snapshot before each
strategy iteration. We provide `forge::fuzz!(strategy, |inputs, ctx| { ... })`
that does this for the common case: snapshot → run body → revert.

```rust
forge::fuzz!(0u64..1_000_000, |bytes_used, forge| {
    let snap = forge.snapshot();
    forge.call_settle_session(sid, 1, bytes_used, blind, ops);
    forge.revert_to(snap);
});
```

## Isolation

Each `#[octra_test]` invocation calls `ForgeCtx::new()`, which allocates a
fresh `ChainState`. There is no global state, no thread-locals, no shared
mock server, so tests run safely under `cargo test`'s default thread pool.
The snapshot/revert API uses simple `Clone` of `ChainState`, which is already
`Clone` in the mock — cheap because the validator/session/earnings maps are
small (test-sized).

## Out of scope (deferred)

- Coverage instrumentation (`forge coverage`): would require an AML interpreter.
- Trace decoding (`forge inspect`): no ABI artifact format yet.
- True `#[octra_test]` proc-macro: shipped as a declarative `octra_test!`
  macro for v0; promoting to a proc-macro is a mechanical follow-up.
