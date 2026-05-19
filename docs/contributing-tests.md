# Contributing — tests

The OctraVPN tree has ~200 cargo tests plus a stack of devnet drills,
formal-method jobs, and bench snapshots. This page is the one-pager on
how to use them.

## Before pushing

```
./scripts/test-all.sh
```

That's the contract. The script runs every gate that doesn't need a
funded devnet wallet:

1. `cargo build --workspace --all-targets`
2. `cargo test --workspace`
3. `cargo test -p octravpn-mesh --features test-helpers`
4. `cargo clippy --workspace --tests --features test-helpers -- -D warnings`
5. `scripts/bench-regression.sh` — compares a fresh
   `octravpn-core` bench against the committed snapshot.

If `test-all.sh` exits 0 you have a green run. CI runs the same gates;
your local result and CI's result should agree.

## Tests by surface

| Command                                                          | What it covers                                                                                |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `cargo test --workspace`                                         | The whole 199+ test suite: core crypto, mesh registry, node FSM, client portal, AML stubs.    |
| `cargo test -p octravpn-mesh --features test-helpers`            | The `PeerRegistry::publish_unverified` tests that the default feature set hides.              |
| `cargo test -p octravpn-core`                                    | Receipt sign/verify, pedersen, onion, earnings hash-chain, wallet enc/dec.                    |
| `cargo test -p octravpn-node`                                    | Operator daemon FSM + receipt-journal + settle path.                                          |
| `cargo test -p octravpn-mesh`                                    | STUN, peer registry, connection FSM, magic-DNS, tailnet bridge.                               |
| `cargo clippy --workspace --tests --features test-helpers -- -D warnings` | Lint gate the way CI runs it.                                                       |
| `./scripts/bench-regression.sh`                                  | `octravpn-core` criterion benches vs `bench-snapshots/core.json`. Fails on >20% slowdown.     |
| `./scripts/verify.sh`                                            | Cross-workspace verification: foundry crypto + octra workspace + (optional) Kani harnesses.   |
| `./scripts/compile-check.sh`                                     | AML compile-gate against `program/main.aml` via Octra RPC.                                    |

The exact count from `cargo test --workspace` is in the 199-test
neighbourhood as of the v3 migration; the workspace adds tests
faster than this doc gets updated.

## Adversarial drills (devnet)

Two drills live under `docker/devnet/`:

* `e2e-adversarial-v3.sh` — v3 main contract: 60+ negative cases
  covering registry/bond/slash/sessions/governance/pause, plus one
  positive ed25519 slash to confirm the path actually fires.
* `e2e-adversarial-v2.sh` — v2 slim registry: regression guard for
  governance-during-pause and intentional confirms.

Run them whenever you touch the AML programs (`program/main*.aml`) or
anything in the chain-side path (`crates/*/src/chain_*.rs`).

How to run:

```
# Funded deployer wallet, > 200 M OU on devnet.
export OCTRA_DEVNET_KEY=/path/to/deployer.key

# Either both drills via the unified runner:
OCTRA_RUN_DRILLS=1 ./scripts/test-all.sh

# Or each one independently:
bash docker/devnet/e2e-adversarial-v3.sh
bash docker/devnet/e2e-adversarial-v2.sh
```

Success looks like every line tagged `PASS` and no `FAIL` lines; a
`REGRESSION GUARD` line is a positive case we expect to confirm
on-chain. Failures print the exact RPC payload that didn't behave.

`scripts/test-all.sh` does **not** run drills by default — they cost
chain gas (devnet OU, but still) and need a wallet — but it will when
`OCTRA_RUN_DRILLS=1`.

For an end-to-end happy-path against devnet, set `OCTRA_RUN_SMOKE=1`
to call `docker/devnet/v3-smoke.sh` (deploys main-v3, drives the full
session lifecycle, replays the earnings hash-chain byte-for-byte
against the on-chain value).

## Bench snapshots

The committed snapshot is `bench-snapshots/core.json`. It captures
mean + 95% CI for every `octravpn-core` criterion bench
(`crates/octravpn-core/benches/core.rs`) under the exact criterion
args recorded in the JSON's `criterion_args` field.

`scripts/bench-regression.sh` re-runs the benches and fails CI if any
result is **more than 20% slower** than its snapshot mean. A bench
that's **>20% faster** is a soft warning — usually it means the
snapshot is stale and someone should re-record it.

When to refresh:

* You landed a perf-changing PR (added a fast path, swapped an algo,
  reduced allocations) and the speedup is real, not measurement noise.
* The committed snapshot host metadata is stale (e.g. moved to a
  different CI architecture).

How to refresh, matching the committed shape exactly:

```
cargo bench -p octravpn-core --bench core -- \
    --sample-size 20 --warm-up-time 1 --measurement-time 2
```

Then update `bench-snapshots/core.json` with the new `mean.point_estimate`
and `mean.confidence_interval.{lower,upper}_bound` from each
`target/criterion/<bench_id>/new/estimates.json`. Keep the `host` block
honest — record the actual machine you ran on, since absolute ns
numbers only make sense relative to the same host.

If `bench-regression.sh` becomes flaky on your hardware, bump
`BENCH_REGRESSION_PCT=30` for a one-off run; if it stays flaky, the
script (not your code) is the bug.

## CI

The workflows live in `.github/workflows/`:

* `ci.yml` runs the safe subset automatically on push/PR: `fmt`,
  `clippy` (with and without `test-helpers`), `test` (with and without
  `test-helpers`), `bench-regression`, plus TLA+/Tamarin/Lean/Kani,
  AML compile-gate, fuzz-build smoke, cargo-audit/deny, tarpaulin
  coverage, and the docker e2e (advisory).
* `release.yml` handles tag-driven release builds.

CI does **not** run the devnet drills or the v3 smoke — those need a
funded wallet, which lives outside the runner. Run them locally.

If you're hunting a CI failure: `./scripts/test-all.sh` reproduces the
required-blocking subset locally with the exact same flags.
