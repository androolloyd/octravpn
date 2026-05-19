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
| `./scripts/bench-regression.sh`                                  | `octravpn-core` criterion benches vs `bench-snapshots/core.json`. Fails on >5% slowdown.      |
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
result is **more than 5% slower** than its snapshot mean. A bench
that's **>5% faster** is a soft warning — usually it means the
snapshot is stale and someone should re-record it.

The threshold was tightened 20% -> 5% in PR #244. The quick-mode
measurement window also went 1 s -> 10 s to keep variance under the
new gate; without the longer window a 5% threshold was within the
runner noise floor.

When to refresh:

* You landed a perf-changing PR (added a fast path, swapped an algo,
  reduced allocations) and the speedup is real, not measurement noise.
* The committed snapshot host metadata is stale (e.g. moved to a
  different CI architecture).

### When to bump (per-bench override)

If a bench is structurally noisier than 5% on the configured host —
e.g. an FHE pass that the kernel scheduler shoves around between
cores, or a flakily-allocating bench whose CV jumps with malloc-arena
pressure — bump it per-bench rather than relaxing the workspace-wide
threshold. Two ways:

1. Permanent (committed): edit `bench-snapshots/thresholds.json` and
   add an entry under `overrides`. Document the cause in `reason` so
   the next person reading the file knows whether the bench is
   structurally noisy or the snapshot is stale. Drop the entry when
   the bench is rewritten / the snapshot is refreshed.

   ```json
   {
     "overrides": {
       "onion_peel_layer": {
         "threshold_pct": 30,
         "reason": "thermal-state-sensitive curve25519 path — see PR #244"
       }
     }
   }
   ```

2. One-off (env var): `BENCH_REGRESSION_PCT_<UPPERCASED-BENCH-NAME>=<int>
   ./scripts/bench-regression.sh`. The script normalises `-` and `/`
   in the bench-id to `_`. Use this when chasing a flake locally; if
   the bump turns out to be needed long-term, move it into
   `thresholds.json`.

The committed overrides as of PR #244 cover every bench whose
quick-mode steady-state delta exceeds the 5% global gate on the
snapshot host (Apple M3 Max). Each entry carries a `reason` field.
Once the snapshot is recaptured under quick-mode settings on a quiet
host the overrides should be removable.

### Fuzz harnesses (nightly)

`.github/workflows/fuzz.yml` runs `cargo +nightly fuzz run` for each
target in `fuzz/fuzz_targets/` on the nightly cron + on-demand
(`workflow_dispatch`). PR #243 wired the nightly run; the
`fuzz-build` job in `ci.yml` is still the per-PR build-smoke gate.

The nightly job:

* Time-budgets each target to 5 min (`-max_total_time=300 -timeout=10`).
  Override at dispatch time via the `max_total_time` input.
* Caches `fuzz/corpus/<target>` + `fuzz/artifacts/<target>` across
  runs so coverage compounds rather than restarting cold.
* On a finding (libfuzzer exit non-zero, non-77), uploads the corpus
  + artifacts as a GH artifact and opens a `fuzz-crash` issue with a
  copy-pasteable repro command. Recurrences comment on the existing
  issue rather than spamming.

Targets that run nightly (matrix is hardcoded in the workflow; update
the list whenever a new fuzz target lands):

* `receipt_decode`
* `onion_peel`
* `tx_canonical`
* `fuzz_acl_parse`
* `fuzz_peer_snapshot_decode`
* `fuzz_ip_alloc`

To reproduce a crash locally:

```
cd fuzz
cargo +nightly fuzz run <target> <path-to-artifact>
```

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
