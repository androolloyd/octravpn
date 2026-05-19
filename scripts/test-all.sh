#!/usr/bin/env bash
# test-all.sh — single entry point for "did my change break anything?".
#
# Required (always runs):
#   * cargo build --workspace --all-targets
#   * cargo test  --workspace
#   * cargo test  -p octravpn-mesh --features test-helpers
#   * cargo clippy --workspace --tests --features test-helpers -- -D warnings
#   * scripts/bench-regression.sh against bench-snapshots/core.json
#
# Opt-in (skipped unless the matching env var is set):
#   OCTRA_RUN_DRILLS=1   — run v3 + v2 adversarial drills against devnet.
#                          Requires a funded deployer wallet pointed at by
#                          OCTRA_DEVNET_KEY (consumed by the drill scripts).
#   OCTRA_RUN_SMOKE=1    — run docker/devnet/v3-smoke.sh end-to-end.
#
# Override knobs:
#   BENCH_REGRESSION_PCT — pass-through tolerance (default 20%).
#   BENCH_REGRESSION_QUICK=1 — shrink criterion measurement time so the
#                          gate fits in a 1-minute CI window. The 20%
#                          threshold still holds; only sensitivity drops.
#
# Exit 0 on success; non-zero (via `set -e`) on the first failing step.

set -euo pipefail
cd "$(dirname "$0")/.."

say() { printf '\n=== %s ===\n' "$*"; }

say "cargo workspace"
cargo build --workspace --all-targets
cargo test --workspace
cargo test -p octravpn-mesh --features test-helpers
cargo clippy --workspace --tests --features test-helpers -- -D warnings

say "bench snapshots"
./scripts/bench-regression.sh

if [[ "${OCTRA_RUN_DRILLS:-0}" == "1" ]]; then
  say "adversarial drills (require OCTRA_DEVNET_KEY)"
  : "${OCTRA_DEVNET_KEY:?set OCTRA_DEVNET_KEY=path/to/deployer.key}"
  # v3 first (current production target), then v2 (still-shippable
  # slim registry). v1.1 is no longer drilled in CI — its semantics are
  # subsumed by v2's REGRESSION GUARD cases.
  for tier in v3 v2; do
    say "adversarial drill: ${tier}"
    bash "docker/devnet/e2e-adversarial-${tier}.sh"
  done
else
  say "adversarial drills (skipped — set OCTRA_RUN_DRILLS=1 + OCTRA_DEVNET_KEY)"
fi

if [[ "${OCTRA_RUN_SMOKE:-0}" == "1" ]]; then
  say "devnet smoke"
  bash docker/devnet/v3-smoke.sh
else
  say "devnet smoke (skipped — set OCTRA_RUN_SMOKE=1)"
fi

say "PASS"
