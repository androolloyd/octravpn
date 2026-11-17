#!/usr/bin/env bash
# One shard of the workspace test suite.
#
# On one runner the suite is ~20 minutes of compiling and ~65 minutes of
# tests, and three packages account for almost all of the test time
# (octra-node-runtime ~45 min, octra-hfhe ~21, octra-node ~15; the other
# sixteen packages share ~5). CI therefore runs these shards in parallel —
# see the `test` matrix in .github/workflows/ci.yml.
#
# Shards are package-level, so each one is an ordinary `cargo test -p …`.
# Nothing here changes which tests exist or how they run: `rest` is
# "the workspace minus the heavy packages", so a new package lands there
# without anyone remembering to list it, and the two runtime shards split
# that package's integration-test targets by name, covering all of them.
#
#   scripts/ci/test-shard.sh <shard> [extra cargo-test args]
#   scripts/ci/test-shard.sh all            # every shard, in sequence
#   scripts/ci/test-shard.sh list
#
# OCTRA_TEST_PROFILE=dev drops --release (useful with --no-run to check
# that every shard still resolves and compiles).
set -euo pipefail
cd "$(dirname "$0")/../.."

SHARDS=(node runtime runtime-circle crypto rest)
# Packages with their own shard; everything else is `rest`.
HEAVY=(octra-node octra-node-runtime octra-hfhe octra-pvac pvac-sidecar-ipc-tests)

shard="${1:-}"
[[ -n "$shard" ]] || { echo "usage: $0 <${SHARDS[*]}|all|list> [cargo-test args]" >&2; exit 2; }
shift
extra=("$@")

profile=(--release)
[[ "${OCTRA_TEST_PROFILE:-release}" == "dev" ]] && profile=()

run() {
  # `${a[@]+"${a[@]}"}` keeps an empty array legal under `set -u` on bash 3.2.
  local cmd=(cargo test --locked ${profile[@]+"${profile[@]}"} "$@" ${extra[@]+"${extra[@]}"})
  printf '+ %s\n' "${cmd[*]}" >&2
  "${cmd[@]}"
}

# Integration-test target names of octra-node-runtime, straight from cargo so
# `tests/foo.rs`, `tests/foo/main.rs` and `[[test]]` entries are all seen.
runtime_tests() {
  cargo metadata --locked --no-deps --format-version 1 | python3 -c '
import json, sys
for package in json.load(sys.stdin)["packages"]:
    if package["name"] == "octra-node-runtime":
        for target in package["targets"]:
            if "test" in target["kind"]:
                print(target["name"])'
}

run_shard() {
  local args=() name
  case "$1" in
    node)
      run -p octra-node --all-targets --all-features
      ;;
    runtime-circle)
      # The Circle host parity targets; `circle_parity` replays the native
      # host through a nested build and is ~20 minutes by itself.
      while IFS= read -r name; do
        [[ "$name" == circle_* ]] && args+=(--test "$name")
      done < <(runtime_tests)
      run -p octra-node-runtime --all-features "${args[@]}"
      ;;
    runtime)
      args=(--lib --bins --examples --benches)
      while IFS= read -r name; do
        [[ "$name" == circle_* ]] || args+=(--test "$name")
      done < <(runtime_tests)
      run -p octra-node-runtime --all-features "${args[@]}"
      ;;
    crypto)
      run -p octra-hfhe -p octra-pvac -p pvac-sidecar-ipc-tests --all-targets --all-features
      ;;
    rest)
      for name in "${HEAVY[@]}"; do args+=(--exclude "$name"); done
      run --workspace "${args[@]}" --all-targets --all-features
      # A change that builds under --all-features but breaks the
      # feature-isolated mesh build must fail here.
      run -p octravpn-mesh --all-targets --features test-helpers
      ;;
    *)
      echo "unknown shard: $1 (expected one of: ${SHARDS[*]})" >&2
      exit 2
      ;;
  esac
}

case "$shard" in
  list) printf '%s\n' "${SHARDS[@]}" ;;
  all)  for name in "${SHARDS[@]}"; do run_shard "$name"; done ;;
  *)    run_shard "$shard" ;;
esac
