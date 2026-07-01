#!/usr/bin/env bash
#
# run-headscale-parity.sh — local, Docker-free driver for the headscale-go
# differential parity gate.
#
# This is a thin wrapper. The actual harness lives in the headscale-rs
# sibling repo (tools/parity/*, scripts/headscale_go_diff.sh,
# scripts/check_parity_golden.py). octravpn compiles the very same
# headscale-api / headscale-api-acl crates that the harness exercises
# (crates/octravpn-mesh/Cargo.toml), so a parity regression there is a
# parity regression here. Running this before you push saves a CI round
# trip against .github/workflows/headscale-parity.yml.
#
# Usage:
#   scripts/run-headscale-parity.sh
#   HEADSCALE_RS_DIR=/path/to/headscale-rs scripts/run-headscale-parity.sh
#   PARITY_UPDATE_GOLDEN=1 scripts/run-headscale-parity.sh   # refresh golden
#
# Environment:
#   HEADSCALE_RS_DIR      Path to the headscale-rs checkout.
#                         Default: <octra>/../headscale-rs
#   PARITY_UPDATE_GOLDEN  Passed through to the harness (1 = rewrite the
#                         checked-in golden after a reviewed change).
#
# NOTE: the differential harness runs `cargo run` to build the Rust parity
# binary and `go run` to build the Go side, then diffs their JSON output.
# That means it is NOT hermetic-free of a build — expect a cold first run
# to compile the headscale-api crate and download the pinned headscale-go
# module tree. Subsequent runs are fast.
#
set -euo pipefail

log()  { printf '\033[1;34m[parity]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[parity] error:\033[0m %s\n' "$*" >&2; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
octra_root="$(cd "${script_dir}/.." && pwd)"

# Locate the sibling headscale-rs checkout.
headscale_rs_dir="${HEADSCALE_RS_DIR:-${octra_root}/../headscale-rs}"
if [[ ! -d "${headscale_rs_dir}" ]]; then
  err "headscale-rs checkout not found at: ${headscale_rs_dir}"
  err "Clone it next to octra, or set HEADSCALE_RS_DIR=/path/to/headscale-rs."
  exit 2
fi
headscale_rs_dir="$(cd "${headscale_rs_dir}" && pwd)"

diff_sh="${headscale_rs_dir}/scripts/headscale_go_diff.sh"
golden_py="${headscale_rs_dir}/scripts/check_parity_golden.py"
refs_py="${headscale_rs_dir}/scripts/check_headscale_go_refs.py"
if [[ ! -x "${diff_sh}" ]]; then
  err "harness not found (or not executable): ${diff_sh}"
  err "Is ${headscale_rs_dir} really a headscale-rs checkout?"
  exit 2
fi

# Tool preflight. Report ALL missing tools at once, not one-at-a-time.
missing=0
require() {
  local bin="$1" why="$2"
  if ! command -v "${bin}" >/dev/null 2>&1; then
    err "missing '${bin}' — needed for ${why}"
    missing=1
  fi
}
require python3 "the hermetic metadata + golden coverage checks"
require cargo   "building the Rust (headscale-rs) side of the diff"
require go      "building the headscale-go side of the diff"
require ruby    "the JSON diff + golden comparison in the harness"
if (( missing )); then
  err "install the tools above and re-run. This gate is otherwise CI-only"
  err "(see .github/workflows/headscale-parity.yml)."
  exit 3
fi

log "octra:        ${octra_root}"
log "headscale-rs: ${headscale_rs_dir}"
log "go:           $(go version 2>/dev/null || echo '?')"
log "ruby:         $(ruby --version 2>/dev/null || echo '?')"

cd "${headscale_rs_dir}"

# 1. Hermetic metadata gate (no cargo/go/ruby): pinned go.mod version has a
#    matching active golden, scenario filenames == `name` fields, and the
#    pinned/current-head goldens cover the scenario sets exactly.
log "metadata + golden coverage check ..."
python3 "${golden_py}"

# 2. Hermetic pin-consistency gate. Run WITHOUT --remote on purpose: the
#    --remote mode does a live `git ls-remote` against upstream headscale's
#    moving `main`, which is non-deterministic. We keep only the local check.
if [[ -f "${refs_py}" ]]; then
  log "pin consistency check (local, no network) ..."
  python3 "${refs_py}"
fi

# 3. The differential harness itself (cargo + go + ruby). Fails loudly on any
#    Rust-vs-Go or Go-vs-golden drift. PARITY_UPDATE_GOLDEN flows through.
scenario_count="$(find tools/parity/scenarios -name '*.json' -type f | wc -l | tr -d ' ')"
log "running differential harness over ${scenario_count} scenarios ..."
"${diff_sh}"

log "headscale-go parity OK (${scenario_count} scenarios)"
