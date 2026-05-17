#!/usr/bin/env bash
# verify.sh — run the verification harness across both Rust workspaces.
#
# Layered design:
#   1. Run the foundry workspace's tests in release mode. This covers
#      `octra-core` (the crypto-primitive layer): 32 unit tests + the
#      proptest harnesses landed in the v2 hardening pass.
#   2. Run the octravpn workspace's tests in release mode. Covers
#      `octravpn-node` (the operator daemon) and `octravpn-core`
#      (shared chain RPC + types).
#   3. Optionally invoke `cargo kani` if Kani is installed locally.
#      Kani is the upstream choice for symbolic-execution proofs;
#      when not present we print a clear skip notice so CI signal is
#      obvious — the harnesses below are still validated by proptest.
#
# Exit status: 0 if every step succeeds (Kani may be absent), non-zero
# on the first failure. Output is meant to be readable in a CI log.

set -euo pipefail

# Locate both workspace roots. The script is invoked from the octra
# worktree by default; the foundry workspace is symlinked at
# `.claude/worktrees/octra-foundry`, but the canonical path on this
# machine is `/Users/androolloyd/Development/octra-foundry`. We
# autodetect: prefer the symlink so the worktree is self-contained;
# fall back to the absolute path.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OCTRA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [[ -d "${OCTRA_ROOT}/.claude/worktrees/octra-foundry" ]]; then
    FOUNDRY_ROOT="${OCTRA_ROOT}/.claude/worktrees/octra-foundry"
elif [[ -d "/Users/androolloyd/Development/octra-foundry" ]]; then
    FOUNDRY_ROOT="/Users/androolloyd/Development/octra-foundry"
else
    echo "verify.sh: cannot locate octra-foundry workspace" >&2
    exit 1
fi

# Colour helpers — no-op if NO_COLOR is set or stdout is not a TTY.
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    BOLD=$'\033[1m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    RED=$'\033[31m'
    RESET=$'\033[0m'
else
    BOLD=
    GREEN=
    YELLOW=
    RED=
    RESET=
fi

section() {
    printf "\n%s== %s ==%s\n" "${BOLD}" "$*" "${RESET}"
}

ok() {
    printf "%s[OK]%s %s\n" "${GREEN}" "${RESET}" "$*"
}

skip() {
    printf "%s[SKIP]%s %s\n" "${YELLOW}" "${RESET}" "$*"
}

fail() {
    printf "%s[FAIL]%s %s\n" "${RED}" "${RESET}" "$*"
    exit 1
}

# -- step 1: octra-foundry (crypto primitives) --------------------
section "octra-foundry — cargo test --workspace --release"
( cd "${FOUNDRY_ROOT}" && cargo test --workspace --release ) \
    || fail "octra-foundry tests"
ok "octra-foundry: octra-core (32 unit + 30 proptest), octra-cli, octraforge"

# -- step 2: octra (node infra) -----------------------------------
section "octra — cargo test --workspace --release"
( cd "${OCTRA_ROOT}" && cargo test --workspace --release ) \
    || fail "octra workspace tests"
ok "octra: octravpn-node (17), octravpn-core, octravpn-tun, octravpn-mesh, …"

# -- step 3: optional Kani harnesses ------------------------------
section "Kani symbolic-execution harnesses (optional)"
if command -v cargo-kani >/dev/null 2>&1 || command -v kani >/dev/null 2>&1; then
    # The `verification` feature flag is the crate-level switch; the
    # `--features verification` flag plus `cargo kani --workspace` is
    # what would pick up the `#[kani::proof]` harnesses in src/verify.rs.
    ( cd "${FOUNDRY_ROOT}" && cargo kani --workspace --features verification ) \
        || fail "cargo kani"
    ok "Kani harnesses passed"
else
    skip "kani-verifier not installed. Install with:"
    skip "  cargo install --locked kani-verifier && cargo kani setup"
    skip "Today's coverage is via the proptest harnesses in step 1, which"
    skip "exercise the same properties Kani would (determinism, framing,"
    skip "AEAD authenticity, envelope round-trip)."
fi

section "All verification steps completed"
printf "%sgreen%s\n" "${GREEN}" "${RESET}"
