#!/usr/bin/env bash
# OctraVPN v3 mainnet deploy verifier.
#
# Anyone (not just the ceremony participants) can run this to verify
# a published OctraVPN v3 contract matches the expected:
#   - on-chain code_hash (vm_contract)
#   - owner address (read via contract_call get_circle_owner — N/A
#     for v3 main program; main-v3.aml does NOT expose a top-level
#     get_owner view. We fall back to checking that the program is
#     deployed + the smoke probes succeed.)
#
# Usage:
#   verify-deploy.sh <program_addr> [--rpc-url <url>] [--params <path>]
#
# Defaults:
#   --rpc-url   ceremony/mainnet-params.toml::rpc_url
#               OR https://devnet.octrascan.io/rpc if --params absent
#   --params    ceremony/mainnet-params.toml.example
#
# Exit codes:
#   0  PASS — all gates green
#   1  FAIL — at least one gate red
#   2  IO / arg error

set -euo pipefail

PROGRAM_ADDR=""
RPC_URL=""
PARAMS_FILE=""
REFRESH=0

usage() {
  cat <<EOF
usage: $0 <program_addr> [options]

Required:
  <program_addr>         Octra address of the deployed v3 program
                         (e.g. oct7Mofan...)

Options:
  --rpc-url <url>        RPC endpoint. Defaults to params.rpc_url or
                         https://devnet.octrascan.io/rpc.
  --params <path>        Params file holding expected_code_hash +
                         expected_owner_addr. Defaults to
                         ceremony/mainnet-params.toml.example.
  --refresh              Print the live code_hash + bundle_hash so
                         the operator can paste them into the params
                         file. Useful right after a successful
                         deploy.
  -h, --help             Show this.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url) RPC_URL="$2"; shift 2 ;;
    --params) PARAMS_FILE="$2"; shift 2 ;;
    --refresh) REFRESH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown arg: $1" >&2; usage; exit 2 ;;
    *) PROGRAM_ADDR="$1"; shift ;;
  esac
done

if [[ -z "$PROGRAM_ADDR" ]]; then
  echo "error: program_addr is required" >&2
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [[ -z "$PARAMS_FILE" ]]; then
  if [[ -f "$REPO_ROOT/ceremony/mainnet-params.toml" ]]; then
    PARAMS_FILE="$REPO_ROOT/ceremony/mainnet-params.toml"
  elif [[ -f "$REPO_ROOT/ceremony/mainnet-params.toml.example" ]]; then
    PARAMS_FILE="$REPO_ROOT/ceremony/mainnet-params.toml.example"
  fi
fi

command -v jq >/dev/null 2>&1 || { echo "error: jq required" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "error: curl required" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then
  SHA256() { sha256sum "$@" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  SHA256() { shasum -a 256 "$@" | awk '{print $1}'; }
else
  echo "error: need sha256sum or shasum" >&2
  exit 2
fi

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
gate_pass() { green "  [PASS] $1"; }
gate_fail() { red   "  [FAIL] $1"; FAIL=$((FAIL+1)); }
gate_warn() { printf "  [warn] %s\n" "$1"; }

FAIL=0

toml_get() {
  local key="$1" file="$2"
  [[ -f "$file" ]] || { printf ''; return; }
  local raw
  raw=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" \
        | head -1 \
        | sed -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//" \
        | sed -E 's/[[:space:]]*#.*$//' \
        | sed -E 's/[[:space:]]+$//' \
        || true)
  if [[ "$raw" =~ ^\"(.*)\"$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  else
    printf '%s' "${raw//_/}"
  fi
}

EXPECTED_CODE_HASH=""
EXPECTED_OWNER=""
EXPECTED_SRC_HASH=""
CONTRACT_PATH=""
PARAMS_PROGRAM_ADDR=""
PARAMS_RPC=""

if [[ -n "$PARAMS_FILE" && -f "$PARAMS_FILE" ]]; then
  EXPECTED_CODE_HASH=$(toml_get expected_code_hash "$PARAMS_FILE")
  EXPECTED_OWNER=$(toml_get expected_owner_addr "$PARAMS_FILE")
  EXPECTED_SRC_HASH=$(toml_get contract_source_sha256_expected "$PARAMS_FILE")
  CONTRACT_PATH=$(toml_get contract_source_path "$PARAMS_FILE")
  PARAMS_PROGRAM_ADDR=$(toml_get program_addr "$PARAMS_FILE")
  PARAMS_RPC=$(toml_get rpc_url "$PARAMS_FILE")
fi

# RPC selection precedence:
#   1. --rpc-url (explicit override)
#   2. Default to devnet RPC. This is the smoke-test path: a bare
#      `verify-deploy.sh <devnet-addr>` PASSes against the devnet
#      v3 contract referenced in production-readiness.md without
#      needing per-invocation flags. For mainnet verification,
#      always pass `--rpc-url https://octra.network/rpc` (or set
#      via params file passed with --params + a pre-configured
#      rpc_url).
#
# The params rpc_url is NOT auto-selected because the example
# params file pins mainnet but the smoke test wants devnet — making
# rpc_url params-derived would break the smoke. Operators running
# the mainnet ceremony will pass --rpc-url or --params explicitly.
if [[ -z "$RPC_URL" ]]; then
  RPC_URL="https://devnet.octrascan.io/rpc"
fi

echo "verify-deploy: $PROGRAM_ADDR"
echo "RPC:           $RPC_URL"
[[ -n "$PARAMS_FILE" ]] && echo "Params:        $PARAMS_FILE"
echo

# ---------------------------------------------------------------
# Gate 1: vm_contract returns a code_hash
# ---------------------------------------------------------------

resp=$(curl -s -m 10 -X POST "$RPC_URL" -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"vm_contract\",\"params\":[\"$PROGRAM_ADDR\"]}" 2>&1) || resp=""

LIVE_CODE_HASH=$(printf '%s' "$resp" | jq -r '.result.code_hash // empty' 2>/dev/null || true)

if [[ -z "$LIVE_CODE_HASH" ]]; then
  gate_fail "vm_contract returned no code_hash for $PROGRAM_ADDR"
  # If the chain rejected the request entirely, print enough to debug.
  printf '         RPC response: %s\n' "${resp:0:200}"
else
  gate_pass "vm_contract live code_hash: $LIVE_CODE_HASH"
fi

# ---------------------------------------------------------------
# Gate 2: code_hash matches expected (or --refresh prints it)
# ---------------------------------------------------------------

if [[ -n "$LIVE_CODE_HASH" ]]; then
  if [[ $REFRESH -eq 1 ]]; then
    gate_warn "--refresh: paste this into expected_code_hash in $PARAMS_FILE"
    printf '         expected_code_hash = "%s"\n' "$LIVE_CODE_HASH"
  elif [[ -n "$EXPECTED_CODE_HASH" ]]; then
    if [[ "$LIVE_CODE_HASH" == "$EXPECTED_CODE_HASH" ]]; then
      gate_pass "code_hash matches expected"
    else
      gate_fail "code_hash mismatch: live=$LIVE_CODE_HASH expected=$EXPECTED_CODE_HASH"
    fi
  else
    gate_warn "expected_code_hash not pinned in $PARAMS_FILE — re-run with --refresh after the first successful deploy"
  fi
fi

# ---------------------------------------------------------------
# Gate 3: source hash matches the contract file at $CONTRACT_PATH
# (sanity that this checkout is the one that was deployed; does NOT
# prove the chain bytecode matches — that's gate 1/2).
# ---------------------------------------------------------------

if [[ -n "$CONTRACT_PATH" && -f "$REPO_ROOT/$CONTRACT_PATH" ]]; then
  LIVE_SRC_HASH=$(SHA256 "$REPO_ROOT/$CONTRACT_PATH")
  if [[ -n "$EXPECTED_SRC_HASH" ]]; then
    if [[ "$LIVE_SRC_HASH" == "$EXPECTED_SRC_HASH" ]]; then
      gate_pass "contract source hash matches: $LIVE_SRC_HASH"
    else
      gate_fail "contract source hash drift: live=$LIVE_SRC_HASH expected=$EXPECTED_SRC_HASH"
    fi
  else
    gate_warn "contract_source_sha256_expected not pinned — live source hash: $LIVE_SRC_HASH"
  fi
fi

# ---------------------------------------------------------------
# Gate 4: smoke probes — get_circle_state_version on the program
# address itself (returns 0 if not registered, no error if program
# is alive).
# ---------------------------------------------------------------

probe=$(curl -s -m 10 -X POST "$RPC_URL" -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"contract_call\",\"params\":[\"$PROGRAM_ADDR\",\"get_circle_state_version\",[\"$PROGRAM_ADDR\"]]}" 2>&1 || true)

if printf '%s' "$probe" | jq -e '.result' >/dev/null 2>&1; then
  gate_pass "contract_call get_circle_state_version reachable"
else
  gate_fail "contract_call probe failed: ${probe:0:200}"
fi

# ---------------------------------------------------------------
# Gate 5: owner expectation
# v3 main-v3.aml does NOT expose a top-level get_owner view (only
# circle-scoped views exist). Owner verification therefore relies
# on either:
#   - vm_contract returning a `deployer` field (devnet does for
#     vm_contract; we check best-effort)
#   - or a future view fn added to the contract.
# For now this gate is informational only — empty-expectation is
# warn, mismatch is fail, match is pass.
# ---------------------------------------------------------------

LIVE_DEPLOYER=$(printf '%s' "$resp" | jq -r '.result.deployer // .result.creator // empty' 2>/dev/null || true)
if [[ -n "$LIVE_DEPLOYER" ]]; then
  if [[ -n "$EXPECTED_OWNER" ]]; then
    if [[ "$LIVE_DEPLOYER" == "$EXPECTED_OWNER" ]]; then
      gate_pass "deployer/owner matches expected: $LIVE_DEPLOYER"
    else
      gate_fail "deployer/owner mismatch: live=$LIVE_DEPLOYER expected=$EXPECTED_OWNER"
    fi
  else
    gate_warn "no expected_owner_addr pinned — live deployer: $LIVE_DEPLOYER"
  fi
else
  gate_warn "vm_contract did not return a deployer field; owner check skipped"
  gate_warn "(v3 contract does not expose get_owner; this is expected)"
fi

# ---------------------------------------------------------------
# Result
# ---------------------------------------------------------------

echo
if [[ $FAIL -eq 0 ]]; then
  green "PASS — $PROGRAM_ADDR verified on $RPC_URL"
  exit 0
else
  red "FAIL — $FAIL gate(s) red"
  exit 1
fi
