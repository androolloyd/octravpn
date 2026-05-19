#!/usr/bin/env bash
# scripts/security/redteam.sh — automated red-team driver.
#
# Runs the full adversarial / fuzz / RPC-fuzz battery and exits
# non-zero with a structured report if any defense failed.
#
# Usage:
#   bash scripts/security/redteam.sh                 # full run
#   FUZZ_SECS=120 bash scripts/security/redteam.sh   # short fuzz pass
#   SKIP_ADV=1   bash scripts/security/redteam.sh   # skip adversarial drills
#   SKIP_FUZZ=1  bash scripts/security/redteam.sh   # skip fuzz suite
#   SKIP_RPCFUZZ=1 bash scripts/security/redteam.sh # skip curl RPC fuzzer
#
# Environment:
#   FUZZ_SECS         — seconds per fuzz target (default 600 = 10 min)
#   OCTRA_RPC_URL     — RPC to hit for the curl fuzzer (default mock)
#   REDTEAM_REPORT    — path to write the JSON report
#                       (default: target/redteam-report.json)
#
# Exit codes:
#   0  — every defense held
#   1  — adversarial drill reported a confirmed-but-shouldn't-be
#   2  — fuzz target panicked or returned non-zero
#   3  — RPC fuzzer found a server panic / 5xx that should be 4xx
#   4  — driver-level failure (missing tool, bad env, etc.)

set -uo pipefail

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Resolve repo root from this script's location (handles being invoked
# from anywhere).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

FUZZ_SECS="${FUZZ_SECS:-600}"
SKIP_ADV="${SKIP_ADV:-0}"
SKIP_FUZZ="${SKIP_FUZZ:-0}"
SKIP_RPCFUZZ="${SKIP_RPCFUZZ:-0}"
OCTRA_RPC_URL="${OCTRA_RPC_URL:-http://localhost:8545}"
REDTEAM_REPORT="${REDTEAM_REPORT:-target/redteam-report.json}"

mkdir -p "$(dirname "$REDTEAM_REPORT")"

# Color
G='\033[32m'; R='\033[31m'; Y='\033[33m'; C='\033[36m'; B='\033[1m'; NC='\033[0m'
hdr()  { printf "\n${C}══════ %s ══════${NC}\n" "$*"; }
ok()   { printf "  ${G}OK${NC}  %s\n" "$*"; }
fail() { printf "  ${R}FAIL${NC} %s\n" "$*"; }
warn() { printf "  ${Y}WARN${NC} %s\n" "$*"; }
say()  { printf "       %s\n" "$*"; }

# Findings accumulator. Each finding is appended as one line of JSON
# to a tmpfile; at the end we wrap it into the structured report.
findings_tmp="$(mktemp)"
trap 'rm -f "$findings_tmp"' EXIT

push_finding() {
  # $1 class (adv|fuzz|rpc|driver)
  # $2 severity (high|medium|low|info)
  # $3 target
  # $4 detail
  printf '{"class":"%s","severity":"%s","target":%s,"detail":%s}\n' \
    "$1" "$2" \
    "$(printf '%s' "$3" | jq -Rs .)" \
    "$(printf '%s' "$4" | jq -Rs .)" \
    >> "$findings_tmp"
}

start_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
overall_exit=0

# Reqd tools.
need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "missing required tool: $1"
    push_finding driver high "$1" "missing tool"
    overall_exit=4
  fi
}
need jq
need curl

# ---------------------------------------------------------------------------
# 1. Adversarial drills (docker/devnet/e2e-adversarial-*.sh)
# ---------------------------------------------------------------------------

if [[ "$SKIP_ADV" != "1" ]]; then
  hdr "Adversarial drills"
  shopt -s nullglob
  drills=(docker/devnet/e2e-adversarial-*.sh)
  shopt -u nullglob
  if [[ ${#drills[@]} -eq 0 ]]; then
    warn "no docker/devnet/e2e-adversarial-*.sh scripts found"
  fi
  for drill in "${drills[@]}"; do
    say "running $drill"
    log="target/redteam-$(basename "$drill" .sh).log"
    if bash "$drill" >"$log" 2>&1; then
      ok "$drill"
    else
      rc=$?
      fail "$drill exited $rc (log: $log)"
      push_finding adv high "$drill" "drill exited $rc — see $log"
      overall_exit=1
    fi
  done
else
  warn "adversarial drills skipped (SKIP_ADV=1)"
fi

# ---------------------------------------------------------------------------
# 2. Fuzz suite (libfuzzer / cargo-fuzz, FUZZ_SECS per target)
# ---------------------------------------------------------------------------

if [[ "$SKIP_FUZZ" != "1" ]]; then
  hdr "Fuzz suite (${FUZZ_SECS}s per target)"
  if ! command -v cargo >/dev/null 2>&1; then
    fail "cargo not on PATH; cannot run fuzz suite"
    push_finding driver high cargo "missing"
    overall_exit=4
  elif ! cargo fuzz --help >/dev/null 2>&1; then
    warn "cargo-fuzz not installed; skipping fuzz suite"
    warn "install with: cargo install --locked cargo-fuzz"
    push_finding driver low cargo-fuzz "not installed; fuzz suite skipped"
  else
    targets=(
      receipt_decode
      onion_peel
      tx_canonical
      fuzz_acl_parse
      fuzz_peer_snapshot_decode
      fuzz_ip_alloc
    )
    for t in "${targets[@]}"; do
      say "fuzz $t for ${FUZZ_SECS}s"
      log="target/redteam-fuzz-${t}.log"
      # cargo fuzz returns non-zero on crash; libfuzzer's
      # -max_total_time graceful-exits with 0 when time elapses.
      if (cd fuzz && cargo +nightly fuzz run "$t" -- \
            -max_total_time="$FUZZ_SECS" -timeout=30) \
            >"$log" 2>&1
      then
        ok "fuzz $t (no crashes)"
      else
        rc=$?
        fail "fuzz $t exited $rc (log: $log)"
        push_finding fuzz high "$t" "cargo fuzz run exited $rc — see $log"
        overall_exit=2
      fi
    done
  fi
else
  warn "fuzz suite skipped (SKIP_FUZZ=1)"
fi

# ---------------------------------------------------------------------------
# 3. RPC fuzzer (curl-based, hits the chain RPC + node control plane)
# ---------------------------------------------------------------------------

if [[ "$SKIP_RPCFUZZ" != "1" ]]; then
  hdr "RPC fuzzer ($OCTRA_RPC_URL)"
  # The fuzzer hits a small library of malformed payloads against
  # every known JSON-RPC method. A successful defense is:
  #   - HTTP 4xx (request rejected by the server), or
  #   - HTTP 200 with a JSON-RPC error object.
  # A defect is:
  #   - HTTP 5xx (server bug / panic),
  #   - timeout / connection-reset (server crashed),
  #   - HTTP 200 with a non-error result for a malformed input
  #     (silent acceptance).

  methods=(
    contract_call
    deploy_circle
    register_circle
    bond_endpoint
    settle_claim
    settle_confirm
    claim_earnings
    open_session
    sweep_session
    octra_balance
    octra_nonce
    octra_isValidator
    octra_listValidators
  )

  # Payload generators (each generator emits ONE malformed params array).
  gen_payload() {
    case $(( RANDOM % 8 )) in
      0) printf '[]' ;;                                          # empty
      1) printf 'null' ;;                                         # null
      2) printf '[{"$INVALID":[1,2,3]}]' ;;                       # nonsense keys
      3) printf '[%s]' "$(head -c 4096 /dev/urandom | base64)" ;; # giant string param
      4) printf '[{"value":-1,"nonce":-1,"fee":-1}]' ;;           # negative numbers
      5) printf '[{"to":"oct"}]' ;;                              # truncated addr
      6) printf '[{"sig":"%s"}]' "$(head -c 96 /dev/urandom | xxd -p | tr -d '\n')" ;;
      7) python3 -c "import sys; sys.stdout.write('[{\"junk\":\"' + 'A'*100000 + '\"}]')" ;;
    esac
  }

  hits=0
  total=0
  ITERATIONS="${RPCFUZZ_ITERATIONS:-200}"
  for ((i=0; i<ITERATIONS; i++)); do
    m="${methods[$(( RANDOM % ${#methods[@]} ))]}"
    p="$(gen_payload)"
    body="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$m\",\"params\":$p}"
    total=$(( total + 1 ))
    code="$(curl -s -o /tmp/redteam-rpc.body -w '%{http_code}' \
              --max-time 6 \
              -X POST "$OCTRA_RPC_URL" \
              -H 'Content-Type: application/json' \
              -d "$body" 2>/dev/null)" || code=000

    case "$code" in
      4*|200)
        # 4xx = clean rejection, 200 = should contain a JSON-RPC error
        if [[ "$code" == "200" ]]; then
          if ! jq -e '.error' /tmp/redteam-rpc.body >/dev/null 2>&1; then
            # 200 + no error object on a malformed payload is a finding,
            # UNLESS the RPC happens to accept this shape (rare for the
            # generators above). Flag as medium for triage.
            warn "$m → 200 with no .error on malformed input"
            push_finding rpc medium "$m" "200 + no error on malformed payload"
            hits=$(( hits + 1 ))
            overall_exit=3
          fi
        fi
        ;;
      5*)
        fail "$m → $code (server-side error on malformed input)"
        push_finding rpc high "$m" "$code on malformed input — possible panic"
        hits=$(( hits + 1 ))
        overall_exit=3
        ;;
      000)
        fail "$m → connection error / timeout (possible crash)"
        push_finding rpc high "$m" "connection error or timeout"
        hits=$(( hits + 1 ))
        overall_exit=3
        ;;
      *)
        # Treat anything else as warn.
        warn "$m → unexpected status $code"
        ;;
    esac
  done
  rm -f /tmp/redteam-rpc.body

  if (( hits == 0 )); then
    ok "RPC fuzzer: $total iterations, no findings"
  else
    fail "RPC fuzzer: $total iterations, $hits finding(s)"
  fi
else
  warn "RPC fuzzer skipped (SKIP_RPCFUZZ=1)"
fi

# ---------------------------------------------------------------------------
# 4. Structured report
# ---------------------------------------------------------------------------

hdr "Report"
end_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Wrap findings_tmp into a JSON document.
{
  printf '{\n'
  printf '  "started_at": "%s",\n' "$start_ts"
  printf '  "ended_at":   "%s",\n' "$end_ts"
  printf '  "exit_code":  %d,\n'  "$overall_exit"
  printf '  "params": { "fuzz_secs": %s, "rpc_url": %s,\n' \
    "$FUZZ_SECS" "$(printf '%s' "$OCTRA_RPC_URL" | jq -Rs .)"
  printf '              "skip_adv": %s, "skip_fuzz": %s,\n' \
    "$([[ $SKIP_ADV = 1 ]] && echo true || echo false)" \
    "$([[ $SKIP_FUZZ = 1 ]] && echo true || echo false)"
  printf '              "skip_rpcfuzz": %s },\n' \
    "$([[ $SKIP_RPCFUZZ = 1 ]] && echo true || echo false)"
  printf '  "findings": [\n'
  if [[ -s "$findings_tmp" ]]; then
    # join lines with commas
    awk 'NR>1 {printf ",\n"} {printf "    %s", $0}' "$findings_tmp"
    printf '\n'
  fi
  printf '  ]\n}\n'
} > "$REDTEAM_REPORT"

say "wrote $REDTEAM_REPORT"
if (( overall_exit == 0 )); then
  ok "every defense held"
else
  fail "overall exit $overall_exit (see $REDTEAM_REPORT)"
fi

exit "$overall_exit"
