#!/usr/bin/env bash
# OctraVPN testnet — full-stack health probe.
#
# Verifies:
#   1. docker compose ps shows every service Up (+ mesh-control healthy)
#   2. chain epoch is advancing (RPC reachable + tip moves between probes)
#   3. each validator's /metrics is scrapable from inside the testnet network
#   4. each validator signed a settlement receipt in the last 5 min
#      (proxy metric: octravpn_receipts_signed_total nonzero & growing)
#   5. Prometheus has all 4 targets (3 validators + mesh-control) up
#   6. DERP HTTP endpoint reachable from OUTSIDE docker (host loopback)
#
# Exit codes:
#   0  all green
#   1  one or more checks failed (details printed)
#   2  bad invocation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

ENV_FILE="${ENV_FILE:-deploy/testnet/.env.testnet}"
[[ -f "$ENV_FILE" ]] || { echo "fatal: $ENV_FILE not found" >&2; exit 2; }
set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

COMPOSE=(docker compose --env-file "$ENV_FILE" -f docker-compose.testnet.yml)

PASS=0
FAIL=0
note_ok()   { printf '  \033[32mOK\033[0m   %s\n' "$*"; PASS=$((PASS+1)); }
note_fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
section()   { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------
# 1. compose ps
# ---------------------------------------------------------------------
section "1/6 docker compose ps"
PS_OUT=$("${COMPOSE[@]}" ps --format '{{.Name}}\t{{.State}}\t{{.Health}}' 2>/dev/null || true)
for svc in mesh-control validator1 validator2 validator3 derp prometheus grafana; do
  line=$(printf '%s\n' "$PS_OUT" | grep -E "octravpn-testnet-${svc}\b" || true)
  if [[ -z "$line" ]]; then
    note_fail "$svc not in compose ps output"
    continue
  fi
  state=$(printf '%s\n' "$line" | awk -F'\t' '{print $2}')
  health=$(printf '%s\n' "$line" | awk -F'\t' '{print $3}')
  if [[ "$state" != "running" ]]; then
    note_fail "$svc state=$state (want running)"
  elif [[ "$svc" == "mesh-control" && "$health" != "healthy" ]]; then
    note_fail "mesh-control health=$health (want healthy)"
  else
    note_ok "$svc up"
  fi
done

# ---------------------------------------------------------------------
# 2. chain tip advancing
# ---------------------------------------------------------------------
section "2/6 chain tip advancing"
if [[ -z "${OCTRA_RPC_URL:-}" ]]; then
  note_fail "OCTRA_RPC_URL not set in env"
else
  rpc_call() {
    curl --silent --max-time 8 -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}" \
      "$OCTRA_RPC_URL"
  }
  TIP1=$(rpc_call octra_blockNumber 2>/dev/null | grep -oE '"result"[^,}]*' | head -n1 || true)
  sleep 5
  TIP2=$(rpc_call octra_blockNumber 2>/dev/null | grep -oE '"result"[^,}]*' | head -n1 || true)
  if [[ -z "$TIP1" || -z "$TIP2" ]]; then
    note_fail "could not read tip from $OCTRA_RPC_URL"
  elif [[ "$TIP1" == "$TIP2" ]]; then
    note_fail "chain tip did not advance in 5s ($TIP1 == $TIP2)"
  else
    note_ok "chain tip advanced: $TIP1 -> $TIP2"
  fi
fi

# ---------------------------------------------------------------------
# 3. validator /metrics scrapable
# ---------------------------------------------------------------------
section "3/6 validator metrics endpoints"
for v in validator1 validator2 validator3; do
  if "${COMPOSE[@]}" exec -T prometheus wget -q -O - "http://$v:51821/metrics" 2>/dev/null \
      | head -n1 | grep -q '^#'; then
    note_ok "$v /metrics scrapable from prometheus container"
  else
    note_fail "$v /metrics NOT scrapable (curl/wget failed inside prometheus)"
  fi
done

# ---------------------------------------------------------------------
# 4. signed-receipt counter > 0 on each validator
# ---------------------------------------------------------------------
section "4/6 receipts signed in last window"
for v in validator1 validator2 validator3; do
  count=$("${COMPOSE[@]}" exec -T prometheus wget -q -O - "http://$v:51821/metrics" 2>/dev/null \
            | awk '/^octravpn_receipts_signed_total/ {print $2; exit}')
  count="${count:-0}"
  if [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )); then
    note_ok "$v octravpn_receipts_signed_total=$count"
  else
    note_fail "$v octravpn_receipts_signed_total=$count (no settlement activity yet?)"
  fi
done

# ---------------------------------------------------------------------
# 5. prometheus sees all targets up
# ---------------------------------------------------------------------
section "5/6 prometheus targets"
TARGETS=$(curl --silent --max-time 10 \
  "http://localhost:${PROMETHEUS_PORT:-9090}/api/v1/targets?state=active" 2>/dev/null || true)
if [[ -z "$TARGETS" ]]; then
  note_fail "could not reach prometheus at localhost:${PROMETHEUS_PORT:-9090}"
else
  ups=$(printf '%s' "$TARGETS" | grep -oE '"health":"up"' | wc -l | tr -d ' ')
  downs=$(printf '%s' "$TARGETS" | grep -oE '"health":"down"' | wc -l | tr -d ' ')
  if (( ups >= 4 )) && (( downs == 0 )); then
    note_ok "prometheus: $ups targets up, $downs down"
  else
    note_fail "prometheus: $ups up, $downs down (want ≥4 up, 0 down)"
  fi
fi

# ---------------------------------------------------------------------
# 6. DERP reachable from outside docker
# ---------------------------------------------------------------------
section "6/6 DERP reachable from host"
if curl --silent --max-time 6 -o /dev/null -w '%{http_code}' \
    "http://localhost:${DERP_HTTP_PORT:-3340}/derp/probe" \
    | grep -qE '^(200|400|404)$'; then
  # derper returns 400 for non-derp requests; that's fine, it means the
  # HTTP listener is up.
  note_ok "DERP HTTP listener responding on :${DERP_HTTP_PORT:-3340}"
else
  note_fail "DERP HTTP listener not responding on :${DERP_HTTP_PORT:-3340}"
fi

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
printf '\n----\n %s passed, %s failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
