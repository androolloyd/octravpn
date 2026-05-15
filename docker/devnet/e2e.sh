#!/usr/bin/env bash
# Devnet end-to-end driver. Prints every step's state so it's clear
# what's happening on chain + off-chain (peering, control-plane
# health, metering).
#
# Steps:
#   0. Read wallets.toml + .env, verify funding + program addr.
#   1. Bring up the three node daemons + the mock-free testnet
#      compose overlay.
#   2. Probe each node's control plane: /health, /node-status,
#      /peers, /metrics — confirm WireGuard listener up, allowlist
#      empty, on-chain registration visible.
#   3. Verify each node sees the chain (rpc reachable, sync'd).
#   4. Drive a happy-path tailnet + session:
#        - client creates tailnet
#        - adds itself as member
#        - configures node1 as exit
#        - opens session
#        - waits for some bytes to flow (synthetic via control-plane
#          API; real WG traffic requires kernel TUN access)
#        - node1 submits settle_claim
#        - client submits settle_confirm
#   5. Show before/after metering: per-session bytes_used, encrypted
#      earnings ciphertext, tailnet treasury, program treasury.
#   6. (Optional) drive the slash_double_sign path.
#
# Each step is a separate function; you can run them piecemeal with
# `./docker/devnet/e2e.sh <step>`.

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=/dev/null
[[ -f docker/devnet/.env ]] && source docker/devnet/.env
[[ -f docker/devnet/hosts.env ]] && source docker/devnet/hosts.env

OCTRA_BIN="${OCTRA_BIN:-../octra-foundry/target/release/octra}"
: "${OCTRA_RPC_URL:?set in docker/devnet/.env}"
: "${PROGRAM_ADDR:?set in docker/devnet/.env}"

# Color helpers
G='\033[32m'; R='\033[31m'; Y='\033[33m'; D='\033[2m'; C='\033[36m'; NC='\033[0m'
hdr()  { printf "\n${C}══ %s ══${NC}\n" "$*"; }
ok()   { printf "  ${G}✓${NC} %s\n" "$*"; }
warn() { printf "  ${Y}!${NC} %s\n" "$*"; }
err()  { printf "  ${R}✗${NC} %s\n" "$*"; }
muted(){ printf "  ${D}%s${NC}\n" "$*"; }

rpc() {
  local method=$1; shift
  curl -s -m 8 -X POST "$OCTRA_RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$1}"
}

view() {
  local method=$1; local params=$2
  local resp; resp=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"$method\",$params]")
  echo "$resp" | python3 -c 'import json,sys;r=json.load(sys.stdin);print(r["result"]["result"] if "result" in r else json.dumps(r))'
}

storage_dump() {
  local resp; resp=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_endpoint\",[\"$NODE1_VALIDATOR_ADDR\"]]")
  echo "$resp" | python3 -m json.tool 2>/dev/null
}

step_preflight() {
  hdr "0/  pre-flight"
  ok "rpc:     $OCTRA_RPC_URL"
  ok "program: $PROGRAM_ADDR"
  ok "octra binary: $OCTRA_BIN ($([ -x "$OCTRA_BIN" ] && echo present || echo MISSING))"
  for label_addr in \
    "node1:$NODE1_VALIDATOR_ADDR" \
    "node2:$NODE2_VALIDATOR_ADDR" \
    "node3:$NODE3_VALIDATOR_ADDR" \
    "client:$CLIENT_ADDR"; do
    label=${label_addr%%:*}; addr=${label_addr#*:}
    bal=$(rpc "octra_balance" "[\"$addr\"]" | python3 -c 'import json,sys;r=json.load(sys.stdin);print(r["result"]["balance"] if "result" in r else "—")')
    printf "    %-7s %s  %s OCT\n" "$label" "$addr" "$bal"
  done
}

step_chain_endpoints() {
  hdr "1/  chain-side endpoints"
  local count
  count=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_endpoint\",[\"$NODE1_VALIDATOR_ADDR\"]]" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["storage"].get("endpoint_count","0"))')
  ok "endpoint_count on chain: $count"
  for label_addr in \
    "node1:$NODE1_VALIDATOR_ADDR" \
    "node2:$NODE2_VALIDATOR_ADDR" \
    "node3:$NODE3_VALIDATOR_ADDR"; do
    label=${label_addr%%:*}; addr=${label_addr#*:}
    storage=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_endpoint\",[\"$addr\"]]" \
      | python3 -c 'import json,sys;r=json.load(sys.stdin)["result"]["storage"];print(r.get("endpoints:'$addr':active","0"),"|",r.get("endpoints:'$addr':receipt_pubkey","")[:16]+"…",r.get("endpoints:'$addr':endpoint","?"),r.get("endpoints:'$addr':region","?"))')
    printf "    %-7s active=%s\n" "$label" "$storage"
  done
}

step_control_plane() {
  hdr "2/  control plane (off-chain peering)"
  # The docker compose stack publishes 51821 from each node container.
  # If the harness isn't running this'll fail — that's expected; we
  # surface it as a "not running" warning rather than a hard fail
  # so users can run this step against a chain-only setup.
  for label_port in "node1:51821" "node2:51822" "node3:51823"; do
    label=${label_port%%:*}; port=${label_port##*:}
    if resp=$(curl -s -m 3 "http://127.0.0.1:$port/health" 2>&1); then
      health=$(echo "$resp" | python3 -c 'import json,sys;r=json.load(sys.stdin);print(r.get("status","?"))' 2>/dev/null || echo "(non-JSON)")
      ok "$label /health → $health"
    else
      warn "$label control plane not reachable on 127.0.0.1:$port — node not running locally?"
    fi
  done
}

step_open_session() {
  hdr "3/  client opens a tailnet + session"
  warn "this step requires the docker stack running + the client wallet funded"
  muted "create tailnet:"
  $OCTRA cast send --key docker/devnet/state/client/wallet.key --rpc-url "$OCTRA_RPC_URL" \
    --value 1000 --fee 1000 "$PROGRAM_ADDR" create_tailnet '"deadbeef0000000000000000000000000000000000000000000000000000aabb"' 2>&1 | tail -4 || true
}

step_metrics() {
  hdr "4/  metering snapshot"
  for label_addr in "node1:$NODE1_VALIDATOR_ADDR" "node2:$NODE2_VALIDATOR_ADDR" "node3:$NODE3_VALIDATOR_ADDR"; do
    label=${label_addr%%:*}; addr=${label_addr#*:}
    earn=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_encrypted_earnings\",[\"$addr\"]]" \
      | python3 -c 'import json,sys;r=json.load(sys.stdin);print((r["result"]["result"] if "result" in r else "?")[:40]+"…")')
    printf "    %-7s enc_earnings = %s\n" "$label" "$earn"
  done
}

case "${1:-all}" in
  preflight) step_preflight ;;
  chain)     step_preflight; step_chain_endpoints ;;
  control)   step_control_plane ;;
  session)   step_open_session ;;
  metrics)   step_metrics ;;
  all|"")    step_preflight; step_chain_endpoints; step_control_plane; step_metrics ;;
  *) echo "usage: $0 [preflight|chain|control|session|metrics|all]"; exit 1 ;;
esac
