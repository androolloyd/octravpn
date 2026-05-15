#!/usr/bin/env bash
# Confirm the devnet environment is ready to bring nodes up:
#   - RPC reachable
#   - Program deployed at PROGRAM_ADDR
#   - All four wallets (node1/2/3 + client) have non-zero balance
#   - Wallet + WG key files exist under $HOST_DEVNET_DIR
set -euo pipefail

cd "$(dirname "$0")/../.."
set -a
# shellcheck source=/dev/null
[[ -f docker/devnet/.env ]] && source docker/devnet/.env
[[ -f docker/devnet/hosts.env ]] && source docker/devnet/hosts.env
set +a

: "${OCTRA_RPC_URL:?set in docker/devnet/.env}"
: "${PROGRAM_ADDR:?set in docker/devnet/.env after deploy}"

HOST_DIR="${HOST_DEVNET_DIR:-./docker/devnet/state}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
fail=0
ok() { green "  [ok]   $1"; }
warn(){ yellow "  [warn] $1"; fail=$((fail+1)); }
err(){  red "  [fail] $1"; fail=$((fail+1)); }

echo "RPC: $OCTRA_RPC_URL"
echo "Program: $PROGRAM_ADDR"
echo

# 1. RPC reachable.
echo "1. RPC reachability"
if status=$(curl -s -m 8 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"node_status","params":[]}' 2>&1); then
  if echo "$status" | grep -q '"epoch"'; then
    epoch=$(echo "$status" | sed -E 's/.*"epoch":([0-9]+).*/\1/')
    ok "RPC live (epoch=$epoch)"
  else
    err "RPC reachable but no epoch in response: $status"
  fi
else
  err "RPC unreachable: $status"
fi

# 2. Program deployed.
echo
echo "2. Program deployed"
prog=$(curl -s -m 8 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"vm_contract\",\"params\":[\"$PROGRAM_ADDR\"]}" 2>&1)
if echo "$prog" | grep -q '"code_hash"'; then
  ch=$(echo "$prog" | sed -E 's/.*"code_hash":"([^"]+)".*/\1/')
  ok "program found (code_hash=${ch:0:16}…)"
else
  err "program not found at $PROGRAM_ADDR"
fi

# 3. Wallet balances.
echo
echo "3. Wallet balances"
check_balance() {
  local label=$1 addr=$2
  if [[ "$addr" == oct__* ]]; then
    err "$label addr is still a placeholder ($addr)"
    return
  fi
  local bal
  bal=$(curl -s -m 8 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
          -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"octra_balance\",\"params\":[\"$addr\"]}" 2>&1)
  if echo "$bal" | grep -q '"balance_raw"'; then
    raw=$(echo "$bal" | sed -E 's/.*"balance_raw":"([0-9]+)".*/\1/')
    if [[ "$raw" == "0" ]]; then
      err "$label balance is 0 (faucet: https://faucet.octra.network)"
    else
      ok "$label balance: $raw OU"
    fi
  else
    err "$label balance lookup failed"
  fi
}

check_balance "node1 ($NODE1_VALIDATOR_ADDR)" "$NODE1_VALIDATOR_ADDR"
check_balance "node2 ($NODE2_VALIDATOR_ADDR)" "$NODE2_VALIDATOR_ADDR"
check_balance "node3 ($NODE3_VALIDATOR_ADDR)" "$NODE3_VALIDATOR_ADDR"
check_balance "client ($CLIENT_ADDR)" "$CLIENT_ADDR"

# 4. Key files exist + permissions.
echo
echo "4. Key files + permissions"
for d in node1 node2 node3; do
  for f in wallet.key wg.key node.toml; do
    p="$HOST_DIR/$d/$f"
    if [[ ! -f "$p" ]]; then
      err "missing $p"
      continue
    fi
    if [[ "$f" != "node.toml" ]]; then
      perm=$(stat -f '%Lp' "$p" 2>/dev/null || stat -c '%a' "$p" 2>/dev/null)
      if [[ "$perm" != "600" ]]; then
        warn "$p has perms $perm (should be 600)"
      else
        ok "$p (chmod 0600)"
      fi
    else
      ok "$p"
    fi
  done
done
for f in client/wallet.key client/client.toml; do
  p="$HOST_DIR/$f"
  [[ -f "$p" ]] && ok "$p" || err "missing $p"
done

echo
if [[ $fail -eq 0 ]]; then
  green "preflight OK — ready for: docker compose -f docker-compose.yml -f docker/devnet/docker-compose.devnet.yml --profile devnet up -d"
else
  red "$fail check(s) failed; resolve before bringing nodes up"
  exit 1
fi
