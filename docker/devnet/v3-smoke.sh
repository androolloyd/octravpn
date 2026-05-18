#!/usr/bin/env bash
# v3 end-to-end smoke test: deploy main-v3, drive the full session
# lifecycle, and verify the earnings hash-chain replays byte-for-byte
# against the on-chain value.
#
# Confirms the v3 architecture on real devnet (https://devnet.octrascan.io/rpc).
# Requires: deployer.key with > 200_000_000 OU; foundry `octra` on PATH
# at $OCTRA_BIN or under ../octra-foundry/target/release/.

set -euo pipefail

OCTRA_BIN="${OCTRA_BIN:-$(realpath "$(dirname "$0")/../../../octra-foundry/target/release/octra")}"
RPC="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"
ROOT="$(realpath "$(dirname "$0")/../..")"
KEY="${DEPLOYER_KEY:-$ROOT/docker/devnet/state/deployer.key}"
AML="${V3_AML:-$ROOT/program/main-v3.aml}"
# Reuse the v2.9 operator circle by default; any circle owned by the
# deployer key works.
OPCIRCLE="${OPCIRCLE:-oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun}"

DEPLOYER_ADDR=$("$OCTRA_BIN" cast wallet addr --key "$KEY")

hdr()  { printf "\n=== %s ===\n" "$1"; }
ok()   { printf "  ✓ %s\n" "$1"; }
fail() { printf "  ✗ %s\n" "$1"; exit 1; }

wait_tx() {
  local tx=$1 label=$2
  sleep 18
  local resp
  resp=$(curl -s -X POST "$RPC" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"octra_transaction\",\"params\":[\"$tx\"]}")
  local status
  status=$(echo "$resp" | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"].get("status","?"))')
  if [[ "$status" == "confirmed" ]]; then
    ok "$label"
  else
    local reason
    reason=$(echo "$resp" | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"].get("error",{}).get("reason",""))')
    fail "$label: $status ($reason)"
  fi
}

send_tx() {
  local val=$1; shift
  local out
  out=$("$OCTRA_BIN" cast send --key "$KEY" --rpc-url "$RPC" \
    --fee 1000 --value "$val" "$V3" "$@" 2>&1)
  echo "$out" | grep -oE '"tx_hash":\s*"[a-f0-9]+"' | head -1 | sed 's/.*"\([a-f0-9]*\)"/\1/'
}

view() {
  local fn=$1; shift
  curl -s -X POST "$RPC" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"contract_call\",\"params\":[\"$V3\",\"$fn\",$1]}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["result"])'
}

hdr "0. deploy main-v3"
OUT=$("$OCTRA_BIN" forge create "$AML" --key "$KEY" --rpc-url "$RPC" \
  --constructor-args 100 1000 100000000 100 1000 2>&1)
V3=$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["address"])')
ok "deployed @ $V3"

hdr "1. register_circle"
echo '{"v":1,"region":"test","prices":{"shared":1000}}' > /tmp/v3-state-root.json
STATE_ROOT=$(python3 -c "import hashlib; print(hashlib.sha256(open('/tmp/v3-state-root.json','rb').read()).hexdigest())")
RECEIPT_PK=$(python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())")
wait_tx "$(send_tx 150000000 register_circle "\"$OPCIRCLE\"" "\"$STATE_ROOT\"" "\"$RECEIPT_PK\"")" "register_circle"

hdr "2. create_tailnet"
echo '{"v":1,"members":[]}' > /tmp/v3-members.json
MEMBERS=$(python3 -c "import hashlib; print(hashlib.sha256(open('/tmp/v3-members.json','rb').read()).hexdigest())")
wait_tx "$(send_tx 10000000 create_tailnet "\"$MEMBERS\"")" "create_tailnet"

hdr "3. open_session"
wait_tx "$(send_tx 0 open_session 0 "\"$OPCIRCLE\"" 1500)" "open_session(max_pay=1500)"

hdr "4. settle_claim (operator: 1 MiB)"
wait_tx "$(send_tx 0 settle_claim 0 1048576)" "settle_claim"

hdr "5. settle_confirm (opener agrees, net=1000)"
BLINDING=$(python3 -c "import os; print(os.urandom(16).hex())")
wait_tx "$(send_tx 0 settle_confirm 0 1048576 1000 "\"$BLINDING\"")" "settle_confirm(blinding=${BLINDING:0:8}…)"

hdr "6. verify hash-chain replays locally"
ON_CHAIN=$(view get_earnings_chain "[\"$OPCIRCLE\"]")
EXPECTED=$(python3 -c "
import hashlib
init = hashlib.sha256('$STATE_ROOT'.encode()).hexdigest()
bh   = hashlib.sha256('$BLINDING'.encode()).hexdigest()
print(hashlib.sha256((init + bh).encode()).hexdigest())
")
if [[ "$ON_CHAIN" == "$EXPECTED" ]]; then
  ok "chain head $ON_CHAIN matches local replay"
else
  fail "hash-chain mismatch: on-chain=$ON_CHAIN, expected=$EXPECTED"
fi

hdr "7. claim_earnings (net 1000 - 0.5% fee = 995 available)"
wait_tx "$(send_tx 0 claim_earnings "\"$OPCIRCLE\"" 995)" "claim_earnings(995)"

hdr "8. overclaim rejection"
TX=$(send_tx 0 claim_earnings "\"$OPCIRCLE\"" 100)
sleep 18
STATUS=$(curl -s -X POST "$RPC" -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"octra_transaction\",\"params\":[\"$TX\"]}" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"].get("status"))')
[[ "$STATUS" == "rejected" ]] && ok "overclaim correctly rejected" || fail "overclaim should reject; got $STATUS"

hdr "9. anchor rotation"
NEW_STATE=$(python3 -c "import hashlib; print(hashlib.sha256(b'v2 state').hexdigest())")
wait_tx "$(send_tx 0 update_circle_state "\"$OPCIRCLE\"" "\"$NEW_STATE\"")" "update_circle_state"
VER=$(view get_circle_state_version "[\"$OPCIRCLE\"]")
[[ "$VER" == "2" ]] && ok "state_version bumped to 2" || fail "version should be 2; got $VER"

printf "\nv3 smoke PASSED @ %s\n" "$V3"
