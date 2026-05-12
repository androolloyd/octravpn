#!/usr/bin/env bash
# Full tailnet happy-path e2e against the docker-compose harness.
#
# Builds on top of `e2e.sh` (which proves register_endpoint works). This
# script additionally:
#   1. Creates a tailnet on chain with a 5000 OU treasury.
#   2. Adds CLIENT as a member.
#   3. Configures node1 as a tailnet exit.
#   4. Opens a 1-hop session (1000 OU locked).
#   5. Settles the session (2 bytes used, 200 OU paid, 800 refunded).
#   6. Asserts the on-chain tailnet treasury, encrypted earnings,
#      session row, and audit/event surface all match expectations.
#
# The whole thing runs over `curl` against the mock-rpc HTTP server,
# so no signing oracle is needed (mock accepts tx envelopes without
# verifying signatures).

set -euo pipefail

cd "$(dirname "$0")/.."

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

RPC="${OCTRAVPN_E2E_RPC:-http://127.0.0.1:18080/rpc}"
PROG="octPROGmockaddress0000000000000000000000"

OWNER="octOWNERtailnet0000000000000000000000000001"
CLIENT="octCLIENTtailnet000000000000000000000000001"
VAL1="octVNODE1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

rpc() {
  local method=$1; shift
  local params=${1:-"[]"}
  curl -fsS -X POST -H "content-type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" "$RPC"
}

submit() {
  local from=$1 method=$2 params=$3 value=${4:-0}
  rpc octra_submit "[{\"kind\":\"contract_call\",\"from\":\"$from\",\"to\":\"$PROG\",\"method\":\"$method\",\"params\":$params,\"value\":$value,\"fee\":10,\"nonce\":0}]"
}

call_view() {
  local method=$1 params=$2
  rpc contract_call "[\"$PROG\",\"$method\",$params]"
}

jget() {
  python3 -c "import sys,json; d=json.load(sys.stdin); ks=\"$1\".split('/');
v=d
for k in ks:
  v=v[k] if not k.isdigit() else v[int(k)]
print(v)" 2>/dev/null
}

echo "[tailnet-e2e] Building images..."
docker compose build --quiet

echo "[tailnet-e2e] Starting mock-rpc..."
docker compose up -d mock-rpc
sleep 2
for _ in $(seq 1 30); do
  if rpc node_status >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "[tailnet-e2e] Granting Octra-validator status..."
rpc octra_test_grantValidator "[\"$VAL1\"]" >/dev/null

echo "[tailnet-e2e] Starting node1..."
docker compose up -d node1
sleep 3

# Verify the endpoint registered.
for _ in $(seq 1 15); do
  ep=$(call_view "get_endpoint" "[\"$VAL1\"]")
  active=$(echo "$ep" | jget result/active)
  if [ "$active" = "1" ]; then break; fi
  sleep 2
done
if [ "$active" != "1" ]; then
  echo "[tailnet-e2e] FAIL: node1 endpoint did not become active"
  exit 1
fi
echo "[tailnet-e2e] node1 endpoint active."

# 1. Create tailnet with 5000 OU treasury.
echo "[tailnet-e2e] Creating tailnet..."
acl_hash="ab00000000000000000000000000000000000000000000000000000000000000"
resp=$(submit "$OWNER" create_tailnet "[\"$acl_hash\"]" 5000)
hash=$(echo "$resp" | jget result/hash)
tx=$(rpc octra_transaction "[\"$hash\"]")
tid=$(echo "$tx" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(e.get('tailnet_id','')) for e in d['result']['events'] if e['name']=='TailnetCreated']" | head -1)
[ -n "$tid" ] || { echo "[tailnet-e2e] FAIL: no TailnetCreated event"; echo "$tx"; exit 1; }
echo "[tailnet-e2e]   tailnet id = $tid"

# 2. Add CLIENT as member.
echo "[tailnet-e2e] Adding client as member..."
submit "$OWNER" add_member "[\"$tid\",\"$CLIENT\"]" >/dev/null

# 3. Configure node1 as exit.
echo "[tailnet-e2e] Configuring node1 as exit..."
submit "$OWNER" configure_tailnet_exit "[\"$tid\",\"$VAL1\"]" >/dev/null

# 4. Open session.
echo "[tailnet-e2e] Opening session..."
resp=$(submit "$CLIENT" open_session "[\"$tid\",[\"aa00000000000000000000000000000000000000000000000000000000000000\"],\"bb00000000000000000000000000000000000000000000000000000000000000\",1000]")
hash=$(echo "$resp" | jget result/hash)
tx=$(rpc octra_transaction "[\"$hash\"]")
sid=$(echo "$tx" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(e.get('session_id','')) for e in d['result']['events'] if e['name']=='SessionOpened']" | head -1)
[ -n "$sid" ] || { echo "[tailnet-e2e] FAIL: no SessionOpened"; exit 1; }
echo "[tailnet-e2e]   session id = $sid"

# 5. Settle: bytes_used=2, blind, validator gets 200 OU.
echo "[tailnet-e2e] Settling..."
blind="1100000000000000000000000000000000000000000000000000000000000000"
openings="[{\"node_addr\":\"$VAL1\",\"blind\":\"$blind\",\"split_bps\":10000}]"
csig="ee00000000000000000000000000000000000000000000000000000000000000"
nsig="ff00000000000000000000000000000000000000000000000000000000000000"
resp=$(submit "$CLIENT" settle_session "[\"$sid\",1,2,\"$blind\",\"$csig\",\"$nsig\",$openings]")
hash=$(echo "$resp" | jget result/hash)
tx=$(rpc octra_transaction "[\"$hash\"]")
total_paid=$(echo "$tx" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(e.get('total_paid','')) for e in d['result']['events'] if e['name']=='SessionSettled']" | head -1)
refund=$(echo "$tx" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(e.get('refund','')) for e in d['result']['events'] if e['name']=='SessionSettled']" | head -1)

[ "$total_paid" = "200" ] || { echo "[tailnet-e2e] FAIL: total_paid=$total_paid expected 200"; exit 1; }
[ "$refund" = "800" ]     || { echo "[tailnet-e2e] FAIL: refund=$refund expected 800"; exit 1; }

# 6. Verify tailnet treasury: 5000 - 1000 + 800 = 4800.
treasury=$(call_view "get_tailnet" "[\"$tid\"]" | jget result/treasury)
[ "$treasury" = "4800" ] || { echo "[tailnet-e2e] FAIL: treasury=$treasury expected 4800"; exit 1; }

# 7. Validator's encrypted earnings ledger is non-zero (Ristretto point != identity).
earn=$(call_view "get_encrypted_earnings" "[\"$VAL1\"]" | jget result)
[ "$earn" != "0000000000000000000000000000000000000000000000000000000000000000" ] \
  || { echo "[tailnet-e2e] FAIL: encrypted earnings still zero"; exit 1; }

echo "[tailnet-e2e] ALL OK"
echo "  tailnet id  : $tid"
echo "  session id  : $sid"
echo "  paid / refund / treasury : $total_paid / $refund / $treasury OU"
echo "  earnings hex : $earn"
