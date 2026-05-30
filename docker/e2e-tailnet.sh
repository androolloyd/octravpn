#!/usr/bin/env bash
# Full tailnet happy-path e2e against the docker-compose harness (v1).
#
# Builds on top of `e2e.sh` (which proves register_endpoint works).
# This script additionally:
#   1. Creates a tailnet on chain with a 5000 OU treasury.
#   2. Adds CLIENT as a member.
#   3. Configures node1 as a tailnet exit.
#   4. CLIENT opens a single-hop session with max_pay = 1000 OU.
#   5. node1 (the exit operator) settles for 2 bytes → 200 OU paid,
#      1 OU protocol fee → 199 net to operator earnings, 800 OU refund.
#   6. Asserts tailnet treasury, encrypted earnings, program treasury,
#      and event surface all match expectations.
#
# Uses curl against the mock-rpc HTTP server; no signing oracle needed.

set -euo pipefail

cd "$(dirname "$0")/.."

# Foundry split: the docker build context is the PARENT of this repo,
# so the sibling `octra-foundry` checkout must exist there.
if [[ ! -d "../octra-foundry" ]]; then
  echo "error: ../octra-foundry not found" >&2
  echo "the docker harness expects octra-foundry to be checked out" >&2
  echo "as a sibling of this repo. clone it before running e2e." >&2
  exit 1
fi

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

# Extract a JSON path (slash-separated) from stdin.
jget() {
  python3 -c "import sys,json; d=json.load(sys.stdin); ks=\"$1\".split('/');
v=d
for k in ks:
  v=v[k] if not k.isdigit() else v[int(k)]
print(v)" 2>/dev/null
}

# Extract a numeric event field from a tx JSON.
event_num() {
  local event_name=$1 field=$2
  python3 -c "import sys,json; d=json.load(sys.stdin);
[print(e.get('$field')) for e in d['result']['events'] if e['name']=='$event_name']" | head -1
}

echo "[tailnet-e2e] Building images..."
# Build the `builder` stage first; the other Dockerfiles FROM it and
# `docker compose build` is parallel by default, so without this the
# node/client builds race and try to pull octravpn-builder from
# docker.io. See docker/e2e.sh for the same rationale.
docker compose build --quiet builder
docker compose build --quiet

echo "[tailnet-e2e] Starting mock-rpc..."
docker compose up -d mock-rpc
sleep 2
for _ in $(seq 1 30); do
  if rpc node_status >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "[tailnet-e2e] Seeding validator status + operator bond..."
rpc octra_test_grantValidator "[\"$VAL1\"]" >/dev/null
rpc octra_test_bondEndpoint "[\"$VAL1\"]" >/dev/null

echo "[tailnet-e2e] Starting node1..."
docker compose up -d node1
sleep 3

# Verify the endpoint registered.
active=""
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
tid=$(echo "$tx" | event_num TailnetCreated tailnet_id)
[ -n "$tid" ] || { echo "[tailnet-e2e] FAIL: no TailnetCreated event"; echo "$tx"; exit 1; }
echo "[tailnet-e2e]   tailnet id = $tid"

# 2. Add CLIENT as member.
echo "[tailnet-e2e] Adding client as member..."
submit "$OWNER" add_member "[$tid,\"$CLIENT\"]" >/dev/null

# 3. Configure node1 as exit.
echo "[tailnet-e2e] Configuring node1 as exit..."
submit "$OWNER" configure_tailnet_exit "[$tid,\"$VAL1\"]" >/dev/null

# 4. Open session: CLIENT picks $VAL1 as exit, deposits max_pay = 1000 OU.
echo "[tailnet-e2e] Opening session..."
resp=$(submit "$CLIENT" open_session "[$tid,\"$VAL1\",1000]")
hash=$(echo "$resp" | jget result/hash)
tx=$(rpc octra_transaction "[\"$hash\"]")
sid=$(echo "$tx" | event_num SessionOpened session_id)
[ -n "$sid" ] || { echo "[tailnet-e2e] FAIL: no SessionOpened"; echo "$tx"; exit 1; }
echo "[tailnet-e2e]   session id = $sid"

# 5. Settle (two-step). The single-call `settle_session` was replaced by
#    an operator-claim / opener-confirm handshake: the exit operator
#    (node1 / $VAL1, the session's `exit`) claims the metered bytes, then
#    the session opener ($CLIENT) confirms the same count. Matching byte
#    counts ⇒ `settle_confirm` emits SessionSettled; a mismatch ⇒
#    SettleDispute instead. node1 reports bytes_used=2 → 200 OU gross,
#    1 OU protocol fee (0.5 %), 199 net to operator earnings, 800 OU refund.
echo "[tailnet-e2e] Settling (operator claim → client confirm)..."
submit "$VAL1" settle_claim "[$sid,2]" >/dev/null
resp=$(submit "$CLIENT" settle_confirm "[$sid,2]")
hash=$(echo "$resp" | jget result/hash)
tx=$(rpc octra_transaction "[\"$hash\"]")
total_paid=$(echo "$tx" | event_num SessionSettled total_paid)
refund=$(echo "$tx" | event_num SessionSettled refund)

[ "$total_paid" = "200" ] || { echo "[tailnet-e2e] FAIL: total_paid=$total_paid expected 200"; exit 1; }
[ "$refund"     = "800" ] || { echo "[tailnet-e2e] FAIL: refund=$refund expected 800"; exit 1; }

# 6. Tailnet treasury: 5000 - 1000 + 800 = 4800.
treasury=$(call_view "get_tailnet" "[$tid]" | jget result/treasury)
[ "$treasury" = "4800" ] || { echo "[tailnet-e2e] FAIL: treasury=$treasury expected 4800"; exit 1; }

# 7. Program treasury collected the 0.5 % protocol fee = 1 OU.
pt=$(call_view "get_program_treasury" "[]" | jget result)
[ "$pt" = "1" ] || { echo "[tailnet-e2e] FAIL: program_treasury=$pt expected 1"; exit 1; }

# 8. Encrypted earnings is the mock-cleartext representation of 199 OU.
earn=$(call_view "get_encrypted_earnings" "[\"$VAL1\"]" | jget result)
[ "$earn" = "hfhe_v1|mock|00000000000000c7" ] \
  || { echo "[tailnet-e2e] FAIL: earnings=$earn expected hfhe_v1|mock|00000000000000c7"; exit 1; }

echo "[tailnet-e2e] ALL OK"
echo "  tailnet id              : $tid"
echo "  session id              : $sid"
echo "  paid / refund / treasury: $total_paid / $refund / $treasury OU"
echo "  program treasury        : $pt OU"
echo "  earnings (mock-clear)   : $earn"
