#!/usr/bin/env bash
# End-to-end smoke test for the OctraVPN docker-compose harness.
#
# Tailnet model:
#   1. Boot mock-rpc.
#   2. Pre-seed each node's validator_addr as an Octra protocol validator
#      via the mock's `octra_test_grantValidator` helper. The OctraVPN
#      program refuses register_endpoint for non-validators.
#   3. Boot the three node daemons. Each calls register_endpoint at
#      startup and starts serving its WireGuard listener + control plane.
#   4. Run the client one-shot to call list_active_endpoints; expect 3.
#   5. Tear everything down.

set -euo pipefail

cd "$(dirname "$0")/.."

# Foundry split: the docker build context is the PARENT of this repo,
# so the sibling `octra-foundry` checkout must exist there. Fail
# fast rather than letting `docker compose build` puke on a missing
# COPY.
if [[ ! -d "../octra-foundry" ]]; then
  echo "error: ../octra-foundry not found" >&2
  echo "the docker harness expects octra-foundry to be checked out" >&2
  echo "as a sibling of this repo. clone it before running e2e." >&2
  exit 1
fi

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

RPC_URL_HOST="${OCTRAVPN_E2E_RPC:-http://127.0.0.1:18080/rpc}"

NODE_ADDRS=(
  "octVNODE1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "octVNODE2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "octVNODE3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

rpc_call() {
  local method=$1; shift
  local params=${1:-"[]"}
  curl -fsS -X POST -H "content-type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$RPC_URL_HOST"
}

wait_rpc_ready() {
  for _ in $(seq 1 30); do
    if rpc_call node_status >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "[e2e] mock-rpc never became ready" >&2
  return 1
}

echo "[e2e] Building images..."
docker compose build --quiet

echo "[e2e] Starting mock-rpc..."
docker compose up -d mock-rpc
wait_rpc_ready
echo "[e2e] mock-rpc up."

echo "[e2e] Seeding validator status + operator bond for each node..."
for addr in "${NODE_ADDRS[@]}"; do
  rpc_call octra_test_grantValidator "[\"$addr\"]" >/dev/null
  rpc_call octra_test_bondEndpoint "[\"$addr\"]" >/dev/null
  echo "  ok  $addr"
done

echo "[e2e] Starting nodes..."
docker compose up -d node1 node2 node3

echo "[e2e] Waiting for endpoint registry to reach 3..."
for _ in $(seq 1 30); do
  list=$(rpc_call contract_call "[\"octPROGmockaddress0000000000000000000000\",\"list_active_endpoints\",[0,50]]" \
    | python3 -c 'import sys,json; r=json.load(sys.stdin).get("result",[]); print(len(r) if isinstance(r,list) else 0)' 2>/dev/null || echo 0)
  if [ "$list" -ge 3 ]; then
    echo "[e2e] OK — $list endpoints registered."
    docker compose logs --tail=20 node1 node2 node3 | grep -E "register_endpoint|endpoint" || true
    exit 0
  fi
  sleep 2
done

echo "[e2e] FAILED — fewer than 3 endpoints after 60s." >&2
docker compose logs --tail=60 mock-rpc node1 node2 node3
exit 1
