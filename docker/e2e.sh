#!/usr/bin/env bash
# End-to-end smoke test for the docker-compose harness.
#
# 1. Boot mock-rpc + 3 nodes.
# 2. Each node registers + attests on chain.
# 3. Spin up the client one-shot to list active validators; expect 3.
# 4. Tear everything down.
#
# Returns non-zero on any failure.

set -euo pipefail

cd "$(dirname "$0")/.."

# Always clean up on exit, even on early failure.
cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[e2e] Building images..."
docker compose build --quiet

echo "[e2e] Starting infra (mock-rpc + 3 nodes)..."
docker compose up -d mock-rpc node1 node2 node3

echo "[e2e] Waiting for nodes to register..."
for _ in $(seq 1 30); do
  count=$(docker compose run --rm client \
    --config /etc/octravpn/client.toml nodes 2>/dev/null \
    | grep -c '^oct' || true)
  if [ "$count" -ge 3 ]; then
    echo "[e2e] OK — $count active validators in registry."
    exit 0
  fi
  sleep 2
done

echo "[e2e] FAILED — fewer than 3 validators after 60s."
docker compose logs --tail=50
exit 1
