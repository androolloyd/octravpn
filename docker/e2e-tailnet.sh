#!/usr/bin/env bash
# Signed, staged/confirmed mock lifecycle and zero-commission tailnet settlement.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -d ../octra-foundry ]]; then
  echo "error: the Compose harness requires sibling ../octra-foundry" >&2
  exit 1
fi
cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker compose build --quiet builder
docker compose build --quiet
docker compose up -d mock-rpc
python3 docker/e2e-tailnet.py
