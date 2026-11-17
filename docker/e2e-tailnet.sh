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

# Quiet when it works, loud when it does not. `--quiet` alone hid the
# compiler's error for a month: CI showed only "failed to solve" and the
# Dockerfile line, never why the build failed.
compose_build() {
    local log
    log=$(mktemp)
    if ! docker compose build "$@" >"$log" 2>&1; then
        echo "[e2e] docker compose build $* failed; last 80 lines:" >&2
        tail -n 80 "$log" >&2
        rm -f "$log"
        return 1
    fi
    rm -f "$log"
}
compose_build builder
compose_build
docker compose up -d mock-rpc
python3 docker/e2e-tailnet.py
