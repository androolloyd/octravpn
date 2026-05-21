#!/usr/bin/env bash
# devnet-mock-teardown.sh — tear down the mock-rpc + 3-node stack.
# Pairs with devnet-mock-bringup.sh. Always succeeds.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
COMPOSE_BASE="${REPO_ROOT}/docker-compose.yml"

if [[ -f "${COMPOSE_BASE}" ]]; then
    (cd "${REPO_ROOT}" && \
        docker compose -f "${COMPOSE_BASE}" down --remove-orphans >&2 || true)
fi

echo "devnet-mock teardown complete" >&2
