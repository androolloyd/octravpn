#!/usr/bin/env bash
# devnet-teardown.sh — tear down the demo-node{1,2,3} stack brought
# up by `devnet-bringup.sh`. Always succeeds. Leaves the deployed
# circle on devnet alone (the next bringup re-adopts it).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
COMPOSE_BASE="${REPO_ROOT}/docker-compose.yml"
COMPOSE_DEMO="${REPO_ROOT}/docker-compose.demo.yml"

if [[ -f "${COMPOSE_BASE}" && -f "${COMPOSE_DEMO}" ]]; then
    (cd "${REPO_ROOT}" && \
        docker compose -f "${COMPOSE_BASE}" -f "${COMPOSE_DEMO}" down --remove-orphans >&2 || true)
fi

echo "devnet teardown complete" >&2
