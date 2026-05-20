#!/usr/bin/env bash
# 3node-mesh-teardown.sh
#
# Tear down the mesh-demo stack. Always succeeds (docker compose down
# on a non-existent stack is a no-op). Pairs with `3node-mesh-bringup.sh`
# — call after a tape recording or on demand.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
COMPOSE_FILE="${REPO_ROOT}/docker-compose.mesh-demo.yml"

if [[ ! -f "${COMPOSE_FILE}" ]]; then
    echo "compose file missing: ${COMPOSE_FILE}" >&2
    exit 0
fi

# `-v` drops the per-peer tailscaled state volumes so the next bringup
# starts from a clean slate. `--remove-orphans` catches any service
# names that drifted between bringup runs.
docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >&2 || true

# Leave the demo/.mesh-state dir behind on purpose: the audit/ + TLS
# cert files are useful for post-mortem inspection, and the cert
# regeneration is idempotent on the next bringup.

echo "mesh-demo teardown complete" >&2
