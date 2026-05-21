#!/usr/bin/env bash
# devnet-mock-bringup.sh
#
# Bring up the in-process mock-rpc chain + 3 octravpn-node containers
# using the canonical docker-compose.yml at the repo root. Mirrors the
# e2e CI job's stack — same images, same wallet/wg/fhe keys baked into
# docker/conf/node{1,2,3}/.
#
# Exit codes:
#   0   READY — mock-rpc + node1/2/3 containers all show 'running'.
#   10  compose preflight (file missing / docker offline) failed.
#   20  docker compose up failed.
#   30  readiness: a node never reported 'running' inside the deadline.
#
# Idempotent: re-running on a warm stack is `docker compose up -d`
# at most.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
COMPOSE_BASE="${REPO_ROOT}/docker-compose.yml"
READY_TIMEOUT_SECS="${DEVNET_MOCK_READY_TIMEOUT:-90}"

if [[ ! -f "${COMPOSE_BASE}" ]]; then
    echo "devnet-mock-bringup: missing ${COMPOSE_BASE}" >&2
    exit 10
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "devnet-mock-bringup: docker not on PATH" >&2
    exit 10
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "devnet-mock-bringup: 'docker compose' v2 missing" >&2
    exit 10
fi

cd "${REPO_ROOT}"

# Force a build pass so a fresh checkout (no prebuilt images) still
# works. The Dockerfile.* layers use cached cargo registry so the
# second invocation is fast.
docker compose -f "${COMPOSE_BASE}" build mock-rpc node1 node2 node3 >&2 || {
    echo "devnet-mock-bringup: image build failed" >&2
    exit 20
}

docker compose -f "${COMPOSE_BASE}" up -d mock-rpc node1 node2 node3 >&2 || {
    echo "devnet-mock-bringup: 'docker compose up' failed" >&2
    exit 20
}

# Poll for all four containers to reach 'running'.
deadline=$(( $(date +%s) + READY_TIMEOUT_SECS ))
want=(octra-mock-rpc-1 octra-node1-1 octra-node2-1 octra-node3-1)
# Container name shape varies with compose project name; resolve via
# `docker compose ps` instead.
while (( $(date +%s) < deadline )); do
    not_running=0
    for svc in mock-rpc node1 node2 node3; do
        state=$(docker compose -f "${COMPOSE_BASE}" ps --status running --services 2>/dev/null | grep -c "^${svc}\$" || true)
        if (( state == 0 )); then
            not_running=$((not_running + 1))
        fi
    done
    if (( not_running == 0 )); then
        echo "devnet-mock stack ready (mock-rpc + node1/2/3 running)" >&2
        echo "READY"
        exit 0
    fi
    sleep 2
done

echo "devnet-mock-bringup: ${not_running} service(s) never reached running" >&2
docker compose -f "${COMPOSE_BASE}" ps >&2 || true
exit 30
