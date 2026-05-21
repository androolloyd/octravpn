#!/usr/bin/env bash
# teardown.sh
#
# Clean up everything start-portal.sh + start-devnet.sh spun up.
# Safe to run on a cold machine — every step is best-effort.

set -euo pipefail

DEMO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO_ROOT=$(cd "${DEMO_DIR}/.." && pwd)

PORTAL_STATE="${DEMO_DIR}/state/portal"
PORTAL_PID="${PORTAL_STATE}/portal.pid"

# 1. Kill any portal we spawned. If the PID file is stale we ignore it.
if [[ -f "${PORTAL_PID}" ]]; then
    pid=$(cat "${PORTAL_PID}" 2>/dev/null || echo "")
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        # Give it 2s to drain; SIGKILL if it lingers.
        for _ in 1 2; do
            kill -0 "${pid}" 2>/dev/null || break
            sleep 1
        done
        kill -9 "${pid}" 2>/dev/null || true
    fi
    rm -f "${PORTAL_PID}"
fi

# 2. Tear down docker stacks if compose is available.
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_BASE="${REPO_ROOT}/docker-compose.yml"
    COMPOSE_DEVNET="${REPO_ROOT}/docker/devnet/docker-compose.devnet.yml"
    if [[ -f "${COMPOSE_BASE}" && -f "${COMPOSE_DEVNET}" ]]; then
        (cd "${REPO_ROOT}" && \
            docker compose -f "${COMPOSE_BASE}" -f "${COMPOSE_DEVNET}" down --remove-orphans >/dev/null 2>&1 || true)
    fi
    # Interop stack uses its own compose file.
    INTEROP_COMPOSE="${REPO_ROOT}/docker/devnet/tailscale-interop/docker-compose.yml"
    if [[ -f "${INTEROP_COMPOSE}" ]]; then
        docker compose -f "${INTEROP_COMPOSE}" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    # Mesh demo stack (used by tapes 04 / 07 / 08 / 09 / 10 / 13 / 14 /
    # 18 / 22 / 00 after the demo-realize rewrite).
    MESH_COMPOSE="${REPO_ROOT}/docker-compose.mesh-demo.yml"
    if [[ -f "${MESH_COMPOSE}" ]]; then
        docker compose -f "${MESH_COMPOSE}" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
fi

# 3. Per-tape one-shot fixture containers spawned by the new
# *-bringup.sh helpers (audit / keygen / portal / pvac). Each
# teardown is best-effort and safe on a cold host.
for sub in audit-fixture-teardown.sh keygen-fixture-teardown.sh \
           portal-container-teardown.sh pvac-teardown.sh \
           devnet-mock-teardown.sh; do
    if [[ -x "${DEMO_DIR}/lib/${sub}" ]]; then
        "${DEMO_DIR}/lib/${sub}" >/dev/null 2>&1 || true
    fi
done

echo "teardown.sh: done" >&2
