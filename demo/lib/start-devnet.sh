#!/usr/bin/env bash
# start-devnet.sh
#
# Bring up the OctraVPN devnet stack (mock-rpc + three node containers
# + builder image) using the project's docker-compose files. Idempotent:
# if the services are already running, `docker compose up -d` is a no-op
# at the container level.
#
# Sourced by VHS tapes that want a chain to talk to without hitting a
# real RPC. Mirrors the boot sequence documented in
# `docker/devnet/README.md`.

set -euo pipefail

DEMO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO_ROOT=$(cd "${DEMO_DIR}/.." && pwd)

if ! command -v docker >/dev/null 2>&1; then
    echo "start-devnet.sh: docker not on PATH; install Docker Desktop or equivalent" >&2
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "start-devnet.sh: 'docker compose' v2 not available" >&2
    exit 1
fi

COMPOSE_BASE="${REPO_ROOT}/docker-compose.yml"
COMPOSE_DEVNET="${REPO_ROOT}/docker/devnet/docker-compose.devnet.yml"

if [[ ! -f "${COMPOSE_BASE}" ]]; then
    echo "start-devnet.sh: missing ${COMPOSE_BASE}" >&2
    exit 1
fi
if [[ ! -f "${COMPOSE_DEVNET}" ]]; then
    echo "start-devnet.sh: missing ${COMPOSE_DEVNET}" >&2
    exit 1
fi

cd "${REPO_ROOT}"
docker compose -f "${COMPOSE_BASE}" -f "${COMPOSE_DEVNET}" up -d mock-rpc node1 node2 node3 >&2

# Light readiness probe — mock-rpc exposes a JSON-RPC port; we just
# wait for the container to report healthy / running. The interop
# harness has the canonical readiness logic; we keep this loose so
# the tape doesn't sit on a long boot.
for _ in $(seq 1 20); do
    state=$(docker inspect -f '{{.State.Status}}' octra-devnet-mock-rpc 2>/dev/null \
            || docker inspect -f '{{.State.Status}}' devnet-mock-rpc 2>/dev/null \
            || echo "missing")
    if [[ "${state}" == "running" ]]; then
        echo "devnet up (mock-rpc running)" >&2
        exit 0
    fi
    sleep 1
done

echo "start-devnet.sh: mock-rpc never reached running state in 20s" >&2
exit 1
