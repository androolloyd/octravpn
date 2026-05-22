#!/usr/bin/env bash
# devnet-bringup.sh
#
# Demo flow's substitute for `devnet-mock-bringup.sh`. Instead of
# spinning up the in-process mock-rpc, this:
#
#   1. Ensures the canonical demo circle exists on the live Octra
#      devnet (delegates to `devnet-circle-deploy.sh`).
#   2. Brings up 3 demo-node containers (`node1/2/3` services overlaid
#      with `docker-compose.demo.yml`) configured to talk to
#      `https://devnet.octrascan.io/rpc`.
#   3. Exports `OCTRAVPN_DEMO_CIRCLE_ID` + `OCTRAVPN_SEALED_PASSPHRASE`
#      into the containers so the tape body can `${OCTRAVPN_DEMO_CIRCLE_ID}`
#      its way to the resolved id.
#
# Idempotent. Re-runs on a warm stack do nothing.
#
# Exit codes:
#   0   READY — circle deploy + node containers running.
#   10  preflight (docker compose / scripts missing) failed.
#   20  circle deploy step failed.
#   30  node container bringup failed.
#   40  readiness deadline exceeded.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
COMPOSE_BASE="${REPO_ROOT}/docker-compose.yml"
COMPOSE_DEMO="${REPO_ROOT}/docker-compose.demo.yml"
READY_TIMEOUT_SECS="${DEVNET_READY_TIMEOUT:-90}"

if [[ ! -f "${COMPOSE_BASE}" || ! -f "${COMPOSE_DEMO}" ]]; then
    echo "devnet-bringup: missing compose file(s)" >&2
    exit 10
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "devnet-bringup: docker not on PATH" >&2
    exit 10
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "devnet-bringup: 'docker compose' v2 missing" >&2
    exit 10
fi

cd "${REPO_ROOT}"

# Step 1 — ensure the demo circle exists + is fully seeded.
CIRCLE_ID=$("${SCRIPT_DIR}/devnet-circle-deploy.sh" 2>&1 | tail -1)
if [[ -z "${CIRCLE_ID}" || "${CIRCLE_ID}" != oct* ]]; then
    echo "devnet-bringup: circle deploy did not return a usable id (got: ${CIRCLE_ID})" >&2
    exit 20
fi
echo "devnet-bringup: circle ready: ${CIRCLE_ID}" >&2

export OCTRAVPN_DEMO_CIRCLE_ID="${CIRCLE_ID}"
export OCTRAVPN_SEALED_PASSPHRASE="${OCTRAVPN_SEALED_PASSPHRASE:-demo}"

# Step 2 — build + bring up the three demo-node containers via the
# demo overlay. The builder image gets cached after the first run.
# If the prebuilt images are already on the host (the common case;
# the e2e job + docker compose builds keep them warm), skip the
# rebuild — it can take 5+ min on a cold cache. Set
# `DEMO_FORCE_REBUILD=1` to override (e.g. after a Cargo.toml bump).
if [[ -n "${DEMO_FORCE_REBUILD:-}" ]] || ! docker image inspect octravpn-node:latest >/dev/null 2>&1; then
    docker compose -f "${COMPOSE_BASE}" -f "${COMPOSE_DEMO}" build builder >&2 || {
        echo "devnet-bringup: builder image build failed" >&2
        exit 30
    }
    docker compose -f "${COMPOSE_BASE}" -f "${COMPOSE_DEMO}" build node1 node2 node3 >&2 || {
        echo "devnet-bringup: node image build failed" >&2
        exit 30
    }
fi

docker compose -f "${COMPOSE_BASE}" -f "${COMPOSE_DEMO}" up -d node1 node2 node3 >&2 || {
    echo "devnet-bringup: 'docker compose up' failed" >&2
    exit 30
}

# Step 3 — wait for all three to reach 'running'.
deadline=$(( $(date +%s) + READY_TIMEOUT_SECS ))
while (( $(date +%s) < deadline )); do
    not_running=0
    for svc in node1 node2 node3; do
        state=$(docker compose -f "${COMPOSE_BASE}" -f "${COMPOSE_DEMO}" \
            ps --status running --services 2>/dev/null \
            | grep -c "^${svc}\$" || true)
        if (( state == 0 )); then
            not_running=$((not_running + 1))
        fi
    done
    if (( not_running == 0 )); then
        echo "devnet stack ready (demo circle: ${CIRCLE_ID})" >&2
        echo "READY"
        # Echo a final clean line that consumers (preflight, tapes) can
        # parse for the resolved circle id.
        printf 'OCTRAVPN_DEMO_CIRCLE_ID=%s\n' "${CIRCLE_ID}"
        exit 0
    fi
    sleep 2
done

echo "devnet-bringup: ${not_running} service(s) never reached running" >&2
docker compose -f "${COMPOSE_BASE}" -f "${COMPOSE_DEMO}" ps >&2 || true
exit 40
