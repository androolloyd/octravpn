#!/usr/bin/env bash
# 3node-mesh-bringup.sh
#
# Cold-start the 3-peer mesh demo and drive stock tailscale through
# the canonical `tailscale up` flow against `octravpn-node mesh serve`.
# Modelled directly on `docker/devnet/tailscale-interop/run-interop.sh`
# — every step from the proven 2-peer interop fixture is preserved
# verbatim with the peer count bumped to 3 plus the analytics indexer
# attached.
#
# Exit codes (mirror run-interop.sh so the calling tape's failure
# surface is recognisable):
#   0   READY — all 3 peers visible in `tailscale status` on peer-1.
#   10  build / compose bring-up failed.
#   20  preauth surface unreachable.
#   30  `tailscale up` failed on at least one peer.
#   40  IP-plane convergence (3 peers visible to peer-1) never landed.
#
# Idempotent: re-running on a warm stack reuses the existing
# containers; the script polls the preauth surface and `tailscale
# status` rather than asserting a clean cold-start.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
COMPOSE_FILE="${REPO_ROOT}/docker-compose.mesh-demo.yml"

# Demo-local state lives under demo/.mesh-state so a `docker compose
# down -v` leaves the cert + audit dir behind for inspection. The
# interop fixture's state dir is untouched.
STATE_DIR="${REPO_ROOT}/demo/.mesh-state"
mkdir -p "${STATE_DIR}/tailscale-wire" "${STATE_DIR}/audit"

# Tunables — env-overridable so the tape author can stretch deadlines
# without editing the script.
READY_TIMEOUT_SECS="${MESH_DEMO_READY_TIMEOUT:-90}"
TS_UP_TIMEOUT_SECS="${MESH_DEMO_TS_UP_TIMEOUT:-90}"

step() {
    printf '\n=== %s ===\n' "$1" >&2
}

# Best-effort teardown happens via the explicit `3node-mesh-teardown.sh`
# — not on EXIT here so the operator can interrupt mid-bringup and
# still poke at the containers for diagnostics. The CI workflow always
# runs teardown after the tape regardless of exit code.

# ---------------------------------------------------------------------------
# Step 1 — build octravpn-node + octravpn-analytics for Linux.
# Reuses the same builder-container path the interop test uses so the
# `target/linux-debug/` cache is shared across both fixtures.
# ---------------------------------------------------------------------------

step "Step 1: build octravpn-node + octravpn-analytics (Linux target)"

# The shared builder always asks Cargo to check the complete dependency graph.
# Existing executables alone cannot establish freshness after a library update.
bash "${SCRIPT_DIR}/build-linux-binaries.sh" >&2 || exit 10

# ---------------------------------------------------------------------------
# Step 2 — bring up the stack.
# ---------------------------------------------------------------------------

step "Step 2: docker compose up"
docker compose -f "${COMPOSE_FILE}" up -d >&2 || {
    echo "COMPOSE FAIL: could not start mesh-control + peers + analytics" >&2
    exit 10
}

# Wait until the mesh-control binary is reachable inside the container.
mesh_reachable=""
for _ in $(seq 1 20); do
    if docker exec mesh-demo-control test -x /usr/local/bin/octravpn-node >/dev/null 2>&1; then
        mesh_reachable=1
        break
    fi
    sleep 1
done
if [[ -z "${mesh_reachable}" ]]; then
    echo "MESH-CONTROL UNREACHABLE: binary not visible inside container in 20s" >&2
    docker compose -f "${COMPOSE_FILE}" logs mesh-control >&2 || true
    exit 10
fi
echo "mesh-control container ready" >&2

# ---------------------------------------------------------------------------
# Step 3 — mint 3 preauth keys via the /admin/preauth HTTP endpoint.
# `mesh serve`'s in-process minter binds each key to the running
# daemon's redemption store, so a key minted here is immediately
# accepted by `tailscale up` against the same listener. Tape 04's
# pattern, scaled to 3 peers.
# ---------------------------------------------------------------------------

step "Step 3: mint 3 preauth keys"

mint_preauth() {
    local label="$1"
    curl -fsS --max-time 5 \
        -H "Authorization: Bearer mesh-demo-token" \
        -H "Content-Type: application/json" \
        -d "{\"user\":\"${label}\",\"reusable\":false}" \
        http://127.0.0.1:51821/admin/preauth 2>/dev/null \
        | sed -nE 's/.*"key"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p'
}

PREAUTH_1=""; PREAUTH_2=""; PREAUTH_3=""
for _ in $(seq 1 15); do
    PREAUTH_1=$(mint_preauth peer-1 || true)
    if [[ -n "${PREAUTH_1}" ]]; then break; fi
    sleep 1
done
if [[ -z "${PREAUTH_1}" ]]; then
    echo "PREAUTH SURFACE MISSING: /admin/preauth never returned a key" >&2
    exit 20
fi
PREAUTH_2=$(mint_preauth peer-2 || true)
PREAUTH_3=$(mint_preauth peer-3 || true)
if [[ -z "${PREAUTH_2}" || -z "${PREAUTH_3}" ]]; then
    echo "PREAUTH SURFACE PARTIAL: peer-2 or peer-3 key missing" >&2
    exit 20
fi
echo "minted 3 preauth keys" >&2

# This isolated interop fixture deliberately permits all registered peers.
# Native DERP otherwise refuses forwarding until an explicit ACL is loaded.
curl -fsS --max-time 5 \
    -X PUT -H "Authorization: Bearer mesh-demo-token" \
    -H "Content-Type: application/json" \
    -d '{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}' \
    http://127.0.0.1:51821/api/v1/policy >/dev/null

# ---------------------------------------------------------------------------
# Step 4 — install the mesh-control self-signed cert into each peer's
# trust store, then `tailscale up`. The peer entrypoint already runs
# the cert-install dance once at boot but we re-run via `docker exec`
# to handle the case where the cert was minted *after* tailscaled came
# up (race with first-bind).
# ---------------------------------------------------------------------------

step "Step 4: wait for the mesh-control TLS cert"
CERT_HOST_PATH="${STATE_DIR}/tailscale-wire/tls.crt"
for _ in $(seq 1 30); do
    if [[ -s "${CERT_HOST_PATH}" ]]; then break; fi
    sleep 1
done
if [[ ! -s "${CERT_HOST_PATH}" ]]; then
    echo "TLS CERT MISSING: ${CERT_HOST_PATH} not present after 30s" >&2
    docker compose -f "${COMPOSE_FILE}" logs mesh-control >&2 || true
    exit 10
fi
echo "TLS cert at ${CERT_HOST_PATH}" >&2

step "Step 4b: install cert into peer trust stores (post-mint refresh)"
for peer in tsi-peer-1 tsi-peer-2 tsi-peer-3; do
    docker exec "${peer}" sh -c '
        set -e
        if [ -s /mnt/mesh-control-state/tailscale-wire/tls.crt ]; then
            mkdir -p /usr/local/share/ca-certificates
            cp /mnt/mesh-control-state/tailscale-wire/tls.crt \
               /usr/local/share/ca-certificates/octravpn-mesh-control.crt
            if command -v update-ca-certificates >/dev/null 2>&1; then
                update-ca-certificates >/dev/null 2>&1 || true
            fi
        fi
    ' || echo "WARN: cert install failed in ${peer}; continuing" >&2
done

step "Step 4c: wait for native DERP on mesh-control"
DERP_READY=""
for _ in $(seq 1 30); do
    if curl -ksf --max-time 3 https://127.0.0.1:8443/derp/probe >/dev/null 2>&1; then
        DERP_READY=1
        break
    fi
    sleep 1
done
if [[ -z "${DERP_READY}" ]]; then
    echo "NATIVE DERP NOT READY: probe endpoint never returned 200" >&2
    docker compose -f "${COMPOSE_FILE}" logs --tail 30 mesh-control >&2 || true
    exit 10
fi
echo "native DERP probe ok" >&2

step "Step 5: tailscale up on each of 3 peers"
LOGIN_SERVER="https://mesh-control"
ts_up() {
    local peer="$1" key="$2"
    docker exec "${peer}" sh -c \
        "/usr/bin/timeout ${TS_UP_TIMEOUT_SECS} tailscale --socket=/var/run/tailscale/tailscaled.sock up \
            --login-server '${LOGIN_SERVER}' \
            --authkey '${key}' \
            --hostname ${peer} \
            --accept-routes \
            --reset" \
        >>/tmp/mesh-demo-up-${peer}.log 2>&1
}
ts_up tsi-peer-1 "${PREAUTH_1}" || { echo "tailscale up failed on peer-1" >&2; tail -n 30 /tmp/mesh-demo-up-tsi-peer-1.log >&2 || true; exit 30; }
ts_up tsi-peer-2 "${PREAUTH_2}" || { echo "tailscale up failed on peer-2" >&2; tail -n 30 /tmp/mesh-demo-up-tsi-peer-2.log >&2 || true; exit 30; }
ts_up tsi-peer-3 "${PREAUTH_3}" || { echo "tailscale up failed on peer-3" >&2; tail -n 30 /tmp/mesh-demo-up-tsi-peer-3.log >&2 || true; exit 30; }
echo "tailscale up succeeded on all 3 peers" >&2

# ---------------------------------------------------------------------------
# Step 6 — readiness: poll `tailscale status` on peer-1 until all
# three peers are visible. The tailscale daemon reports its own
# peer-set; this is cheaper + more accurate than polling the admin
# `/api/v1/machines` route (which requires admin-router mount, not
# done in the current Hub-free `mesh serve`).
# ---------------------------------------------------------------------------

step "Step 6: wait for 3-peer convergence on the IP plane"
deadline=$(( $(date +%s) + READY_TIMEOUT_SECS ))
last_count="?"
peer_count=0
while (( $(date +%s) < deadline )); do
    peer_count=$(docker exec tsi-peer-1 tailscale --socket=/var/run/tailscale/tailscaled.sock status \
        --peers --json 2>/dev/null \
        | grep -c '"HostName"' || true)
    # `tailscale status --peers --json` lists peers OTHER than self —
    # so 2 peers visible on peer-1 means all 3 are up.
    if [[ "${peer_count}" != "${last_count}" ]]; then
        echo "peer-1 sees ${peer_count}/2 peers" >&2
        last_count="${peer_count}"
    fi
    if (( peer_count >= 2 )); then
        echo "READY"
        exit 0
    fi
    sleep 2
done

echo "IP-PLANE CONVERGENCE FAILED: peer-1 only saw ${peer_count} of 2 expected peers" >&2
docker compose -f "${COMPOSE_FILE}" logs --tail 40 mesh-control >&2 || true
exit 40
