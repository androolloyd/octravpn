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
INTEROP_DIR="${REPO_ROOT}/docker/devnet/tailscale-interop"

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

LINUX_TARGET_DIR="${REPO_ROOT}/target/linux-debug"
mkdir -p "${LINUX_TARGET_DIR}/debug"

# Fast-path: if both Linux binaries already exist at the expected paths,
# skip the docker-cargo-build entirely. The CI workflow's preceding
# "Build octravpn-node + analytics" step is expected to drop them here;
# local operators can build once and re-render tapes without rebuilding.
if [[ -x "${LINUX_TARGET_DIR}/debug/octravpn-node" \
   && -x "${LINUX_TARGET_DIR}/debug/octravpn-analytics" ]]; then
    echo "linux binaries already present under ${LINUX_TARGET_DIR}/debug/ — skipping rebuild" >&2
else
    OCTRA_FOUNDRY="${REPO_ROOT}/../octra-foundry"
    if [[ ! -d "${OCTRA_FOUNDRY}" ]]; then
        echo "BUILD FAIL: ../octra-foundry not found next to repo root" >&2
        exit 10
    fi
    HEADSCALE_RS="${REPO_ROOT}/../headscale-rs"
    if [[ ! -d "${HEADSCALE_RS}" ]]; then
        echo "BUILD FAIL: ../headscale-rs not found next to repo root" >&2
        exit 10
    fi

    BUILDER_IMAGE="octravpn-builder:latest"
    if ! docker image inspect "${BUILDER_IMAGE}" >/dev/null 2>&1; then
        echo "octravpn-builder:latest not present; falling back to rust:1.88-bookworm" >&2
        BUILDER_IMAGE="rust:1.88-bookworm"
    fi

    mkdir -p "${LINUX_TARGET_DIR}/cargo-registry" \
             "${LINUX_TARGET_DIR}/cargo-git"

    docker run --rm \
        -v "${REPO_ROOT}":/work/octra \
        -v "${OCTRA_FOUNDRY}":/work/octra-foundry \
        -v "${HEADSCALE_RS}":/work/headscale-rs \
        -v "${LINUX_TARGET_DIR}":/work/octra/target \
        -v "${LINUX_TARGET_DIR}/cargo-registry":/usr/local/cargo/registry \
        -v "${LINUX_TARGET_DIR}/cargo-git":/usr/local/cargo/git \
        -w /work/octra \
        "${BUILDER_IMAGE}" \
        bash -c "cargo build --bin octravpn-node && cargo build --bin octravpn-analytics" >&2 || {
            echo "BUILD FAIL: cargo build inside ${BUILDER_IMAGE} failed" >&2
            exit 10
        }
    test -x "${LINUX_TARGET_DIR}/debug/octravpn-node" || {
        echo "BUILD FAIL: binary not at ${LINUX_TARGET_DIR}/debug/octravpn-node" >&2
        exit 10
    }
    test -x "${LINUX_TARGET_DIR}/debug/octravpn-analytics" || {
        echo "BUILD FAIL: binary not at ${LINUX_TARGET_DIR}/debug/octravpn-analytics" >&2
        exit 10
    }
    echo "linux binaries built under ${LINUX_TARGET_DIR}/debug/" >&2
fi

# ---------------------------------------------------------------------------
# Step 1b — mint the derp-1 TLS cert (shared with the interop fixture).
# We reuse the interop fixture's `derp-certs/` directory by reference,
# so a single openssl invocation services both stacks.
# ---------------------------------------------------------------------------

step "Step 1b: ensure derp-1 self-signed cert"

mkdir -p "${INTEROP_DIR}/derp-certs"
DERP_CERT="${INTEROP_DIR}/derp-certs/derp-1.crt"
DERP_KEY="${INTEROP_DIR}/derp-certs/derp-1.key"
if [[ ! -s "${DERP_CERT}" || ! -s "${DERP_KEY}" ]]; then
    if ! command -v openssl >/dev/null 2>&1; then
        echo "OPENSSL MISSING: needed to mint derp-1 self-signed cert" >&2
        exit 10
    fi
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${DERP_KEY}" \
        -out "${DERP_CERT}" \
        -days 30 \
        -subj "/CN=derp-1" \
        -addext "subjectAltName=DNS:derp-1" \
        >/dev/null 2>&1 || {
            echo "OPENSSL FAIL: could not mint derp-1 cert" >&2
            exit 10
        }
    chmod 0644 "${DERP_CERT}" "${DERP_KEY}"
    echo "minted derp-1 cert at ${DERP_CERT}" >&2
else
    echo "derp-1 cert already present at ${DERP_CERT}; reusing" >&2
fi

# ---------------------------------------------------------------------------
# Step 2 — bring up the stack.
# ---------------------------------------------------------------------------

step "Step 2: docker compose up"
docker compose -f "${COMPOSE_FILE}" build derp-1 >&2 || {
    echo "DERPER BUILD FAIL: could not build the derper sidecar image" >&2
    exit 10
}
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

step "Step 4c: wait for derp-1 probe endpoint"
DERP_READY=""
for _ in $(seq 1 30); do
    if docker exec tsi-peer-1 sh -c \
        'wget -qO- --no-check-certificate https://derp-1/derp/probe 2>/dev/null || \
         curl -fsSk https://derp-1/derp/probe 2>/dev/null' >/dev/null 2>&1; then
        DERP_READY=1
        break
    fi
    sleep 1
done
if [[ -z "${DERP_READY}" ]]; then
    echo "DERP-1 NOT READY: probe endpoint never returned 200" >&2
    docker compose -f "${COMPOSE_FILE}" logs derp-1 >&2 | tail -30 || true
    exit 10
fi
echo "derp-1 probe ok" >&2

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
