#!/usr/bin/env bash
# portal-container-bringup.sh
#
# Containerized portal fixture for tapes 02 / 15 / 16. Spins up
# mock-rpc + node1 (so the portal has a chain to talk to) via the
# root docker-compose.yml, then starts an `octravpn portal` container
# bound to the same network. Exposes /healthz on the host at
# 127.0.0.1:51823 so curl probes from the recording terminal work.
#
# Exit codes:
#   0   READY — /healthz returns 200 from the host.
#   10  preflight (compose / binary) failed.
#   20  mock chain bringup failed.
#   30  portal container failed to come up.
#   40  /healthz never reached 200 in the deadline.
#
# Idempotent: re-runs leave the chain stack alone and recycle just the
# portal container.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)

# Ensure the chain substrate is up.
"${SCRIPT_DIR}/devnet-mock-bringup.sh" >&2 || {
    echo "portal-container-bringup: chain bringup failed" >&2
    exit 20
}

COMPOSE_BASE="${REPO_ROOT}/docker-compose.yml"
NET_NAME="$(docker compose -f "${COMPOSE_BASE}" config --format json 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(iter(d.get("networks", {})), "octravpn_octravpn"))' \
    2>/dev/null || echo octravpn_octravpn)"

PORTAL_CONTAINER="${PORTAL_CONTAINER:-octravpn-portal-demo}"
PORTAL_BIND_HOST="${PORTAL_BIND_HOST:-127.0.0.1:51823}"
READY_TIMEOUT_SECS="${PORTAL_READY_TIMEOUT:-30}"

# Locate a client binary to mount in. On a fresh macOS host the Linux
# binary won't exist yet — kick the shared builder. The helper is a
# no-op when the artefact is already fresh (sub-second), so CI (which
# pre-stages the binary) doesn't pay any cost.
LINUX_BIN="${REPO_ROOT}/target/linux-debug/debug/octravpn"
if [[ ! -x "${LINUX_BIN}" ]]; then
    if ! "${SCRIPT_DIR}/build-linux-binaries.sh" >&2; then
        echo "portal-container-bringup: build-linux-binaries.sh failed" >&2
        exit 10
    fi
fi

BIN=""
for candidate in \
    "${LINUX_BIN}" \
    "${REPO_ROOT}/target/release/octravpn" \
    "${REPO_ROOT}/target/debug/octravpn"; do
    if [[ -x "${candidate}" ]]; then
        BIN="${candidate}"
        break
    fi
done
if [[ -z "${BIN}" ]]; then
    echo "portal-container-bringup: octravpn binary not found under target/" >&2
    echo "  run demo/lib/build-linux-binaries.sh to produce target/linux-debug/debug/octravpn" >&2
    exit 10
fi

# Client config — point at the mock-rpc on the compose network.
PORTAL_STATE="${REPO_ROOT}/demo/.portal-state"
mkdir -p "${PORTAL_STATE}"
if [[ ! -f "${PORTAL_STATE}/config.toml" ]]; then
    cat > "${PORTAL_STATE}/config.toml" <<'TOML'
[chain]
rpc_url          = "http://mock-rpc:18080/rpc"
program_addr     = "octPROGmockaddress0000000000000000000000"
# The oct:// portal handler refuses to start on the v1.1 path —
# circles are a v2/v3 substrate.  Pin to v2 (mock-rpc's surface
# matches v2; v3 here would also work but pulls extra anchors we
# don't fixture).
protocol_version = "v2"

# ClientConfig requires a [wallet] section even though the portal
# only reads chain assets — the deserializer fails fast otherwise.
# The path doesn't need to point at a real key; the portal subcommand
# never signs.  Use a deterministic dummy for reproducibility.
[wallet]
addr        = "octWALLETportaldemo000000000000000000000"
secret_path = "/etc/octravpn/wallet.key"

[portal]
bind = "0.0.0.0:51823"
TOML
fi

# Materialize a dummy wallet.key so the portal binary's lazy-loader
# (if it touches the file at startup) doesn't ENOENT.  Content is
# ignored as long as nothing signs.
if [[ ! -f "${PORTAL_STATE}/wallet.key" ]]; then
    echo "00000000000000000000000000000000" > "${PORTAL_STATE}/wallet.key"
    chmod 0600 "${PORTAL_STATE}/wallet.key"
fi

docker rm -f "${PORTAL_CONTAINER}" >/dev/null 2>&1 || true

# Resolve the actual network from the running compose project. The
# default project name is the parent dir basename.
PROJECT_NETWORK="$(docker network ls --format '{{.Name}}' | grep -E '^[a-z0-9_-]+_octravpn$' | head -1 || true)"
if [[ -z "${PROJECT_NETWORK}" ]]; then
    PROJECT_NETWORK="octra_octravpn"
fi

docker run -d --name "${PORTAL_CONTAINER}" \
    --network "${PROJECT_NETWORK}" \
    -p "${PORTAL_BIND_HOST}:51823" \
    -v "${BIN}":/usr/local/bin/octravpn:ro \
    -v "${PORTAL_STATE}":/etc/octravpn:ro \
    debian:bookworm-slim \
    /usr/local/bin/octravpn --config /etc/octravpn/config.toml portal --bind 0.0.0.0:51823 \
    >/dev/null || {
        echo "portal-container-bringup: docker run failed" >&2
        exit 30
    }

# Wait for /healthz to respond on the host-published port.
host_port="${PORTAL_BIND_HOST##*:}"
host_host="${PORTAL_BIND_HOST%%:*}"
deadline=$(( $(date +%s) + READY_TIMEOUT_SECS ))
while (( $(date +%s) < deadline )); do
    if curl -fsS --max-time 1 "http://${host_host}:${host_port}/healthz" >/dev/null 2>&1; then
        echo "portal container ready at http://${host_host}:${host_port}/" >&2
        echo "READY"
        exit 0
    fi
    sleep 1
done

echo "portal-container-bringup: /healthz never reached 200 in ${READY_TIMEOUT_SECS}s" >&2
docker logs --tail 30 "${PORTAL_CONTAINER}" >&2 || true
exit 40
