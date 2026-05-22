#!/usr/bin/env bash
# portal-container-bringup.sh
#
# Containerized portal fixture for tapes 02 / 15 / 16. Wires the portal
# to the LIVE Octra devnet (https://devnet.octrascan.io/rpc) — no
# mock-rpc — and ensures the demo circle (5 sealed assets, passphrase
# `demo`) is deployed. Starts an `octravpn portal` container bound to
# the host at 127.0.0.1:51823 so curl probes from the recording
# terminal work.
#
# Exports into the portal container env:
#   OCTRAVPN_DEMO_CIRCLE_ID   — the resolved devnet circle id
#   OCTRAVPN_SEALED_PASSPHRASE — shared passphrase (default `demo`)
#
# Exit codes:
#   0   READY — /healthz returns 200 from the host.
#   10  preflight (compose / binary) failed.
#   20  devnet circle setup failed.
#   30  portal container failed to come up.
#   40  /healthz never reached 200 in the deadline.
#
# Idempotent: re-runs reuse the circle on-chain and just recycle the
# portal container.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)

# Ensure the demo circle exists + is fully seeded on devnet. The
# bringup script prints the circle id on its last line; we capture it
# into the portal env so the tape body can `${OCTRAVPN_DEMO_CIRCLE_ID}`
# its way to the real id.
CIRCLE_OUT=$("${SCRIPT_DIR}/devnet-circle-deploy.sh" 2>&1) || {
    echo "portal-container-bringup: devnet circle setup failed" >&2
    printf '%s\n' "${CIRCLE_OUT}" >&2
    exit 20
}
OCTRAVPN_DEMO_CIRCLE_ID=$(printf '%s\n' "${CIRCLE_OUT}" | tail -1)
if [[ -z "${OCTRAVPN_DEMO_CIRCLE_ID}" || "${OCTRAVPN_DEMO_CIRCLE_ID}" != oct* ]]; then
    echo "portal-container-bringup: could not resolve circle id (got: ${OCTRAVPN_DEMO_CIRCLE_ID})" >&2
    exit 20
fi
export OCTRAVPN_DEMO_CIRCLE_ID
export OCTRAVPN_SEALED_PASSPHRASE="${OCTRAVPN_SEALED_PASSPHRASE:-demo}"

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

# Portal config — point at the live Octra devnet. Re-render every
# bringup so a stale `mock-rpc:18080` config from a prior tape run
# can't sneak through. The portal subcommand reads `chain.rpc_url`
# directly; we leave protocol_version at v2 (the chain.rs default for
# circles).
PORTAL_STATE="${REPO_ROOT}/demo/.portal-state"
mkdir -p "${PORTAL_STATE}"
cat > "${PORTAL_STATE}/config.toml" <<TOML
[chain]
rpc_url          = "https://devnet.octrascan.io/rpc"
program_addr     = "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3"
# The oct:// portal handler refuses to start on the v1.1 path —
# circles are a v2/v3 substrate. Pin to v2.
protocol_version = "v2"

# ClientConfig requires a [wallet] section even though the portal
# only reads chain assets — the deserializer fails fast otherwise.
# The path doesn't need to point at a real key; the portal subcommand
# never signs. Use a deterministic dummy for reproducibility.
[wallet]
addr        = "octWALLETportaldemo000000000000000000000"
secret_path = "/etc/octravpn/wallet.key"

[portal]
bind = "0.0.0.0:51823"
TOML

# Materialize a dummy wallet.key so the portal binary's lazy-loader
# (if it touches the file at startup) doesn't ENOENT.  Content is
# ignored as long as nothing signs.
if [[ ! -f "${PORTAL_STATE}/wallet.key" ]]; then
    echo "00000000000000000000000000000000" > "${PORTAL_STATE}/wallet.key"
    chmod 0600 "${PORTAL_STATE}/wallet.key"
fi

docker rm -f "${PORTAL_CONTAINER}" >/dev/null 2>&1 || true

# Portal talks to the live devnet over the internet, so it doesn't
# need the compose network. Reuse it if present (so a tape that boots
# the demo-node stack alongside can still reach the portal by service
# name), otherwise fall back to the default bridge.
PROJECT_NETWORK="$(docker network ls --format '{{.Name}}' | grep -E '^[a-z0-9_-]+_octravpn$' | head -1 || true)"
if [[ -z "${PROJECT_NETWORK}" ]] || ! docker network inspect "${PROJECT_NETWORK}" >/dev/null 2>&1; then
    PROJECT_NETWORK="bridge"
fi

docker run -d --name "${PORTAL_CONTAINER}" \
    --network "${PROJECT_NETWORK}" \
    -p "${PORTAL_BIND_HOST}:51823" \
    -e OCTRAVPN_DEMO_CIRCLE_ID="${OCTRAVPN_DEMO_CIRCLE_ID}" \
    -e OCTRAVPN_SEALED_PASSPHRASE="${OCTRAVPN_SEALED_PASSPHRASE}" \
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
