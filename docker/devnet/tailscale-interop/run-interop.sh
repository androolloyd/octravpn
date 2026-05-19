#!/usr/bin/env bash
# Tailscale-interop test harness.
#
# Drives a stock `tailscale/tailscale:latest` client through the
# canonical join + ping flow against the OctraVPN mesh control plane.
#
# Exit codes (the test's spec — DO NOT renumber without updating the
# corresponding documentation in
# `docs/tailscale-interop-finding.md` and the calling subagent
# prompt):
#
#   0   tailscale ping succeeded end-to-end.
#   10  mesh-control didn't reach /health (or its preauth surface).
#   20  preauth-key minting surface not available.
#   30  tailscale up failed on at least one peer.
#   40  peers never converged on the IP plane.
#   50  tailscale ping failed despite peers being up.
#
# This harness is intentionally **docker-only**. The OctraVPN test
# rig forbids running daemons natively (see
# `memory/feedback_docker_only.md`); native paths are not supported.

set -euo pipefail

# ---------------------------------------------------------------------------
# Layout + paths.
# ---------------------------------------------------------------------------

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../../.." && pwd)
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

# Shared state directory for the mesh-control container + the peer
# containers (cert distribution). Created idempotently — the compose
# file bind-mounts ./state into /work/state on mesh-control and
# /mnt/mesh-control-state on each peer. The TLS cert + Noise static
# key land under tailscale-wire/.
mkdir -p "${SCRIPT_DIR}/state/tailscale-wire"

# Pretty-prints a step header so the operator can tell which exit code
# corresponds to which failure point.
step() {
    printf '\n=== %s ===\n' "$1" >&2
}

# Best-effort teardown. Always run on exit so a Ctrl-C doesn't leak
# containers across the next run.
cleanup() {
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 1 — build a Linux-compatible octravpn-node binary.
#
# The compose file bind-mounts the binary into the mesh-control
# container at /usr/local/bin/octravpn-node. On macOS hosts a host
# `cargo build` produces a Mach-O which can't be exec'd inside a
# Linux container; instead we run cargo build inside the existing
# `octravpn-builder` image (or, if not present, a stock
# `rust:1.88-bookworm`) and emit to `target/linux-debug/`. The build
# is bind-mounted, so the second run is incremental.
#
# Why not a build stage in the compose file: the `octravpn-builder`
# image already exists in the project's docker harness; reusing it
# keeps the workspace target/ caches warm across `e2e.sh` and the
# interop test.
# ---------------------------------------------------------------------------

step "Step 1: build octravpn-node (Linux target via container)"

# The `octra-foundry` sibling provides path-deps (`octra-core`,
# `octra-mock-rpc`). The interop build needs it bind-mounted next to
# the repo just like the rest of the OctraVPN harness does.
OCTRA_FOUNDRY="${REPO_ROOT}/../octra-foundry"
if [[ ! -d "${OCTRA_FOUNDRY}" ]]; then
    echo "BUILD FAIL: ../octra-foundry not found next to repo root" >&2
    exit 10
fi

# The `headscale-rs` sibling provides the `headscale-api` crate which
# hosts the Tailscale-wire layer (migrated 2026-05-19). octravpn-mesh
# depends on it via `path = "../../../headscale-rs/headscale-api"`, so
# the builder container needs both repos mounted side-by-side.
HEADSCALE_RS="${REPO_ROOT}/../headscale-rs"
if [[ ! -d "${HEADSCALE_RS}" ]]; then
    echo "BUILD FAIL: ../headscale-rs not found next to repo root" >&2
    exit 10
fi

# Prefer the project's own builder image (which already has the
# system deps, the rust toolchain, and a warm cargo cache); fall
# back to a stock rust:1.88-bookworm if it hasn't been built locally
# yet.
BUILDER_IMAGE="octravpn-builder:latest"
if ! docker image inspect "${BUILDER_IMAGE}" >/dev/null 2>&1; then
    echo "octravpn-builder:latest not present; falling back to rust:1.88-bookworm" >&2
    BUILDER_IMAGE="rust:1.88-bookworm"
fi

LINUX_TARGET_DIR="${REPO_ROOT}/target/linux-debug"
mkdir -p "${LINUX_TARGET_DIR}" \
         "${LINUX_TARGET_DIR}/cargo-registry" \
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
    bash -c "cargo build --bin octravpn-node" >&2 || {
        echo "BUILD FAIL: cargo build inside ${BUILDER_IMAGE} failed" >&2
        exit 10
    }

LINUX_BIN="${LINUX_TARGET_DIR}/debug/octravpn-node"
test -x "${LINUX_BIN}" || {
    echo "BUILD FAIL: binary not at ${LINUX_BIN}" >&2
    exit 10
}
echo "linux binary at ${LINUX_BIN}" >&2

# ---------------------------------------------------------------------------
# Step 2 — bring up the compose stack.
# ---------------------------------------------------------------------------

step "Step 2: docker compose up"
docker compose -f "${COMPOSE_FILE}" up -d >&2 || {
    echo "COMPOSE FAIL: could not start mesh-control + ts peers" >&2
    exit 10
}

# Wait for mesh-control to be up. The current harness runs the
# container as a sleep-forever shim with the binary bind-mounted —
# see the docker-compose.yml comment for why. "Health" here just
# means the binary is reachable via `docker exec`. When the full
# coordination plane lands, this check upgrades to polling
# /health like the rest of the OctraVPN harness.
mesh_reachable=""
for _ in $(seq 1 20); do
    if docker exec tsi-mesh-control test -x /usr/local/bin/octravpn-node >/dev/null 2>&1; then
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
echo "mesh-control container ready (binary present in /usr/local/bin)" >&2

# ---------------------------------------------------------------------------
# Step 3 — preauth-key minting surface.
#
# The test probes BOTH paths; either landing is enough to clear
# exit code 20.
#
#   3a. `docker exec mesh-control octravpn-node mesh mint-preauth …`
#       Catches "operator pastes a key from a `docker exec` session"
#       workflow.
#
#   3b. `curl -H "Authorization: Bearer …" /admin/preauth`
#       Catches "automation harness wants a key without an interactive
#       shell" workflow.
# ---------------------------------------------------------------------------

step "Step 3: mint a preauth key (CLI + HTTP)"

CLI_KEY=""
if docker exec tsi-mesh-control octravpn-node mesh mint-preauth --user interop-test \
       >/tmp/tsi-cli-key 2>/tmp/tsi-cli-key.err; then
    CLI_KEY=$(tr -d '[:space:]' </tmp/tsi-cli-key)
fi

HTTP_KEY=""
HTTP_BODY=$(curl -fsS --max-time 5 \
    -H "Authorization: Bearer interop-test-token" \
    -H "Content-Type: application/json" \
    -d '{"user":"interop-test","reusable":false}' \
    http://127.0.0.1:51821/admin/preauth 2>/dev/null || true)
if [[ -n "${HTTP_BODY}" ]]; then
    # The endpoint returns a flat JSON object; grab the value of
    # the `"key"` field without taking a hard dep on python/jq.
    HTTP_KEY=$(printf '%s' "${HTTP_BODY}" | sed -nE 's/.*"key"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')
fi

if [[ -z "${CLI_KEY}" && -z "${HTTP_KEY}" ]]; then
    echo "PREAUTH SURFACE MISSING:" >&2
    echo "  CLI:  $(cat /tmp/tsi-cli-key.err 2>/dev/null || echo '(no stderr)')" >&2
    echo "  HTTP: ${HTTP_BODY:-(empty)}" >&2
    exit 20
fi

if [[ -n "${CLI_KEY}" ]]; then
    echo "preauth via CLI: ${CLI_KEY}" >&2
fi
if [[ -n "${HTTP_KEY}" ]]; then
    echo "preauth via HTTP: ${HTTP_KEY}" >&2
fi
# Prefer the HTTP-minted key for the tailscale up step: it's the
# one that's tied to the running daemon's in-memory store. (When
# the future coordination plane lands, only that key path is
# bound into the same MeteringSession.)
PREAUTH_KEY="${HTTP_KEY:-${CLI_KEY}}"

# ---------------------------------------------------------------------------
# Step 4 — `tailscale up` on both peers using the minted key.
#
# This step is expected to fail in the current bridge: we have no
# `/key` + `/machine/{node_key}/{register,map}` wire protocol on
# the mesh-control side. The script still tries — exit code 30 is
# the documented "preauth surface reachable, full Tailscale wire
# protocol not". See docs/tailscale-interop-blocker.md for the
# remaining gap.
# ---------------------------------------------------------------------------

step "Step 4: install self-signed cert into peer trust stores"

# Wait for mesh-control to have minted the TLS cert under its state
# dir (the wire-layer's `tls::load_or_generate` writes it on first
# bind to :443). The cert is shared into each peer via a read-only
# bind mount at /mnt/mesh-control-state. We then copy it into
# /usr/local/share/ca-certificates/ and run `update-ca-certificates`
# so `tailscale up`'s forced-443 dial doesn't fail TLS verification.
CERT_HOST_PATH="${SCRIPT_DIR}/state/tailscale-wire/tls.crt"
for _ in $(seq 1 30); do
    if [[ -s "${CERT_HOST_PATH}" ]]; then
        break
    fi
    sleep 1
done
if [[ ! -s "${CERT_HOST_PATH}" ]]; then
    echo "TLS CERT MISSING: ${CERT_HOST_PATH} not present after 30s" >&2
    docker compose -f "${COMPOSE_FILE}" logs mesh-control >&2 || true
    exit 10
fi
echo "TLS cert minted at ${CERT_HOST_PATH}" >&2

for peer in tsi-peer-a tsi-peer-b; do
    # The tailscale/tailscale image is alpine-based; it ships with
    # `update-ca-certificates` from `ca-certificates`. Reversible:
    # the cert lands at a well-known path and the script is
    # idempotent (re-running on a warm container is a no-op).
    docker exec "${peer}" sh -c '
        set -e
        if [ -s /mnt/mesh-control-state/tailscale-wire/tls.crt ]; then
            mkdir -p /usr/local/share/ca-certificates
            cp /mnt/mesh-control-state/tailscale-wire/tls.crt \
               /usr/local/share/ca-certificates/octravpn-mesh-control.crt
            if command -v update-ca-certificates >/dev/null 2>&1; then
                update-ca-certificates >/dev/null 2>&1 || true
            elif command -v c_rehash >/dev/null 2>&1; then
                # Alpine path: append + rehash.
                cat /mnt/mesh-control-state/tailscale-wire/tls.crt \
                    >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true
            fi
        fi
    ' || {
        echo "WARN: cert install failed in ${peer}; continuing" >&2
    }
done

step "Step 4b: tailscale up on both peers"

# Stock `tailscale up` v1.78+ forces an HTTPS-on-443 dial regardless
# of the login-server scheme. Point at https:// up front so the
# initial /key probe goes over TLS too — we have one less code path
# to debug.
LOGIN_SERVER="https://tsi-mesh-control"
TS_UP_OK=1
for peer in tsi-peer-a tsi-peer-b; do
    # `tailscale up` blocks forever waiting for the coordination
    # server when there's nothing on the other end of the
    # login-server URL — wrap the call in `timeout` so the test
    # terminates cleanly. 20s is generous: a working coordination
    # plane completes `up` in well under 5s in this docker harness;
    # anything longer is a stall.
    if ! docker exec "${peer}" sh -c \
        "/usr/bin/timeout 20 tailscale --socket=/var/run/tailscale/tailscaled.sock up \
            --login-server '${LOGIN_SERVER}' \
            --authkey '${PREAUTH_KEY}' \
            --hostname ${peer} \
            --accept-routes \
            --reset" \
        >>/tmp/tsi-up-${peer}.log 2>&1; then
        TS_UP_OK=0
        echo "tailscale up failed on ${peer}; tail of log:" >&2
        tail -n 30 /tmp/tsi-up-${peer}.log >&2 || true
    fi
done

if [[ ${TS_UP_OK} -ne 1 ]]; then
    echo "TAILSCALE-UP FAILED on at least one peer; coordination plane gap (see docs/tailscale-interop-blocker.md)" >&2
    exit 30
fi

# ---------------------------------------------------------------------------
# Step 5 — converge on the IP plane.
# ---------------------------------------------------------------------------

step "Step 5: wait for IP-plane convergence"
PEER_B_IP=""
for _ in $(seq 1 30); do
    PEER_B_IP=$(docker exec tsi-peer-b tailscale ip -4 2>/dev/null | head -1 || true)
    if [[ -n "${PEER_B_IP}" ]]; then
        break
    fi
    sleep 1
done
if [[ -z "${PEER_B_IP}" ]]; then
    echo "IP-PLANE CONVERGENCE FAILED: peer-b never advertised a tailscale IP" >&2
    exit 40
fi
echo "peer-b tailscale ip: ${PEER_B_IP}" >&2

# ---------------------------------------------------------------------------
# Step 6 — tailscale ping.
# ---------------------------------------------------------------------------

step "Step 6: tailscale ping from peer-a to peer-b"
if ! docker exec tsi-peer-a tailscale ping --c 3 --timeout 5s "${PEER_B_IP}" >&2; then
    echo "TAILSCALE-PING FAILED despite peers being up" >&2
    exit 50
fi

echo "OK: tailscale interop succeeded" >&2
exit 0
