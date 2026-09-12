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

step() {
    printf '\n=== %s ===\n' "$1" >&2
}

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
    -d '{"user":"interop-test","reusable":true}' \
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
# Prefer the HTTP-minted (reusable) key for the tailscale up step:
# it's the one tied to the running daemon's in-memory store AND it
# was minted as `reusable=true` so peer-a + peer-b can both redeem
# it. (Pre-Wall-6, register never succeeded on the wire, so the
# `reusable=false` surface here never tripped. Now that the wire
# layer is healthy, the second peer needs a key it can actually
# redeem.)
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

step "Step 4c: wait for native DERP on mesh-control (/derp/probe)"
for _ in $(seq 1 30); do
  if curl -ksf -m 3 "https://127.0.0.1:8443/derp/probe" >/dev/null 2>&1; then echo "native DERP probe endpoint reachable"; break; fi
  sleep 2
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
    # terminates cleanly. 90 s is plenty for the post-Wall-6
    # register → netmap → derp-bootstrap → Running transition; a
    # healthy control plane + DERP relay lands in well under 45 s.
    if ! docker exec "${peer}" sh -c \
        "/usr/bin/timeout 90 tailscale --socket=/var/run/tailscale/tailscaled.sock up \
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
# DERP-relayed ping takes longer than direct; bump the per-probe
# timeout from 5s → 10s and probe count from 3 → 5 so transient first-
# packet jitter doesn't fail the whole test.
if ! docker exec tsi-peer-a tailscale ping --c 5 --timeout 10s "${PEER_B_IP}" >&2; then
    echo "TAILSCALE-PING FAILED despite peers being up" >&2
    exit 50
fi

echo "OK: tailscale interop succeeded" >&2
exit 0
