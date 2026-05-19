#!/usr/bin/env bash
# run-interop.sh — orchestration script for the stock-tailscale ↔
# octravpn-mesh interop scenario.
#
# Lifecycle:
#   1. docker compose up --build (control + 2 stock tailscale clients).
#   2. Wait for the control container to become healthy.
#   3. Mint a preauth key per client. (See "PREAUTH GAP" below — there
#      is no CLI/RPC for this in THIS repo's octravpn-mesh; the script
#      attempts the lowest-friction surface and records the failure
#      mode if no minting endpoint exists.)
#   4. `docker compose exec` into each tailscale container and run
#      `tailscale up --login-server=http://headscale:51821
#      --authkey=...  --tun=userspace-networking`.
#   5. Wait up to 60s for both clients to settle.
#   6. Run `tailscale ping <peer-IP>` from A to B and assert success.
#
# Exit codes:
#   0   tailscale ping A→B succeeded (Tailscale wire protocol intact).
#   10  control plane never came up.
#   20  preauth-key minting unavailable (octravpn-mesh exposes none).
#   30  `tailscale up` failed (most likely cause: octravpn-node does
#        not implement Tailscale's /key and /machine/{mkey}/map
#        endpoints — see crates/octravpn-node/src/control.rs).
#   40  client never reached "Running" state inside 60 s.
#   50  `tailscale ping` failed across the mesh.
#
# Always tears the stack down on exit via `trap`.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
PROJECT_NAME="octravpn-tailscale-interop"

# Resolve the cargo build context. The control-plane image needs
# `octra/` and the sibling `octra-foundry/` visible side-by-side
# (octravpn-core path-deps into the latter). When this script lives in
# a git worktree under `.claude/worktrees/...`, the worktree's octra/
# files are not adjacent to octra-foundry/ on disk, so we stage a
# build context in a tmpdir with the right shape.
#
# If OCTRA_BUILD_CTX is set in the env, we trust it as-is.

if [ -z "${OCTRA_BUILD_CTX:-}" ]; then
  # Locate this checkout's repo root (the octra/ tree containing
  # SCRIPT_DIR). SCRIPT_DIR is .../docker/devnet/tailscale-interop, so
  # the repo root is three levels up.
  OCTRA_SRC="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"
  # Locate the sibling octra-foundry/ checkout. Try parent of the main
  # checkout first, then walk up.
  FOUNDRY_SRC=""
  for candidate in \
      "$(dirname "${OCTRA_SRC}")/octra-foundry" \
      "/Users/androolloyd/Development/octra-foundry"; do
    if [ -d "${candidate}/crates/octra-core" ]; then
      FOUNDRY_SRC="${candidate}"
      break
    fi
  done
  if [ -z "${FOUNDRY_SRC}" ]; then
    cat >&2 <<EOF
[run-interop] FATAL: could not locate the sibling octra-foundry/
              checkout. The control image's cargo build needs it for
              path-deps in crates/octravpn-core/Cargo.toml. Set
              OCTRA_BUILD_CTX explicitly to a directory containing
              both octra/ and octra-foundry/ and re-run.
EOF
    exit 2
  fi
  # Stage a build context: a tmpdir holding bind-mounted copies of
  # both checkouts so the Dockerfile's `COPY octra-foundry` and `COPY
  # octra` see the worktree's source (not the main checkout's stale
  # files).
  STAGE_DIR="$(mktemp -d -t octravpn-interop-XXXXXX)"
  echo "[run-interop] staging build context at ${STAGE_DIR}"
  # rsync excludes target/ to keep the build context small.
  rsync -a --delete --exclude='target/' --exclude='.git/' \
        "${OCTRA_SRC}/" "${STAGE_DIR}/octra/"
  rsync -a --delete --exclude='target/' --exclude='.git/' \
        "${FOUNDRY_SRC}/" "${STAGE_DIR}/octra-foundry/"
  OCTRA_BUILD_CTX="${STAGE_DIR}"
  # Ensure the stage dir gets cleaned up alongside the docker
  # teardown.
  STAGE_DIR_TO_CLEAN="${STAGE_DIR}"
fi
export OCTRA_BUILD_CTX
echo "[run-interop] OCTRA_BUILD_CTX=${OCTRA_BUILD_CTX}"

# All `docker compose` invocations go through this so the project name
# and compose file are pinned consistently for `up`, `exec`, and `down`.
dc() {
  docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" "$@"
}

cleanup() {
  local rc=$?
  echo
  echo "[run-interop] tearing down (exit code was ${rc})"
  dc logs --tail=200 mesh-control tailscale-a tailscale-b 2>&1 | sed 's/^/  /' || true
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  if [ -n "${STAGE_DIR_TO_CLEAN:-}" ] && [ -d "${STAGE_DIR_TO_CLEAN}" ]; then
    rm -rf "${STAGE_DIR_TO_CLEAN}"
  fi
  exit "${rc}"
}
trap cleanup EXIT INT TERM

# -----------------------------------------------------------------
# Step 1: bring the stack up.
# -----------------------------------------------------------------
echo "[run-interop] step 1/6: docker compose up --build -d"
dc up --build -d

# -----------------------------------------------------------------
# Step 2: wait for control-plane health.
# -----------------------------------------------------------------
echo "[run-interop] step 2/6: wait for mesh-control health"
deadline=$(( $(date +%s) + 120 ))
while :; do
  status="$(docker inspect -f '{{.State.Health.Status}}' octravpn-mesh-control 2>/dev/null || echo missing)"
  if [ "${status}" = "healthy" ]; then
    echo "[run-interop]   mesh-control is healthy"
    break
  fi
  if [ "$(date +%s)" -ge "${deadline}" ]; then
    echo "[run-interop] FATAL: mesh-control never became healthy (status=${status})"
    exit 10
  fi
  sleep 2
done

# -----------------------------------------------------------------
# Step 3: mint preauth keys.
#
# PREAUTH GAP — found 2026-05-19:
# `crates/octravpn-mesh/src/headscale_bridge.rs` is documented as a
# pin-only module ("zero Rust-API coupling to headscale-rs"). The
# crate has no public surface for minting Tailscale preauth keys, and
# `octravpn-node`'s control plane only exposes /session, /session/:id,
# /health, /metrics, /events — none of which are Tailscale-protocol
# endpoints. There is therefore no CLI, no RPC, and no exec-able
# surface inside the control container that can produce a preauth
# key the stock tailscale CLI will accept.
#
# We probe for one anyway. If the probe ever starts returning a key
# (e.g. once the bridge lands), the test will proceed automatically.
# -----------------------------------------------------------------
echo "[run-interop] step 3/6: mint preauth keys"

mint_preauth_key() {
  local label="$1"
  # Surface 1: hypothetical `octravpn-node mesh mint-preauth` subcommand.
  if dc exec -T mesh-control sh -c '/usr/local/bin/octravpn-node mesh mint-preauth --help' >/dev/null 2>&1; then
    dc exec -T mesh-control sh -c "/usr/local/bin/octravpn-node mesh mint-preauth --label ${label}"
    return 0
  fi
  # Surface 2: hypothetical HTTP admin endpoint on the control plane.
  if dc exec -T mesh-control sh -c 'command -v curl' >/dev/null 2>&1; then
    if dc exec -T mesh-control sh -c \
      "curl -fsS -X POST http://127.0.0.1:51821/admin/preauth -d '{\"label\":\"${label}\"}'" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

if AUTHKEY_A="$(mint_preauth_key tailscale-a 2>/dev/null)" \
   && AUTHKEY_B="$(mint_preauth_key tailscale-b 2>/dev/null)" \
   && [ -n "${AUTHKEY_A}" ] && [ -n "${AUTHKEY_B}" ]; then
  echo "[run-interop]   minted authkey A (${#AUTHKEY_A} chars), authkey B (${#AUTHKEY_B} chars)"
else
  # Drift-diagnostic probes: hit the Tailscale-protocol endpoints a
  # stock tailscale client would try first. Each is expected to 404 /
  # connection-refuse against the current octravpn-node control
  # plane; we surface the responses so the finding is unambiguous.
  echo "[run-interop]   diagnostic: probing Tailscale-protocol endpoints on mesh-control"
  for path in /key /machine/dummy/map /derp/probe; do
    code="$(dc exec -T tailscale-a sh -c \
      "wget --no-check-certificate -qSO- --timeout=3 \
       http://headscale:51821${path} 2>&1 | head -3" || true)"
    echo "[run-interop]     GET ${path} -> $(printf '%s' "${code}" | head -1)"
  done
  cat <<EOF
[run-interop] FATAL: no preauth-key minting surface available.
[run-interop]
[run-interop]   octravpn-mesh does not expose a CLI or RPC for minting
[run-interop]   Tailscale preauth keys. See
[run-interop]   crates/octravpn-mesh/src/headscale_bridge.rs — the
[run-interop]   integration boundary is pin-only at this commit. Until
[run-interop]   that bridge lands, no stock tailscale client can join
[run-interop]   this mesh. This is the finding the test was built to
[run-interop]   surface.
EOF
  exit 20
fi

# -----------------------------------------------------------------
# Step 4: bring each tailscale CLI up against the control plane.
# -----------------------------------------------------------------
echo "[run-interop] step 4/6: tailscale up against http://headscale:51821"

tailscale_up() {
  local svc="$1" key="$2"
  dc exec -T "${svc}" sh -c \
    "tailscale --socket=/tmp/tailscaled.sock up \
        --login-server=http://headscale:51821 \
        --authkey='${key}' \
        --hostname='${svc}' \
        --accept-routes \
        --reset \
        --timeout=30s" \
    && return 0
  return 1
}

if ! tailscale_up tailscale-a "${AUTHKEY_A}"; then
  cat <<EOF
[run-interop] FATAL: \`tailscale up\` against the OctraVPN control plane failed.
[run-interop]
[run-interop]   Most likely cause: \`octravpn-node\` does not expose
[run-interop]   Tailscale's coordination endpoints. The router in
[run-interop]   crates/octravpn-node/src/control.rs only mounts:
[run-interop]     POST /session,  GET /session/:id,  GET /health,
[run-interop]     GET /metrics,   GET /events
[run-interop]   None of these are the \`/key\`, \`/machine/{mkey}/map\`,
[run-interop]   or Noise TS2021 surface a stock tailscale binary
[run-interop]   requires.
EOF
  exit 30
fi
tailscale_up tailscale-b "${AUTHKEY_B}" || exit 30

# -----------------------------------------------------------------
# Step 5: wait for both clients to settle into a "Running" state.
# -----------------------------------------------------------------
echo "[run-interop] step 5/6: wait for both clients to reach Running"
settled=0
for _ in $(seq 1 60); do
  a_state="$(dc exec -T tailscale-a tailscale --socket=/tmp/tailscaled.sock status --json 2>/dev/null | grep -o '"BackendState":"[^"]*"' | head -1 || true)"
  b_state="$(dc exec -T tailscale-b tailscale --socket=/tmp/tailscaled.sock status --json 2>/dev/null | grep -o '"BackendState":"[^"]*"' | head -1 || true)"
  if [ "${a_state}" = '"BackendState":"Running"' ] && [ "${b_state}" = '"BackendState":"Running"' ]; then
    settled=1
    break
  fi
  sleep 1
done
if [ "${settled}" -ne 1 ]; then
  echo "[run-interop] FATAL: clients never reached Running (a=${a_state:-?} b=${b_state:-?})"
  exit 40
fi

# Discover B's tailnet IP from A's view of the network map.
PEER_IP_B="$(dc exec -T tailscale-a sh -c \
  "tailscale --socket=/tmp/tailscaled.sock status | awk '/tailscale-b/ {print \$1; exit}'" \
  | tr -d '\r')"
if [ -z "${PEER_IP_B}" ]; then
  echo "[run-interop] FATAL: A could not see B in its tailnet map"
  exit 40
fi
echo "[run-interop]   A sees B at ${PEER_IP_B}"

# -----------------------------------------------------------------
# Step 6: tailscale ping A → B (the actual interop assertion).
# -----------------------------------------------------------------
echo "[run-interop] step 6/6: tailscale ping A → B (${PEER_IP_B})"
if dc exec -T tailscale-a sh -c \
     "tailscale --socket=/tmp/tailscaled.sock ping --c 3 --timeout 5s ${PEER_IP_B}"; then
  echo
  echo "[run-interop] PASS: stock tailscale CLI joined OctraVPN mesh and pinged peer"
  exit 0
fi
echo "[run-interop] FATAL: \`tailscale ping\` A→B failed despite both nodes Running"
exit 50
