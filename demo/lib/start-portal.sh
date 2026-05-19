#!/usr/bin/env bash
# start-portal.sh
#
# Boot the `octravpn portal` HTTP server in the background and wait
# for /healthz to return 200. Idempotent: a second invocation that
# finds a portal already listening on the bind address is a no-op.
#
# Intended to be sourced from a VHS `.tape` file via:
#
#   Source demo/lib/start-portal.sh
#
# Inputs (env, all optional):
#   OCTRAVPN_BIN     path to the `octravpn` client binary. Defaults to
#                    `target/release/octravpn`, then `target/debug/octravpn`,
#                    then `octravpn` on PATH.
#   OCTRAVPN_CONFIG  path to the client config. Defaults to
#                    `demo/state/portal/config.toml`. The config is
#                    expected to exist; we do not synthesize one (use
#                    `octravpn init` first — see 01-init-keygen.tape).
#   PORTAL_BIND      host:port. Defaults to 127.0.0.1:51823 to match
#                    `DEFAULT_PORTAL_PORT` in the client crate.
#   PORTAL_LOG       log file. Defaults to demo/state/portal/portal.log.

set -euo pipefail

DEMO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO_ROOT=$(cd "${DEMO_DIR}/.." && pwd)

OCTRAVPN_BIN="${OCTRAVPN_BIN:-}"
if [[ -z "${OCTRAVPN_BIN}" ]]; then
    if [[ -x "${REPO_ROOT}/target/release/octravpn" ]]; then
        OCTRAVPN_BIN="${REPO_ROOT}/target/release/octravpn"
    elif [[ -x "${REPO_ROOT}/target/debug/octravpn" ]]; then
        OCTRAVPN_BIN="${REPO_ROOT}/target/debug/octravpn"
    elif command -v octravpn >/dev/null 2>&1; then
        OCTRAVPN_BIN="$(command -v octravpn)"
    else
        echo "start-portal.sh: octravpn binary not found; run 'cargo build -p octravpn-client' first" >&2
        exit 1
    fi
fi

PORTAL_BIND="${PORTAL_BIND:-127.0.0.1:51823}"
PORTAL_HOST="${PORTAL_BIND%%:*}"
PORTAL_PORT="${PORTAL_BIND##*:}"
PORTAL_STATE="${DEMO_DIR}/state/portal"
PORTAL_LOG="${PORTAL_LOG:-${PORTAL_STATE}/portal.log}"
PORTAL_PID="${PORTAL_STATE}/portal.pid"
OCTRAVPN_CONFIG="${OCTRAVPN_CONFIG:-${PORTAL_STATE}/config.toml}"

mkdir -p "${PORTAL_STATE}"

# Already up?
if curl -fsS --max-time 2 "http://${PORTAL_BIND}/healthz" >/dev/null 2>&1; then
    echo "portal already serving at http://${PORTAL_BIND}/" >&2
    exit 0
fi

if [[ ! -f "${OCTRAVPN_CONFIG}" ]]; then
    echo "start-portal.sh: missing config at ${OCTRAVPN_CONFIG}" >&2
    echo "  run: octravpn init --dir ${PORTAL_STATE}" >&2
    exit 1
fi

# Spawn detached; log to file so the tape isn't polluted by daemon stdout.
nohup "${OCTRAVPN_BIN}" --config "${OCTRAVPN_CONFIG}" portal --bind "${PORTAL_BIND}" \
    >"${PORTAL_LOG}" 2>&1 &
echo $! > "${PORTAL_PID}"

# Poll for /healthz (portal responds once chain context is built).
for _ in $(seq 1 30); do
    if curl -fsS --max-time 1 "http://${PORTAL_BIND}/healthz" >/dev/null 2>&1; then
        echo "portal ready at http://${PORTAL_BIND}/" >&2
        exit 0
    fi
    sleep 1
done

echo "start-portal.sh: portal failed to come up in 30s; see ${PORTAL_LOG}" >&2
exit 1
