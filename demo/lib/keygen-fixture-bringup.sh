#!/usr/bin/env bash
# keygen-fixture-bringup.sh
#
# Single-container fixture for tape 01 (init + keygen). Mounts the
# Linux octravpn binary into a throwaway debian container and exposes
# a clean /work scratch dir. The tape drives `docker exec` calls
# against this container to walk init/keygen/identity flows; nothing
# touches the host beyond the optional fixture dir.
#
# Exit codes:
#   0   READY
#   10  binary or docker preflight failed.
#
# Idempotent: re-running recycles the container.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
CONTAINER_NAME="${KEYGEN_FIXTURE_CONTAINER:-octravpn-keygen-fixture}"

# Prefer the Linux-built binary so this works on macOS hosts too.
BIN=""
for candidate in \
    "${REPO_ROOT}/target/linux-debug/debug/octravpn" \
    "${REPO_ROOT}/target/release/octravpn" \
    "${REPO_ROOT}/target/debug/octravpn"; do
    if [[ -x "${candidate}" ]]; then
        BIN="${candidate}"
        break
    fi
done

if [[ -z "${BIN}" ]]; then
    echo "keygen-fixture-bringup: octravpn binary not found under target/" >&2
    echo "  run 'cargo build -p octravpn-client' (in the builder container for Linux targets)" >&2
    exit 10
fi

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker run -d --name "${CONTAINER_NAME}" \
    -v "${BIN}":/usr/local/bin/octravpn:ro \
    -w /work \
    debian:bookworm-slim \
    sleep infinity >/dev/null || {
        echo "keygen-fixture-bringup: docker run failed" >&2
        exit 10
    }

# A clean scratch dir each bringup keeps the recording deterministic.
docker exec "${CONTAINER_NAME}" sh -c 'rm -rf /work/* /work/.??* 2>/dev/null; mkdir -p /work' || true

echo "keygen-fixture container '${CONTAINER_NAME}' ready" >&2
echo "READY"
