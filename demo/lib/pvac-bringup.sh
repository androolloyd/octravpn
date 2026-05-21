#!/usr/bin/env bash
# pvac-bringup.sh
#
# Bring up a containerized PVAC sidecar for tape 20 (pvac-rotation).
# Builds the sidecar image from pvac-sidecar/Dockerfile and runs it in
# the background. The container sleeps and exposes the
# `octra-pvac-sidecar` binary at /usr/local/bin/ so `docker exec`
# invocations can drive it interactively (the sidecar speaks JSON over
# stdio so it's normally driven by rotate-pvac.sh from inside another
# container).
#
# Exit codes:
#   0   READY — image built, container running, binary reachable.
#   10  build failed.
#   20  docker run failed.
#   30  sidecar binary not reachable inside the container.
#
# Idempotent: re-runs reuse the image and recycle the container.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
SIDECAR_DIR="${REPO_ROOT}/pvac-sidecar"
IMAGE_TAG="${PVAC_IMAGE_TAG:-octravpn-pvac-sidecar:demo}"
CONTAINER_NAME="${PVAC_CONTAINER:-octravpn-pvac}"

if [[ ! -d "${SIDECAR_DIR}" ]]; then
    echo "pvac-bringup: ${SIDECAR_DIR} missing" >&2
    exit 10
fi

# Build (cached) — the sidecar's Dockerfile compiles the GPL'd C++
# sources into the runtime layer. First-run cost is ~3-5 min cold.
docker build -t "${IMAGE_TAG}" "${SIDECAR_DIR}" >&2 || {
    echo "pvac-bringup: docker build failed" >&2
    exit 10
}

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

# State dir mounted in so the in-container rotate-pvac.sh flows can
# write sealed envelopes that the host can inspect post-recording.
mkdir -p "${REPO_ROOT}/demo/.pvac-state"

# Override entrypoint so the container stays alive; the bundled
# entrypoint is the JSON-over-stdio loop which exits on EOF.
docker run -d --name "${CONTAINER_NAME}" \
    --entrypoint /bin/sh \
    -v "${REPO_ROOT}/demo/.pvac-state":/work/state \
    "${IMAGE_TAG}" \
    -c 'sleep infinity' >/dev/null || {
        echo "pvac-bringup: docker run failed" >&2
        exit 20
    }

# Verify the binary is present where rotate-pvac.sh expects it.
if ! docker exec "${CONTAINER_NAME}" sh -c 'command -v octra-pvac-sidecar || test -x /opt/octra-pvac-sidecar || test -x /usr/local/bin/octra-pvac-sidecar' >/dev/null 2>&1; then
    echo "pvac-bringup: sidecar binary not found inside container" >&2
    docker logs "${CONTAINER_NAME}" >&2 || true
    exit 30
fi

echo "pvac sidecar container '${CONTAINER_NAME}' ready" >&2
echo "READY"
