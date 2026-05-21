#!/usr/bin/env bash
# pvac-teardown.sh — tear down the pvac-sidecar container.
# Pairs with pvac-bringup.sh. Always succeeds.

set -euo pipefail

CONTAINER_NAME="${PVAC_CONTAINER:-octravpn-pvac}"
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
echo "pvac teardown complete" >&2
