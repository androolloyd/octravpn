#!/usr/bin/env bash
# keygen-fixture-teardown.sh — drop the keygen-fixture container.

set -euo pipefail

CONTAINER_NAME="${KEYGEN_FIXTURE_CONTAINER:-octravpn-keygen-fixture}"
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
echo "keygen-fixture teardown complete" >&2
