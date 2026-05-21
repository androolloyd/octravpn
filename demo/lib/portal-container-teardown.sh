#!/usr/bin/env bash
# portal-container-teardown.sh — drop portal + chain stack.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PORTAL_CONTAINER="${PORTAL_CONTAINER:-octravpn-portal-demo}"

docker rm -f "${PORTAL_CONTAINER}" >/dev/null 2>&1 || true
"${SCRIPT_DIR}/devnet-mock-teardown.sh" >&2 || true
echo "portal-container teardown complete" >&2
