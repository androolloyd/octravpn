#!/usr/bin/env bash
# audit-fixture-teardown.sh — drop the audit-fixture container.
# Pairs with audit-fixture-bringup.sh. Always succeeds.

set -euo pipefail

CONTAINER_NAME="${AUDIT_FIXTURE_CONTAINER:-octravpn-audit-fixture}"
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
echo "audit-fixture teardown complete" >&2
