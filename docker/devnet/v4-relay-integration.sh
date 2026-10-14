#!/usr/bin/env bash
# The full native daemon harness replaces the old contract-only smoke,
# which used a foreign circle, omitted session value and ignored receipts.
set -euo pipefail
exec bash "$(dirname "$0")/v4-relay-e2e.sh" "$@"
