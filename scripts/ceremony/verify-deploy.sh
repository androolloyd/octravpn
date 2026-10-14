#!/usr/bin/env bash
# Explicit expectations only; private-admin/factory or legacy owner verification.
set -euo pipefail
exec python3 "$(dirname "$0")/verify-deployment.py" "$@"
