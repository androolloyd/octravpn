#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FOUNDRY_ROOT="${FOUNDRY_ROOT:-$ROOT/../octra-foundry}"
PROVER="${PRIVATE_ADMIN_PROVER:-$ROOT/target/release/octravpn-private-admin}"
EVIDENCE="${PRIVATE_ADMIN_EVIDENCE:-$ROOT/out/private-admin-e2e/evidence.json}"
cargo build --release -p octravpn-private-admin
docker build --target builder -t octra-private-admin-builder "$FOUNDRY_ROOT/docker/octra-node"
docker build -f docker/private-admin/Dockerfile -t octra-private-admin-vm "$ROOT"
python3 scripts/private-admin/e2e.py --prover "$PROVER" --evidence "$EVIDENCE"
