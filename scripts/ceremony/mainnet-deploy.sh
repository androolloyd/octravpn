#!/usr/bin/env bash
# The previous ceremony described unsupported multisig CLI flags and did
# not produce a native, authorized deployment transaction. Fail closed.
set -euo pipefail
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo 'Prepare an unsigned v5 private-admin candidate with:'
  echo '  python3 scripts/ceremony/prepare-candidate.py prepare --program-version 5 --params ceremony/private-admin-candidate.toml.example --compiler-patch scripts/private-admin/standalone-label-fix.patch --amlc /path/to/amlc --out out/mainnet-candidate'
  echo 'For the explicitly limited RC, use scripts/ceremony/deploy-canary.py (offline plan by default). It qualifies private proofs with zero escrow before operator funding.'
  echo 'Unrestricted launch still requires verified target, circuit/setup and release evidence.'
  exit 0
fi
echo 'Unrestricted deployment blocked: verified target, private-admin setup and release evidence are required.' >&2
echo 'Use scripts/ceremony/prepare-candidate.py to compile a reviewable unsigned candidate.' >&2
exit 2
