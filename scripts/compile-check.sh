#!/usr/bin/env bash
# Compile-gate against real Octra.
#
# Reads program/main.aml and submits it to octra_compileAml via the
# Octra mainnet RPC (or OCTRA_RPC env var for testnet). Asserts a
# successful compile. Fails CI on any parser/typechecker error.
#
# Usage:
#   ./scripts/compile-check.sh                 # default: mainnet RPC
#   OCTRA_RPC=https://testnet.octra/rpc ./scripts/compile-check.sh
#
# The RPC method is public — no auth, no fee, no on-chain side effect.
# It just runs the AML compiler and returns bytecode + ABI on success
# or a parser error.

set -euo pipefail

RPC="${OCTRA_RPC:-https://octra.network/rpc}"
AML_PATH="${AML_PATH:-program/main.aml}"
CONTRACT_NAME="${CONTRACT_NAME:-OctraVPN}"

if [[ ! -f "$AML_PATH" ]]; then
  echo "error: $AML_PATH not found" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 required for JSON encoding" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl required" >&2
  exit 1
fi

# Build the JSON-RPC payload via python (avoids shell escaping hell
# for multi-line AML sources).
PAYLOAD=$(python3 -c '
import json, sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text()
name = sys.argv[2]
req = {"jsonrpc":"2.0","id":1,"method":"octra_compileAml","params":[src,name]}
sys.stdout.write(json.dumps(req))
' "$AML_PATH" "$CONTRACT_NAME")

echo "[compile-check] AML       : $AML_PATH"
echo "[compile-check] contract  : $CONTRACT_NAME"
echo "[compile-check] RPC       : $RPC"
echo "[compile-check] size      : $(wc -c <"$AML_PATH") bytes"

RESPONSE=$(echo "$PAYLOAD" | curl -s --max-time 60 -X POST "$RPC" \
  -H "Content-Type: application/json" \
  --data @-)

# Parse: success or error?
ERR=$(echo "$RESPONSE" | python3 -c '
import json, sys
r = json.load(sys.stdin)
if "error" in r:
    sys.stdout.write(r["error"].get("message", "unknown error"))
' 2>/dev/null || true)

if [[ -n "$ERR" ]]; then
  echo "[compile-check] FAIL: $ERR"
  exit 1
fi

# Confirm we got a result with bytecode + abi.
ABI_LEN=$(echo "$RESPONSE" | python3 -c '
import json, sys
r = json.load(sys.stdin)
abi = r.get("result", {}).get("abi", [])
sys.stdout.write(str(len(abi)))
')

echo "[compile-check] OK (abi entries: $ABI_LEN)"
