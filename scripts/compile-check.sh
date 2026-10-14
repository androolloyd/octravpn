#!/usr/bin/env bash
# Read-only compile gate. A target RPC must be selected explicitly.
set -euo pipefail
: "${OCTRA_RPC:?Set OCTRA_RPC to the explicitly selected target RPC}"
AML_PATH="${AML_PATH:-program/main-v4.aml}"
PAYLOAD=$(python3 - "$AML_PATH" <<'PY'
import json, pathlib, sys
print(json.dumps({'jsonrpc':'2.0','id':1,'method':'octra_compileAml','params':[pathlib.Path(sys.argv[1]).read_text()]}))
PY
)
RESPONSE=$(printf '%s' "$PAYLOAD" | curl -fsS --max-time 90 -H 'Content-Type: application/json' --data-binary @- "$OCTRA_RPC")
printf '%s' "$RESPONSE" | python3 -c '
import base64, hashlib, json, sys
r=json.load(sys.stdin)
if r.get("id") != 1 or "error" in r or not isinstance(r.get("result"),dict):
    raise SystemExit("compile gate failed: invalid/error response: "+str(r))
a=r["result"]
try:
    code=base64.b64decode(a["bytecode"],validate=True)
    abi=json.loads(a["abi"]) if isinstance(a["abi"],str) else a["abi"]
except (KeyError,ValueError,TypeError) as e:
    raise SystemExit("compile gate failed: malformed artifact: "+str(e))
methods=abi.get("functions") if isinstance(abi,dict) else abi
if not code or not isinstance(methods,list) or not methods or not all(isinstance(m,dict) and isinstance(m.get("name"),str) for m in methods):
    raise SystemExit("compile gate failed: empty bytecode or malformed ABI")
if not isinstance(a.get("instructions"),int) or a["instructions"] <= 0:
    raise SystemExit("compile gate failed: missing instruction count")
print("compile gate PASS: methods=%d bytecode_sha256=%s"%(len(methods),hashlib.sha256(code).hexdigest()))
'
