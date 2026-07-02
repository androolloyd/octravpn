#!/usr/bin/env bash
# Validate the v4 relay settlement-hash cross-impl PIN on devnet.
#
# Decisive check (one view call, no tx / no value semantics): does Octra AML
# sha256(<base64 preimage>) equal a STANDARD sha256 of that string's bytes?
# The Rust SignedReceipt::settlement_hash() = hex(sha256(settlement_preimage().as_bytes()))
# and v4 relay_claim gates on require(sha256(preimage) == committed_H). If the
# chain's sha256 of the base64 ASCII preimage differs from the standard one, the
# whole hashlock is broken and the preimage encoding must be reworked first.
#
# Exit: 0 PASS(pin holds) · 1 FAIL(pin broken) · 2 INCONCLUSIVE(env/deploy/tooling)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
OCTRA_BIN="${OCTRA_BIN:-$ROOT/../octra-foundry/target/release/octra}"
OCTRA_RPC_URL="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"
DEPLOYER_KEY="${DEPLOYER_KEY:-$ROOT/docker/devnet/state/deployer.key}"
PIN_AML="${PIN_AML:-$ROOT/program/pin-probe.aml}"

hdr(){ printf "\n=== %s ===\n" "$1"; }; ok(){ printf "  + %s\n" "$1"; }; fail(){ printf "  ! %s\n" "$1"; }
rpc(){ curl -s -m 15 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"; }

echo "settlement-hash-pin-probe — v4 relay hashlock cross-impl pin go/no-go"
echo "  RPC=$OCTRA_RPC_URL"
echo "  AML=$PIN_AML"

hdr preflight; miss=0
command -v curl    >/dev/null || { fail "curl missing"; miss=1; }
command -v python3 >/dev/null || { fail "python3 missing"; miss=1; }
[[ -x "$OCTRA_BIN" ]]  || { fail "octra bin missing: $OCTRA_BIN"; miss=1; }
[[ -f "$DEPLOYER_KEY" ]] || { fail "deployer key missing: $DEPLOYER_KEY"; miss=1; }
[[ -f "$PIN_AML" ]]    || { fail "pin AML missing: $PIN_AML"; miss=1; }
if [[ $miss -eq 0 ]] && ! rpc node_status "[]" | python3 -c 'import json,sys;json.load(sys.stdin)' >/dev/null 2>&1; then
  fail "RPC did not answer node_status — harness up?"; miss=1; fi
[[ $miss -ne 0 ]] && { echo; echo "VERDICT: INCONCLUSIVE (environment not ready)"; exit 2; }

# Representative preimage: base64 of domain + 224 bytes (243B total — the exact
# v4 settlement_preimage shape). H_STD = standard sha256 of the base64 string,
# which is precisely what Rust settlement_hash() produces.
read -r PREIMAGE H_STD < <(python3 - <<'PY'
import base64, hashlib
buf = b"octravpn-settle-v1|" + bytes([0xAB]) * 224
p = base64.b64encode(buf).decode()
print(p, hashlib.sha256(p.encode()).hexdigest())
PY
)
ok "preimage (base64, ${#PREIMAGE} chars): ${PREIMAGE:0:28}..."
ok "H_std = standard sha256(preimage) [== Rust settlement_hash]: $H_STD"

hdr "deploy pin-probe.aml"
DEP="$("$OCTRA_BIN" forge create "$PIN_AML" --key "$DEPLOYER_KEY" --rpc-url "$OCTRA_RPC_URL" 2>&1)"
C="$(printf '%s' "$DEP" | python3 -c 'import sys,re;t=sys.stdin.read();m=re.search(r"(oct[0-9A-Za-z]{20,})",t);print(m.group(1) if m else "")')"
if [[ -z "$C" ]]; then fail "forge create did not surface a contract address:"; printf '%s\n' "$DEP" | tail -6
  echo; echo "VERDICT: INCONCLUSIVE (deploy/compile failed)"; exit 2; fi
ok "deployed @ $C"

hdr "1. THE PIN — chain sha256(preimage) vs standard sha256"
# Retry the view until the deploy has finalized (returns non-empty). The
# contract_call result nests the value at .result.result.
H_AML=""
for _ in $(seq 1 12); do
  sleep 4
  H_AML="$(rpc contract_call "[\"$C\",\"hash_of\",[\"$PREIMAGE\"]]" | python3 -c '
import json,sys
try:
  r=json.load(sys.stdin).get("result")
  if isinstance(r,dict): r=r.get("result")
  print((r or "").strip())
except Exception: print("")')"
  [[ -n "$H_AML" ]] && break
done
ok "H_aml = chain sha256(preimage): ${H_AML:-<empty>}"

echo
if [[ -z "$H_AML" ]]; then
  fail "hash_of view returned empty (RPC/contract read issue, not a chain answer)"
  echo "VERDICT: INCONCLUSIVE (view returned no hash)"; exit 2
elif [[ "$H_AML" == "$H_STD" ]]; then
  ok "MATCH — chain sha256 == standard sha256 of the base64 preimage"
  echo "VERDICT: PASS — settlement_hash pin HOLDS. Rust settlement_hash() == AML sha256(settlement_preimage); the v4 relay hashlock is sound and safe to wire."
  exit 0
else
  fail "MISMATCH — chain and standard sha256 differ"
  echo "VERDICT: FAIL — pin BROKEN. settlement_preimage/settlement_hash must be reworked to match AML sha256 semantics before wiring v4 relay_claim."
  exit 1
fi
