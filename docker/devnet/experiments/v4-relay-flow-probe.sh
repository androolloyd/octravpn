#!/usr/bin/env bash
# End-to-end devnet validation of the v4 relay-settlement MECHANICS
# (program/v4-relay-htlc.aml): the sha256-preimage hashlock over an escrowed
# deposit, plus the claim / wrong-preimage-reject / past-deadline-reject /
# refund status machine. The settlement_hash pin is already validated
# (settlement-hash-pin-probe.sh); this proves the money moves correctly.
#
# Verification is STATE-BASED (get_status), so a require() revert is caught
# reliably (status unchanged) no matter how the RPC reports reverts.
#
# Exit: 0 PASS (all steps) · 1 FAIL (a step behaved wrong) · 2 INCONCLUSIVE (env/deploy)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
OCTRA_BIN="${OCTRA_BIN:-$ROOT/../octra-foundry/target/release/octra}"
OCTRA_RPC_URL="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"
DEPLOYER_KEY="${DEPLOYER_KEY:-$ROOT/docker/devnet/state/deployer.key}"
HTLC_AML="${HTLC_AML:-$ROOT/program/v4-relay-htlc.aml}"

hdr(){ printf "\n=== %s ===\n" "$1"; }; ok(){ printf "  + %s\n" "$1"; }; fail(){ printf "  ! %s\n" "$1"; }
rpc(){ curl -s -m 15 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"; }
# Submit a call and WAIT for it to reach a terminal state before returning, so
# nonce ordering is preserved and the subsequent state read is accurate. State
# (get_status) remains the source of truth for pass/fail; this only sequences.
send(){ local v="$1"; shift; local out h st i
  out="$("$OCTRA_BIN" cast send --key "$DEPLOYER_KEY" --rpc-url "$OCTRA_RPC_URL" --value "$v" --fee 1000 "$C" "$@" 2>&1)"
  h="$(printf '%s' "$out" | python3 -c 'import sys,re;t=sys.stdin.read();m=re.search(r"tx_hash\"\s*:\s*\"([0-9a-fA-F]+)\"",t);print(m.group(1) if m else "")')"
  if [[ -z "$h" ]]; then printf "    (submit failed: %s)\n" "$(printf '%s' "$out" | tr '\n' ' ' | head -c 140)"; return 1; fi
  for i in $(seq 1 25); do sleep 3
    st="$(rpc octra_transaction "[\"$h\"]" | python3 -c 'import json,sys
try: print((json.load(sys.stdin).get("result") or {}).get("status",""))
except Exception: print("")')"
    case "$st" in confirmed|failed|rejected|reverted) return 0;; esac
  done; return 0; }
status(){ rpc contract_call "[\"$C\",\"get_status\",[$1]]" | python3 -c '
import json,sys
try:
  r=json.load(sys.stdin).get("result")
  if isinstance(r,dict): r=r.get("result")
  print(str(r).strip() if r is not None else "")
except Exception: print("")'; }

FAILS=0
# assert_status <id> <expected> <label>: poll (inclusion delay) until match or timeout.
assert_status(){ local id="$1" want="$2" label="$3" got=""
  for _ in $(seq 1 10); do sleep 3; got="$(status "$id")"; [[ "$got" == "$want" ]] && break; done
  if [[ "$got" == "$want" ]]; then ok "$label  (status=$got)"; else fail "$label  (status=$got, wanted $want)"; FAILS=$((FAILS+1)); fi; }

echo "v4-relay-flow-probe — hashlock escrow claim/refund mechanics"
echo "  RPC=$OCTRA_RPC_URL"; echo "  AML=$HTLC_AML"

hdr preflight; miss=0
command -v curl >/dev/null || { fail "curl missing"; miss=1; }
command -v python3 >/dev/null || { fail "python3 missing"; miss=1; }
[[ -x "$OCTRA_BIN" ]]  || { fail "octra bin missing"; miss=1; }
[[ -f "$DEPLOYER_KEY" ]] || { fail "deployer key missing"; miss=1; }
[[ -f "$HTLC_AML" ]]   || { fail "htlc AML missing"; miss=1; }
if [[ $miss -eq 0 ]] && ! rpc node_status "[]" | python3 -c 'import json,sys;json.load(sys.stdin)' >/dev/null 2>&1; then
  fail "RPC not answering"; miss=1; fi
[[ $miss -ne 0 ]] && { echo; echo "VERDICT: INCONCLUSIVE (env not ready)"; exit 2; }

read -r PREIMAGE H < <(python3 - <<'PY'
import base64, hashlib
p = base64.b64encode(b"octravpn-settle-v1|" + bytes([0xAB])*224).decode()
print(p, hashlib.sha256(p.encode()).hexdigest())
PY
)
WRONG="$(python3 -c 'import base64;print(base64.b64encode(b"WRONG-preimage-not-the-committed-one").decode())')"
OP="$("$OCTRA_BIN" cast wallet addr --key "$DEPLOYER_KEY" 2>/dev/null)"
ok "operator/opener = $OP"; ok "committed H = $H"

hdr "deploy v4-relay-htlc.aml"
DEP="$("$OCTRA_BIN" forge create "$HTLC_AML" --key "$DEPLOYER_KEY" --rpc-url "$OCTRA_RPC_URL" 2>&1)"
C="$(printf '%s' "$DEP" | python3 -c 'import sys,re;t=sys.stdin.read();m=re.search(r"(oct[0-9A-Za-z]{20,})",t);print(m.group(1) if m else "")')"
[[ -z "$C" ]] && { fail "deploy failed:"; printf '%s\n' "$DEP" | tail -6; echo; echo "VERDICT: INCONCLUSIVE (deploy)"; exit 2; }
ok "deployed @ $C"; sleep 6

hdr "1. HAPPY PATH — arm -> claim(preimage)"
send 5000 arm "$OP" "$H" 1000000        # id 0
assert_status 0 1 "arm#0 escrow ARMED"
send 0 claim 0 "$PREIMAGE"
assert_status 0 2 "claim#0 CLAIMED (hashlock gate passed, escrow paid out)"

hdr "2. WRONG PREIMAGE — must reject, then correct one claims"
send 3000 arm "$OP" "$H" 1000000        # id 1
assert_status 1 1 "arm#1 ARMED"
send 0 claim 1 "$WRONG"
assert_status 1 1 "claim#1 WRONG preimage REJECTED (still ARMED, no payout)"
send 0 claim 1 "$PREIMAGE"
assert_status 1 2 "claim#1 correct preimage CLAIMED"

hdr "3. REFUND — past-deadline claim rejected, opener refunds"
send 2000 arm "$OP" "$H" 0              # id 2, deadline = current epoch
assert_status 2 1 "arm#2 ARMED (expiry=0 -> immediately past window)"
send 0 claim 2 "$PREIMAGE"
assert_status 2 1 "claim#2 past-deadline REJECTED (still ARMED)"
send 0 refund 2
assert_status 2 3 "refund#2 REFUNDED"

echo
if [[ $FAILS -eq 0 ]]; then
  echo "VERDICT: PASS — v4 relay hashlock escrow works end-to-end on devnet: preimage-gated claim pays out, wrong preimage + past-deadline are rejected, and refund returns the escrow. The v4 relay-settlement mechanics are validated."
  exit 0
else
  echo "VERDICT: FAIL — $FAILS step(s) behaved incorrectly (see above). The relay mechanics need work before the full main-v3 merge."
  exit 1
fi
