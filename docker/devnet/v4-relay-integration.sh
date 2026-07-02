#!/usr/bin/env bash
# v4 relay-settlement INTEGRATION smoke: drive the real v3 program (main-v4 =
# main-v3 + relay fns) through register_circle -> create_tailnet -> open_session
# -> arm_relay -> relay_claim, proving the unilateral hashlock settlement works
# inside the full v3 machinery (not just the isolated HTLC probe).
#
# The settlement_hash pin and the isolated escrow mechanics are already validated
# (settlement-hash-pin-probe.sh / v4-relay-flow-probe.sh). This wires them into
# the actual session/circle/earnings model.
#
# Requires: deployer.key funded; foundry octra at $OCTRA_BIN. Set V4_AML to the
# merged program (default program/main-v4.aml).
set -euo pipefail

OCTRA_BIN="${OCTRA_BIN:-$(realpath "$(dirname "$0")/../../../octra-foundry/target/release/octra")}"
RPC="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"
ROOT="$(realpath "$(dirname "$0")/../..")"
KEY="${DEPLOYER_KEY:-$ROOT/docker/devnet/state/deployer.key}"
AML="${V4_AML:-$ROOT/program/main-v4.aml}"
OPCIRCLE="${OPCIRCLE:-oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun}"

# Relay params. net <= max_pay (deposit). The preimage/H are the pin-validated
# representative pair (identical shape to SignedReceipt::settlement_preimage()).
MAXPAY="${MAXPAY:-5000}"
NET="${NET:-3000}"
EXPIRY="${EXPIRY:-100000}"   # within main-v4 RELAY_EXPIRY_[MIN=10,MAX=100000]; large open claim window
STATUS_ARMED=3
STATUS_CLAIMED=4

hdr()  { printf "\n=== %s ===\n" "$1"; }
ok()   { printf "  + %s\n" "$1"; }
fail() { printf "  ! %s\n" "$1"; exit 1; }

wait_tx() {
  local tx=$1 label=$2
  [[ -z "$tx" ]] && fail "$label: no tx hash (submit failed)"
  sleep 18
  local resp status
  resp=$(curl -s -X POST "$RPC" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"octra_transaction\",\"params\":[\"$tx\"]}")
  status=$(echo "$resp" | python3 -c 'import json,sys;print((json.load(sys.stdin).get("result") or {}).get("status","?"))')
  if [[ "$status" == "confirmed" ]]; then ok "$label"; else
    local reason; reason=$(echo "$resp" | python3 -c 'import json,sys;r=(json.load(sys.stdin).get("result") or {}).get("error",{});print(r.get("reason","") if isinstance(r,dict) else r)')
    fail "$label: $status ($reason)"
  fi
}
send_tx() { local val=$1; shift
  "$OCTRA_BIN" cast send --key "$KEY" --rpc-url "$RPC" --fee 1000 --value "$val" "$V4" "$@" 2>&1 \
    | grep -oE '"tx_hash":\s*"[a-f0-9]+"' | head -1 | sed 's/.*"\([a-f0-9]*\)"/\1/'; }
view() { local fn=$1; shift
  curl -s -X POST "$RPC" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"contract_call\",\"params\":[\"$V4\",\"$fn\",$1]}" \
    | python3 -c 'import json,sys
r=json.load(sys.stdin).get("result")
print((r.get("result") if isinstance(r,dict) else r) if r is not None else "")'; }

[[ -f "$AML" ]] || fail "merged program not found: $AML (waiting on the main-v3+relay merge)"

read -r PREIMAGE H < <(python3 - <<'PY'
import base64, hashlib
p = base64.b64encode(b"octravpn-settle-v1|" + bytes([0xAB])*224).decode()
print(p, hashlib.sha256(p.encode()).hexdigest())
PY
)

hdr "0. deploy main-v4 (main-v3 + relay)"
OUT=$("$OCTRA_BIN" forge create "$AML" --key "$KEY" --rpc-url "$RPC" --constructor-args 100 1000 100000000 100 1000 2>&1)
V4=$(printf '%s' "$OUT" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("address",""))
except Exception: print("")')
[[ -z "$V4" ]] && V4=$(printf '%s' "$OUT" | grep -oE 'oct[0-9A-Za-z]{20,}' | head -1)
[[ -z "$V4" ]] && { printf '%s\n' "$OUT" | tail -6; fail "deploy failed / no address"; }
ok "deployed @ $V4"
sleep 8  # let the deploy finalize before the first call

hdr "1. register_circle"
printf '{"v":1,"region":"test","prices":{"shared":1000}}' > /tmp/v4-state.json
STATE_ROOT=$(python3 -c "import hashlib;print(hashlib.sha256(open('/tmp/v4-state.json','rb').read()).hexdigest())")
RECEIPT_PK=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
wait_tx "$(send_tx 150000000 register_circle "\"$OPCIRCLE\"" "\"$STATE_ROOT\"" "\"$RECEIPT_PK\"")" "register_circle"

hdr "2. create_tailnet (tid=0 on a fresh deploy)"
MEMBERS=$(python3 -c "import hashlib;print(hashlib.sha256(b'{\"v\":1,\"members\":[]}').hexdigest())")
wait_tx "$(send_tx 10000000 create_tailnet "\"$MEMBERS\"")" "create_tailnet"

hdr "3. open_session(tid=0, circle, max_pay=$MAXPAY)"
wait_tx "$(send_tx 0 open_session 0 "\"$OPCIRCLE\"" "$MAXPAY")" "open_session"
SOPEN=$(view get_session_status "[0]"); ok "session 0 status (OPEN) = $SOPEN"

hdr "4. arm_relay(0, H, net=$NET, expiry=$EXPIRY)  [client commits the settlement hash]"
wait_tx "$(send_tx 0 arm_relay 0 "\"$H\"" "$NET" "$EXPIRY")" "arm_relay"
S=$(view get_session_status "[0]")
[[ "$S" == "$STATUS_ARMED" ]] && ok "session 0 -> RELAY_ARMED ($S)" || fail "expected RELAY_ARMED($STATUS_ARMED), got $S"

hdr "5. relay_claim(0, preimage)  [operator reveals; unilateral payout]"
E_BEFORE=$(view get_earnings_total "[\"$OPCIRCLE\"]")
wait_tx "$(send_tx 0 relay_claim 0 "\"$PREIMAGE\"")" "relay_claim"
S=$(view get_session_status "[0]")
[[ "$S" == "$STATUS_CLAIMED" ]] && ok "session 0 -> RELAY_CLAIMED ($S)" || fail "expected RELAY_CLAIMED($STATUS_CLAIMED), got $S"
E_AFTER=$(view get_earnings_total "[\"$OPCIRCLE\"]")
ok "circle earnings: $E_BEFORE -> $E_AFTER"
[[ "$E_AFTER" -gt "$E_BEFORE" ]] && ok "earnings credited by the unilateral relay claim" || fail "earnings did not increase (expected net-after-fee credited)"

echo
echo "VERDICT: PASS — v4 relay settlement works INSIDE the full v3 program: open_session -> arm_relay -> relay_claim settles unilaterally via the sha256 preimage, flips the session RELAY_CLAIMED, and credits circle earnings. The v4 relay-settlement path is validated end-to-end in production shape."
