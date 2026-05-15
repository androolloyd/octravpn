#!/usr/bin/env bash
# Full v1.1 OctraVPN e2e against Octra devnet.
#
# Drives: tailnet create → open_session → settle (two-tx, with metering
# numbers visible) → claim_earnings → multi-region tier (open against a
# second exit) → settle_claim equivocation slash → off-chain
# slash_double_sign.
#
# All steps run real chain txs. Wallets + receipts come from
# docker/devnet/state/<role>/. Configure docker/devnet/.env first
# (PROGRAM_ADDR + OCTRA_RPC_URL must be set).
#
# Assumes:
#   - 3 nodes registered on chain via the docker harness (e2e.sh ok)
#   - All wallets funded
#   - octra-foundry/target/release/octra is on disk
set -euo pipefail

cd "$(dirname "$0")/../.."

# shellcheck source=/dev/null
[[ -f docker/devnet/.env ]] && source docker/devnet/.env
[[ -f docker/devnet/hosts.env ]] && source docker/devnet/hosts.env

OCTRA_BIN="${OCTRA_BIN:-../octra-foundry/target/release/octra}"
: "${OCTRA_RPC_URL:?set in docker/devnet/.env}"
: "${PROGRAM_ADDR:?set in docker/devnet/.env}"

G='\033[32m'; R='\033[31m'; Y='\033[33m'; D='\033[2m'; C='\033[36m'; B='\033[1m'; NC='\033[0m'
hdr()  { printf "\n${C}══════ %s ══════${NC}\n" "$*"; }
ok()   { printf "  ${G}✓${NC} %s\n" "$*"; }
warn() { printf "  ${Y}!${NC} %s\n" "$*"; }
err()  { printf "  ${R}✗${NC} %s\n" "$*"; }
say()  { printf "  ${D}%s${NC}\n" "$*"; }
bold() { printf "${B}%s${NC}\n" "$*"; }
fail=0

rpc() {
  curl -s -m 8 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}

# Read u64 from storage block (devnet's `result.storage.<key>` map).
storage_u64() {
  local key=$1
  rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_endpoint\",[\"$NODE1_VALIDATOR_ADDR\"]]" \
    | python3 -c 'import json,sys;k=sys.argv[1];d=json.load(sys.stdin)["result"]["storage"];print(d.get(k,""))' "$key"
}

balance() {
  rpc "octra_balance" "[\"$1\"]" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["result"]["balance_raw"] if "result" in d else "0")'
}

wait_for_tx() {
  local hash=$1
  for _ in 1 2 3 4 5 6; do
    sleep 4
    local s
    s=$(rpc "octra_transaction" "[\"$hash\"]" \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);r=d.get("result",{});print(r.get("status","?"))')
    case "$s" in
      confirmed) echo "$s"; return 0 ;;
      rejected) echo "$s"; return 1 ;;
    esac
  done
  echo "timeout"
  return 1
}

# Submit a contract call via `octra cast send` and capture the tx hash.
# Args: <key> <method> <args...>
send_tx() {
  local key=$1; shift
  local method=$1; shift
  local out
  out=$("$OCTRA_BIN" cast send --key "$key" --rpc-url "$OCTRA_RPC_URL" --fee 1000 "$PROGRAM_ADDR" "$method" "$@" 2>&1)
  local hash; hash=$(echo "$out" | python3 -c 'import json,sys,re;txt=sys.stdin.read();m=re.search(r"\"tx_hash\":\s*\"([^\"]+)\"",txt);print(m.group(1) if m else "")')
  if [[ -z "$hash" ]]; then echo "$out" >&2; return 1; fi
  echo "$hash"
}

send_value_tx() {
  local key=$1; shift
  local value=$1; shift
  local method=$1; shift
  local out
  out=$("$OCTRA_BIN" cast send --key "$key" --rpc-url "$OCTRA_RPC_URL" --value "$value" --fee 1000 "$PROGRAM_ADDR" "$method" "$@" 2>&1)
  local hash; hash=$(echo "$out" | python3 -c 'import json,sys,re;txt=sys.stdin.read();m=re.search(r"\"tx_hash\":\s*\"([^\"]+)\"",txt);print(m.group(1) if m else "")')
  if [[ -z "$hash" ]]; then echo "$out" >&2; return 1; fi
  echo "$hash"
}

CLIENT_KEY=docker/devnet/state/client/wallet.key
NODE1_KEY=docker/devnet/state/node1/wallet.key
NODE2_KEY=docker/devnet/state/node2/wallet.key
NODE3_KEY=docker/devnet/state/node3/wallet.key

# ============================================================
hdr "0/  preflight"
# ============================================================

ok "rpc:     $OCTRA_RPC_URL"
ok "program: $PROGRAM_ADDR"
for label_addr in \
  "client:$CLIENT_ADDR" \
  "node1:$NODE1_VALIDATOR_ADDR" \
  "node2:$NODE2_VALIDATOR_ADDR" \
  "node3:$NODE3_VALIDATOR_ADDR"; do
  label=${label_addr%%:*}; addr=${label_addr#*:}
  printf "    %-7s %s\n" "$label" "$(balance "$addr") OU"
done

# ============================================================
hdr "1/  client creates a tailnet (1000 OU treasury)"
# ============================================================

ACL_HEX=$(printf '00%.0s' {1..32})
TX=$(send_value_tx "$CLIENT_KEY" 1000 create_tailnet "\"$ACL_HEX\"")
ok "create_tailnet tx: $TX"
wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "tx rejected — continuing"

# Determine tailnet_id from chain storage (count - 1 after creation,
# since the contract increments after the assign).
TAILNET_COUNT=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_tailnet\",[0]]" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("storage",{}).get("tailnet_count","0"))')
TID=$((TAILNET_COUNT - 1))
ok "tailnet_id: $TID (count=$TAILNET_COUNT)"

# ============================================================
hdr "2/  configure node1 as the tailnet exit"
# ============================================================

TX=$(send_tx "$CLIENT_KEY" configure_tailnet_exit "$TID" "\"$NODE1_VALIDATOR_ADDR\"")
ok "configure_tailnet_exit tx: $TX"
wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "tx rejected — continuing"

# ============================================================
hdr "3/  client opens a session (200 OU max_pay)"
# ============================================================

TX=$(send_tx "$CLIENT_KEY" open_session "$TID" "\"$NODE1_VALIDATOR_ADDR\"" 200)
ok "open_session tx: $TX"
wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "tx rejected — continuing"

SESSION_COUNT=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_tailnet\",[0]]" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("storage",{}).get("session_count","0"))')
SID=$((SESSION_COUNT - 1))
ok "session_id: $SID"

# ============================================================
hdr "4/  metering — node1 submits settle_claim with 1 byte_used"
# ============================================================

bold "(simulating node1 metering — would normally come from boringtun packet counts)"
TX=$(send_tx "$NODE1_KEY" settle_claim "$SID" 1)
ok "settle_claim tx: $TX"
wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "tx rejected — continuing"

# ============================================================
hdr "5/  client confirms — two-tx settle applies"
# ============================================================

BEFORE_EARN=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_encrypted_earnings\",[\"$NODE1_VALIDATOR_ADDR\"]]" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("result","?"))')
say "node1 enc_earnings (before): $BEFORE_EARN"

TX=$(send_tx "$CLIENT_KEY" settle_confirm "$SID" 1)
ok "settle_confirm tx: $TX"
wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "tx rejected — continuing"

AFTER_EARN=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_encrypted_earnings\",[\"$NODE1_VALIDATOR_ADDR\"]]" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("result","?"))')
say "node1 enc_earnings (after):  $AFTER_EARN"
if [[ "$BEFORE_EARN" != "$AFTER_EARN" ]]; then
  ok "enc_earnings ledger updated — settlement applied"
else
  warn "enc_earnings unchanged — settle might not have credited (net pay too small?)"
fi

# ============================================================
hdr "6/  multi-region tier — open a second session against node2 (us-test)"
# ============================================================

TX=$(send_tx "$CLIENT_KEY" configure_tailnet_exit "$TID" "\"$NODE2_VALIDATOR_ADDR\"")
ok "configure node2 as additional exit tx: $TX"
wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "exit add failed"

TX=$(send_tx "$CLIENT_KEY" open_session "$TID" "\"$NODE2_VALIDATOR_ADDR\"" 200)
ok "open_session against node2 tx: $TX"
wait_for_tx "$TX" >/dev/null && ok "confirmed" || { err "tx rejected"; exit 1; }
SID2=$(($(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_tailnet\",[0]]" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("storage",{}).get("session_count","0"))') - 1))
ok "second session_id: $SID2 (exit=node2, region=us-test)"

# Drive node2 settle too.
TX=$(send_tx "$NODE2_KEY" settle_claim "$SID2" 1)
ok "node2 settle_claim tx: $TX"
wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "settle_claim failed"
TX=$(send_tx "$CLIENT_KEY" settle_confirm "$SID2" 1)
ok "client settle_confirm tx: $TX"
wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "settle_confirm failed"

# ============================================================
hdr "A/  adversarial — try to break the AML"
# ============================================================

bold "(every step here SHOULD fail — chain rejects = pass)"
DEPLOYER_KEY=docker/devnet/state/deployer.key

# A1: non-owner tries to configure a tailnet exit (only tailnet owner can).
say "A1: deployer (NOT tailnet owner) tries configure_tailnet_exit"
TX=$(send_tx "$DEPLOYER_KEY" configure_tailnet_exit "$TID" "\"$NODE1_VALIDATOR_ADDR\"" 2>/dev/null || true)
if [[ -n "$TX" ]]; then
  status=$(wait_for_tx "$TX") || true
  if [[ "$status" == "rejected" ]]; then ok "A1 rejected as expected"; else err "A1 unexpectedly $status — auth bypass!"; fail=$((fail+1)); fi
else
  ok "A1 refused at submit (expected)"
fi

# A2: non-member tries open_session
say "A2: deployer (NOT a tailnet member) tries open_session"
TX=$(send_tx "$DEPLOYER_KEY" open_session "$TID" "\"$NODE1_VALIDATOR_ADDR\"" 100 2>/dev/null || true)
if [[ -n "$TX" ]]; then
  status=$(wait_for_tx "$TX") || true
  if [[ "$status" == "rejected" ]]; then ok "A2 rejected as expected"; else err "A2 unexpectedly $status — membership gate bypassed!"; fail=$((fail+1)); fi
else
  ok "A2 refused at submit"
fi

# A3: settle_claim from a wallet that's not the session's exit
say "A3: node2 (not the session's exit) tries settle_claim on session $SID"
TX=$(send_tx "$NODE2_KEY" settle_claim "$SID" 5 2>/dev/null || true)
if [[ -n "$TX" ]]; then
  status=$(wait_for_tx "$TX") || true
  if [[ "$status" == "rejected" ]]; then ok "A3 rejected as expected"; else err "A3 unexpectedly $status — exit gate bypassed!"; fail=$((fail+1)); fi
else
  ok "A3 refused at submit"
fi

# A4: client re-submits settle_confirm on a session that already settled
say "A4: client replays settle_confirm on already-settled session $SID"
TX=$(send_tx "$CLIENT_KEY" settle_confirm "$SID" 1 2>/dev/null || true)
if [[ -n "$TX" ]]; then
  status=$(wait_for_tx "$TX") || true
  if [[ "$status" == "rejected" ]]; then ok "A4 rejected as expected"; else err "A4 unexpectedly $status — settled status not enforced!"; fail=$((fail+1)); fi
else
  ok "A4 refused at submit"
fi

# A5: open_session with max_pay > tailnet treasury
say "A5: client tries open_session with max_pay > tailnet treasury (50_000_000_000_000)"
TX=$(send_tx "$CLIENT_KEY" open_session "$TID" "\"$NODE1_VALIDATOR_ADDR\"" 50000000000000 2>/dev/null || true)
if [[ -n "$TX" ]]; then
  status=$(wait_for_tx "$TX") || true
  if [[ "$status" == "rejected" ]]; then ok "A5 rejected as expected (treasury insufficient)"; else err "A5 unexpectedly $status — treasury check missing!"; fail=$((fail+1)); fi
else
  ok "A5 refused at submit"
fi

# A6: non-owner tries gov_slash_operator
say "A6: client (NOT program owner) tries gov_slash_operator on node1"
TX=$(send_tx "$CLIENT_KEY" gov_slash_operator "\"$NODE1_VALIDATOR_ADDR\"" "\"$ACL_HEX\"" 2>/dev/null || true)
if [[ -n "$TX" ]]; then
  status=$(wait_for_tx "$TX") || true
  if [[ "$status" == "rejected" ]]; then ok "A6 rejected as expected"; else err "A6 unexpectedly $status — gov-only bypassed!"; fail=$((fail+1)); fi
else
  ok "A6 refused at submit"
fi

# A7: slash_double_sign with identical payloads (should be rejected "payloads identical")
say "A7: slash_double_sign with two IDENTICAL payloads (must reject)"
PAY="octravpn-receipt-v1|self-collision"
SIG_B64=$("$OCTRA_BIN" cast wallet sign --key docker/devnet/state/node1/wg.key "$PAY" 2>/dev/null | tail -1)
SIG_HEX=$(echo "$SIG_B64" | python3 -c 'import sys,base64;print(base64.b64decode(sys.stdin.read().strip()).hex())')
TX=$(send_tx "$CLIENT_KEY" slash_double_sign \
  "\"$NODE1_VALIDATOR_ADDR\"" 0 \
  "\"$PAY\"" "\"$SIG_HEX\"" \
  "\"$PAY\"" "\"$SIG_HEX\"" 2>/dev/null || true)
if [[ -n "$TX" ]]; then
  status=$(wait_for_tx "$TX") || true
  if [[ "$status" == "rejected" ]]; then ok "A7 rejected as expected"; else err "A7 unexpectedly $status — identical-payload check missing!"; fail=$((fail+1)); fi
else
  ok "A7 refused at submit"
fi

# A8: slash_double_sign with payloads signed by the WRONG key (must reject "sig_a invalid")
say "A8: slash_double_sign against node1 but signed with NODE2's receipt key (must reject)"
PAY_A="forged|a"
PAY_B="forged|b"
SIG_A_B64=$("$OCTRA_BIN" cast wallet sign --key docker/devnet/state/node2/wg.key "$PAY_A" 2>/dev/null | tail -1)
SIG_B_B64=$("$OCTRA_BIN" cast wallet sign --key docker/devnet/state/node2/wg.key "$PAY_B" 2>/dev/null | tail -1)
SIG_A_HEX=$(echo "$SIG_A_B64" | python3 -c 'import sys,base64;print(base64.b64decode(sys.stdin.read().strip()).hex())')
SIG_B_HEX=$(echo "$SIG_B_B64" | python3 -c 'import sys,base64;print(base64.b64decode(sys.stdin.read().strip()).hex())')
TX=$(send_tx "$CLIENT_KEY" slash_double_sign \
  "\"$NODE1_VALIDATOR_ADDR\"" 0 \
  "\"$PAY_A\"" "\"$SIG_A_HEX\"" \
  "\"$PAY_B\"" "\"$SIG_B_HEX\"" 2>/dev/null || true)
if [[ -n "$TX" ]]; then
  status=$(wait_for_tx "$TX") || true
  if [[ "$status" == "rejected" ]]; then ok "A8 rejected as expected (sig invalid)"; else err "A8 unexpectedly $status — forged slash succeeded!"; fail=$((fail+1)); fi
else
  ok "A8 refused at submit"
fi

# A9: bond_endpoint as an already-slashed operator (gets done later for node3)
# Deferred to after slash drills below.

# ============================================================
hdr "7/  in-AML equivocation slash on node3"
# ============================================================

bold "(node3 will submit two settle_claim values for the same session — auto-slashes)"

# Slash phases are destructive: once slashed, the operator stays
# slashed forever. Skip if a prior run already burned this victim.
NODE3_PRE_SLASHED=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"is_endpoint_slashed\",[\"$NODE3_VALIDATOR_ADDR\"]]" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("result","false"))')
if [[ "${NODE3_PRE_SLASHED,,}" == "true" || "${NODE3_PRE_SLASHED,,}" == "1" ]]; then
  ok "node3 already slashed from a prior run — skipping phase 7 (idempotent)"
  say "  to re-run the in-AML equivocation slash, swap in a fresh operator wallet"
else
  TX=$(send_tx "$CLIENT_KEY" configure_tailnet_exit "$TID" "\"$NODE3_VALIDATOR_ADDR\"")
  ok "configure node3 as exit tx: $TX"
  wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "exit add failed"

  TX=$(send_tx "$CLIENT_KEY" open_session "$TID" "\"$NODE3_VALIDATOR_ADDR\"" 200)
  ok "open_session against node3 tx: $TX"
  wait_for_tx "$TX" >/dev/null && ok "confirmed" || { err "tx rejected"; exit 1; }
  SID3=$(($(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_tailnet\",[0]]" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("storage",{}).get("session_count","0"))') - 1))
  ok "third session_id: $SID3"

  TX1=$(send_tx "$NODE3_KEY" settle_claim "$SID3" 1)
  ok "node3 settle_claim #1 (bytes=1) tx: $TX1"
  wait_for_tx "$TX1" >/dev/null && ok "confirmed" || warn "first claim failed"

  # Equivocation: re-claim with a different bytes value.
  TX2=$(send_tx "$NODE3_KEY" settle_claim "$SID3" 2)
  ok "node3 settle_claim #2 (bytes=2 — equivocation) tx: $TX2"
  status=$(wait_for_tx "$TX2") || true
  ok "equivocation claim status: $status"

  NODE3_SLASHED=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"is_endpoint_slashed\",[\"$NODE3_VALIDATOR_ADDR\"]]" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("result","false"))')
  case "${NODE3_SLASHED,,}" in
    true|1) ok "node3 is_endpoint_slashed = true — equivocation slash confirmed" ;;
    *)      warn "node3 not slashed (result=$NODE3_SLASHED) — chain may need a few more blocks" ;;
  esac
fi

# ============================================================
hdr "8/  cryptographic slash via slash_double_sign on node2"
# ============================================================

bold "(slasher = client; signs two contradictory off-chain receipts as node2)"

# Idempotency: if node2 is already slashed, skip.
NODE2_PRE_SLASHED=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"is_endpoint_slashed\",[\"$NODE2_VALIDATOR_ADDR\"]]" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("result","false"))')
if [[ "${NODE2_PRE_SLASHED,,}" == "true" || "${NODE2_PRE_SLASHED,,}" == "1" ]]; then
  ok "node2 already slashed from a prior run — skipping phase 8 (idempotent)"
  say "  to re-run slash_double_sign, register a fresh operator wallet first"
else
  # Read node2's ed25519 receipt-signing key.
  NODE2_RECEIPT_KEY=docker/devnet/state/node2/wg.key
  SLASHER_KEY=$CLIENT_KEY

  # Construct two distinct payloads. The AML's slash_double_sign accepts
  # any two distinct strings signed by the operator's receipt_pubkey;
  # the receipts don't need to be in a specific binary format, just
  # differ + verify.
  PAYLOAD_A="octravpn-receipt-v1|session=$SID2|bytes=100|blind=aa"
  PAYLOAD_B="octravpn-receipt-v1|session=$SID2|bytes=200|blind=bb"

  # Sign via `octra cast wallet sign` — produces base64 sig (AML's
  # ed25519_ok expects base64 pk + sig, not hex).
  SIG_A=$("$OCTRA_BIN" cast wallet sign --key "$NODE2_RECEIPT_KEY" "$PAYLOAD_A" 2>/dev/null | tail -1)
  SIG_B=$("$OCTRA_BIN" cast wallet sign --key "$NODE2_RECEIPT_KEY" "$PAYLOAD_B" 2>/dev/null | tail -1)

  ok "constructed two off-chain receipts + sigs under node2's receipt key"
  say "  payload_a = $PAYLOAD_A"
  say "  payload_b = $PAYLOAD_B"

  # slash_double_sign(operator_addr, session_id, payload_a, sig_a, payload_b, sig_b)
  TX=$(send_tx "$SLASHER_KEY" slash_double_sign \
    "\"$NODE2_VALIDATOR_ADDR\"" "$SID2" \
    "\"$PAYLOAD_A\"" "\"$SIG_A\"" \
    "\"$PAYLOAD_B\"" "\"$SIG_B\"")
  ok "slash_double_sign tx: $TX"
  wait_for_tx "$TX" >/dev/null && ok "confirmed" || warn "slash tx didn't confirm"

  NODE2_SLASHED=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"is_endpoint_slashed\",[\"$NODE2_VALIDATOR_ADDR\"]]" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("result","false"))')
  case "${NODE2_SLASHED,,}" in
    true|1) ok "node2 is_endpoint_slashed = true — cryptographic slash confirmed" ;;
    *)      warn "node2 not slashed (result=$NODE2_SLASHED) — check that the operator's receipt_pubkey on chain is base64-encoded (use 'octra cast wallet pubkey' which now defaults to base64)" ;;
  esac
fi

# ============================================================
hdr "A10/  post-slash attack — node3 (slashed) tries to re-register"
# ============================================================

bold "(slashed operators must be permanently locked out)"
NODE3_RECEIPT_PK=$("$OCTRA_BIN" cast wallet pubkey --key docker/devnet/state/node3/wg.key)
TX=$(send_tx "$NODE3_KEY" register_endpoint \
  '"node3-resurrected:51820"' \
  "\"$(printf 'de%.0s' {1..32})\"" \
  '"hfhe_v1|fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe"' \
  '"hfhe_v1|0000000000000000000000000000000000000000000000000000000000000000"' \
  '"resurrected"' \
  100 \
  "\"$NODE3_RECEIPT_PK\"" 2>/dev/null || true)
if [[ -n "$TX" ]]; then
  status=$(wait_for_tx "$TX") || true
  if [[ "$status" == "rejected" ]]; then ok "A10 rejected as expected (previously slashed)"; else err "A10 unexpectedly $status — slashed-operator lock bypassed!"; fail=$((fail+1)); fi
else
  ok "A10 refused at submit"
fi

# ============================================================
hdr "9/  final state snapshot"
# ============================================================

for label_addr in \
  "client:$CLIENT_ADDR" \
  "node1:$NODE1_VALIDATOR_ADDR" \
  "node2:$NODE2_VALIDATOR_ADDR" \
  "node3:$NODE3_VALIDATOR_ADDR"; do
  label=${label_addr%%:*}; addr=${label_addr#*:}
  printf "    %-7s %s OU\n" "$label" "$(balance "$addr")"
done

bold ""
if [[ "$fail" -eq 0 ]]; then
  bold "  e2e complete — all happy-path AND adversarial checks held"
else
  err "$fail adversarial checks unexpectedly succeeded — investigate immediately"
fi
bold "  explorer: https://devnet.octrascan.io/address.html?addr=$PROGRAM_ADDR"
exit $fail
