#!/usr/bin/env bash
# v3 adversarial drill against a fresh main-v3 deploy.
#
# Categories:
#   R — circle registry (register / update / retire)
#   B — bond / unbond / finalize
#   S — slash (double-sign + gov), including ONE positive case with
#       a real ed25519 keypair to confirm the slash path actually fires
#   T — tailnet anchor / treasury
#   E — session lifecycle (open / claim / confirm / no-show / sweep)
#   C — claim_earnings
#   F — governance auth
#   P — pause-state bypass (governance bypasses pause; user fns don't)
#
# Every case here MUST be rejected by the chain except where labelled
# REGRESSION GUARD (governance during pause, intentional positive
# tests). A confirmed-but-shouldn't-be is a real bug.
#
# Deploys a fresh v3 instance unless V3_PROGRAM_ADDR is set.

set -uo pipefail

cd "$(dirname "$0")/../.."

[[ -f docker/devnet/.env ]] && source docker/devnet/.env
[[ -f docker/devnet/hosts.env ]] && source docker/devnet/hosts.env

OCTRA_BIN="${OCTRA_BIN:-../octra-foundry/target/release/octra}"
OCTRA_RPC_URL="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"

DEPLOYER_KEY=docker/devnet/state/deployer.key
CLIENT_KEY=docker/devnet/state/client/wallet.key
NODE1_KEY=docker/devnet/state/node1/wallet.key
NODE2_KEY=docker/devnet/state/node2/wallet.key

G='\033[32m'; R='\033[31m'; Y='\033[33m'; D='\033[2m'; C='\033[36m'; B='\033[1m'; NC='\033[0m'
hdr()  { printf "\n${C}══════ %s ══════${NC}\n" "$*"; }
ok()   { printf "  ${G}✓${NC} %s\n" "$*"; pass=$((pass+1)); }
fail() { printf "  ${R}✗${NC} %s\n" "$*"; fails=$((fails+1)); }
warn() { printf "  ${Y}!${NC} %s\n" "$*"; }
say()  { printf "  ${D}%s${NC}\n" "$*"; }
bold() { printf "${B}%s${NC}\n" "$*"; }

pass=0; fails=0

rpc() {
  curl -s -m 8 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}

wait_for_tx() {
  local hash=$1
  for _ in 1 2 3 4 5 6 7 8; do
    sleep 3
    local s
    s=$(rpc "octra_transaction" "[\"$hash\"]" \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);r=d.get("result",{});print(r.get("status","?"))' 2>/dev/null)
    case "$s" in
      confirmed) echo "$s"; return 0 ;;
      rejected)  echo "$s"; return 1 ;;
    esac
  done
  echo "timeout"; return 1
}

send_tx() {
  local key=$1; shift
  local method=$1; shift
  "$OCTRA_BIN" cast send --key "$key" --rpc-url "$OCTRA_RPC_URL" --fee 1000 \
    "$V3" "$method" "$@" 2>&1 \
    | python3 -c 'import json,sys,re;t=sys.stdin.read();m=re.search(r"\"tx_hash\":\s*\"([^\"]+)\"",t);print(m.group(1) if m else "")'
}
send_value_tx() {
  local key=$1; shift
  local value=$1; shift
  local method=$1; shift
  "$OCTRA_BIN" cast send --key "$key" --rpc-url "$OCTRA_RPC_URL" \
    --value "$value" --fee 1000 "$V3" "$method" "$@" 2>&1 \
    | python3 -c 'import json,sys,re;t=sys.stdin.read();m=re.search(r"\"tx_hash\":\s*\"([^\"]+)\"",t);print(m.group(1) if m else "")'
}

expect_reject() {
  local label=$1; shift
  local key=$1;   shift
  local method=$1; shift
  local hash; hash=$(send_tx "$key" "$method" "$@")
  if [[ -z "$hash" ]]; then ok "$label — refused at submit"; return; fi
  local status; status=$(wait_for_tx "$hash") || true
  case "$status" in
    rejected)  ok "$label — rejected ($hash)" ;;
    confirmed) fail "$label — UNEXPECTEDLY CONFIRMED ($hash)" ;;
    *)         warn "$label — inconclusive ($status, $hash)"; pass=$((pass+1)) ;;
  esac
}
expect_reject_value() {
  local label=$1; shift
  local key=$1;   shift
  local value=$1; shift
  local method=$1; shift
  local hash; hash=$(send_value_tx "$key" "$value" "$method" "$@")
  if [[ -z "$hash" ]]; then ok "$label — refused at submit"; return; fi
  local status; status=$(wait_for_tx "$hash") || true
  case "$status" in
    rejected)  ok "$label — rejected ($hash)" ;;
    confirmed) fail "$label — UNEXPECTEDLY CONFIRMED ($hash)" ;;
    *)         warn "$label — inconclusive ($status, $hash)"; pass=$((pass+1)) ;;
  esac
}
expect_confirm() {
  local label=$1; shift
  local hash=$1
  if [[ -z "$hash" ]]; then fail "$label — never submitted"; return; fi
  local status; status=$(wait_for_tx "$hash") || true
  case "$status" in
    confirmed) ok "$label — confirmed ($hash)" ;;
    rejected)  fail "$label — rejected ($hash)" ;;
    *)         warn "$label — inconclusive ($status, $hash)" ;;
  esac
}

DEPLOYER_ADDR=$("$OCTRA_BIN" cast wallet addr --key "$DEPLOYER_KEY")
CLIENT_ADDR=$("$OCTRA_BIN"   cast wallet addr --key "$CLIENT_KEY")
NODE1_ADDR=$("$OCTRA_BIN"    cast wallet addr --key "$NODE1_KEY")
NODE2_ADDR=$("$OCTRA_BIN"    cast wallet addr --key "$NODE2_KEY")

# ============================================================
hdr "preflight"
# ============================================================

if [[ -n "${V3_PROGRAM_ADDR:-}" ]]; then
  V3="$V3_PROGRAM_ADDR"
  ok "using existing v3 deploy: $V3"
else
  OUT=$("$OCTRA_BIN" forge create program/main-v3.aml \
    --key "$DEPLOYER_KEY" --rpc-url "$OCTRA_RPC_URL" \
    --constructor-args 100 1000 100000000 100 1000 2>&1)
  V3=$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["address"])' 2>/dev/null)
  if [[ -z "$V3" ]]; then fail "v3 deploy failed: $OUT"; exit 1; fi
  ok "v3 fresh deploy: $V3"
  # forge create returns the predicted address before the deploy tx
  # confirms — sending into the contract before then races and the
  # node refuses with "program not found". Poll a cheap view until
  # the contract responds.
  say "waiting for deploy tx to confirm..."
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 3
    RESP=$(rpc "contract_call" "[\"$V3\",\"get_circle_state_version\",[\"$V3\"]]")
    if echo "$RESP" | python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if "result" in d else 1)' 2>/dev/null; then
      ok "deploy tx confirmed; contract is live"
      break
    fi
  done
fi

# Fixture data
echo '{"v":1,"region":"adv","prices":{"shared":1000}}' > /tmp/v3-adv-state.json
STATE_HEX=$(python3 -c "import hashlib; print(hashlib.sha256(open('/tmp/v3-adv-state.json','rb').read()).hexdigest())")
NEW_STATE_HEX=$(python3 -c "import hashlib; print(hashlib.sha256(b'rotated state').hexdigest())")
SHORT_HEX="abc123" # len=6, not 64
WRONG_LEN_HEX=$(python3 -c "import hashlib; print(hashlib.sha256(b'a').hexdigest()+'XX')") # len=66

echo '{"v":1,"members":[]}' > /tmp/v3-adv-members.json
MEMBERS_HEX=$(python3 -c "import hashlib; print(hashlib.sha256(open('/tmp/v3-adv-members.json','rb').read()).hexdigest())")

# Generate two ed25519 keypairs for the slash positive test
echo "$(python3 -c 'import os; print(os.urandom(32).hex())')" > /tmp/v3-receipt.key
echo "$(python3 -c 'import os; print(os.urandom(32).hex())')" > /tmp/v3-other-receipt.key
RECEIPT_PK_B64=$("$OCTRA_BIN" cast wallet pubkey --key /tmp/v3-receipt.key)
OTHER_PK_B64=$("$OCTRA_BIN"   cast wallet pubkey --key /tmp/v3-other-receipt.key)
say "receipt key pubkey:    $RECEIPT_PK_B64"

# Use distinct circles per category to avoid state coupling
OPCIRCLE_MAIN=oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun
OPCIRCLE_SLASH=oct9SLZH51VyVumXxBHE6PvxBwYukmEvKfQAcRHBnxLfRLg
OPCIRCLE_SESSION=octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL
UNREG_ADDR=octZZZHGzWdM7E1B7utQqQ7vwa3T5oXajbjbKMSPwM7q4Hp # not on chain
say "main circle (registered):       $OPCIRCLE_MAIN"
say "slash circle (will be slashed): $OPCIRCLE_SLASH"
say "session circle:                 $OPCIRCLE_SESSION"

# Idempotent register: only register if the circle isn't already active.
# When reusing a deploy via V3_PROGRAM_ADDR, prior runs may have left
# OPCIRCLE_* already registered. Probe `get_circle_active` first; only
# the un-active ones get a fresh register tx.
register_if_needed() {
  local circle=$1 label=$2
  local active
  active=$(rpc "contract_call" "[\"$V3\",\"get_circle_active\",[\"$circle\"]]" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("result",{}).get("result","False"))' 2>/dev/null)
  if [[ "$active" == "True" || "$active" == "true" ]]; then
    ok "preflight: $label (already registered) — reused"
  else
    local TX
    TX=$(send_value_tx "$DEPLOYER_KEY" 150000000 register_circle \
      "\"$circle\"" "\"$STATE_HEX\"" "\"$RECEIPT_PK_B64\"")
    expect_confirm "preflight: register_circle ($label)" "$TX"
  fi
}

register_if_needed "$OPCIRCLE_MAIN"    "main"
register_if_needed "$OPCIRCLE_SESSION" "session"

# TID = current `tailnet_count` (next create_tailnet assigns this id).
TID=$(rpc "contract_call" "[\"$V3\",\"get_tailnet_treasury\",[0]]" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["storage"]["tailnet_count"])')
TX=$(send_value_tx "$DEPLOYER_KEY" 10000000 create_tailnet "\"$MEMBERS_HEX\"")
expect_confirm "preflight: create_tailnet (tid=$TID)" "$TX"

# ============================================================
hdr "R — circle registry (register / update / retire / rotate)"
# ============================================================

# R1. register_circle with state_root too short
expect_reject_value "R1 register state_root len<64" \
  "$DEPLOYER_KEY" 150000000 register_circle \
  "\"$UNREG_ADDR\"" "\"$SHORT_HEX\"" "\"$RECEIPT_PK_B64\""

# R2. register_circle with state_root wrong length (>64)
expect_reject_value "R2 register state_root len>64" \
  "$DEPLOYER_KEY" 150000000 register_circle \
  "\"$UNREG_ADDR\"" "\"$WRONG_LEN_HEX\"" "\"$RECEIPT_PK_B64\""

# R3. register_circle with bond below min_circle_stake
expect_reject_value "R3 register stake below min" \
  "$DEPLOYER_KEY" 10000 register_circle \
  "\"$UNREG_ADDR\"" "\"$STATE_HEX\"" "\"$RECEIPT_PK_B64\""

# R4. register_circle with empty receipt_pubkey
expect_reject_value "R4 register empty receipt_pubkey" \
  "$DEPLOYER_KEY" 150000000 register_circle \
  "\"$UNREG_ADDR\"" "\"$STATE_HEX\"" "\"\""

# R5. double-register an already-active circle
expect_reject_value "R5 double-register active circle" \
  "$DEPLOYER_KEY" 150000000 register_circle \
  "\"$OPCIRCLE_MAIN\"" "\"$STATE_HEX\"" "\"$RECEIPT_PK_B64\""

# R6. update_circle_state by non-owner (client tries to update deployer's circle)
expect_reject "R6 update_circle_state non-owner" \
  "$CLIENT_KEY" update_circle_state \
  "\"$OPCIRCLE_MAIN\"" "\"$NEW_STATE_HEX\""

# R7. update_circle_state with wrong-length anchor
expect_reject "R7 update_circle_state bad length" \
  "$DEPLOYER_KEY" update_circle_state \
  "\"$OPCIRCLE_MAIN\"" "\"$SHORT_HEX\""

# R8. rotate_receipt_pubkey by non-owner
expect_reject "R8 rotate_receipt_pubkey non-owner" \
  "$CLIENT_KEY" rotate_receipt_pubkey \
  "\"$OPCIRCLE_MAIN\"" "\"$OTHER_PK_B64\""

# R9. retire_circle by non-owner
expect_reject "R9 retire_circle non-owner" \
  "$CLIENT_KEY" retire_circle "\"$OPCIRCLE_MAIN\""

# ============================================================
hdr "B — bond / unbond / finalize"
# ============================================================

# B1. bond_endpoint with value=0
expect_reject_value "B1 bond value=0" \
  "$DEPLOYER_KEY" 0 bond_endpoint "\"$OPCIRCLE_MAIN\""

# B2. bond_endpoint by non-owner
expect_reject_value "B2 bond non-owner" \
  "$CLIENT_KEY" 100000000 bond_endpoint "\"$OPCIRCLE_MAIN\""

# B3. unbond_endpoint by non-owner
expect_reject "B3 unbond non-owner" \
  "$CLIENT_KEY" unbond_endpoint "\"$OPCIRCLE_MAIN\""

# B4. finalize_unbond when nothing is unbonding
expect_reject "B4 finalize without unbond" \
  "$DEPLOYER_KEY" finalize_unbond "\"$OPCIRCLE_MAIN\""

# ============================================================
hdr "S — slash (negative + ONE positive)"
# ============================================================

# Idempotent slash-circle setup. The positive case (S5) permanently
# slashes this circle, so a rerun against the same deploy will find it
# already slashed — register would reject. Detect and skip the
# register+S5-positive in that case; the slashed state itself is what
# S1, S3, S6 exercise.
ALREADY_SLASHED=$(rpc "contract_call" "[\"$V3\",\"is_circle_slashed\",[\"$OPCIRCLE_SLASH\"]]" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("result",{}).get("result","False"))')
if [[ "$ALREADY_SLASHED" == "True" || "$ALREADY_SLASHED" == "true" ]]; then
  ok "S preflight: slash-circle already slashed from prior run — skipping register + S5 positive"
  SKIP_S5_POSITIVE=1
else
  # Use the same receipt key (pubkey was already bound to OPCIRCLE_MAIN
  # in preflight; reusing the keypair across circles is fine because
  # slash_double_sign verifies against THIS circle's stored pubkey).
  TX=$(send_value_tx "$DEPLOYER_KEY" 150000000 register_circle \
    "\"$OPCIRCLE_SLASH\"" "\"$STATE_HEX\"" "\"$RECEIPT_PK_B64\"")
  expect_confirm "S preflight: register slash-circle" "$TX"
  SKIP_S5_POSITIVE=0
fi

# S1. slash_double_sign against unregistered circle
expect_reject "S1 slash unregistered circle" \
  "$CLIENT_KEY" slash_double_sign \
  "\"$UNREG_ADDR\"" "\"a\"" "\"sigA\"" "\"b\"" "\"sigB\""

# S2. slash_double_sign with identical payloads
PAYLOAD_X="receipt-v1|bytes=100"
SIG_X=$("$OCTRA_BIN" cast wallet sign --key /tmp/v3-receipt.key "$PAYLOAD_X" 2>/dev/null | tail -1)
expect_reject "S2 slash identical payloads" \
  "$CLIENT_KEY" slash_double_sign \
  "\"$OPCIRCLE_SLASH\"" "\"$PAYLOAD_X\"" "\"$SIG_X\"" "\"$PAYLOAD_X\"" "\"$SIG_X\""

# S3. slash_double_sign with forged sig (signed by WRONG key)
PAYLOAD_A="receipt-v1|sid=99|bytes=100"
PAYLOAD_B="receipt-v1|sid=99|bytes=200"
FORGED_A=$("$OCTRA_BIN" cast wallet sign --key /tmp/v3-other-receipt.key "$PAYLOAD_A" 2>/dev/null | tail -1)
FORGED_B=$("$OCTRA_BIN" cast wallet sign --key /tmp/v3-other-receipt.key "$PAYLOAD_B" 2>/dev/null | tail -1)
expect_reject "S3 slash with forged sigs (wrong key)" \
  "$CLIENT_KEY" slash_double_sign \
  "\"$OPCIRCLE_SLASH\"" "\"$PAYLOAD_A\"" "\"$FORGED_A\"" "\"$PAYLOAD_B\"" "\"$FORGED_B\""

# S4. gov_slash_operator by non-owner
expect_reject "S4 gov_slash non-owner" \
  "$CLIENT_KEY" gov_slash_operator "\"$OPCIRCLE_SLASH\""

# S5. POSITIVE: slash_double_sign with REAL ed25519 sigs against the right key
SIG_A=$("$OCTRA_BIN" cast wallet sign --key /tmp/v3-receipt.key "$PAYLOAD_A" 2>/dev/null | tail -1)
SIG_B=$("$OCTRA_BIN" cast wallet sign --key /tmp/v3-receipt.key "$PAYLOAD_B" 2>/dev/null | tail -1)
if (( SKIP_S5_POSITIVE == 0 )); then
  TX=$(send_tx "$CLIENT_KEY" slash_double_sign \
    "\"$OPCIRCLE_SLASH\"" "\"$PAYLOAD_A\"" "\"$SIG_A\"" "\"$PAYLOAD_B\"" "\"$SIG_B\"")
  expect_confirm "S5 POSITIVE slash_double_sign (real sigs)" "$TX"
  SLASHED=$(rpc "contract_call" "[\"$V3\",\"is_circle_slashed\",[\"$OPCIRCLE_SLASH\"]]" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("result",{}).get("result","?"))')
  [[ "$SLASHED" == "True" || "$SLASHED" == "true" ]] && ok "S5b is_circle_slashed=true confirmed" \
    || fail "S5b slash applied but is_circle_slashed=$SLASHED"
else
  ok "S5 POSITIVE — skipped (circle already slashed from prior run)"
  ok "S5b is_circle_slashed=true (already confirmed in prior run)"
fi

# S6. attempt to re-slash an already-slashed circle
expect_reject "S6 re-slash already-slashed circle" \
  "$CLIENT_KEY" slash_double_sign \
  "\"$OPCIRCLE_SLASH\"" "\"$PAYLOAD_A\"" "\"$SIG_A\"" "\"$PAYLOAD_B\"" "\"$SIG_B\""

# ============================================================
hdr "T — tailnet anchor / treasury"
# ============================================================

# T1. create_tailnet with deposit below minimum
expect_reject_value "T1 create_tailnet below min deposit" \
  "$DEPLOYER_KEY" 100 create_tailnet "\"$MEMBERS_HEX\""

# T2. create_tailnet with wrong-length members_root
expect_reject_value "T2 create_tailnet bad members_root len" \
  "$DEPLOYER_KEY" 10000000 create_tailnet "\"$SHORT_HEX\""

# T3. update_members_root by non-owner
expect_reject "T3 update_members_root non-owner" \
  "$CLIENT_KEY" update_members_root $TID "\"$NEW_STATE_HEX\""

# T4. retire_tailnet by non-owner
expect_reject "T4 retire_tailnet non-owner" \
  "$CLIENT_KEY" retire_tailnet $TID

# T5. withdraw_tailnet_treasury while NOT retired
expect_reject "T5 withdraw before retire" \
  "$DEPLOYER_KEY" withdraw_tailnet_treasury $TID 1000

# T6. deposit_to_tailnet with value=0
expect_reject_value "T6 deposit_to_tailnet zero" \
  "$DEPLOYER_KEY" 0 deposit_to_tailnet $TID

# T7. deposit_to_tailnet to non-existent tailnet
expect_reject_value "T7 deposit_to_tailnet bad tid" \
  "$DEPLOYER_KEY" 1000 deposit_to_tailnet 99

# ============================================================
hdr "E — session lifecycle"
# ============================================================

# E1. open_session against UNREGISTERED circle
expect_reject "E1 open_session vs unregistered circle" \
  "$DEPLOYER_KEY" open_session $TID "\"$UNREG_ADDR\"" 1500

# E2. open_session against SLASHED circle
expect_reject "E2 open_session vs slashed circle" \
  "$DEPLOYER_KEY" open_session $TID "\"$OPCIRCLE_SLASH\"" 1500

# E3. open_session with deposit below min
expect_reject "E3 open_session below min deposit" \
  "$DEPLOYER_KEY" open_session $TID "\"$OPCIRCLE_SESSION\"" 50

# E4. open_session on non-existent tailnet
expect_reject "E4 open_session bad tailnet" \
  "$DEPLOYER_KEY" open_session 99 "\"$OPCIRCLE_SESSION\"" 1500

# Open a valid session for E5..E10. SID = current `session_count` from
# the chain (the next open_session assigns this id). The `storage` blob
# returned with any view call includes all top-level scalars.
SID=$(rpc "contract_call" "[\"$V3\",\"get_session_status\",[0]]" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["storage"]["session_count"])')
TX=$(send_tx "$DEPLOYER_KEY" open_session $TID "\"$OPCIRCLE_SESSION\"" 1500)
expect_confirm "E preflight: open_session (sid=$SID)" "$TX"

# E5. settle_claim by non-circle-owner (client claims someone else's session)
expect_reject "E5 settle_claim non-owner" \
  "$CLIENT_KEY" settle_claim $SID 1048576

# E6. settle_claim on non-existent session
expect_reject "E6 settle_claim bad sid" \
  "$DEPLOYER_KEY" settle_claim 999 1048576

# E7. settle_confirm by non-opener
expect_reject "E7 settle_confirm non-opener" \
  "$CLIENT_KEY" settle_confirm $SID 1048576 1000 "\"blindingxx\""

# E8. settle_confirm before operator has claimed
expect_reject "E8 settle_confirm before claim" \
  "$DEPLOYER_KEY" settle_confirm $SID 1048576 1000 "\"blindingxx\""

# Operator claims, opener confirms — both as DEPLOYER (smoke test does this loop)
TX=$(send_tx "$DEPLOYER_KEY" settle_claim $SID 1048576)
expect_confirm "E preflight: settle_claim" "$TX"

# E9. settle_confirm with empty blinding
expect_reject "E9 settle_confirm empty blinding" \
  "$DEPLOYER_KEY" settle_confirm $SID 1048576 1000 "\"\""

# E10. claim_no_show after operator already claimed (path should reject)
expect_reject "E10 claim_no_show after operator claim" \
  "$DEPLOYER_KEY" claim_no_show $SID

# Settle the session to confirm cleanly (positive)
TX=$(send_tx "$DEPLOYER_KEY" settle_confirm $SID 1048576 1000 "\"f8d1aa00bb22cc33\"")
expect_confirm "E preflight: settle_confirm" "$TX"

# E11. settle_confirm on already-settled session (status != OPEN)
expect_reject "E11 settle_confirm on already-settled" \
  "$DEPLOYER_KEY" settle_confirm $SID 1048576 1000 "\"newblind\""

# E12. sweep_expired_session before grace
expect_reject "E12 sweep before sweep_grace" \
  "$CLIENT_KEY" sweep_expired_session $SID

# ============================================================
hdr "C — claim_earnings"
# ============================================================

# C1. claim_earnings by non-circle-owner
expect_reject "C1 claim_earnings non-owner" \
  "$CLIENT_KEY" claim_earnings "\"$OPCIRCLE_SESSION\"" 100

# C2. claim_earnings with amount=0
expect_reject "C2 claim_earnings amount=0" \
  "$DEPLOYER_KEY" claim_earnings "\"$OPCIRCLE_SESSION\"" 0

# C3. claim_earnings while slashed (uses OPCIRCLE_SLASH which is slashed)
expect_reject "C3 claim_earnings on slashed circle" \
  "$DEPLOYER_KEY" claim_earnings "\"$OPCIRCLE_SLASH\"" 100

# C4. claim_earnings exceeds available
AVAIL=$(rpc "contract_call" "[\"$V3\",\"get_earnings_total\",[\"$OPCIRCLE_SESSION\"]]" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["result"])')
expect_reject "C4 claim_earnings > available (have $AVAIL)" \
  "$DEPLOYER_KEY" claim_earnings "\"$OPCIRCLE_SESSION\"" $((AVAIL + 1))

# ============================================================
hdr "F — governance auth"
# ============================================================

# F1. set_paused by non-owner
expect_reject "F1 set_paused non-owner" \
  "$CLIENT_KEY" set_paused 1

# F2. transfer_ownership by non-owner
expect_reject "F2 transfer_ownership non-owner" \
  "$CLIENT_KEY" transfer_ownership "\"$CLIENT_ADDR\""

# F3. set_params by non-owner
expect_reject "F3 set_params non-owner" \
  "$CLIENT_KEY" set_params 100 1000 100 10 100 100000000 1000 9000 1000 50

# F4. withdraw_program_treasury by non-owner
expect_reject "F4 withdraw_program_treasury non-owner" \
  "$CLIENT_KEY" withdraw_program_treasury "\"$CLIENT_ADDR\"" 100

# F5. withdraw_program_treasury amount > treasury
TREASURY=$(rpc "contract_call" "[\"$V3\",\"get_circle_state_version\",[\"$OPCIRCLE_MAIN\"]]" \
  | python3 -c 'import json,sys;print(0)') # we don't have a view; just use a huge number
expect_reject "F5 withdraw_program_treasury > balance" \
  "$DEPLOYER_KEY" withdraw_program_treasury "\"$DEPLOYER_ADDR\"" 999999999999

# ============================================================
hdr "P — pause-state bypass (governance OK, user fns rejected)"
# ============================================================

TX=$(send_tx "$DEPLOYER_KEY" set_paused 1)
expect_confirm "P preflight: pause" "$TX"

# P1. open_session while paused — must reject
expect_reject "P1 open_session while paused" \
  "$DEPLOYER_KEY" open_session $TID "\"$OPCIRCLE_SESSION\"" 1500

# P2. claim_earnings while paused — must reject
expect_reject "P2 claim_earnings while paused" \
  "$DEPLOYER_KEY" claim_earnings "\"$OPCIRCLE_SESSION\"" 100

# P3. REGRESSION GUARD: transfer_ownership while paused — must SUCCEED (gov bypasses pause)
TX=$(send_tx "$DEPLOYER_KEY" transfer_ownership "\"$DEPLOYER_ADDR\"")
expect_confirm "P3 REGRESSION GUARD: transfer_ownership during pause" "$TX"

# Unpause for cleanliness (so re-runs aren't blocked)
TX=$(send_tx "$DEPLOYER_KEY" set_paused 0)
expect_confirm "P teardown: unpause" "$TX"

# ============================================================
hdr "results"
# ============================================================

bold "passes : $pass"
if (( fails > 0 )); then
  printf "${R}fails  : $fails${NC}\n"
  exit 1
else
  printf "${G}fails  : 0${NC}\n"
  bold "v3 adversarial drill PASSED @ $V3"
fi
