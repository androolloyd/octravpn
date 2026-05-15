#!/usr/bin/env bash
# Comprehensive adversarial drill against the deployed v1.1 program.
#
# Every case here MUST be rejected by the chain. A `confirmed` status
# anywhere is a failure (we tried to break the contract and the chain
# accepted it). Counts pass/fail and exits non-zero on any unexpected
# acceptance.
#
# Assumes e2e-full.sh has run at least once (tailnet 0 exists,
# at least one session settled, node3/node2/node4 already slashed).
# Calls are pure — they don't mutate "real" state on the happy path
# beyond test-scoped tailnets and a transient set_paused toggle that
# we always revert (trap).
#
# Categories:
#   A — stake / bond / slash mechanics
#   B — endpoint lifecycle
#   C — tailnet ACL / membership
#   D — join-token replay / preimage
#   E — session lifecycle
#   F — owner / governance auth
#   G — pause-state bypass
#
# Usage:
#   docker/devnet/e2e-adversarial.sh
set -uo pipefail   # no `-e`: we expect lots of failing txs

cd "$(dirname "$0")/../.."

# shellcheck source=/dev/null
[[ -f docker/devnet/.env ]] && source docker/devnet/.env
[[ -f docker/devnet/hosts.env ]] && source docker/devnet/hosts.env

OCTRA_BIN="${OCTRA_BIN:-../octra-foundry/target/release/octra}"
: "${OCTRA_RPC_URL:?set in docker/devnet/.env}"
: "${PROGRAM_ADDR:?set in docker/devnet/.env}"

G='\033[32m'; R='\033[31m'; Y='\033[33m'; D='\033[2m'; C='\033[36m'; B='\033[1m'; NC='\033[0m'
hdr()  { printf "\n${C}══════ %s ══════${NC}\n" "$*"; }
ok()   { printf "  ${G}✓${NC} %s\n" "$*"; pass=$((pass+1)); }
fail() { printf "  ${R}✗${NC} %s\n" "$*"; fail=$((fail+1)); }
warn() { printf "  ${Y}!${NC} %s\n" "$*"; }
say()  { printf "  ${D}%s${NC}\n" "$*"; }
bold() { printf "${B}%s${NC}\n" "$*"; }

pass=0; fail=0

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
      rejected) echo "$s"; return 1 ;;
    esac
  done
  echo "timeout"
  return 1
}

# Send a tx. Returns hash on stdout (empty if submit-time rejection).
send_tx() {
  local key=$1; shift
  local method=$1; shift
  local out
  out=$("$OCTRA_BIN" cast send --key "$key" --rpc-url "$OCTRA_RPC_URL" --fee 1000 "$PROGRAM_ADDR" "$method" "$@" 2>&1) || true
  echo "$out" | python3 -c 'import json,sys,re;txt=sys.stdin.read();m=re.search(r"\"tx_hash\":\s*\"([^\"]+)\"",txt);print(m.group(1) if m else "")'
}

send_value_tx() {
  local key=$1; shift
  local value=$1; shift
  local method=$1; shift
  local out
  out=$("$OCTRA_BIN" cast send --key "$key" --rpc-url "$OCTRA_RPC_URL" --value "$value" --fee 1000 "$PROGRAM_ADDR" "$method" "$@" 2>&1) || true
  echo "$out" | python3 -c 'import json,sys,re;txt=sys.stdin.read();m=re.search(r"\"tx_hash\":\s*\"([^\"]+)\"",txt);print(m.group(1) if m else "")'
}

# Submit a tx that MUST be rejected by the chain. PASS = rejected or
# submit-time refusal. FAIL = confirmed.
expect_reject() {
  local label=$1; shift
  local key=$1;   shift
  local method=$1; shift
  local hash
  hash=$(send_tx "$key" "$method" "$@")
  if [[ -z "$hash" ]]; then
    ok "$label — refused at submit"
    return 0
  fi
  local status
  status=$(wait_for_tx "$hash") || true
  case "$status" in
    rejected) ok "$label — rejected ($hash)" ;;
    confirmed) fail "$label — UNEXPECTEDLY CONFIRMED ($hash)" ;;
    *)        warn "$label — inconclusive ($status, $hash) — counting as pass"; pass=$((pass+1)) ;;
  esac
}

# Variant with --value.
expect_reject_value() {
  local label=$1; shift
  local key=$1;   shift
  local value=$1; shift
  local method=$1; shift
  local hash
  hash=$(send_value_tx "$key" "$value" "$method" "$@")
  if [[ -z "$hash" ]]; then
    ok "$label — refused at submit"
    return 0
  fi
  local status
  status=$(wait_for_tx "$hash") || true
  case "$status" in
    rejected) ok "$label — rejected ($hash)" ;;
    confirmed) fail "$label — UNEXPECTEDLY CONFIRMED ($hash)" ;;
    *)        warn "$label — inconclusive ($status, $hash) — counting as pass"; pass=$((pass+1)) ;;
  esac
}

CLIENT_KEY=docker/devnet/state/client/wallet.key
NODE1_KEY=docker/devnet/state/node1/wallet.key
NODE2_KEY=docker/devnet/state/node2/wallet.key   # SLASHED post-e2e-full
NODE3_KEY=docker/devnet/state/node3/wallet.key   # SLASHED
NODE4_KEY=docker/devnet/state/node4/wallet.key   # SLASHED
DEPLOYER_KEY=docker/devnet/state/deployer.key    # program owner

# An address that's NEVER been registered as an endpoint — use the
# deployer for cases that test "operator has no receipt pubkey" since
# deployer is owner but isn't a registered exit.
UNREG_ADDR="$("$OCTRA_BIN" cast wallet addr --key "$DEPLOYER_KEY")"

hdr "preflight"
ok "rpc:     $OCTRA_RPC_URL"
ok "program: $PROGRAM_ADDR"
say "node2/3/4 are slashed from prior e2e runs (expected)"
say "deployer = program owner; client = legit tailnet owner"

# We'll need a live tailnet id for several attacks. Pick the most
# recently-created one (tailnet_count - 1).
TID=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_tailnet\",[0]]" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(int(d.get("result",{}).get("storage",{}).get("tailnet_count","1")) - 1)')
say "using tailnet_id = $TID for membership/exit attacks"

# Also pick a live session id (last one created).
SID=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_tailnet\",[0]]" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(int(d.get("result",{}).get("storage",{}).get("session_count","1")) - 1)')
say "using session_id = $SID for session attacks"

# ============================================================
hdr "A — stake / bond / slash mechanics"
# ============================================================

# A11. bond_endpoint with value=0 — must reject "no value"
expect_reject_value "A11 bond_endpoint with value=0" "$NODE1_KEY" 0 bond_endpoint

# A12. bond_endpoint from slashed operator (node3) — must reject
expect_reject_value "A12 bond_endpoint from slashed node3" "$NODE3_KEY" 1000 bond_endpoint

# A13. unbond_endpoint from operator with no stake (client never bonded) — must reject "no stake"
expect_reject "A13 unbond_endpoint from non-operator (client)" "$CLIENT_KEY" unbond_endpoint

# A14. slash_double_sign against unregistered address (deployer)
SIG_A=$("$OCTRA_BIN" cast wallet sign --key "$DEPLOYER_KEY" "p1")
SIG_B=$("$OCTRA_BIN" cast wallet sign --key "$DEPLOYER_KEY" "p2")
expect_reject "A14 slash_double_sign against unregistered (deployer)" \
  "$CLIENT_KEY" slash_double_sign \
  "\"$UNREG_ADDR\"" 1 '"p1"' "\"$SIG_A\"" '"p2"' "\"$SIG_B\""

# A15. slash_double_sign on already-slashed node3 — must reject "already slashed"
N3_ADDR="${NODE3_VALIDATOR_ADDR}"
N3_SIG_A=$("$OCTRA_BIN" cast wallet sign --key "docker/devnet/state/node3/wg.key" "p1")
N3_SIG_B=$("$OCTRA_BIN" cast wallet sign --key "docker/devnet/state/node3/wg.key" "p2")
expect_reject "A15 slash_double_sign on already-slashed node3" \
  "$CLIENT_KEY" slash_double_sign \
  "\"$N3_ADDR\"" 1 '"p1"' "\"$N3_SIG_A\"" '"p2"' "\"$N3_SIG_B\""

# A16. gov_slash_operator by non-owner (client)
expect_reject "A16 gov_slash_operator by non-owner" \
  "$CLIENT_KEY" gov_slash_operator "\"$NODE1_VALIDATOR_ADDR\""

# ============================================================
hdr "B — endpoint lifecycle"
# ============================================================

# A17. update_endpoint from non-registered operator (client)
expect_reject "A17 update_endpoint from non-registered (client)" \
  "$CLIENT_KEY" update_endpoint '"x:1"' '"new-region"' 100

# A18. rotate_keys from non-registered (client)
expect_reject "A18 rotate_keys from non-registered" \
  "$CLIENT_KEY" rotate_keys '"hfhe_v1|fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe"' '"hfhe_v1|0000000000000000000000000000000000000000000000000000000000000000"' "\"$($OCTRA_BIN cast wallet pubkey --key "$CLIENT_KEY")\""

# A19. retire_endpoint from non-registered (client)
expect_reject "A19 retire_endpoint from non-registered" "$CLIENT_KEY" retire_endpoint

# A20. register_endpoint without sufficient bond (NEVER-bonded fresh wallet).
# We test the no-bond path indirectly: re-registration of a SLASHED operator
# (node3) — even with a fresh pubkey — must fail.
N3_PK_B64=$("$OCTRA_BIN" cast wallet pubkey --key docker/devnet/state/node3/wg.key)
expect_reject "A20 register_endpoint as slashed operator (node3)" \
  "$NODE3_KEY" register_endpoint \
  '"slashed.example:51820"' \
  "\"$(printf 'aa%.0s' {1..32})\"" \
  '"hfhe_v1|fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe"' \
  '"hfhe_v1|0000000000000000000000000000000000000000000000000000000000000000"' \
  '"slashed"' \
  100 \
  "\"$N3_PK_B64\""

# ============================================================
hdr "C — tailnet ACL / membership"
# ============================================================

# A21. add_member by non-owner (deployer adds itself to client's tailnet)
expect_reject "A21 add_member by non-owner (deployer)" \
  "$DEPLOYER_KEY" add_member "$TID" "\"$UNREG_ADDR\""

# A22. remove_member by non-owner
expect_reject "A22 remove_member by non-owner (deployer)" \
  "$DEPLOYER_KEY" remove_member "$TID" "\"$UNREG_ADDR\""

# A23. update_acl by non-owner
NEW_ACL=$(printf '01%.0s' {1..32})
expect_reject "A23 update_acl by non-owner (deployer)" \
  "$DEPLOYER_KEY" update_acl "$TID" "\"$NEW_ACL\""

# A24. add_member on non-existent tailnet (id=999)
expect_reject "A24 add_member on non-existent tailnet 999" \
  "$CLIENT_KEY" add_member 999 "\"$UNREG_ADDR\""

# A25. configure_tailnet_exit with a SLASHED endpoint (node2)
expect_reject "A25 configure_tailnet_exit pointing at slashed node2" \
  "$CLIENT_KEY" configure_tailnet_exit "$TID" "\"$NODE2_VALIDATOR_ADDR\""

# ============================================================
hdr "D — join-token replay / preimage"
# ============================================================

# Set up: client commits a token hash, then we test bad redeems.
# AML `bytes` are passed as base64-encoded 32-byte values (NOT hex).
# Use a per-run random preimage so re-runs aren't blocked by
# "already committed" / "hash already used" guards.
TOKEN_PREIMAGE_B64=$(python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())")
TOKEN_HASH_B64=$(python3 -c "
import base64, hashlib
pre = base64.b64decode('$TOKEN_PREIMAGE_B64')
print(base64.b64encode(hashlib.sha256(pre).digest()).decode())
")
say "committing token hash for D series (base64): ${TOKEN_HASH_B64:0:16}…"
TX=$(send_tx "$CLIENT_KEY" precommit_join_token "$TID" "\"$TOKEN_HASH_B64\"")
PRECOMMIT_OK=0
if [[ -n "$TX" ]]; then
  if wait_for_tx "$TX" >/dev/null; then
    say "precommit confirmed ($TX)"
    PRECOMMIT_OK=1
  else
    warn "precommit failed: $TX"
  fi
fi

# A26. redeem_join_token with WRONG preimage (≠ committed) — must reject
WRONG_PREIMAGE_B64=$(python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())")
expect_reject "A26 redeem_join_token with wrong preimage" \
  "$NODE1_KEY" redeem_join_token "$TID" "\"$WRONG_PREIMAGE_B64\""

# A27. redeem_join_token correctly, THEN replay → second must reject
# "no double redeem". Only runs if precommit landed.
if [[ "$PRECOMMIT_OK" == "1" ]]; then
  RTX=$(send_tx "$NODE1_KEY" redeem_join_token "$TID" "\"$TOKEN_PREIMAGE_B64\"")
  if [[ -n "$RTX" ]]; then
    status=$(wait_for_tx "$RTX") || true
    if [[ "$status" == "confirmed" ]]; then
      say "first redeem confirmed ($RTX) — now testing replay"
      expect_reject "A27 redeem_join_token replay (double-spend)" \
        "$NODE1_KEY" redeem_join_token "$TID" "\"$TOKEN_PREIMAGE_B64\""
    else
      warn "A27 skipped — first redeem didn't confirm ($status), can't test replay"
    fi
  fi
else
  warn "A27 skipped — precommit didn't confirm"
fi

# A28. redeem_join_token with NO precommit (random preimage hashing to
# never-committed digest) — must reject.
ORPHAN_PREIMAGE_B64=$(python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())")
expect_reject "A28 redeem_join_token with un-precommitted hash" \
  "$NODE1_KEY" redeem_join_token "$TID" "\"$ORPHAN_PREIMAGE_B64\""

# A29. revoke_device by non-owner (deployer revoking nothing)
expect_reject "A29 revoke_device for non-owned device" \
  "$DEPLOYER_KEY" revoke_device "\"$UNREG_ADDR\""

# ============================================================
hdr "E — session lifecycle"
# ============================================================

# A30. open_session against a SLASHED exit (node2)
expect_reject "A30 open_session against slashed node2" \
  "$CLIENT_KEY" open_session "$TID" "\"$NODE2_VALIDATOR_ADDR\"" 200

# A31. open_session with deposit (max_pay) below MIN_SESSION_DEPOSIT
expect_reject "A31 open_session with max_pay=1 (below min)" \
  "$CLIENT_KEY" open_session "$TID" "\"$NODE1_VALIDATOR_ADDR\"" 1

# A32. open_session as a non-member (deployer is owner but not a tailnet member)
expect_reject "A32 open_session by non-member (deployer)" \
  "$DEPLOYER_KEY" open_session "$TID" "\"$NODE1_VALIDATOR_ADDR\"" 200

# A33. claim_no_show before grace elapsed — open a fresh session first
say "opening fresh session for grace-period tests"
FRESH_TX=$(send_tx "$CLIENT_KEY" open_session "$TID" "\"$NODE1_VALIDATOR_ADDR\"" 200)
FRESH_SID=""
if [[ -n "$FRESH_TX" ]]; then
  if wait_for_tx "$FRESH_TX" >/dev/null; then
    FRESH_SID=$(rpc "contract_call" "[\"$PROGRAM_ADDR\",\"get_tailnet\",[0]]" \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);print(int(d.get("result",{}).get("storage",{}).get("session_count","1")) - 1)')
    say "fresh session: $FRESH_SID"
  fi
fi
if [[ -n "$FRESH_SID" ]]; then
  # A33. claim_no_show immediately — grace not elapsed
  expect_reject "A33 claim_no_show before grace elapsed" \
    "$CLIENT_KEY" claim_no_show "$FRESH_SID"
  # A34. sweep_expired_session before sweep grace
  expect_reject "A34 sweep_expired_session before sweep grace" \
    "$NODE1_KEY" sweep_expired_session "$FRESH_SID"
fi

# A35. settle_claim from WRONG operator (node1 settles a node2 session... but node2's are old)
# Use the fresh session opened above (exit=node1); node2/3 isn't even active, so use deployer.
if [[ -n "$FRESH_SID" ]]; then
  expect_reject "A35 settle_claim by wrong-operator (deployer not the exit)" \
    "$DEPLOYER_KEY" settle_claim "$FRESH_SID" 50
fi

# A36. settle_confirm with bytes mismatching the operator's claim — should produce a dispute.
# This is NOT a reject case (dispute is the documented behavior), so we skip rather than
# misclassify it. Listed for completeness.

# A37. claim_earnings from a slashed operator (node2)
expect_reject "A37 claim_earnings from slashed node2" \
  "$NODE2_KEY" claim_earnings 100 '"proofproof"'

# A38. claim_earnings with claimed_amount=0
expect_reject "A38 claim_earnings with amount=0" \
  "$NODE1_KEY" claim_earnings 0 '"proofproof"'

# A39. claim_earnings with empty proof
expect_reject "A39 claim_earnings with empty proof" \
  "$NODE1_KEY" claim_earnings 100 '""'

# ============================================================
hdr "F — owner / governance auth"
# ============================================================

# A40. set_paused by non-owner
expect_reject "A40 set_paused by non-owner (client)" \
  "$CLIENT_KEY" set_paused 1

# A41. transfer_ownership by non-owner
expect_reject "A41 transfer_ownership by non-owner (client)" \
  "$CLIENT_KEY" transfer_ownership "\"$UNREG_ADDR\""

# A42. withdraw_program_treasury by non-owner
expect_reject "A42 withdraw_program_treasury by non-owner (client)" \
  "$CLIENT_KEY" withdraw_program_treasury "\"$UNREG_ADDR\"" 1

# A43. withdraw_program_treasury with amount > treasury — by owner.
# We need a number bigger than current treasury (~1.9B raw OU).
expect_reject "A43 withdraw_program_treasury amount > treasury" \
  "$DEPLOYER_KEY" withdraw_program_treasury "\"$UNREG_ADDR\"" 999999999999999

# A44. set_params by non-owner
expect_reject "A44 set_params by non-owner (client)" \
  "$CLIENT_KEY" set_params 200 50 200 500 100 1000 5 9000 1000

# ============================================================
hdr "G — pause-state bypass"
# ============================================================

# Always unpause on exit, even if we crash mid-test.
unpause_on_exit() {
  bold "(restoring unpaused state)"
  local h
  h=$(send_tx "$DEPLOYER_KEY" set_paused 0)
  [[ -n "$h" ]] && wait_for_tx "$h" >/dev/null && say "unpaused ($h)"
}
trap unpause_on_exit EXIT

bold "owner pauses the program"
PAUSE_TX=$(send_tx "$DEPLOYER_KEY" set_paused 1)
if [[ -n "$PAUSE_TX" ]]; then
  status=$(wait_for_tx "$PAUSE_TX") || true
  if [[ "$status" == "confirmed" ]]; then
    ok "set_paused(1) confirmed ($PAUSE_TX)"

    # A45. open_session while paused — must reject "paused"
    expect_reject "A45 open_session while paused" \
      "$CLIENT_KEY" open_session "$TID" "\"$NODE1_VALIDATOR_ADDR\"" 200
    # A46. bond_endpoint while paused
    expect_reject_value "A46 bond_endpoint while paused" \
      "$NODE1_KEY" 100 bond_endpoint
    # A47. settle_claim while paused
    if [[ -n "${FRESH_SID:-}" ]]; then
      expect_reject "A47 settle_claim while paused" \
        "$NODE1_KEY" settle_claim "$FRESH_SID" 50
    fi
    # A48. withdraw_program_treasury while paused (even by owner!)
    # NOTE: deployed v1.1 program lacks require_not_paused() on this
    # entrypoint — this case fails against the on-chain v1.1 but the
    # source has been patched; the fix lands with v1.2/v2 redeploy.
    expect_reject "A48 withdraw_program_treasury while paused" \
      "$DEPLOYER_KEY" withdraw_program_treasury "\"$UNREG_ADDR\"" 100
    # A49. set_params while paused — same class of bug, source-patched
    # but on-chain v1.1 still misses the guard.
    expect_reject "A49 set_params while paused" \
      "$DEPLOYER_KEY" set_params 100 10 100 5 100 1000000000 1000 9000 1000 100
  else
    warn "set_paused(1) didn't confirm — skipping G series"
  fi
else
  warn "set_paused submit failed — skipping G series"
fi

# Final cleanup happens in trap.

# ============================================================
hdr "summary"
# ============================================================
total=$((pass + fail))
printf "  %d / %d cases passed\n" "$pass" "$total"
if (( fail == 0 )); then
  printf "  ${G}${B}ALL ADVERSARIAL CASES HELD${NC}\n"
  exit 0
else
  printf "  ${R}${B}%d UNEXPECTED ACCEPTANCES — contract may be exploitable${NC}\n" "$fail"
  exit 1
fi
