#!/usr/bin/env bash
# credit-token-redeploy-smoke.sh — DECISIVE go/no-go probe for P1.2
# (an enlarged main-v3-class AML still compiles AND executes on-chain).
#
# What it proves:
#   Deploy a bigger main-v3-class program that carries an added OCS01-style
#   credit surface, then drive:
#       mint_credit  ->  transfer_credit  ->  balance_of
#   and confirm the balances move exactly as the AML says. If a program of
#   this class compiles with the foundry AML compiler AND the credit path
#   executes + settles on devnet, P1.2 is a GO.
#
# Source AML (override with CREDIT_AML):
#   Default: program/main-v3-credit.draft.aml  — the P1.2 splice candidate
#   (constructor(); payable mint_credit(); transfer_credit(to,amount);
#    view balance_of(holder)). This is the credit-carrying main-v3-class
#    contract. The *true* enlarged target is a full main-v3 + credit splice;
#    deploying this draft proves the load-bearing risk — that the added
#    credit surface compiles and executes — which is what P1.2 hinges on.
#   If the draft is absent, the AML-dependent steps are STUBBED with a
#   printed TODO and the probe exits INCONCLUSIVE (never a false PASS).
#
# HONESTY / WHAT IS UNPROVEN:
#   * This exercises the PROVEN AML feature set (map[address]uint, payable/
#     value, transfer(), nonreentrant, require/emit) — no fhe_* host calls
#     (those revert on devnet; see MEMORY octra_aml_fhe_load_pk_blocked).
#   * A compile failure or a rejected exec is a real FAIL (exit 1), not a
#     tooling hiccup. Env/AML-missing problems exit 2 (INCONCLUSIVE).
#
# Usage:
#   docker/devnet/experiments/credit-token-redeploy-smoke.sh
# Env overrides:
#   OCTRA_BIN, OCTRA_RPC_URL, DEPLOYER_KEY, CREDIT_AML, MINT_OU, XFER_OU
#
# Exit: 0 PASS · 1 FAIL (compile/exec) · 2 INCONCLUSIVE (env/AML missing)

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"

OCTRA_BIN="${OCTRA_BIN:-$ROOT/../octra-foundry/target/release/octra}"
OCTRA_RPC_URL="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"
DEPLOYER_KEY="${DEPLOYER_KEY:-$ROOT/docker/devnet/state/deployer.key}"
CREDIT_AML="${CREDIT_AML:-$ROOT/program/main-v3-credit.draft.aml}"
MINT_OU="${MINT_OU:-5000}"     # OCT attached to mint_credit (== units minted)
XFER_OU="${XFER_OU:-2000}"     # credit units to transfer

hdr()  { printf "\n=== %s ===\n" "$1"; }
ok()   { printf "  + %s\n" "$1"; }
fail() { printf "  ! %s\n" "$1"; }

rpc() {
  curl -s -m 12 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}

# Wait for a tx hash to reach a terminal state. Prints "confirmed" | "rejected(reason)" | "timeout".
wait_tx() {
  local hash="$1"
  [[ -z "$hash" ]] && { echo "no_hash"; return; }
  local i out st
  for i in $(seq 1 12); do
    sleep 3
    out=$(rpc octra_transaction "[\"$hash\"]" | python3 -c '
import json,sys
try: r=json.load(sys.stdin).get("result") or {}
except Exception: r={}
st=r.get("status","?"); e=r.get("error"); rs=""
if isinstance(e,dict): rs=e.get("reason") or e.get("message") or ""
elif isinstance(e,str): rs=e
print(st+"|"+str(rs))
' 2>/dev/null)
    st="${out%%|*}"
    case "$st" in
      confirmed) echo "confirmed"; return;;
      rejected|failed|reverted) echo "rejected(${out#*|})"; return;;
    esac
  done
  echo "timeout"
}

# cast send returning the tx_hash (empty on submit refusal).
send() {
  local value="$1"; shift; local method="$1"; shift
  "$OCTRA_BIN" cast send --key "$DEPLOYER_KEY" --rpc-url "$OCTRA_RPC_URL" \
    --value "$value" --fee 1000 "$V3C" "$method" "$@" 2>&1 \
    | python3 -c 'import sys,re;t=sys.stdin.read();m=re.search(r"\"(?:tx_)?hash\":\s*\"([0-9a-fA-Fx]+)\"",t);print(m.group(1) if m else "")'
}

# balance_of(holder) via read-only contract_call. Prints the integer or "".
balance_of() {
  rpc contract_call "[\"$V3C\",\"balance_of\",[\"$1\"]]" | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin); r=d.get("result")
    if isinstance(r,dict): r=r.get("result")
    print(r if r is not None else "")
except Exception: print("")
'
}

echo "credit-token-redeploy-smoke — P1.2 (enlarged AML compiles + executes) go/no-go"
echo "  RPC=$OCTRA_RPC_URL"
echo "  AML=$CREDIT_AML"

# ── preflight ─────────────────────────────────────────────────────────
hdr "preflight"
miss=0
command -v curl    >/dev/null || { fail "curl missing"; miss=1; }
command -v python3 >/dev/null || { fail "python3 missing"; miss=1; }
[[ -x "$OCTRA_BIN" ]] || { fail "octra binary not found/executable: $OCTRA_BIN  (build: cd ../octra-foundry && cargo build --release -p octra-cli)"; miss=1; }
[[ -f "$DEPLOYER_KEY" ]] || { fail "deployer key not found: $DEPLOYER_KEY"; miss=1; }
if [[ "$miss" -eq 0 ]] && ! rpc node_status "[]" | python3 -c 'import json,sys;json.load(sys.stdin)' >/dev/null 2>&1; then
  fail "RPC did not answer node_status — is the harness up?"; miss=1
fi
if [[ "$miss" -ne 0 ]]; then echo; echo "VERDICT: INCONCLUSIVE (environment not ready)"; exit 2; fi

if [[ ! -f "$CREDIT_AML" ]]; then
  hdr "AML source MISSING — stubbing the credit path"
  cat <<TODO
  ! $CREDIT_AML not found.
  ! TODO(P1.2): provide the enlarged main-v3-class AML (main-v3 spliced with
    the OCS01 credit surface) at CREDIT_AML, then the steps below run for real:
        1) octra forge create <AML>            # compile + deploy
        2) octra cast send --value $MINT_OU <addr> mint_credit
        3) octra cast send <addr> transfer_credit <recipient> $XFER_OU
        4) contract_call balance_of(<holder>)  # assert balances moved
  ! Without the AML this probe cannot prove P1.2. Not asserting PASS.
TODO
  echo; echo "VERDICT: INCONCLUSIVE (AML source absent — see TODO above)"; exit 2
fi

DEPLOYER_ADDR="$("$OCTRA_BIN" cast wallet addr --key "$DEPLOYER_KEY")"
ok "deployer=$DEPLOYER_ADDR"
# Fresh recipient (needs no funds; transfer_credit requires to != caller).
RCPT_KEY="$(mktemp -t credit-rcpt.XXXXXX)"
"$OCTRA_BIN" cast wallet new --out "$RCPT_KEY" >/dev/null 2>&1
RECIPIENT_ADDR="$("$OCTRA_BIN" cast wallet addr --key "$RCPT_KEY" 2>/dev/null)"
rm -f "$RCPT_KEY"
[[ -n "$RECIPIENT_ADDR" ]] || { fail "could not derive recipient address"; echo; echo "VERDICT: INCONCLUSIVE (tooling)"; exit 2; }
ok "recipient=$RECIPIENT_ADDR"

# ── 1. compile + deploy ───────────────────────────────────────────────
hdr "1. forge create (compile + deploy the enlarged program)"
CREATE_OUT="$("$OCTRA_BIN" forge create "$CREDIT_AML" --key "$DEPLOYER_KEY" --rpc-url "$OCTRA_RPC_URL" 2>&1)"
V3C="$(printf '%s' "$CREATE_OUT" | python3 -c 'import json,sys,re
t=sys.stdin.read()
try: print(json.loads(t).get("address",""))
except Exception:
    m=re.search(r"\"address\":\s*\"([^\"]+)\"",t); print(m.group(1) if m else "")')"
DEPLOY_HASH="$(printf '%s' "$CREATE_OUT" | python3 -c 'import json,sys,re
t=sys.stdin.read()
try: print(json.loads(t).get("tx_hash",""))
except Exception:
    m=re.search(r"\"tx_hash\":\s*\"([^\"]*)\"",t); print(m.group(1) if m else "")')"
if [[ -z "$V3C" ]]; then
  fail "compile/deploy FAILED — no address returned. Raw output:"
  printf '%s\n' "$CREATE_OUT" | sed 's/^/    /' | head -30
  echo; echo "VERDICT: FAIL — the enlarged AML did not compile+deploy (P1.2 NO-GO)"; exit 1
fi
ok "deployed @ $V3C"
if [[ -n "$DEPLOY_HASH" ]]; then
  st="$(wait_tx "$DEPLOY_HASH")"
  [[ "$st" == confirmed ]] && ok "deploy confirmed ($DEPLOY_HASH)" || { fail "deploy not confirmed: $st"; echo; echo "VERDICT: FAIL — deploy did not confirm (P1.2 NO-GO)"; exit 1; }
else
  ok "no deploy tx_hash surfaced; pausing for inclusion"; sleep 18
fi

# ── 2. mint_credit (payable) ──────────────────────────────────────────
hdr "2. mint_credit  (attach ${MINT_OU} OU -> ${MINT_OU} credit units to deployer)"
H="$(send "$MINT_OU" mint_credit)"
if [[ -z "$H" ]]; then fail "mint_credit refused at submit"; echo; echo "VERDICT: FAIL — mint_credit not accepted (P1.2 NO-GO)"; exit 1; fi
st="$(wait_tx "$H")"
[[ "$st" == confirmed ]] || { fail "mint_credit $st"; echo; echo "VERDICT: FAIL — mint_credit did not confirm (P1.2 NO-GO)"; exit 1; }
ok "mint_credit confirmed ($H)"
BAL="$(balance_of "$DEPLOYER_ADDR")"
if [[ "$BAL" == "$MINT_OU" ]]; then ok "balance_of(deployer) == $BAL"; else
  fail "balance_of(deployer)=$BAL, expected $MINT_OU"; echo; echo "VERDICT: FAIL — mint did not credit correctly (P1.2 NO-GO)"; exit 1
fi

# ── 3. transfer_credit ────────────────────────────────────────────────
hdr "3. transfer_credit  (deployer -> recipient, ${XFER_OU} units)"
H="$(send 0 transfer_credit "$RECIPIENT_ADDR" "$XFER_OU")"
if [[ -z "$H" ]]; then fail "transfer_credit refused at submit"; echo; echo "VERDICT: FAIL — transfer_credit not accepted (P1.2 NO-GO)"; exit 1; fi
st="$(wait_tx "$H")"
[[ "$st" == confirmed ]] || { fail "transfer_credit $st"; echo; echo "VERDICT: FAIL — transfer_credit did not confirm (P1.2 NO-GO)"; exit 1; }
ok "transfer_credit confirmed ($H)"

# ── 4. balance_of confirm (both sides) ────────────────────────────────
hdr "4. balance_of confirm"
RB="$(balance_of "$RECIPIENT_ADDR")"
DB="$(balance_of "$DEPLOYER_ADDR")"
EXPECT_D=$(( MINT_OU - XFER_OU ))
okall=1
if [[ "$RB" == "$XFER_OU" ]]; then ok "balance_of(recipient) == $RB"; else fail "balance_of(recipient)=$RB, expected $XFER_OU"; okall=0; fi
if [[ "$DB" == "$EXPECT_D" ]]; then ok "balance_of(deployer)  == $DB"; else fail "balance_of(deployer)=$DB, expected $EXPECT_D"; okall=0; fi

hdr "VERDICT — P1.2 enlarged AML compiles + executes"
if [[ "$okall" -eq 1 ]]; then
  echo "VERDICT: PASS — enlarged main-v3-class program compiled, deployed, and the"
  echo "  mint -> transfer -> balance credit path executed + settled on-chain."
  echo "  DECISION: P1.2 is a GO for a program of this class @ $V3C."
  exit 0
else
  echo "VERDICT: FAIL — balances did not move as the AML specifies (P1.2 NO-GO)."
  echo "  Program @ $V3C compiled+deployed but the credit path did not settle correctly."
  exit 1
fi
