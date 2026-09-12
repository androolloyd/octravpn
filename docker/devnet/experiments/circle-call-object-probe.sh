#!/usr/bin/env bash
# circle-call-object-probe.sh — DECISIVE go/no-go probe for P2.2
# (chain-enforced enrollment via native `circle_call` object ops).
#
# The 6-step native object probe:
#   1. bind_object_native            — create an object bound to the circle
#   2. define_object_policy_native   — set the allowlist policy on it
#   3. attach_object_member_native   — attach an ALLOWLISTED wallet (expect OK)
#   4. attach_object_member_native   — attach a NON-allowlisted wallet
#                                      ***THIS MUST REVERT***  <- decisive
#   5. detach_object_member_native   — detach the allowlisted wallet
#   6. circle_object_members (RPC)   — read back the membership set
#
# THE decisive assertion is STEP 4. If the chain ENFORCES the policy, an
# attach of a wallet outside the allowlist is REVERTED on-chain. That is
# the whole point of P2.2: enrollment is enforced by the chain, not by an
# off-chain daemon that can be bypassed.
#   * Step 4 REVERTED  -> PASS: chain enforces enrollment (P2.2 viable natively).
#   * Step 4 CONFIRMED -> FAIL: chain accepted a non-allowlisted member ==
#                         no enforcement == a real security hole; P2.2 cannot
#                         ride the native rail as-is.
#   * Step 4 UNKNOWN_OP / BYTECODE_NOT_FOUND -> FALLBACK: circle_call object
#                         ops are not executable on devnet; enforce enrollment
#                         in the AML `contract_call` layer instead.
#
# HONESTY / WHAT IS UNPROVEN:
#   * Native `circle_call` sub-method EXECUTION on devnet is UNCONFIRMED.
#     This is a PROBE. It never assumes success; every step prints the raw
#     chain response and a per-step verdict.
#   * op_type=`circle_call` with a `message` carrying `{"method": <submethod>}`
#     is the documented shape, but the ARG field names inside each
#     sub-method message are BEST-EFFORT and UNVERIFIED against the webcli
#     reference. A param-shape REVERT on steps 1-3 still proves the op is
#     recognized; only UNKNOWN_OP/BYTECODE_NOT_FOUND is the negative signal.
#
# Usage:
#   docker/devnet/experiments/circle-call-object-probe.sh
# Env overrides:
#   OCTRA_BIN, OCTRA_RPC_URL, OWNER_KEY (circle owner/signer), OPCIRCLE
#
# Exit code: 0 on a DECISIVE result (PASS or FALLBACK/FAIL); nonzero only
# when INCONCLUSIVE (tooling/bad-sig/timeout).

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=/dev/null
source "$HERE/_oplib.sh"

OPCIRCLE="${OPCIRCLE:-oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun}"
OWNER_KEY="${OWNER_KEY:-$ROOT/docker/devnet/state/deployer.key}"
OBJ_ID="${OBJ_ID:-obj-enroll-$(date +%s)}"    # unique per run to avoid clashes

hdr()  { printf "\n=== %s ===\n" "$1"; }
line() { printf "  %s\n" "$1"; }

# run_step SUBMETHOD MESSAGE -> sets STEP_VERDICT + STEP_STATUS globals.
run_step() {
  local submethod="$1" msg="$2"
  submit_op "$OWNER_KEY" circle_call "$OPCIRCLE" 0 1000 "$msg"
  line "submit: $(printf '%s' "$OP_RESPONSE" | head -c 400)"
  if [[ -n "$OP_TXHASH" ]]; then
    line "tx_hash=$OP_TXHASH — waiting…"
    STEP_STATUS="$(wait_status "$OP_TXHASH")"
  else
    STEP_STATUS="rejected|${OP_SUBMIT_REASON}"
  fi
  STEP_VERDICT="$(classify_verdict "${STEP_STATUS%%|*}" "${STEP_STATUS#*|}")"
  line "status=${STEP_STATUS%%|*}  reason=${STEP_STATUS#*|}"
  line "-> ${STEP_VERDICT}"
}
mkmsg() { # mkmsg method key1 val1 [key2 val2 ...] -> compact JSON message
  python3 -c '
import json,sys
m={"method":sys.argv[1]}
it=iter(sys.argv[2:])
for k in it: m[k]=next(it)
print(json.dumps(m,separators=(",",":")))
' "$@"
}

echo "circle-call-object-probe — P2.2 chain-enforced enrollment go/no-go"
echo "  RPC=$OCTRA_RPC_URL"
echo "  circle=$OPCIRCLE"
echo "  object=$OBJ_ID"

hdr "preflight"
if ! oplib_preflight; then echo; echo "VERDICT: INCONCLUSIVE (environment not ready)"; exit 2; fi
[[ -f "$OWNER_KEY" ]] || { echo "  ! owner key not found: $OWNER_KEY"; echo; echo "VERDICT: INCONCLUSIVE (no key)"; exit 2; }
OWNER_ADDR="$(wallet_addr "$OWNER_KEY")"
line "owner/signer=$OWNER_ADDR"

# Allowlisted member = the owner itself (guaranteed to exist).
ALLOWED_ADDR="$OWNER_ADDR"
# Non-allowlisted member = a freshly generated wallet address (never in
# any policy). We only need its ADDRESS, not to fund or sign with it.
TMP_KEY="$(mktemp -t probe-outsider.XXXXXX)"
"$OCTRA_BIN" cast wallet new --out "$TMP_KEY" >/dev/null 2>&1
OUTSIDER_ADDR="$(wallet_addr "$TMP_KEY" 2>/dev/null)"
rm -f "$TMP_KEY"
[[ -n "$OUTSIDER_ADDR" ]] || { echo "  ! could not derive an outsider address"; echo; echo "VERDICT: INCONCLUSIVE (tooling)"; exit 2; }
line "allowlisted member = $ALLOWED_ADDR"
line "outsider  (must be rejected in step 4) = $OUTSIDER_ADDR"

# ── step 1 ────────────────────────────────────────────────────────────
hdr "1. bind_object_native  (create object bound to circle)"
run_step bind_object_native "$(mkmsg bind_object_native object_id "$OBJ_ID" kind enrollment)"
V1="$STEP_VERDICT"

# ── step 2 ────────────────────────────────────────────────────────────
hdr "2. define_object_policy_native  (allowlist = [owner])"
POLICY_MSG="$(python3 -c "import json;print(json.dumps({'method':'define_object_policy_native','object_id':'$OBJ_ID','policy':{'allow':['$ALLOWED_ADDR'],'mode':'allowlist'}},separators=(',',':')))")"
run_step define_object_policy_native "$POLICY_MSG"
V2="$STEP_VERDICT"

# ── step 3 (allowed) ──────────────────────────────────────────────────
hdr "3. attach_object_member_native  (ALLOWLISTED wallet — expect OK)"
run_step attach_object_member_native "$(mkmsg attach_object_member_native object_id "$OBJ_ID" member "$ALLOWED_ADDR")"
V3="$STEP_VERDICT"
S3="$STEP_STATUS"

# ── step 4 (THE decisive assertion: expect REVERT) ────────────────────
hdr "4. attach_object_member_native  (NON-allowlisted wallet — MUST REVERT)"
line "expectation: the chain REJECTS this because $OUTSIDER_ADDR is not in the allowlist."
run_step attach_object_member_native "$(mkmsg attach_object_member_native object_id "$OBJ_ID" member "$OUTSIDER_ADDR")"
V4="$STEP_VERDICT"
S4="$STEP_STATUS"

# ── step 5 (detach) ───────────────────────────────────────────────────
hdr "5. detach_object_member_native  (detach the allowlisted wallet)"
run_step detach_object_member_native "$(mkmsg detach_object_member_native object_id "$OBJ_ID" member "$ALLOWED_ADDR")"
V5="$STEP_VERDICT"

# ── step 6 (read back) ────────────────────────────────────────────────
hdr "6. circle_object_members (RPC read-back)"
MEMBERS_RESP="$(rpc circle_object_members "[\"$OPCIRCLE\",\"$OBJ_ID\"]")"
line "circle_object_members => $(printf '%s' "$MEMBERS_RESP" | head -c 400)"
MEMBERS_HAS_OUTSIDER="no"
printf '%s' "$MEMBERS_RESP" | grep -q "$OUTSIDER_ADDR" && MEMBERS_HAS_OUTSIDER="YES"
line "outsider present in membership set? ${MEMBERS_HAS_OUTSIDER}"

# ── verdict ───────────────────────────────────────────────────────────
hdr "VERDICT — P2.2 chain-enforced enrollment (decided by STEP 4)"
echo "  step1 bind=${V1}  step2 policy=${V2}  step3 attach-allowed=${V3}"
echo "  step4 attach-outsider=${V4}  step5 detach=${V5}"
rc=0
case "$V4" in
  REVERTED)
    echo "VERDICT: PASS — the chain REVERTED the non-allowlisted attach (step 4)."
    echo "  Enrollment is enforced ON-CHAIN. DECISION: P2.2 can ride the native rail."
    if [[ "$MEMBERS_HAS_OUTSIDER" == YES ]]; then
      echo "  WARNING: but circle_object_members STILL lists the outsider — the revert"
      echo "  did not roll back membership. Treat as PARTIAL; investigate before shipping."
      rc=1
    fi
    ;;
  CONFIRMED)
    echo "VERDICT: FAIL — the chain ACCEPTED a non-allowlisted member (step 4 CONFIRMED)."
    echo "  There is NO on-chain enrollment enforcement: this is a security hole."
    echo "  DECISION: do NOT rely on the native rail for P2.2 as-is."
    rc=1
    ;;
  UNKNOWN_OP|BYTECODE_NOT_FOUND)
    echo "VERDICT: FALLBACK — circle_call object ops are not executable on devnet (${V4})."
    echo "  DECISION: enforce enrollment in the AML contract_call layer, not native ops."
    ;;
  TOOLING_BADSIG|TIMEOUT|NO_TXHASH)
    echo "VERDICT: INCONCLUSIVE — step 4 hit ${V4} (tooling/timeout, NOT a chain answer)."
    echo "  Re-run after fixing; do NOT record a P2.2 decision from this run."
    rc=2
    ;;
  *)
    echo "VERDICT: INCONCLUSIVE — step 4 => ${V4}. Inspect the raw response above."
    rc=2
    ;;
esac
echo
echo "step4=${V4}  (status=${S4%%|*}, reason=${S4#*|})"
echo "step3=${V3}  (status=${S3%%|*})"
exit "$rc"
