#!/usr/bin/env bash
# relay-outbox-probe.sh — DECISIVE go/no-go probe for P2.1 (native relay rail).
#
# Question it answers:
#   Does the Octra chain EXECUTE the native relay ops, or are they
#   unknown / passive-storage no-ops?  Specifically:
#     (a) does `circle_outbox_open` commit against the operator circle, and
#     (b) does `relay_claim` verify sha256(preimage) == committed_hash
#         ON-CHAIN?
#
# Decision:
#   PASS  (both ops CONFIRMED, claim verifies)  -> build the native relay rail.
#   FAIL/FALLBACK (UNKNOWN_OP / BYTECODE_NOT_FOUND) -> relay rides the AML
#         fallback (a `contract_call` method on main-v3), not a native op.
#   REVERTED (op recognized, claim refused)     -> rail EXISTS but our
#         message shape or the sha256 binding is wrong; needs a follow-up
#         with the exact webcli field names before deciding.
#
# HONESTY / WHAT IS UNPROVEN:
#   * Native relay-op EXECUTION on devnet is UNCONFIRMED. This script is a
#     PROBE, not a demo — it never assumes success and prints the raw chain
#     response for every step.
#   * The op_type strings (`circle_outbox_open`, `relay_claim`) are the
#     documented Octra webcli op_types, but the `message` FIELD NAMES below
#     are BEST-EFFORT and UNVERIFIED against the webcli reference. If a step
#     REVERTS, read the reason: a *param/shape* revert still proves the op
#     is recognized (a positive signal for P2.1); an UNKNOWN_OP verdict is
#     the negative signal.
#   * We compute sha256(preimage) LOCALLY and print it, so a human can
#     confirm the commitment is well-formed regardless of chain support.
#
# Usage:
#   docker/devnet/experiments/relay-outbox-probe.sh
# Env overrides:
#   OCTRA_BIN, OCTRA_RPC_URL, RELAY_KEY (signer key file), OPCIRCLE (circle id)
#
# Exit code: 0 when the probe reached a DECISIVE conclusion (PASS or
# FALLBACK/FAIL are both valid answers to the go/no-go question);
# nonzero only when the probe is INCONCLUSIVE (tooling/bad-sig/timeout).

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=/dev/null
source "$HERE/_oplib.sh"

# Reuse the demo operator circle by default (same id v3-smoke.sh uses).
# Any circle owned by $RELAY_KEY works; the demo devnet circle is
# octEY88M…3b (see MEMORY demo_devnet_circle) — override OPCIRCLE for it.
OPCIRCLE="${OPCIRCLE:-oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun}"
RELAY_KEY="${RELAY_KEY:-$ROOT/docker/devnet/state/deployer.key}"

hdr()  { printf "\n=== %s ===\n" "$1"; }
line() { printf "  %s\n" "$1"; }

echo "relay-outbox-probe — P2.1 native relay rail go/no-go"
echo "  RPC=$OCTRA_RPC_URL"
echo "  circle=$OPCIRCLE"

hdr "preflight"
if ! oplib_preflight; then
  echo
  echo "VERDICT: INCONCLUSIVE (environment not ready)"
  exit 2
fi
[[ -f "$RELAY_KEY" ]] || { echo "  ! signer key not found: $RELAY_KEY"; echo; echo "VERDICT: INCONCLUSIVE (no key)"; exit 2; }
line "signer=$(wallet_addr "$RELAY_KEY")  key=$RELAY_KEY"
line "octra=$OCTRA_BIN"

# ── commitment ────────────────────────────────────────────────────────
# preimage is 32 random bytes (hex); committed hash H = sha256(preimage).
PREIMAGE_HEX="$(python3 -c 'import os;print(os.urandom(32).hex())')"
COMMIT_HASH="$("$OCTRA_BIN" cast sha256 "$PREIMAGE_HEX" 2>/dev/null)"
# Fall back to python if the cast helper output isn't a bare hash.
if ! printf '%s' "$COMMIT_HASH" | grep -qiE '^[0-9a-f]{64}$'; then
  COMMIT_HASH="$(python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex('$PREIMAGE_HEX')).hexdigest())")"
fi
hdr "commitment (computed locally)"
line "preimage = ${PREIMAGE_HEX}"
line "H = sha256(preimage) = ${COMMIT_HASH}"

# ── step 1: circle_outbox_open ────────────────────────────────────────
# BEST-EFFORT message shape (UNVERIFIED webcli field names):
#   { commit, ttl_epochs, max_claim }
hdr "1. circle_outbox_open  (op_type=circle_outbox_open, to_=circle)"
OB_MSG="$(python3 -c "import json;print(json.dumps({'commit':'$COMMIT_HASH','ttl_epochs':64,'max_claim':1000},separators=(',',':')))")"
submit_op "$RELAY_KEY" circle_outbox_open "$OPCIRCLE" 0 1000 "$OB_MSG"
line "submit: $(printf '%s' "$OP_RESPONSE" | head -c 400)"
if [[ -n "$OP_TXHASH" ]]; then
  line "tx_hash=$OP_TXHASH — waiting for terminal status…"
  OB_STATUS="$(wait_status "$OP_TXHASH")"
else
  OB_STATUS="rejected|${OP_SUBMIT_REASON}"
fi
OB_VERDICT="$(classify_verdict "${OB_STATUS%%|*}" "${OB_STATUS#*|}")"
line "status=${OB_STATUS%%|*}  reason=${OB_STATUS#*|}"
line "-> ${OB_VERDICT}"

# ── step 2: relay_claim (present preimage; chain must verify sha256) ───
# BEST-EFFORT message shape (UNVERIFIED): { commit, preimage }
hdr "2. relay_claim  (present preimage; expect on-chain sha256(preimage)==H)"
RC_MSG="$(python3 -c "import json;print(json.dumps({'commit':'$COMMIT_HASH','preimage':'$PREIMAGE_HEX'},separators=(',',':')))")"
submit_op "$RELAY_KEY" relay_claim "$OPCIRCLE" 0 1000 "$RC_MSG"
line "submit: $(printf '%s' "$OP_RESPONSE" | head -c 400)"
if [[ -n "$OP_TXHASH" ]]; then
  line "tx_hash=$OP_TXHASH — waiting for terminal status…"
  RC_STATUS="$(wait_status "$OP_TXHASH")"
else
  RC_STATUS="rejected|${OP_SUBMIT_REASON}"
fi
RC_VERDICT="$(classify_verdict "${RC_STATUS%%|*}" "${RC_STATUS#*|}")"
line "status=${RC_STATUS%%|*}  reason=${RC_STATUS#*|}"
line "-> ${RC_VERDICT}"

# ── verdict ───────────────────────────────────────────────────────────
hdr "VERDICT — P2.1 native relay rail"
rc=0
if [[ "$OB_VERDICT" == CONFIRMED && "$RC_VERDICT" == CONFIRMED ]]; then
  echo "VERDICT: PASS — native relay rail EXECUTES on-chain."
  echo "  circle_outbox_open committed AND relay_claim confirmed (sha256 verified on-chain)."
  echo "  DECISION: build P2.1 on the native rail."
elif [[ "$OB_VERDICT" == TOOLING_BADSIG || "$RC_VERDICT" == TOOLING_BADSIG || \
        "$OB_VERDICT" == TIMEOUT || "$RC_VERDICT" == TIMEOUT || \
        "$OB_VERDICT" == NO_TXHASH || "$RC_VERDICT" == NO_TXHASH ]]; then
  echo "VERDICT: INCONCLUSIVE — tooling/signing/timeout, NOT a chain answer."
  echo "  Re-run after fixing the flagged step; do NOT treat this as FALLBACK."
  rc=2
elif [[ "$OB_VERDICT" == UNKNOWN_OP || "$OB_VERDICT" == BYTECODE_NOT_FOUND || \
        "$RC_VERDICT" == UNKNOWN_OP || "$RC_VERDICT" == BYTECODE_NOT_FOUND ]]; then
  echo "VERDICT: FAIL/FALLBACK — chain does NOT execute native relay ops"
  echo "  (${OB_VERDICT} / ${RC_VERDICT})."
  echo "  DECISION: implement P2.1 relay as an AML contract_call method on main-v3,"
  echo "  not a native op_type."
else
  echo "VERDICT: REVERTED — an op was RECOGNIZED but refused"
  echo "  (open=${OB_VERDICT}, claim=${RC_VERDICT})."
  echo "  The native rail likely EXISTS; our message field names are best-effort"
  echo "  (UNVERIFIED against webcli). Follow up with the exact webcli schema"
  echo "  before finalizing P2.1. Not a clean PASS, not a clean FALLBACK."
fi
echo
echo "open=${OB_VERDICT}  claim=${RC_VERDICT}"
exit "$rc"
