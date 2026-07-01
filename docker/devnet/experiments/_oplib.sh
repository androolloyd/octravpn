# _oplib.sh — shared helper for the native-op devnet probes.
#
# NOT a standalone script: `source` this from relay-outbox-probe.sh and
# circle-call-object-probe.sh. It knows how to build, SIGN, and SUBMIT an
# arbitrary Octra `op_type` transaction envelope, then classify the
# chain's response into a decisive verdict token.
#
# ── Why this exists ────────────────────────────────────────────────────
# The foundry `octra` CLI has dedicated builders for exactly three
# op_types: `deploy_circle`, `circle_asset_put`, `circle_asset_put_encrypted`
# (see octra-foundry crates/octra-cli/src/cast/circle.rs) plus the AML
# `contract_call` path (`cast send`). It has NO builder for the native
# relay / object ops we are probing (`circle_outbox_open`, `relay_claim`,
# `relay_cancel`, `ingress_commit`, `circle_call`). So we hand-build the
# envelope here.
#
# ── How signing stays honest (no reimplemented crypto) ─────────────────
# The bytes a wallet signs are `OctraTx::to_canonical_json()` — a fixed
# insertion-order JSON string (octra-foundry crates/octra-core/src/tx.rs):
#
#   {"from":"..","to_":"..","amount":"<int>","nonce":<int>,"ou":"<int>",
#    "timestamp":<float>,"op_type":".."[,"encrypted_data":".."][,"message":".."]}
#
# We reconstruct that exact string in Python, then hand it to
# `octra cast wallet sign` (real ed25519 over the UTF-8 bytes) — we never
# re-implement the signature. We use an INTEGER `timestamp` (epoch
# seconds) on purpose: Rust's f64 `Display` prints an integral float
# WITHOUT a trailing `.0` (e.g. `1717000000`), and a JSON integer
# deserializes into the tx's `f64 timestamp` and re-serializes to the
# same string — so the bytes we sign are byte-identical to the bytes the
# chain recomputes in `verify_envelope_signature`. This sidesteps the one
# real footgun (float formatting divergence between Python and Rust).
#
# If the signature were ever wrong, the chain rejects with a signature
# error BEFORE dispatching on op_type — which would masquerade as
# "op unsupported". `classify_verdict` detects that case explicitly and
# returns TOOLING_BADSIG so a probe can never turn a signing bug into a
# false negative.
#
# Requires (same contract as docker/devnet/v3-smoke.sh):
#   * pre-built `octra` binary at $OCTRA_BIN (default:
#     ../octra-foundry/target/release/octra) — this lib does NOT build it.
#   * curl, python3 on PATH.
#   * $OCTRA_RPC_URL (default devnet).

# shellcheck shell=bash

OCTRA_BIN="${OCTRA_BIN:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." 2>/dev/null && pwd)/../octra-foundry/target/release/octra}"
OCTRA_RPC_URL="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"

# Globals published by submit_op (initialized so `set -u` never trips).
OP_RESPONSE=""       # raw octra_submit response JSON
OP_TXHASH=""         # extracted tx hash ("" if the submit itself errored)
OP_SUBMIT_REASON=""  # submit-time error/reason ("" when a tx hash came back)

# ── low-level JSON-RPC ────────────────────────────────────────────────
rpc() {
  # rpc <method> <params-json>
  curl -s -m 12 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}

oplib_preflight() {
  local missing=0
  command -v curl    >/dev/null || { echo "  ! curl not on PATH"; missing=1; }
  command -v python3 >/dev/null || { echo "  ! python3 not on PATH"; missing=1; }
  if [[ ! -x "$OCTRA_BIN" ]]; then
    echo "  ! octra binary not found/executable at: $OCTRA_BIN"
    echo "    build it first:  (cd ../octra-foundry && cargo build --release -p octra-cli)"
    echo "    or point OCTRA_BIN at your binary. This probe does NOT build it."
    missing=1
  fi
  if [[ "$missing" -eq 0 ]]; then
    # Liveness ping — a probe against a dead RPC is inconclusive, not a fail.
    if ! rpc node_status "[]" | python3 -c 'import json,sys;json.load(sys.stdin)' >/dev/null 2>&1; then
      echo "  ! RPC $OCTRA_RPC_URL did not answer node_status — is the harness up?"
      missing=1
    fi
  fi
  return "$missing"
}

wallet_addr() { "$OCTRA_BIN" cast wallet addr --key "$1"; }

# next_nonce KEY -> confirmed on-chain nonce + 1.
# Fetch fresh before every op; only call after the previous op has reached
# a terminal (confirmed/rejected) state, so the confirmed nonce is stable.
next_nonce() {
  local addr; addr=$(wallet_addr "$1")
  rpc octra_balance "[\"$addr\"]" | python3 -c '
import json,sys
try:
    r = json.load(sys.stdin).get("result") or {}
    print(int(r.get("nonce", 0) or 0) + 1)
except Exception:
    print(1)
'
}

# Build the canonical signing string for an op envelope, EXACTLY matching
# OctraTx::to_canonical_json (octra-core/src/tx.rs). Optional fields
# (encrypted_data, message) appear only when non-empty, in that order.
# Prints the canonical string on one line.
_oplib_canonical() {
  FROM="$1" TO="$2" AMOUNT="$3" NONCE="$4" OU="$5" TS="$6" OPTYPE="$7" ED="$8" MSG="$9" \
  python3 - <<'PY'
import os
def esc(s):  # port of push_json_str: escape ", \, control chars; pass ASCII/UTF-8 through
    out=[]
    for ch in s:
        o=ord(ch)
        if ch=='"': out.append('\\"')
        elif ch=='\\': out.append('\\\\')
        elif ch=='\n': out.append('\\n')
        elif ch=='\r': out.append('\\r')
        elif ch=='\t': out.append('\\t')
        elif o<0x20: out.append('\\u%04x'%o)
        else: out.append(ch)
    return ''.join(out)
f=os.environ; parts=[]
parts.append('"from":"%s"'  % esc(f["FROM"]))
parts.append('"to_":"%s"'   % esc(f["TO"]))
parts.append('"amount":"%s"'% esc(f["AMOUNT"]))
parts.append('"nonce":%s'   % f["NONCE"])            # unquoted int
parts.append('"ou":"%s"'    % esc(f["OU"]))
parts.append('"timestamp":%s' % f["TS"])             # integer epoch secs -> Rust f64 Display drops ".0"
parts.append('"op_type":"%s"' % esc(f["OPTYPE"]))
if f["ED"]:  parts.append('"encrypted_data":"%s"' % esc(f["ED"]))
if f["MSG"]: parts.append('"message":"%s"' % esc(f["MSG"]))
print("{"+",".join(parts)+"}")
PY
}

# Build the full JSON-RPC octra_submit body (envelope + signature +
# public_key). Prints the request body on one line.
_oplib_submit_body() {
  FROM="$1" TO="$2" AMOUNT="$3" NONCE="$4" OU="$5" TS="$6" OPTYPE="$7" ED="$8" MSG="$9" SIG="${10}" PK="${11}" \
  python3 - <<'PY'
import os,json
f=os.environ
env={"from":f["FROM"],"to_":f["TO"],"amount":f["AMOUNT"],"nonce":int(f["NONCE"]),
     "ou":f["OU"],"timestamp":int(f["TS"]),"op_type":f["OPTYPE"]}
if f["ED"]:  env["encrypted_data"]=f["ED"]
if f["MSG"]: env["message"]=f["MSG"]
env["signature"]=f["SIG"]; env["public_key"]=f["PK"]
print(json.dumps({"jsonrpc":"2.0","id":1,"method":"octra_submit","params":[env]}))
PY
}

# submit_op KEY OP_TYPE TO AMOUNT OU MESSAGE ENCRYPTED_DATA
# Builds+signs+submits one op tx. Publishes results via GLOBALS
# (OP_RESPONSE, OP_TXHASH, OP_SUBMIT_REASON) — so DO NOT call this inside
# `$(...)`; a subshell would swallow the globals. Call it directly:
#     submit_op "$KEY" relay_claim "$CIRCLE" 0 1000 "$MSG"
#     echo "$OP_RESPONSE"; [[ -n "$OP_TXHASH" ]] && ...
submit_op() {
  local key="$1" optype="$2" to="$3" amount="$4" ou="$5" msg="$6" ed="${7:-}"
  local from ts nonce canon sig pk body resp
  OP_RESPONSE=""; OP_TXHASH=""; OP_SUBMIT_REASON=""
  from=$(wallet_addr "$key")
  ts=$(date +%s)
  nonce=$(next_nonce "$key")
  canon=$(_oplib_canonical "$from" "$to" "$amount" "$nonce" "$ou" "$ts" "$optype" "$ed" "$msg")
  # Real ed25519 over the canonical UTF-8 bytes — canon starts with '{' so
  # `cast wallet sign` takes the UTF-8 path (not the hex path).
  sig=$("$OCTRA_BIN" cast wallet sign --key "$key" "$canon" 2>/dev/null)
  pk=$("$OCTRA_BIN" cast wallet pubkey --key "$key" --format base64 2>/dev/null)
  if [[ -z "$sig" || -z "$pk" ]]; then
    OP_SUBMIT_REASON="tooling: cast wallet sign/pubkey produced no output"
    OP_RESPONSE='{"error":{"message":"local signing failed"}}'; return 0
  fi
  body=$(_oplib_submit_body "$from" "$to" "$amount" "$nonce" "$ou" "$ts" "$optype" "$ed" "$msg" "$sig" "$pk")
  resp=$(curl -s -m 12 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" -d "$body")
  OP_RESPONSE="$resp"
  # Extract tx_hash + any submit-time error/reason.
  eval "$(echo "$resp" | python3 -c '
import json,sys,shlex
try: d=json.load(sys.stdin)
except Exception: d={}
def deep(x):  # collect any reason/message/error strings anywhere
    s=[]
    if isinstance(x,dict):
        for k,v in x.items():
            if k in ("reason","message","error","detail") and isinstance(v,str): s.append(v)
            s+=deep(v)
    elif isinstance(x,list):
        for v in x: s+=deep(v)
    return s
txh=""
def findhash(x):
    global txh
    if txh: return
    if isinstance(x,dict):
        for k,v in x.items():
            if k in ("tx_hash","hash","txhash") and isinstance(v,str) and v: txh=v; return
            findhash(v)
    elif isinstance(x,list):
        for v in x: findhash(v)
findhash(d)
reason="; ".join(deep(d)) if not txh else ""
print("OP_TXHASH="+shlex.quote(txh))
print("OP_SUBMIT_REASON="+shlex.quote(reason))
')"
}

# wait_status TXHASH -> prints "status|reason". Polls octra_transaction.
wait_status() {
  local hash="$1"
  [[ -z "$hash" ]] && { echo "no_txhash|"; return; }
  local i out
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 3
    out=$(rpc octra_transaction "[\"$hash\"]" | python3 -c '
import json,sys
try: r=json.load(sys.stdin).get("result") or {}
except Exception: r={}
st=r.get("status","?")
rs=""
e=r.get("error")
if isinstance(e,dict): rs=e.get("reason") or e.get("message") or ""
elif isinstance(e,str): rs=e
if not rs: rs=r.get("reason","") or ""
print(st+"|"+str(rs))
' 2>/dev/null)
    case "${out%%|*}" in
      confirmed|rejected|failed|reverted) echo "$out"; return ;;
    esac
  done
  echo "timeout|"
}

# classify_verdict STATUS REASON -> one verdict token on stdout:
#   CONFIRMED          op executed and committed
#   BYTECODE_NOT_FOUND circle is passive storage / no executable code
#   UNKNOWN_OP         chain does not recognize this op_type
#   REVERTED           op recognized + executed, logic path rejected it
#   TOOLING_BADSIG     signature/nonce rejected -> probe INCONCLUSIVE
#   REJECTED           rejected, cause unclassified
#   TIMEOUT/NO_TXHASH  never reached terminal state
# Lowercasing keeps the keyword match robust to chain casing.
classify_verdict() {
  # `st`/`rs` (not `status`) — `status` is a read-only special var in zsh.
  local st="$1" rs="$2"
  local r; r=$(printf '%s' "$st $rs" | tr '[:upper:]' '[:lower:]')
  case "$r" in
    *"bytecode not found"*|*"no bytecode"*|*"bytecode missing"*|*"not a contract"*) echo BYTECODE_NOT_FOUND; return;;
    *"unknown op"*|*"unsupported op"*|*"invalid op_type"*|*"unrecognized op"*|*"unknown method"*|*"op_type"*) echo UNKNOWN_OP; return;;
    *"signature"*|*"public_key"*|*"sig verify"*|*"bad sig"*|*"invalid sig"*|*"from="*|*"nonce"*) echo TOOLING_BADSIG; return;;
  esac
  case "$st" in
    confirmed) echo CONFIRMED; return;;
    reverted)  echo REVERTED; return;;
    timeout)   echo TIMEOUT; return;;
    no_txhash) echo NO_TXHASH; return;;
  esac
  # rejected/failed with a logic-y reason == the op ran and refused.
  if [[ -n "$rs" ]]; then echo REVERTED; else echo REJECTED; fi
}
