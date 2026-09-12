# _oplib.sh — shared helper for the native-op devnet probes.
#
# NOT a standalone script: `source` this from relay-outbox-probe.sh and
# circle-call-object-probe.sh. It knows how to build, SIGN, and SUBMIT an
# arbitrary Octra `op_type` transaction envelope, then classify the
# chain's response into a decisive verdict token.
# (One offline exception: `bash _oplib.sh selftest` prints and checks the
# signing preimage against pinned vectors — no RPC, no octra binary.)
#
# ── Why this exists ────────────────────────────────────────────────────
# The foundry `octra` CLI has dedicated builders for exactly three
# op_types: `deploy_circle`, `circle_asset_put`, `circle_asset_put_encrypted`
# (see octra-foundry crates/octra-cli/src/cast/circle.rs) plus the AML
# `contract_call` path (`cast send`). It has NO builder for the native
# relay / object ops we are probing (`circle_outbox_open`,
# `circle_relay_claim`, `circle_relay_cancel`, `circle_ingress_commit`,
# `circle_call` — those are the node's canonical strings, see
# op_type_of_string in lite_node transaction.ml:198-239; the bare
# `relay_claim`-style names do NOT parse). So we hand-build the envelope
# here.
#
# ── How signing stays honest (no reimplemented crypto) ─────────────────
# The bytes a wallet signs are what the NODE recomputes in
# `Transaction.serialize_for_signing` (lite_node lib/core/transaction.ml:
# 309-326; verified at admission via `Transaction.verify`, called from
# node_runtime/tx_view.ml:1146). That is a compact Yojson object in this
# EXACT field order — no chain_id anywhere:
#
#   {"from":"..","to_":"..","amount":"<int>","nonce":<int>,"ou":"<int>",
#    "timestamp":<float>,"op_type":".."[,"encrypted_data":".."][,"message":".."]}
#
# We reconstruct that exact string in Python (a byte-faithful port of
# Yojson 3.0.0's writer), then hand it to `octra cast wallet sign` (real
# ed25519 over the UTF-8 bytes, base64 output) — we never re-implement
# the signature.
#
# The one real footgun is float rendering: Yojson prints an INTEGRAL
# float WITH a trailing `.0` (e.g. `1717000000.0`). An earlier version
# of this lib signed the bare-integer rendering (`1717000000`) on the
# theory that the verifier used Rust f64 `Display` semantics — the node
# is OCaml, so every op it signed failed verification. That single
# divergence is what parked P2.1/P2.2 as TOOLING_BADSIG. Do NOT "fix"
# this back by imitating octra-foundry's `OctraTx::to_canonical_json`
# (octra-core/src/tx.rs write_kv_float): it uses Rust `{}` Display and
# drops the `.0`, i.e. it disagrees with the chain on integral floats.
# `bash _oplib.sh selftest` pins the expected bytes.
#
# If the signature were ever wrong, the chain rejects with a signature
# error BEFORE dispatching on op_type — which would masquerade as
# "op unsupported". `classify_verdict` detects that case explicitly and
# returns TOOLING_BADSIG so a probe can never turn a signing bug into a
# false negative. (Related landmine: a MISSING op_type key does not
# error — of_yojson silently falls back to Standard (transaction.ml:296),
# whose amount>0 check then rejects our amount-"0" relay ops with a
# bogus "amount must be positive". Always send op_type explicitly.)
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
# the node's Transaction.serialize_for_signing (lite_node transaction.ml:
# 309-326), i.e. Yojson.Safe.to_string of the assoc. Optional fields
# (encrypted_data, message) appear only when non-empty, in THAT order —
# encrypted_data is appended before message (transaction.ml:318-325).
# Prints the canonical string on one line.
_oplib_canonical() {
  FROM="$1" TO="$2" AMOUNT="$3" NONCE="$4" OU="$5" TS="$6" OPTYPE="$7" ED="$8" MSG="$9" \
  python3 - <<'PY'
import os
def esc(s):
    # Port of Yojson 3.0.0 write.ml string escaping: named escapes for
    # " \ \b \f \n \r \t; other C0 controls AND 0x7f as lowercase \u00xx;
    # everything else (incl. non-ASCII UTF-8) passes through as raw bytes.
    out=[]
    for ch in s:
        o=ord(ch)
        if ch=='"': out.append('\\"')
        elif ch=='\\': out.append('\\\\')
        elif ch=='\b': out.append('\\b')
        elif ch=='\f': out.append('\\f')
        elif ch=='\n': out.append('\\n')
        elif ch=='\r': out.append('\\r')
        elif ch=='\t': out.append('\\t')
        elif o<0x20 or o==0x7f: out.append('\\u%04x'%o)
        else: out.append(ch)
    return ''.join(out)
def yfloat(v):
    # Port of Yojson 3.0.0 write_float: shortest of %.16g/%.17g that
    # round-trips, then a trailing ".0" whenever the result has no '.'
    # or exponent (float_needs_period). This is THE line that fixes
    # TOOLING_BADSIG: an integral epoch-seconds timestamp must render
    # "1717000000.0", not "1717000000".
    x=float(v)
    s='%.16g'%x
    if float(s)!=x: s='%.17g'%x
    if all(c.isdigit() or c=='-' for c in s): s+='.0'
    return s
f=os.environ; parts=[]
parts.append('"from":"%s"'  % esc(f["FROM"]))
parts.append('"to_":"%s"'   % esc(f["TO"]))       # trailing underscore is the wire key
parts.append('"amount":"%s"'% esc(f["AMOUNT"]))   # string, not number
parts.append('"nonce":%s'   % int(f["NONCE"]))    # unquoted int
parts.append('"ou":"%s"'    % esc(f["OU"]))       # string, not number
parts.append('"timestamp":%s' % yfloat(f["TS"]))
parts.append('"op_type":"%s"' % esc(f["OPTYPE"])) # ALWAYS explicit (missing => silent Standard)
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
# timestamp goes on the wire as a JSON float: the node's parser accepts
# Int too and coerces (transaction.ml:290-292), so only VALUE equality
# with the signed preimage matters here — but Python's float repr of an
# integral value ("1717000000.0") happens to byte-match Yojson anyway.
env={"from":f["FROM"],"to_":f["TO"],"amount":f["AMOUNT"],"nonce":int(f["NONCE"]),
     "ou":f["OU"],"timestamp":float(f["TS"]),"op_type":f["OPTYPE"]}
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

# ── offline preimage self-test ────────────────────────────────────────
# `bash _oplib.sh selftest` — exercises _oplib_canonical against vectors
# whose expected bytes were derived by hand from the node source
# (transaction.ml:309-326 + Yojson 3.0.0's writer). Diff these against
# the node's own serialize_for_signing without spending a tx. Exits
# nonzero on any mismatch, so probes/CI can gate on it before signing.
_oplib_selftest() {
  local fail=0
  _st_case() {  # _st_case NAME EXPECTED <canonical-args...>
    local name="$1" want="$2"; shift 2
    local got; got=$(_oplib_canonical "$@")
    echo "[$name]"
    echo "  preimage: $got"
    if [[ "$got" != "$want" ]]; then
      echo "  MISMATCH, expected: $want"
      fail=1
    fi
  }
  # 1. The shape both parked probes sign: a relay op, amount "0", no
  #    optional fields. The trailing ".0" on the timestamp is the whole
  #    P2.1/P2.2 bug — if this vector regresses, everything regresses.
  _st_case relay_no_optionals \
    '{"from":"octAAAA","to_":"octBBBB","amount":"0","nonce":7,"ou":"1000","timestamp":1717000000.0,"op_type":"relay_claim"}' \
    octAAAA octBBBB 0 7 1000 1717000000 relay_claim "" ""
  # 2. Both optional fields present: encrypted_data must precede message.
  _st_case both_optionals \
    '{"from":"octAAAA","to_":"octBBBB","amount":"5","nonce":8,"ou":"5000","timestamp":1717000000.0,"op_type":"circle_call","encrypted_data":"QUJD","message":"hi"}' \
    octAAAA octBBBB 5 8 5000 1717000000 circle_call QUJD hi
  # 3. Escaping + a non-integral timestamp (no ".0" appended): quotes and
  #    backslashes get named escapes, C0 controls and DEL get \u00xx.
  _st_case escaping_and_fractional_ts \
    '{"from":"octAAAA","to_":"octBBBB","amount":"0","nonce":9,"ou":"1000","timestamp":1717000000.5,"op_type":"circle_outbox_open","message":"a\"b\\c\t\n\u0001\u007f"}' \
    octAAAA octBBBB 0 9 1000 1717000000.5 circle_outbox_open "" "$(printf 'a"b\\c\t\n\001\177')"
  if [[ "$fail" -eq 0 ]]; then
    echo "selftest: OK (3 vectors)"
  else
    echo "selftest: FAILED — do not sign with this build"
  fi
  return "$fail"
}

# Run the self-test when executed directly (the file is otherwise
# source-only; sourcing must never trigger this).
if [[ "${BASH_SOURCE[0]}" == "${0}" && "${1:-}" == "selftest" ]]; then
  _oplib_selftest
fi
