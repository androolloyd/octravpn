#!/usr/bin/env bash
# upstream-reality-probe.sh — settle, against LIVE devnet, every open
# [unverified] question from docs/octra-upstream-delta-2026-08-17.md.
#
# Eight independently-reported items (PASS / FAIL / INCONCLUSIVE each, raw
# responses captured under docker/devnet/.generated/upstream-reality-probe/):
#
#   1. current epoch vs the three activation gates (1,299,000 circle exec;
#      1,330,000 wasm-compute/private bundle; 1,334,000 participation set-fold)
#   2. op_type acceptance: legacy "call" vs "program_exec"  ** HIGH PRIORITY **
#      (lite_node transaction.ml:198-239 parses BOTH in source; this asks the
#      RUNNING devnet binary — our foundry emits "call" on every v3/v4 tx)
#   3. storage >4096 bytes: write-side reality vs read-side display slice
#      (contract_rpc.ml:444-470 slices at 4096 with truncated:true; the "full"
#      mode returns up to the 4 MiB VM cap)
#   4. contract_receipt / octra_programReceipt shape for a confirmed tx
#      (aliases per rpc_dispatch.ml:187)
#   5. octra_transaction terminal statuses carry reasons
#      (history_read_rpc.ml:131-175: pending/confirmed/rejected/dropped)
#   6. octra_isValidator absent + octra_validatorSetProof present
#      (status_read_rpc.ml:339; isValidator exists nowhere in the node)
#   7. octra_pvacStatus (+ octra_pvacMigrationStatus) for the May-registered
#      wallet (rpc_view.ml:464-472 shape)
#   8. fhe_load_pk probed as a LIVE TX, receipt read back — a view call
#      returns a bare "execution reverted" and tells us nothing; the live
#      receipt carries the VM's concrete reason ("fhe_load_pk not allowed" or
#      "fhe pubkey not available: <addr>", contract_vm.ml:2573-2581)
#
# ── Why this does NOT source _oplib.sh ────────────────────────────────
# _oplib.sh signs an INTEGER timestamp on the theory that the chain re-renders
# the same bytes. The verifier (transaction.ml serialize_for_signing, called
# from verify) re-renders the preimage with Yojson, which prints an integral
# float WITH a trailing ".0" — and webcli's format_timestamp (tx_builder.hpp:
# 55-58, nlohmann dump) agrees. So _oplib's integer-timestamp txs are
# guaranteed bad-sig against the real node (that is upstream-delta §6a.4).
# Fixing _oplib.sh belongs to that work item; this probe carries its own
# correct builder: sign "<secs>.0" and submit the same float.
#
# Deliberately NOT probed: a "dropped" tx (needs staging eviction we cannot
# force from outside; item 5 reports the rejected path decisively and the
# unknown-hash response as context, never a faked dropped verdict).
#
# Requires (same contract as the sibling probes in this directory):
#   * pre-built foundry `octra` at $OCTRA_BIN (default
#     ../octra-foundry/target/release/octra) — this probe does NOT build it
#   * curl, python3 on PATH; a funded $DEPLOYER_KEY
#   * $OCTRA_RPC_URL (default devnet)
#
# Re-runnable: the tiny probe program deploys once and its address is cached
# in .generated/upstream-reality-probe/program.addr; later runs reuse it
# (override with PROBE_PROGRAM_ADDR=oct...). Raw captures are overwritten
# per run.
#
# Exit: 0 all decisive and the HIGH item passed · 1 HIGH item FAILED
#       ("call" no longer accepted — every foundry submission is broken) ·
#       2 HIGH item INCONCLUSIVE or env not ready
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"

# Same env layering as preflight.sh / v4-relay-e2e.sh.
set -a
# shellcheck source=/dev/null
[[ -f "$ROOT/docker/devnet/.env" ]] && source "$ROOT/docker/devnet/.env"
# shellcheck source=/dev/null
[[ -f "$ROOT/docker/devnet/hosts.env" ]] && source "$ROOT/docker/devnet/hosts.env"
set +a

OCTRA_BIN="${OCTRA_BIN:-$ROOT/../octra-foundry/target/release/octra}"
OCTRA_RPC_URL="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"
DEPLOYER_KEY="${DEPLOYER_KEY:-$ROOT/docker/devnet/state/deployer.key}"
# The wallet whose ~4.1 MB PVAC pubkey registration confirmed 2026-05-18
# (memory: octra_devnet_rpc_body_cap) — node1's operator wallet.
PVAC_WALLET_ADDR="${PVAC_WALLET_ADDR:-${NODE1_VALIDATOR_ADDR:-octG15XHxJ15yAAsyrjdTxzPMjhJCwjZrjZMJkvHf76FdYH}}"

# The real envelope has no chain_id (transaction.ml:273-325); a poisoned env
# var would make the foundry CLI weave one into the preimage => guaranteed 101.
unset OCTRA_CHAIN_ID

OUT="$ROOT/docker/devnet/.generated/upstream-reality-probe"
ADDR_FILE="$OUT/program.addr"
PROBE_AML="$OUT/upstream-reality-probe.aml"

GATE_CIRCLE_EXEC=1299000
GATE_WASM_COMPUTE=1330000
GATE_PARTICIPATION=1334000

TX_FEE=1000          # ContractCall/ProgramExec ou floor is exactly 1_000 (transaction.ml:388-402)
BLOB_LEN=8000        # comfortably past the 4096 display slice, far under the 4 MiB VM cap

hdr(){ printf "\n=== %s ===\n" "$1"; }
ok(){ printf "  + %s\n" "$1"; }
note(){ printf "    %s\n" "$1"; }
bad(){ printf "  ! %s\n" "$1"; }

# ── verdict ledger (bash-3.2-safe parallel arrays) ────────────────────
ITEM_NAMES=(); ITEM_VERDICTS=(); ITEM_DETAILS=()
record(){ # record <name> <PASS|FAIL|INCONCLUSIVE> <detail>
  ITEM_NAMES+=("$1"); ITEM_VERDICTS+=("$2"); ITEM_DETAILS+=("$3")
  case "$2" in PASS) ok "$1: $3";; *) bad "$1: $2 — $3";; esac
}

rpc(){ # rpc <method> <params-json>
  curl -s -m 15 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}
rpc_cap(){ # rpc_cap <capture-name> <method> <params-json> — echoes AND saves raw
  local resp; resp="$(rpc "$2" "$3")"
  printf '%s' "$resp" > "$OUT/$1.json"
  printf '%s' "$resp"
}
# jget <python-expr over parsed dict d> — stdin is JSON, prints expr or "".
jget(){ python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: d={}
try: v=eval(sys.argv[1])
except Exception: v=""
print("" if v is None else v)' "$1"; }

wallet_addr(){ "$OCTRA_BIN" cast wallet addr --key "$1"; }
next_nonce(){ # confirmed on-chain nonce + 1 (ledger.ml:241); call only between terminal txs
  rpc octra_balance "[\"$(wallet_addr "$1")\"]" \
    | jget '(int((d.get("result") or {}).get("nonce",0) or 0))+1'
}

# ── hand-built op_type submit (the correct preimage) ──────────────────
# Canonical string per lite_node serialize_for_signing (transaction.ml:309-326):
#   {"from","to_","amount"(str),"nonce"(int),"ou"(str),"timestamp"(float),
#    "op_type"[,"encrypted_data"][,"message"]}
# Signed as UTF-8 text; the timestamp is an integral epoch-second rendered
# "<secs>.0" so it byte-matches Yojson's re-render on the verifier side.
_canon(){ # _canon FROM TO AMOUNT NONCE OU TS_TEXT OPTYPE ED MSG
  FROM="$1" TO="$2" AMOUNT="$3" NONCE="$4" OU="$5" TS="$6" OPTYPE="$7" ED="$8" MSG="$9" \
  python3 - <<'PY'
import os
def esc(s):  # Yojson-compatible string escaping for our clean-ASCII payloads
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
f=os.environ
parts=['"from":"%s"'%esc(f["FROM"]), '"to_":"%s"'%esc(f["TO"]),
       '"amount":"%s"'%esc(f["AMOUNT"]), '"nonce":%s'%f["NONCE"],
       '"ou":"%s"'%esc(f["OU"]), '"timestamp":%s'%f["TS"],
       '"op_type":"%s"'%esc(f["OPTYPE"])]
if f["ED"]:  parts.append('"encrypted_data":"%s"'%esc(f["ED"]))
if f["MSG"]: parts.append('"message":"%s"'%esc(f["MSG"]))
print("{"+",".join(parts)+"}")
PY
}

SUB_RESP=""; SUB_HASH=""; SUB_ERR=""
submit_op(){ # submit_op <capture-name> <op_type> <to> <method(ED)> <params-json(MSG)>
  # Publishes SUB_RESP / SUB_HASH / SUB_ERR globals — do not call in $(...).
  local cap="$1" optype="$2" to="$3" method="$4" params="$5"
  local from ts nonce canon sig pk body
  SUB_RESP=""; SUB_HASH=""; SUB_ERR=""
  from="$(wallet_addr "$DEPLOYER_KEY")"
  ts="$(date +%s).0"
  nonce="$(next_nonce "$DEPLOYER_KEY")"
  canon="$(_canon "$from" "$to" 0 "$nonce" "$TX_FEE" "$ts" "$optype" "$method" "$params")"
  # Real ed25519 over the canonical UTF-8 bytes — never reimplemented locally.
  sig="$("$OCTRA_BIN" cast wallet sign --key "$DEPLOYER_KEY" "$canon" 2>/dev/null)"
  pk="$("$OCTRA_BIN" cast wallet pubkey --key "$DEPLOYER_KEY" --format base64 2>/dev/null)"
  if [[ -z "$sig" || -z "$pk" ]]; then
    SUB_ERR="tooling: cast wallet sign/pubkey produced no output"; return 0
  fi
  body="$(FROM="$from" TO="$to" NONCE="$nonce" OU="$TX_FEE" TS="$ts" OPTYPE="$optype" \
          ED="$method" MSG="$params" SIG="$sig" PK="$pk" python3 - <<'PY'
import os,json
f=os.environ
env={"from":f["FROM"],"to_":f["TO"],"amount":"0","nonce":int(f["NONCE"]),
     "ou":f["OU"],"timestamp":float(f["TS"]),"op_type":f["OPTYPE"]}
# float(".0"-suffixed integral secs) round-trips to "<secs>.0" in json.dumps —
# the same text we signed, and the same text Yojson re-renders on verify.
if f["ED"]:  env["encrypted_data"]=f["ED"]
if f["MSG"]: env["message"]=f["MSG"]
env["signature"]=f["SIG"]; env["public_key"]=f["PK"]
print(json.dumps({"jsonrpc":"2.0","id":1,"method":"octra_submit","params":[env]}))
PY
)"
  SUB_RESP="$(curl -s -m 15 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" -d "$body")"
  printf '%s' "$SUB_RESP" > "$OUT/$cap.json"
  SUB_HASH="$(printf '%s' "$SUB_RESP" | jget '(d.get("result") or {}).get("tx_hash","")')"
  if [[ -z "$SUB_HASH" ]]; then
    SUB_ERR="$(printf '%s' "$SUB_RESP" | jget '(d.get("error") or {}).get("message","") or str(d.get("error") or "")')"
  fi
}

wait_tx(){ # wait_tx <hash> <capture-name> -> "status|reason"; saves last raw lookup
  local hash="$1" cap="$2" i out
  [[ -z "$hash" ]] && { echo "no_txhash|"; return; }
  for i in $(seq 1 30); do
    sleep 3
    out="$(rpc octra_transaction "[\"$hash\"]")"
    printf '%s' "$out" > "$OUT/$cap.json"
    out="$(printf '%s' "$out" | python3 -c '
import json,sys
try: r=json.load(sys.stdin).get("result") or {}
except Exception: r={}
st=r.get("status","?"); rs=""
e=r.get("error")
if isinstance(e,dict): rs=e.get("reason") or e.get("message") or ""
elif isinstance(e,str): rs=e
if not rs: rs=r.get("reason","") or ""
print(st+"|"+str(rs))')"
    case "${out%%|*}" in
      confirmed|rejected|failed|reverted|dropped) echo "$out"; return;;
    esac
  done
  echo "timeout|"
}

# cast-send path (op_type "call" via the foundry — the production tx shape).
SEND_HASH=""; SEND_STATUS=""; SEND_REASON=""
send_call(){ # send_call <capture-name> <method> [json-args...]
  local cap="$1" method="$2"; shift 2
  local out
  SEND_HASH=""; SEND_STATUS=""; SEND_REASON=""
  out="$("$OCTRA_BIN" cast send --key "$DEPLOYER_KEY" --rpc-url "$OCTRA_RPC_URL" \
        --fee "$TX_FEE" "$C" "$method" "$@" 2>&1)"
  SEND_HASH="$(printf '%s' "$out" | python3 -c 'import sys,re;t=sys.stdin.read();m=re.search(r"tx_hash\"\s*:\s*\"([0-9a-fA-F]+)\"",t);print(m.group(1) if m else "")')"
  if [[ -z "$SEND_HASH" ]]; then
    SEND_STATUS="submit_failed"
    SEND_REASON="$(printf '%s' "$out" | tr '\n' ' ' | head -c 200)"
    return 0
  fi
  out="$(wait_tx "$SEND_HASH" "$cap")"
  SEND_STATUS="${out%%|*}"; SEND_REASON="${out#*|}"
}

view_result(){ # view_result <fn> <params-json>  -> bare view return value
  rpc contract_call "[\"$C\",\"$1\",$2]" \
    | jget '(d.get("result") or {}).get("result","")'
}

sig_shaped(){ # a signature/nonce reject means OUR tooling failed, not the chain answered
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    *signature*|*"public_key"*|*"bad sig"*|*"invalid sig"*|*nonce*) return 0;;
    *) return 1;;
  esac
}

echo "upstream-reality-probe — settles the [unverified] items of docs/octra-upstream-delta-2026-08-17.md"
echo "  RPC=$OCTRA_RPC_URL"
echo "  captures -> ${OUT#"$ROOT"/}"

# ── preflight (env problems are INCONCLUSIVE, never FAIL) ─────────────
hdr preflight
miss=0
command -v curl >/dev/null    || { bad "curl missing"; miss=1; }
command -v python3 >/dev/null || { bad "python3 missing"; miss=1; }
[[ -x "$OCTRA_BIN" ]] || { bad "octra binary missing at $OCTRA_BIN (build: cd ../octra-foundry && cargo build --release -p octra-cli)"; miss=1; }
[[ -f "$DEPLOYER_KEY" ]] || { bad "deployer key missing at $DEPLOYER_KEY"; miss=1; }
if [[ $miss -eq 0 ]] && ! rpc node_status "[]" | python3 -c 'import json,sys;json.load(sys.stdin)' >/dev/null 2>&1; then
  bad "RPC $OCTRA_RPC_URL not answering node_status"; miss=1
fi
[[ $miss -ne 0 ]] && { echo; echo "VERDICT: INCONCLUSIVE (env not ready)"; exit 2; }
mkdir -p "$OUT"
OP="$(wallet_addr "$DEPLOYER_KEY")"
ok "signer  = $OP"
ok "pvac wallet under test = $PVAC_WALLET_ADDR"

# ── item 1: epoch vs activation gates ─────────────────────────────────
hdr "1. current epoch vs activation gates"
EPOCH="$(rpc_cap 01-node-status node_status "[]" | jget '(d.get("result") or {}).get("epoch","")')"
if [[ "$EPOCH" =~ ^[0-9]+$ ]]; then
  gates=""
  for g in "circle-exec:$GATE_CIRCLE_EXEC" "wasm-compute:$GATE_WASM_COMPUTE" "participation:$GATE_PARTICIPATION"; do
    if [[ "$EPOCH" -ge "${g#*:}" ]]; then gates="$gates ${g%%:*}=ACTIVE"; else gates="$gates ${g%%:*}=pending(${g#*:})"; fi
  done
  record "1 epoch-gates" PASS "epoch=$EPOCH;$gates"
else
  record "1 epoch-gates" INCONCLUSIVE "node_status returned no numeric epoch (see 01-node-status.json)"
fi

# ── deploy or reuse the tiny probe program ────────────────────────────
# Items 2/3/4/5/8 all need a program we control. One deploy, cached address.
hdr "deploy or reuse probe program"
cat > "$PROBE_AML" <<'AML'
// Generated by docker/devnet/experiments/upstream-reality-probe.sh — a
// minimal target for the upstream reality probe. Stays inside the proven
// AML feature set (state, require, len). Each method backs one probe item:
//   ping           — no-op mutation for the op_type-literal test (item 2);
//                    pokes is the state-based truth that it really executed
//                    (the chain has no tx events to assert on)
//   put_blob       — stores an oversized bytes value (item 3)
//   always_fail    — deliberate require() revert (item 5 terminal reasons)
//   probe_fhe_load — first instruction is fhe_load_pk, so the receipt's
//                    error is the VM's own gate message (item 8)
contract UpstreamRealityProbe {
  state {
    pokes: uint
    blob: bytes
  }

  constructor() {
    self.pokes = 0
    self.blob = "0"
  }

  fn ping(): bool {
    self.pokes = self.pokes + 1
    return true
  }

  view fn get_pokes(): uint {
    return self.pokes
  }

  fn put_blob(v: bytes): bool {
    self.blob = v
    return true
  }

  view fn blob_len(): uint {
    return len(self.blob)
  }

  fn always_fail(): bool {
    require(1 == 2, "PROBE_ALWAYS_FAIL deliberate revert for terminal-status probe")
    return true
  }

  fn probe_fhe_load(a: string): bool {
    let pk = fhe_load_pk(a)
    return true
  }
}
AML

C=""
if [[ -n "${PROBE_PROGRAM_ADDR:-}" ]]; then
  C="$PROBE_PROGRAM_ADDR"; ok "using PROBE_PROGRAM_ADDR=$C"
elif [[ -f "$ADDR_FILE" ]]; then
  C="$(cat "$ADDR_FILE")"
  if rpc contract_call "[\"$C\",\"get_pokes\",[]]" \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if "result" in d else 1)' 2>/dev/null; then
    ok "reusing cached probe program @ $C"
  else
    note "cached program @ $C no longer answers; redeploying"; C=""
  fi
fi
if [[ -z "$C" ]]; then
  DEP="$("$OCTRA_BIN" forge create "$PROBE_AML" --key "$DEPLOYER_KEY" --rpc-url "$OCTRA_RPC_URL" 2>&1)"
  printf '%s' "$DEP" > "$OUT/00-deploy.log"
  # Prefer the JSON "address" field; the bare-regex fallback must skip the
  # signer's own address ("submitted from: oct..." precedes the program addr).
  C="$(printf '%s' "$DEP" | python3 -c '
import sys,re
t=sys.stdin.read(); me=sys.argv[1]
m=re.search(r"\"address\"\s*:\s*\"(oct[0-9A-Za-z]{20,})\"",t)
if m: print(m.group(1)); raise SystemExit
for cand in re.findall(r"\boct[0-9A-Za-z]{20,}\b",t):
    if cand != me: print(cand); raise SystemExit
print("")' "$OP")"
  if [[ -n "$C" ]]; then
    # forge create returns at submit; give the 10s epoch tick time to apply.
    live=0
    for _ in $(seq 1 12); do
      sleep 5
      if rpc contract_call "[\"$C\",\"get_pokes\",[]]" \
          | python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if "result" in d else 1)' 2>/dev/null; then
        live=1; break
      fi
    done
    if [[ $live -eq 1 ]]; then
      printf '%s' "$C" > "$ADDR_FILE"; ok "deployed probe program @ $C"
    else
      bad "deployed @ $C but views never answered (see 00-deploy.log)"; C=""
    fi
  else
    bad "forge create produced no address (see 00-deploy.log)"
  fi
fi

if [[ -z "$C" ]]; then
  # Without the program, items 2/3/4/5/8 cannot run. Record and move on to
  # the pure-RPC items rather than aborting the whole probe.
  for it in "2 optype-legacy-call" "2 optype-program-exec" "3 storage-4k-slice" \
            "4 receipt-shape" "5 terminal-reasons" "8 fhe-load-pk-live"; do
    record "$it" INCONCLUSIVE "probe program unavailable (deploy failed)"
  done
else
  # ── item 2 (HIGH): op_type "call" vs "program_exec" ─────────────────
  hdr "2. op_type acceptance — legacy \"call\" vs \"program_exec\" (HIGH)"
  # Calibration first: an op_type the parser can never accept, so we know
  # what a parse-level rejection looks like on the RUNNING binary
  # (op_type_of_string failure surfaces via of_yojson at submit).
  submit_op 02-optype-bogus definitely_not_an_op "$C" ping "[]"
  BOGUS_ERR="$SUB_ERR"
  if [[ -n "$SUB_HASH" ]]; then
    # Should be impossible (op_type_of_string has no such arm) — but if the
    # chain staged it we must wait it out or the next submit's nonce collides.
    note "calibration bogus-op was STAGED ($SUB_HASH) — waiting for terminal state"
    wait_tx "$SUB_HASH" 02-optype-bogus-status >/dev/null
  fi
  note "calibration bogus-op submit error: ${BOGUS_ERR:-<staged; see 02-optype-bogus-status.json>}"

  probe_optype(){ # probe_optype <literal> <capture> -> echoes EXECUTED|PARSE_REJECTED|BADSIG|REJECTED:<r>|TIMEOUT
    local lit="$1" cap="$2" pokes_before pokes_after st rs out
    pokes_before="$(view_result get_pokes "[]")"
    submit_op "$cap" "$lit" "$C" ping "[]"
    if [[ -z "$SUB_HASH" ]]; then
      if sig_shaped "$SUB_ERR"; then echo "BADSIG"; else echo "PARSE_REJECTED"; fi
      return
    fi
    out="$(wait_tx "$SUB_HASH" "$cap-status")"
    st="${out%%|*}"; rs="${out#*|}"
    case "$st" in
      confirmed)
        # State-based truth: events don't exist, pokes does. Re-poll a few
        # times so a view lagging the epoch apply can't fake a FAIL on the
        # HIGH item.
        pokes_after="$(view_result get_pokes "[]")"
        for _ in 1 2 3; do
          if [[ -n "$pokes_before" && -n "$pokes_after" && "$pokes_after" -gt "$pokes_before" ]] 2>/dev/null; then
            break
          fi
          sleep 3; pokes_after="$(view_result get_pokes "[]")"
        done
        if [[ -n "$pokes_before" && -n "$pokes_after" && "$pokes_after" -gt "$pokes_before" ]] 2>/dev/null; then
          echo "EXECUTED"
        else
          echo "REJECTED:confirmed-but-pokes-unchanged($pokes_before->$pokes_after)"
        fi;;
      timeout) echo "TIMEOUT";;
      *) if sig_shaped "$rs"; then echo "BADSIG"; else echo "REJECTED:$rs"; fi;;
    esac
  }

  R_CALL="$(probe_optype call 02-optype-call)"
  note "op_type \"call\" -> $R_CALL"
  R_PEXEC="$(probe_optype program_exec 02-optype-program-exec)"
  note "op_type \"program_exec\" -> $R_PEXEC"

  case "$R_CALL" in
    EXECUTED) record "2 optype-legacy-call" PASS "legacy \"call\" accepted and executed (foundry tooling unaffected)";;
    BADSIG|TIMEOUT) record "2 optype-legacy-call" INCONCLUSIVE "$R_CALL — not a chain answer; re-run";;
    PARSE_REJECTED) record "2 optype-legacy-call" FAIL "\"call\" rejected at parse (bogus-op calibration: ${BOGUS_ERR:-n/a}) — every foundry submission is broken; migrate to \"program_exec\"";;
    *) record "2 optype-legacy-call" FAIL "\"call\" did not execute: $R_CALL";;
  esac
  case "$R_PEXEC" in
    EXECUTED)       record "2 optype-program-exec" PASS "\"program_exec\" accepted and executed";;
    PARSE_REJECTED) record "2 optype-program-exec" PASS "decisive: \"program_exec\" NOT recognized by the running binary (predates the rename?)";;
    BADSIG|TIMEOUT) record "2 optype-program-exec" INCONCLUSIVE "$R_PEXEC";;
    *)              record "2 optype-program-exec" PASS "decisive: recognized but did not execute: $R_PEXEC";;
  esac

  # ── item 3: storage write >4096 then read back both ways ────────────
  hdr "3. storage >4096 bytes — write, then embedded vs full read"
  BLOB="$(python3 -c 'import sys;n=int(sys.argv[1]);h="PROBE4K-HEAD|";t="|PROBE4K-TAIL";print(h+"x"*(n-len(h)-len(t))+t)' "$BLOB_LEN")"
  send_call 03-put-blob-tx put_blob "\"$BLOB\""
  if [[ "$SEND_STATUS" == "confirmed" ]]; then
    PUT_BLOB_TX="$SEND_HASH"
    EMB="$(rpc_cap 03-embedded-storage contract_call "[\"$C\",\"blob_len\",[]]")"
    EMB_LEN="$(printf '%s' "$EMB" | jget 'len(((d.get("result") or {}).get("storage") or {}).get("blob",""))')"
    VIEW_LEN="$(printf '%s' "$EMB" | jget '(d.get("result") or {}).get("result","")')"
    FULL="$(rpc_cap 03-storage-full octra_contractStorage "[\"$C\",\"blob\",\"full\"]")"
    FULL_LEN="$(printf '%s' "$FULL" | jget 'len((d.get("result") or {}).get("value") or "")')"
    FULL_TRUNC="$(printf '%s' "$FULL" | jget '(d.get("result") or {}).get("truncated")')"
    FULL_TAIL_OK="$(printf '%s' "$FULL" | jget '"yes" if ((d.get("result") or {}).get("value") or "").endswith("|PROBE4K-TAIL") else "no"')"
    DEF="$(rpc_cap 03-storage-default octra_contractStorage "[\"$C\",\"blob\"]")"
    DEF_LEN="$(printf '%s' "$DEF" | jget 'len((d.get("result") or {}).get("value") or "")')"
    DEF_TRUNC="$(printf '%s' "$DEF" | jget '(d.get("result") or {}).get("truncated")')"
    detail="len(blob) view=$VIEW_LEN embedded=$EMB_LEN default=$DEF_LEN(trunc=$DEF_TRUNC) full=$FULL_LEN(trunc=$FULL_TRUNC,tail=$FULL_TAIL_OK)"
    if [[ "$FULL_LEN" == "$BLOB_LEN" && "$FULL_TAIL_OK" == "yes" ]]; then
      record "3 storage-4k-slice" PASS "write intact; 4096 is read-side only — $detail"
    elif [[ "$FULL_LEN" =~ ^[0-9]+$ && "$FULL_LEN" -lt "$BLOB_LEN" ]]; then
      record "3 storage-4k-slice" FAIL "value came back short even in full mode — write-side truncation is REAL — $detail"
    else
      record "3 storage-4k-slice" INCONCLUSIVE "unexpected read shapes — $detail (see 03-*.json)"
    fi
  else
    PUT_BLOB_TX=""
    record "3 storage-4k-slice" INCONCLUSIVE "put_blob did not confirm: $SEND_STATUS $SEND_REASON"
  fi

  # ── item 4: receipt shape for a known confirmed tx ──────────────────
  hdr "4. contract_receipt / octra_programReceipt shape"
  if [[ -n "$PUT_BLOB_TX" ]]; then
    RC="$(rpc_cap 04-contract-receipt contract_receipt "[\"$PUT_BLOB_TX\"]")"
    RA="$(rpc_cap 04-program-receipt octra_programReceipt "[\"$PUT_BLOB_TX\"]")"
    KEYS="$(printf '%s' "$RC" | jget '",".join(sorted((d.get("result") or {}).keys()))')"
    RC_OK="$(printf '%s' "$RC" | jget '"yes" if "success" in (d.get("result") or {}) else "no"')"
    RA_OK="$(printf '%s' "$RA" | jget '"yes" if "success" in (d.get("result") or {}) else "no"')"
    if [[ "$RC_OK" == "yes" && "$RA_OK" == "yes" ]]; then
      record "4 receipt-shape" PASS "both aliases answer; keys={$KEYS}"
    elif [[ "$RC_OK" == "yes" || "$RA_OK" == "yes" ]]; then
      record "4 receipt-shape" FAIL "alias mismatch: contract_receipt=$RC_OK octra_programReceipt=$RA_OK"
    else
      record "4 receipt-shape" INCONCLUSIVE "no success field from either alias (see 04-*.json)"
    fi
  else
    record "4 receipt-shape" INCONCLUSIVE "no confirmed tx available (item 3 did not confirm)"
  fi

  # ── item 5: terminal statuses carry reasons ─────────────────────────
  hdr "5. octra_transaction terminal statuses"
  send_call 05-always-fail-status always_fail
  UNKNOWN_HASH="$(printf '0%.0s' $(seq 1 64))"
  rpc_cap 05-unknown-hash octra_transaction "[\"$UNKNOWN_HASH\"]" >/dev/null
  case "$SEND_STATUS" in
    rejected|failed|reverted)
      if printf '%s' "$SEND_REASON" | grep -q "PROBE_ALWAYS_FAIL"; then
        record "5 terminal-reasons" PASS "status=$SEND_STATUS carries our require() reason verbatim (dropped untestable from outside; unknown-hash raw in 05-unknown-hash.json)"
      elif [[ -n "$SEND_REASON" ]]; then
        record "5 terminal-reasons" PASS "status=$SEND_STATUS carries a reason (\"$SEND_REASON\") though not our require string"
      else
        record "5 terminal-reasons" FAIL "status=$SEND_STATUS but NO reason attached — confirm-loop plans depend on reasons"
      fi;;
    confirmed) record "5 terminal-reasons" FAIL "always_fail CONFIRMED — require() did not reject";;
    *) record "5 terminal-reasons" INCONCLUSIVE "status=$SEND_STATUS $SEND_REASON";;
  esac

  # ── item 8: fhe_load_pk as a LIVE tx, receipt read back ─────────────
  hdr "8. fhe_load_pk live-tx receipt (not a view call)"
  send_call 08-fhe-load-status probe_fhe_load "\"$PVAC_WALLET_ADDR\""
  if [[ -n "$SEND_HASH" ]]; then
    FR="$(rpc_cap 08-fhe-load-receipt contract_receipt "[\"$SEND_HASH\"]")"
    FR_ERR="$(printf '%s' "$FR" | jget 'str((d.get("result") or {}).get("error") or "")')"
    case "$SEND_STATUS" in
      confirmed)
        record "8 fhe-load-pk-live" PASS "fhe_load_pk($PVAC_WALLET_ADDR) EXECUTED in a live tx — the AML->HFHE bridge is live for this wallet";;
      rejected|failed|reverted)
        if [[ -n "$FR_ERR" || -n "$SEND_REASON" ]]; then
          record "8 fhe-load-pk-live" PASS "decisive gate message: receipt.error=\"$FR_ERR\" tx.reason=\"$SEND_REASON\" (contract_vm.ml:2573-2581 wording tells us WHICH gate)"
        else
          record "8 fhe-load-pk-live" INCONCLUSIVE "reverted but neither receipt nor tx carries a reason (see 08-*.json)"
        fi;;
      *) record "8 fhe-load-pk-live" INCONCLUSIVE "status=$SEND_STATUS $SEND_REASON";;
    esac
  else
    record "8 fhe-load-pk-live" INCONCLUSIVE "submit failed: $SEND_REASON"
  fi
fi

# ── item 6: validator RPC surface ─────────────────────────────────────
hdr "6. octra_isValidator absent / octra_validatorSetProof present"
IV="$(rpc_cap 06-is-validator octra_isValidator "[\"$OP\"]")"
IV_ERR="$(printf '%s' "$IV" | jget '(d.get("error") or {}).get("code","")')"
IV_ANS="$(printf '%s' "$IV" | jget '"yes" if "result" in d else "no"')"
VP="$(rpc_cap 06-validator-set-proof octra_validatorSetProof "[]")"
VP_OK="$(printf '%s' "$VP" | jget '"yes" if isinstance(d.get("result"),(dict,list)) else "no"')"
if [[ -n "$IV_ERR" && "$VP_OK" == "yes" ]]; then
  record "6 validator-rpc-surface" PASS "octra_isValidator errors (code=$IV_ERR) and octra_validatorSetProof answers — ValidatorOracle must move to the proof"
elif [[ "$IV_ANS" == "yes" ]]; then
  record "6 validator-rpc-surface" FAIL "octra_isValidator unexpectedly ANSWERED (see 06-is-validator.json) — upstream analysis wrong"
else
  record "6 validator-rpc-surface" INCONCLUSIVE "isValidator err=${IV_ERR:-<no json>} validatorSetProof=$VP_OK (see 06-*.json)"
fi

# ── item 7: PVAC status for the May-registered wallet ─────────────────
hdr "7. octra_pvacStatus / octra_pvacMigrationStatus"
PS="$(rpc_cap 07-pvac-status octra_pvacStatus "[\"$PVAC_WALLET_ADDR\"]")"
PS_HAS="$(printf '%s' "$PS" | jget '(d.get("result") or {}).get("has_pvac_pubkey")')"
PS_FMT="$(printf '%s' "$PS" | jget '(d.get("result") or {}).get("pubkey_format")')"
PS_CANON="$(printf '%s' "$PS" | jget '(d.get("result") or {}).get("canonical_binding")')"
MS="$(rpc_cap 07-pvac-migration-status octra_pvacMigrationStatus "[\"$PVAC_WALLET_ADDR\"]")"
MS_SUMMARY="$(printf '%s' "$MS" | jget '"result-keys:"+",".join(sorted((d.get("result") or {}).keys())) if isinstance(d.get("result"),dict) else "error:"+str((d.get("error") or {}).get("message",""))')"
if [[ -n "$PS_HAS" ]]; then
  record "7 pvac-status" PASS "has_pvac_pubkey=$PS_HAS pubkey_format=${PS_FMT:-null} canonical_binding=${PS_CANON:-null}; migration: $MS_SUMMARY"
else
  record "7 pvac-status" INCONCLUSIVE "octra_pvacStatus returned no has_pvac_pubkey field (see 07-pvac-status.json)"
fi

# ── summary ───────────────────────────────────────────────────────────
hdr summary
printf '%-28s %-13s %s\n' "ITEM" "VERDICT" "DETAIL"
printf '%-28s %-13s %s\n' "----" "-------" "------"
HIGH_FAIL=0; HIGH_INC=0
i=0
while [[ $i -lt ${#ITEM_NAMES[@]} ]]; do
  printf '%-28s %-13s %s\n' "${ITEM_NAMES[$i]}" "${ITEM_VERDICTS[$i]}" "${ITEM_DETAILS[$i]}"
  if [[ "${ITEM_NAMES[$i]}" == "2 optype-legacy-call" ]]; then
    [[ "${ITEM_VERDICTS[$i]}" == "FAIL" ]] && HIGH_FAIL=1
    [[ "${ITEM_VERDICTS[$i]}" == "INCONCLUSIVE" ]] && HIGH_INC=1
  fi
  i=$((i+1))
done
echo
echo "raw captures: $OUT/"
if [[ $HIGH_FAIL -eq 1 ]]; then
  echo "VERDICT: FAIL — the HIGH-priority op_type item failed: legacy \"call\" is no longer accepted; every foundry-built submission is broken until the signer migrates."
  exit 1
elif [[ $HIGH_INC -eq 1 ]]; then
  echo "VERDICT: INCONCLUSIVE — the HIGH-priority op_type item did not get a chain answer; re-run before trusting anything above."
  exit 2
fi
echo "VERDICT: PASS — HIGH-priority item decisive; read per-item verdicts above (a FAIL on a non-HIGH row is a finding, not a probe error)."
exit 0
