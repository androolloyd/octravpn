#!/usr/bin/env bash
# v3-smoke-hfhe.sh — honest HFHE settle path against the mock-rpc.
#
# Brings up `octra-mock-rpc` with `OCTRAVPN_E2E_USE_HFHE_MOCK=1` and
# drives the six AML host calls — `fhe_load_pk`, `fhe_deser`,
# `fhe_add`, `fhe_add_const`, `fhe_verify_zero`, `fhe_ser` — through
# the JSON-RPC surface exposed by `crates/octra-mock-rpc/src/aml/host_fhe.rs`.
#
# This is the conformance test for what the real Octra devnet WILL do
# once its `fhe_*` bridge lands. Today devnet reverts every fhe_* call
# (see docs/octra-dev-questions.md §1) — this script proves our client
# side is contract-correct against an honest implementation.
#
# Exit code 0 on success; nonzero on the first failed assertion.
# Mirrors v3-smoke.sh's exit-code shape.

set -euo pipefail

ROOT="$(realpath "$(dirname "$0")/../..")"
FOUNDRY_ROOT="${FOUNDRY_ROOT:-$(realpath "$ROOT/../octra-foundry")}"
RPC_PORT="${RPC_PORT:-18099}"
RPC="http://127.0.0.1:${RPC_PORT}/rpc"

hdr()  { printf "\n=== %s ===\n" "$1"; }
ok()   { printf "  + %s\n" "$1"; }
fail() { printf "  ! %s\n" "$1"; cleanup; exit 1; }

# Tooling check: we need cargo, curl, python3, jq is optional.
command -v cargo  >/dev/null || fail "cargo not on PATH"
command -v curl   >/dev/null || fail "curl not on PATH"
command -v python3 >/dev/null || fail "python3 not on PATH"

PROXY_ADDR="${PROXY_ADDR:-octProxyTestAddr0000000000000000000000000}"

MOCK_PID=""
cleanup() {
  if [[ -n "${MOCK_PID}" ]] && kill -0 "$MOCK_PID" 2>/dev/null; then
    kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# -- helpers -----------------------------------------------------------

rpc() {
  local method=$1; shift
  local params=$1
  curl -fsS -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

extract() {
  python3 -c 'import json,sys; d=json.load(sys.stdin);
err=d.get("error");
sys.exit("rpc error: "+json.dumps(err)) if err else 0;
print(d["result"]'"$1"')'
}

# -- 0. build + start the mock ----------------------------------------

hdr "0. build octra-mock-rpc"
(cd "$FOUNDRY_ROOT" && cargo build -p octra-mock-rpc --release) >/dev/null 2>&1 \
  || fail "cargo build octra-mock-rpc failed"
ok "built"

hdr "1. spawn mock with OCTRAVPN_E2E_USE_HFHE_MOCK=1 on :$RPC_PORT"
OCTRAVPN_E2E_USE_HFHE_MOCK=1 \
  "$FOUNDRY_ROOT/target/release/octra-mock-rpc" \
  --listen "127.0.0.1:$RPC_PORT" \
  --program-addr "octPROGRAMaddress0000000000000000000000" \
  >/tmp/v3-smoke-hfhe-mock.log 2>&1 &
MOCK_PID=$!
# Poll until /rpc responds; bail after 5s.
for _ in $(seq 1 50); do
  if curl -fsS -X POST "$RPC" -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"node_status","params":[]}' \
        >/dev/null 2>&1; then
    ok "mock up (pid=$MOCK_PID)"; break
  fi
  sleep 0.1
done
curl -fsS -X POST "$RPC" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"node_status","params":[]}' \
  >/dev/null 2>&1 || fail "mock failed to come up (see /tmp/v3-smoke-hfhe-mock.log)"

# -- 2. register PVAC pubkey ------------------------------------------

hdr "2. register PVAC pubkey for $PROXY_ADDR"
RESP=$(rpc octra_registerPvacPubkey "[\"$PROXY_ADDR\"]")
PK_B64=$(echo "$RESP" | extract '["pubkey_b64"]')
[[ -n "$PK_B64" ]] || fail "no pubkey_b64 returned"
ok "registered (pk bytes len=$(echo -n "$PK_B64" | base64 -d | wc -c | tr -d ' '))"

hdr "3. fhe_load_pk roundtrip"
RESP=$(rpc octra_fheLoadPk "[\"$PROXY_ADDR\"]")
LOADED_PK=$(echo "$RESP" | extract '["pubkey_b64"]')
[[ "$LOADED_PK" == "$PK_B64" ]] || fail "fhe_load_pk returned different blob"
ok "fhe_load_pk == registered pk"

hdr "4. fhe_load_pk on unregistered address reverts"
set +e
ERR=$(rpc octra_fheLoadPk '["octNoSuchAddr0000000000000000000000000000"]' 2>&1)
set -e
echo "$ERR" | grep -q "pubkey not registered" \
  || fail "unregistered load_pk should revert with 'pubkey not registered', got: $ERR"
ok "unregistered → 'pubkey not registered'"

# -- 5. encrypt 5 + 3 and verify decrypt = 8 --------------------------

hdr "5. encrypt(5) + encrypt(3) → fhe_add → decrypt == 8"
CT5=$(rpc octra_fheEncrypt "[\"$PROXY_ADDR\", 5]" | extract '["ct_b64"]')
CT3=$(rpc octra_fheEncrypt "[\"$PROXY_ADDR\", 3]" | extract '["ct_b64"]')
SUM=$(rpc octra_fheAdd "[\"$CT5\", \"$CT3\"]" | extract '["ct_b64"]')
DEC=$(rpc octra_fheDecrypt "[\"$PROXY_ADDR\", \"$SUM\"]" | extract '["value"]')
[[ "$DEC" == "8" ]] || fail "decrypt(5+3) = $DEC, want 8"
ok "5+3 → decrypts to 8"

# -- 6. malformed ciphertext rejected ---------------------------------

hdr "6. malformed ciphertext rejected"
BAD=$(python3 -c "import base64; print(base64.b64encode(b'short').decode())")
set +e
ERR=$(rpc octra_fheAdd "[\"$BAD\", \"$CT3\"]" 2>&1)
set -e
echo "$ERR" | grep -q "too short" \
  || fail "malformed ct should error with 'too short', got: $ERR"
ok "malformed ct → 'too short'"

# -- 7. settle / claim path: prove enc(balance) - claim = 0 -----------

hdr "7. settle_path: enc(8) - claim 8 via fhe_add_const + zero-proof"
ENC8=$(rpc octra_fheEncrypt "[\"$PROXY_ADDR\", 8]" | extract '["ct_b64"]')
# Two's-complement encoding of -8 in u64: 2^64 - 8 = 18446744073709551608
NEG_CLAIM=18446744073709551608
DELTA=$(rpc octra_fheAddConst "[\"$PROXY_ADDR\", \"$ENC8\", $NEG_CLAIM]" | extract '["ct_b64"]')
DEC_DELTA=$(rpc octra_fheDecrypt "[\"$PROXY_ADDR\", \"$DELTA\"]" | extract '["value"]')
[[ "$DEC_DELTA" == "0" ]] || fail "delta should decrypt to 0, got $DEC_DELTA"
PROOF=$(rpc octra_fheMakeZeroProof "[\"$PROXY_ADDR\", \"$DELTA\"]" | extract '["proof_b64"]')
OK=$(rpc octra_fheVerifyZero "[\"$PROXY_ADDR\", \"$DELTA\", \"$PROOF\"]" | extract '["ok"]')
[[ "$OK" == "True" ]] || fail "fhe_verify_zero should accept honest proof, got $OK"
ok "verify_zero accepts honest proof (enc(8) - 8 == 0)"

# -- 8. overclaim rejected --------------------------------------------

hdr "8. overclaim attempt: enc(8) - 100 ≠ 0 → verify_zero rejects"
NEG_OVER=18446744073709551516   # 2^64 - 100
DELTA_BAD=$(rpc octra_fheAddConst "[\"$PROXY_ADDR\", \"$ENC8\", $NEG_OVER]" | extract '["ct_b64"]')
PROOF_BAD=$(rpc octra_fheMakeZeroProof "[\"$PROXY_ADDR\", \"$DELTA_BAD\"]" | extract '["proof_b64"]')
OK_BAD=$(rpc octra_fheVerifyZero "[\"$PROXY_ADDR\", \"$DELTA_BAD\", \"$PROOF_BAD\"]" | extract '["ok"]')
[[ "$OK_BAD" == "False" ]] || fail "verify_zero should reject overclaim, got $OK_BAD"
ok "overclaim rejected"

# -- 9. determinism: encrypt(5) twice → byte-identical ----------------

hdr "9. determinism: encrypt(5) is pure"
CT5_AGAIN=$(rpc octra_fheEncrypt "[\"$PROXY_ADDR\", 5]" | extract '["ct_b64"]')
[[ "$CT5_AGAIN" == "$CT5" ]] || fail "encrypt(5) not deterministic"
ok "two encrypt(5) calls → byte-identical"

printf "\nv3-smoke-hfhe PASSED — honest HFHE settle path conforms.\n"
exit 0
