#!/usr/bin/env bash
# WIRED v4 relay-settlement smoke for Octra devnet.
#
# What this proves:
#   - main-v4 deploy/reuse is live on devnet.
#   - node1 and client run through the docker/devnet builder plus shared
#     binary volume, with generated configs pointed at the v4 program.
#   - The real node control route accepts a real dual-signed
#     SignedReceipt over POST /session/:id/receipt and durably vaults it.
#   - The real operator Rust caller path runs:
#       octravpn-node v3 relay-claim --session-id <id>
#     which reads the vaulted receipt, computes SignedReceipt::
#     settlement_preimage(), checks RELAY_ARMED plus deadline, and
#     submits relay_claim.
#
# Known limitation:
#   There is currently no standalone client CLI for settler.rs'
#   submit_arm_relay() path. The production arm path is tied to the
#   tunnel shutdown settle flow. This smoke therefore commits the
#   settlement_hash from a real SignedReceipt, then clearly labels
#   arm_relay as a cast fallback. The POST route and relay-claim CLI are
#   the wired Rust paths exercised end-to-end.
#
# Usage:
#   ./docker/devnet/v4-relay-e2e.sh
#   V4_PROGRAM_ADDR=oct... ./docker/devnet/v4-relay-e2e.sh
#   KEEP_STACK=1 ./docker/devnet/v4-relay-e2e.sh
#
# Required local inputs:
#   - docker/devnet/.env with OCTRA_RPC_URL, or OCTRA_RPC_URL exported.
#   - docker/devnet/state/{deployer.key,node1/wallet.key,node1/wg.key,client/wallet.key}
#   - ../octra-foundry/target/release/octra, or OCTRA_BIN exported.
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ -f docker/devnet/.env ]]; then
  # shellcheck source=/dev/null
  source docker/devnet/.env
fi
if [[ -f docker/devnet/hosts.env ]]; then
  # shellcheck source=/dev/null
  source docker/devnet/hosts.env
fi

OCTRA_RPC_URL="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"
OCTRA_BIN="${OCTRA_BIN:-../octra-foundry/target/release/octra}"
V4_AML="${V4_AML:-program/main-v4.aml}"

DEPLOYER_KEY="${DEPLOYER_KEY:-docker/devnet/state/deployer.key}"
CLIENT_KEY="${CLIENT_KEY:-docker/devnet/state/client/wallet.key}"
NODE1_KEY="${NODE1_KEY:-docker/devnet/state/node1/wallet.key}"
NODE1_WG_KEY="${NODE1_WG_KEY:-docker/devnet/state/node1/wg.key}"

MIN_CIRCLE_STAKE="${MIN_CIRCLE_STAKE:-150000000}"
TAILNET_DEPOSIT="${TAILNET_DEPOSIT:-10000000}"
MAX_PAY="${MAX_PAY:-5000}"
RELAY_NET="${RELAY_NET:-3000}"
RELAY_EXPIRY_EPOCHS="${RELAY_EXPIRY_EPOCHS:-200}"
TX_FEE="${TX_FEE:-1000}"
STATUS_RELAY_ARMED=3
STATUS_RELAY_CLAIMED=4

COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-octra-v4-relay-e2e}"
KEEP_STACK="${KEEP_STACK:-0}"
RUN_STATE_REL="${RUN_STATE_REL:-docker/devnet/.generated/v4-relay-e2e-state}"
HELPER_REL="docker/devnet/.generated/v4-relay-helper"

G='\033[32m'; R='\033[31m'; Y='\033[33m'; D='\033[2m'; C='\033[36m'; B='\033[1m'; NC='\033[0m'
hdr()  { printf "\n${C}== %s ==${NC}\n" "$*"; }
ok()   { printf "  ${G}+${NC} %s\n" "$*"; }
warn() { printf "  ${Y}!${NC} %s\n" "$*"; }
say()  { printf "  ${D}%s${NC}\n" "$*"; }
bold() { printf "${B}%s${NC}\n" "$*"; }
fail() { printf "  ${R}x${NC} %s\n" "$*" >&2; exit 1; }

COMPOSE=(docker compose)
if [[ -f docker/devnet/.env ]]; then
  COMPOSE+=(--env-file docker/devnet/.env)
fi
COMPOSE+=(
  -f docker-compose.yml
  -f docker/devnet/docker-compose.devnet.yml
  --profile devnet
)

cleanup() {
  local code=$?
  if [[ "$KEEP_STACK" == "1" ]]; then
    say "KEEP_STACK=1; leaving compose project '$COMPOSE_PROJECT_NAME' up for inspection"
  else
    COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
    PROGRAM_ADDR="${V4:-oct_placeholder}" \
    HOST_DEVNET_DIR="${RUN_STATE_ABS:-$RUN_STATE_REL}" \
    OCTRA_RPC_URL="$OCTRA_RPC_URL" \
      "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$code"
}
trap cleanup EXIT

require_file() {
  [[ -f "$1" ]] || fail "required file missing: $1"
}

rpc() {
  curl -s -m 10 -X POST "$OCTRA_RPC_URL" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}

json_field_or_regex() {
  local field=$1
  python3 -c '
import json, re, sys
field = sys.argv[1]
txt = sys.stdin.read()
try:
    obj = json.loads(txt)
    val = obj.get(field)
    if val:
        print(val)
        sys.exit(0)
except Exception:
    pass
if field == "address":
    m = re.search(r"\"address\"\s*:\s*\"(oct[0-9A-Za-z]{20,})\"", txt) or re.search(r"\boct[0-9A-Za-z]{20,}\b", txt)
elif field == "tx_hash":
    m = re.search(r"\"tx_hash\"\s*:\s*\"([^\"]+)\"", txt)
else:
    m = None
print(m.group(1) if m else "")
' "$field"
}

tx_hash_from_output() {
  python3 -c '
import re, sys
txt = sys.stdin.read()
m = re.search(r"\"tx_hash\"\s*:\s*\"([^\"]+)\"", txt)
print(m.group(1) if m else "")
'
}

wait_for_tx() {
  local hash=$1 label=${2:-tx}
  [[ -n "$hash" ]] || fail "$label: no tx hash"
  local status reason
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
    sleep 3
    status=$(rpc "octra_transaction" "[\"$hash\"]" \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);r=d.get("result") or {};print(r.get("status","?"))' 2>/dev/null || true)
    case "$status" in
      confirmed) ok "$label confirmed ($hash)"; return 0 ;;
      rejected)
        reason=$(rpc "octra_transaction" "[\"$hash\"]" \
          | python3 -c 'import json,sys;d=json.load(sys.stdin);r=d.get("result") or {};e=r.get("error") or {};print(e.get("reason","") if isinstance(e,dict) else e)' 2>/dev/null || true)
        fail "$label rejected ($hash) $reason"
        ;;
    esac
  done
  fail "$label did not confirm before timeout ($hash; last status=$status)"
}

send_tx() {
  local key=$1; shift
  local method=$1; shift
  local out hash
  out=$("$OCTRA_BIN" cast send --key "$key" --rpc-url "$OCTRA_RPC_URL" \
    --fee "$TX_FEE" "$V4" "$method" "$@" 2>&1) || {
      printf '%s\n' "$out" >&2
      return 1
    }
  hash=$(printf '%s' "$out" | tx_hash_from_output)
  [[ -n "$hash" ]] || {
    printf '%s\n' "$out" >&2
    return 1
  }
  printf '%s\n' "$hash"
}

send_value_tx() {
  local key=$1; shift
  local value=$1; shift
  local method=$1; shift
  local out hash
  out=$("$OCTRA_BIN" cast send --key "$key" --rpc-url "$OCTRA_RPC_URL" \
    --value "$value" --fee "$TX_FEE" "$V4" "$method" "$@" 2>&1) || {
      printf '%s\n' "$out" >&2
      return 1
    }
  hash=$(printf '%s' "$out" | tx_hash_from_output)
  [[ -n "$hash" ]] || {
    printf '%s\n' "$out" >&2
    return 1
  }
  printf '%s\n' "$hash"
}

view_result() {
  local fn=$1 params=$2
  rpc "contract_call" "[\"$V4\",\"$fn\",$params]" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);r=d.get("result") or {};print(r.get("result",""))'
}

storage_value() {
  local fn=$1 params=$2 key=$3
  rpc "contract_call" "[\"$V4\",\"$fn\",$params]" \
    | python3 -c '
import json, sys
key = sys.argv[1]
d = json.load(sys.stdin)
print(((d.get("result") or {}).get("storage") or {}).get(key, ""))
' "$key"
}

wait_contract_live() {
  local addr=$1
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 3
    if rpc "contract_call" "[\"$addr\",\"get_circle_state_version\",[\"$addr\"]]" \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if "result" in d else 1)' 2>/dev/null; then
      ok "main-v4 contract is answering views"
      return 0
    fi
  done
  fail "main-v4 contract did not answer views before timeout: $addr"
}

wait_control_port() {
  local url=$1
  local code
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    sleep 2
    code=$(curl -s -o /dev/null -w '%{http_code}' "$url" || true)
    case "$code" in
      200|503) ok "node1 control plane answered $url (HTTP $code)"; return 0 ;;
    esac
  done
  fail "node1 control plane did not answer $url"
}

write_smoke_configs() {
  rm -rf "$RUN_STATE_ABS"
  mkdir -p "$RUN_STATE_ABS/node1" "$RUN_STATE_ABS/client"
  cp "$NODE1_KEY" "$RUN_STATE_ABS/node1/wallet.key"
  cp "$NODE1_WG_KEY" "$RUN_STATE_ABS/node1/wg.key"
  cp "$CLIENT_KEY" "$RUN_STATE_ABS/client/wallet.key"
  chmod 600 "$RUN_STATE_ABS"/node1/*.key "$RUN_STATE_ABS"/client/*.key 2>/dev/null || true

  cat > "$RUN_STATE_ABS/node1/node.toml" <<EOF
# Generated by docker/devnet/v4-relay-e2e.sh.
# This config deliberately leaves [chain].protocol_version at its
# default v1.1 so octravpn-node run does not auto-register/update v3
# circle state before the smoke's explicit setup txs. The relay-claim
# CLI below still uses the v3 Rust caller against program_addr.
[chain]
rpc_url             = "$OCTRA_RPC_URL"
program_addr        = "$V4"
validator_addr      = "$NODE1_ADDR"
wallet_secret_path  = "/etc/octravpn/wallet.key"

[tunnel]
public_endpoint     = "$NODE1_PUBLIC_ENDPOINT"
listen              = "0.0.0.0:51820"
wg_secret_path      = "/etc/octravpn/wg.key"

[pricing]
price_per_mb        = $NODE1_PRICE_PER_MB
region              = "$NODE1_REGION"

[control]
listen               = "0.0.0.0:51821"
audit_dir            = "/tmp/octravpn-v4-relay-e2e/audit"
receipt_journal_path = "/tmp/octravpn-v4-relay-e2e/receipts.bin"
receipt_vault_path   = "/tmp/octravpn-v4-relay-e2e/receipt-vault.bin"

[control.relay]
enabled             = true
relay_expiry_epochs = $RELAY_EXPIRY_EPOCHS

[attestation]
poll_interval_secs  = 60

[pvac]
enabled              = false
binary_path          = "./pvac-sidecar/octra-pvac-sidecar"
restart_backoff_ms   = 250
request_timeout_secs = 30
EOF

  cat > "$RUN_STATE_ABS/client/client.toml" <<EOF
# Generated by docker/devnet/v4-relay-e2e.sh.
[chain]
rpc_url      = "$OCTRA_RPC_URL"
program_addr = "$V4"

[wallet]
addr        = "$CLIENT_ADDR"
secret_path = "/etc/octravpn/wallet.key"

[v3.relay]
enabled             = true
relay_expiry_epochs = $RELAY_EXPIRY_EPOCHS
EOF
}

write_helper_crate() {
  mkdir -p "$HELPER_REL/src"
  cat > "$HELPER_REL/Cargo.toml" <<'TOML'
[package]
name = "v4-relay-handback"
version = "0.1.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
anyhow = "1"
octravpn-core = { path = "/work/octra/crates/octravpn-core" }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
TOML

  cat > "$HELPER_REL/src/main.rs" <<'RS'
use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::{
    control::{
        announce_signing_payload, AnnounceSessionRequest, PostReceiptResponse,
        SessionStateResponse,
    },
    receipt::SignedReceipt,
    session::SessionId,
    sig::KeyPair,
};
use serde_json::json;

fn arg_value(args: &[String], name: &str) -> Result<String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .ok_or_else(|| anyhow!("missing {name}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let control_url = arg_value(&args, "--control-url")?;
    let session_id: u64 = arg_value(&args, "--session-id")?.parse()?;
    let open_tx_hash = arg_value(&args, "--open-tx-hash")?;

    let id = SessionId::from_u64(session_id);
    let session_kp = KeyPair::generate();
    let client_wg_pubkey = [0x42u8; 32];
    let announce_payload =
        announce_signing_payload(&id, &session_kp.public, &client_wg_pubkey, &open_tx_hash);
    let announce = AnnounceSessionRequest {
        session_id: id.clone(),
        client_pubkey: session_kp.public,
        client_wg_pubkey,
        open_tx_hash,
        client_sig: session_kp.sign(&announce_payload),
    };

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .build()?;
    let base = control_url.trim_end_matches('/');

    let resp = http
        .post(format!("{base}/session"))
        .json(&announce)
        .send()
        .await
        .context("POST /session")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("POST /session failed: status={status} body={body}");
    }

    let state_resp = http
        .get(format!("{base}/session/{}", id.to_hex()))
        .send()
        .await
        .context("GET /session/:id")?;
    if !state_resp.status().is_success() {
        let status = state_resp.status();
        let body = state_resp.text().await.unwrap_or_default();
        bail!("GET /session/:id failed: status={status} body={body}");
    }
    let state: SessionStateResponse = state_resp.json().await.context("decode session state")?;
    let proposed = state.proposed.ok_or_else(|| anyhow!("node returned no proposed receipt"))?;

    let payload = proposed.receipt.signing_payload();
    let signed = SignedReceipt {
        receipt: proposed.receipt,
        client_pubkey: session_kp.public,
        client_sig: session_kp.sign(&payload),
        node_pubkey: proposed.node_pubkey,
        node_sig: proposed.node_sig,
        enc_bytes_used: proposed.enc_bytes_used,
        enc_net: proposed.enc_net,
        pvac_zero_proof: proposed.pvac_zero_proof,
    };
    signed.verify().context("dual-signed receipt self-verify")?;
    let settlement_hash = signed.settlement_hash();

    let post_resp = http
        .post(format!("{base}/session/{}/receipt", id.to_hex()))
        .json(&signed)
        .send()
        .await
        .context("POST /session/:id/receipt")?;
    if !post_resp.status().is_success() {
        let status = post_resp.status();
        let body = post_resp.text().await.unwrap_or_default();
        bail!("POST /session/:id/receipt failed: status={status} body={body}");
    }
    let posted: PostReceiptResponse = post_resp.json().await.context("decode receipt POST")?;
    if !posted.accepted {
        bail!("node rejected countersigned receipt");
    }
    if posted.settlement_hash != settlement_hash {
        bail!(
            "settlement_hash mismatch: local={} node={}",
            settlement_hash,
            posted.settlement_hash
        );
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "session_id": session_id,
            "session_id_hex": id.to_hex(),
            "receipt_seq": signed.receipt.seq,
            "bytes_used": signed.receipt.bytes_used,
            "settlement_hash": settlement_hash,
            "posted": true
        }))?
    );
    Ok(())
}
RS
}

build_binaries() {
  hdr "2/ build node, client, and receipt handback helper"
  COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
  PROGRAM_ADDR="$V4" \
  HOST_DEVNET_DIR="$RUN_STATE_ABS" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
    "${COMPOSE[@]}" run --rm builder bash -c '
      set -euo pipefail
      export PATH="/usr/local/cargo/bin:${PATH}"   # bash -l would drop this in the rust image
      if ! command -v pkg-config >/dev/null || ! command -v protoc >/dev/null; then
        apt-get update -qq
        apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates protobuf-compiler libprotobuf-dev >/dev/null
      fi
      cargo build --release -p octravpn-node -p octravpn-client
      cp -f target/release/octravpn-node /out/octravpn-node
      cp -f target/release/octravpn /out/octravpn
      CARGO_TARGET_DIR=/work/octra/target/v4-relay-helper \
        cargo build --release --manifest-path /work/octra/docker/devnet/.generated/v4-relay-helper/Cargo.toml
      cp -f /work/octra/target/v4-relay-helper/release/v4-relay-handback /out/v4-relay-handback
    '
  ok "builder produced /bin/octravpn/{octravpn-node,octravpn,v4-relay-handback}"
}

start_node() {
  hdr "3/ start node1 control plane"
  COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
  PROGRAM_ADDR="$V4" \
  HOST_DEVNET_DIR="$RUN_STATE_ABS" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
    "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
  COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
  PROGRAM_ADDR="$V4" \
  HOST_DEVNET_DIR="$RUN_STATE_ABS" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
    "${COMPOSE[@]}" up -d --force-recreate node1
  wait_control_port "http://127.0.0.1:51821/health"
}

extract_helper_field() {
  local field=$1
  python3 -c '
import json, sys
field = sys.argv[1]
txt = sys.stdin.read()
start = txt.find("{")
end = txt.rfind("}")
if start < 0 or end < start:
    print("")
    sys.exit(0)
obj = json.loads(txt[start:end+1])
print(obj.get(field, ""))
' "$field"
}

hdr "0/ preflight"
command -v python3 >/dev/null || fail "python3 is required"
command -v curl >/dev/null || fail "curl is required"
command -v docker >/dev/null || fail "docker is required for this smoke"
require_file "$OCTRA_BIN"
require_file "$CLIENT_KEY"
require_file "$NODE1_KEY"
require_file "$NODE1_WG_KEY"
[[ -n "${V4_PROGRAM_ADDR:-}" ]] || require_file "$DEPLOYER_KEY"
require_file "$V4_AML"

CLIENT_ADDR=$("$OCTRA_BIN" cast wallet addr --key "$CLIENT_KEY")
NODE1_ADDR=$("$OCTRA_BIN" cast wallet addr --key "$NODE1_KEY")
NODE1_PUBLIC_ENDPOINT="${NODE1_PUBLIC_ENDPOINT:-node1:51820}"
NODE1_PRICE_PER_MB="${NODE1_PRICE_PER_MB:-100}"
NODE1_REGION="${NODE1_REGION:-relay-smoke}"
CIRCLE_ADDR="${CIRCLE_ADDR:-$NODE1_ADDR}"
RUN_STATE_ABS="$(mkdir -p "$(dirname "$RUN_STATE_REL")" && cd "$(dirname "$RUN_STATE_REL")" && pwd)/$(basename "$RUN_STATE_REL")"

ok "rpc:        $OCTRA_RPC_URL"
ok "client:     $CLIENT_ADDR"
ok "node1:      $NODE1_ADDR"
ok "circle:     $CIRCLE_ADDR"
ok "project:    $COMPOSE_PROJECT_NAME"

hdr "1/ deploy or reuse main-v4"
if [[ -n "${V4_PROGRAM_ADDR:-}" ]]; then
  V4="$V4_PROGRAM_ADDR"
  ok "using V4_PROGRAM_ADDR=$V4"
else
  OUT=$("$OCTRA_BIN" forge create "$V4_AML" \
    --key "$DEPLOYER_KEY" --rpc-url "$OCTRA_RPC_URL" \
    --constructor-args 100 1000 100000000 100 1000 2>&1)
  V4=$(printf '%s' "$OUT" | json_field_or_regex address)
  DEPLOY_TX=$(printf '%s' "$OUT" | json_field_or_regex tx_hash)
  [[ -n "$V4" ]] || {
    printf '%s\n' "$OUT" >&2
    fail "forge create did not return a program address"
  }
  ok "deployed main-v4 @ $V4"
  if [[ -n "$DEPLOY_TX" ]]; then
    wait_for_tx "$DEPLOY_TX" "deploy main-v4"
  fi
fi
wait_contract_live "$V4"

write_smoke_configs
write_helper_crate
build_binaries
start_node

hdr "4/ on-chain setup"
STATE_ROOT=$(python3 - <<'PY'
import hashlib, json
body = {"v": 1, "region": "relay-smoke", "prices": {"shared": 1000}}
raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
print(hashlib.sha256(raw).hexdigest())
PY
)
MEMBERS_ROOT=$(python3 - <<'PY'
import hashlib, json
body = {"v": 1, "members": []}
raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
print(hashlib.sha256(raw).hexdigest())
PY
)
RECEIPT_PK_B64=$("$OCTRA_BIN" cast wallet pubkey --key "$NODE1_WG_KEY")

ACTIVE=$(view_result get_circle_active "[\"$CIRCLE_ADDR\"]" || true)
ACTIVE=$(printf '%s' "$ACTIVE" | tr '[:upper:]' '[:lower:]')  # portable lowercase (bash 3.2-safe)
case "$ACTIVE" in
  true|1)
    ok "register_circle skipped; circle already active"
    ;;
  *)
    TX=$(send_value_tx "$NODE1_KEY" "$MIN_CIRCLE_STAKE" register_circle \
      "\"$CIRCLE_ADDR\"" "\"$STATE_ROOT\"" "\"$RECEIPT_PK_B64\"")
    wait_for_tx "$TX" "register_circle(node1 owns circle)"
    ;;
esac

TID=$(storage_value get_tailnet_treasury "[0]" tailnet_count)
[[ "$TID" =~ ^[0-9]+$ ]] || fail "could not read tailnet_count before create_tailnet"
TX=$(send_value_tx "$CLIENT_KEY" "$TAILNET_DEPOSIT" create_tailnet "\"$MEMBERS_ROOT\"")
wait_for_tx "$TX" "create_tailnet(client owner, tid=$TID)"

say "main-v4 has no configure_tailnet_exit; open_session selects the exit circle directly."
SID=$(storage_value get_session_status "[0]" session_count)
[[ "$SID" =~ ^[0-9]+$ ]] || fail "could not read session_count before open_session"
TX=$(send_tx "$CLIENT_KEY" open_session "$TID" "\"$CIRCLE_ADDR\"" "$MAX_PAY")
OPEN_TX="$TX"
wait_for_tx "$TX" "open_session(client opener, sid=$SID)"
STATUS=$(view_result get_session_status "[$SID]")
[[ "$STATUS" == "0" ]] || fail "expected SESSION_OPEN(0) after open_session; got $STATUS"
ok "session $SID is SESSION_OPEN"

hdr "5/ real POST /session/:id/receipt route"
HANDOFF_OUT=$(
  COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
  PROGRAM_ADDR="$V4" \
  HOST_DEVNET_DIR="$RUN_STATE_ABS" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
    "${COMPOSE[@]}" run --rm --no-deps client \
      /bin/octravpn/v4-relay-handback \
      --control-url http://node1:51821 \
      --session-id "$SID" \
      --open-tx-hash "$OPEN_TX" 2>&1
) || true
printf '%s\n' "$HANDOFF_OUT"
SETTLEMENT_HASH=$(printf '%s' "$HANDOFF_OUT" | extract_helper_field settlement_hash)
RECEIPT_SEQ=$(printf '%s' "$HANDOFF_OUT" | extract_helper_field receipt_seq)
[[ "$SETTLEMENT_HASH" =~ ^[0-9a-f]{64}$ ]] || fail "helper did not return a 64-char settlement_hash"
ok "POST route vaulted real SignedReceipt seq=$RECEIPT_SEQ hash=$SETTLEMENT_HASH"

hdr "6/ arm_relay (cast fallback, real receipt hash)"
say "cast fallback: no standalone client CLI currently invokes settler.rs::submit_arm_relay without running the tunnel shutdown flow."
TX=$(send_tx "$CLIENT_KEY" arm_relay "$SID" "\"$SETTLEMENT_HASH\"" "$RELAY_NET" "$RELAY_EXPIRY_EPOCHS")
wait_for_tx "$TX" "arm_relay cast fallback"
STATUS=$(view_result get_session_status "[$SID]")
[[ "$STATUS" == "$STATUS_RELAY_ARMED" ]] || fail "expected RELAY_ARMED($STATUS_RELAY_ARMED); got $STATUS"
ok "session $SID is RELAY_ARMED"

hdr "7/ real Rust relay-claim CLI"
E_BEFORE=$(view_result get_earnings_total "[\"$CIRCLE_ADDR\"]")
CLAIM_OUT=$(
  COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
  PROGRAM_ADDR="$V4" \
  HOST_DEVNET_DIR="$RUN_STATE_ABS" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
    "${COMPOSE[@]}" exec -T node1 \
      /bin/octravpn/octravpn-node --config /etc/octravpn/node.toml \
      v3 relay-claim --session-id "$SID" 2>&1
) || true
printf '%s\n' "$CLAIM_OUT"
CLAIM_TX=$(printf '%s\n' "$CLAIM_OUT" | sed -n 's/^relay_claim: tx_hash = //p' | head -1)
[[ -n "$CLAIM_TX" ]] || fail "relay-claim CLI did not print a tx hash"
wait_for_tx "$CLAIM_TX" "relay_claim via octravpn-node CLI"

STATUS=$(view_result get_session_status "[$SID]")
[[ "$STATUS" == "$STATUS_RELAY_CLAIMED" ]] || fail "expected RELAY_CLAIMED($STATUS_RELAY_CLAIMED); got $STATUS"
E_AFTER=$(view_result get_earnings_total "[\"$CIRCLE_ADDR\"]")
python3 - "$E_BEFORE" "$E_AFTER" <<'PY' || fail "earnings did not increase: before=$E_BEFORE after=$E_AFTER"
import sys
before = int(sys.argv[1])
after = int(sys.argv[2])
sys.exit(0 if after > before else 1)
PY
ok "session $SID is RELAY_CLAIMED and earnings increased: $E_BEFORE -> $E_AFTER"

bold ""
bold "VERDICT: PASS"
say "Rust-exercised: POST /session/:id/receipt route, receipt vault, octravpn-node v3 relay-claim CLI."
say "Cast fallback: arm_relay only, using the settlement_hash from the real vaulted SignedReceipt."
