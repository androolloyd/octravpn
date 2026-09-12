#!/usr/bin/env bash
# run-members-policy.sh — live proof of design item 4: the anchored member
# set is enforced on the stock-Tailscale wire, against a REAL lite_node
# (sequence 12) and the deployed main-v4 program.
#
# What it proves, in order (each step is an assertion):
#   1. a fresh native circle gets its first anchor via `circle bootstrap`
#      (sealed /state-root.json + register_circle) and reads back;
#   2. mesh-control boots with --members-policy-circle and installs a
#      deny-all packet filter before any member is anchored;
#   3. two stock tailscale peers join; with NO members anchored, an ICMP
#      ping (subject to the packet filter) between them FAILS;
#   4. `auth members admit` peer-a  → within an epoch the policy re-renders
#      (matched=1): a→b succeeds, b→a still fails (b is not a member);
#   5. admit peer-b → both directions succeed;
#   6. `auth members evict` peer-a → a→b fails again, b→a still succeeds.
#
# Exit codes:
#   0   all assertions held
#   10  preflight (RPC / program / binaries / keys)
#   20  chain setup (circle deploy or bootstrap never became readable)
#   30  mesh-control did not come up / policy never applied
#   40  tailscale up / convergence
#   60  an enforcement assertion failed
#
# Env knobs: OCTRA_RPC_URL_HOST (host-side RPC), OCTRA_RPC_URL (in-container
# RPC), V4_PROGRAM_ADDR, OPERATOR_KEY, OPERATOR_WG_KEY, MEMBER_WALLET_B,
# OCTRAVPN_SEALED_PASSPHRASE, KEEP_STACK=1 (leave containers up).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../../.." && pwd)
COMPOSE=(docker compose -f "${SCRIPT_DIR}/docker-compose.yml" -f "${SCRIPT_DIR}/docker-compose.members-policy.yml")

OCTRA_BIN="${OCTRA_BIN:-${REPO_ROOT}/../octra-foundry/target/release/octra}"
NODE_BIN="${REPO_ROOT}/target/linux-debug/debug/octravpn-node"
RPC_HOST="${OCTRA_RPC_URL_HOST:-http://127.0.0.1:18080/rpc}"
RPC_CONTAINER="${OCTRA_RPC_URL:-http://host.internal:18080/rpc}"
V4="${V4_PROGRAM_ADDR:-octEeiD9nQpoBmUQs7zj2sKuWAhtFQx1ue5oudsy9ULmpeg}"
OPERATOR_KEY="${OPERATOR_KEY:-${REPO_ROOT}/docker/devnet/state/node1/wallet.key}"
OPERATOR_WG_KEY="${OPERATOR_WG_KEY:-${REPO_ROOT}/docker/devnet/state/node1/wg.key}"
# Member wallets are labels in the anchored set (the CLI binds a wallet to a
# node key); peer-b gets the client devkey's address, peer-a the operator's.
MEMBER_WALLET_B="${MEMBER_WALLET_B:-oct6ktv5K1qQrQsFR9eZjmckZrFh5XxV6Bndbh5iwenDVGB}"
export OCTRAVPN_SEALED_PASSPHRASE="${OCTRAVPN_SEALED_PASSPHRASE:-members-policy-e2e}"
MP="${SCRIPT_DIR}/state/members-policy"
ADMIN_TOKEN="interop-test-token"
LOGIN_SERVER="https://tsi-mesh-control"

step() { printf '\n=== %s ===\n' "$1" >&2; }
ok()   { printf '  + %s\n' "$1" >&2; }
fail() { printf '  ! %s\n' "$1" >&2; exit "$2"; }
rpc()  { curl -sS --max-time 10 "${RPC_HOST}" -H 'content-type: application/json' -d "$1"; }
view() { # view <fn> <json-args>  → result JSON (or empty)
  rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"contract_call\",\"params\":[\"${V4}\",\"$1\",$2]}" \
    | python3 -c 'import sys,json; r=json.load(sys.stdin); print(json.dumps(r.get("result")))' 2>/dev/null || true
}
wait_tx() { # wait_tx <hash> <label>
  local st
  for _ in $(seq 1 40); do
    st=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"octra_transaction\",\"params\":[\"$1\"]}" \
      | python3 -c 'import sys,json; r=json.load(sys.stdin).get("result") or {}; e=r.get("error") or {}; print(r.get("status",""), e.get("reason",""))' 2>/dev/null || true)
    case "${st}" in
      confirmed*|applied*|success*) ok "$2: confirmed"; return 0 ;;
      rejected*|failed*|reverted*) fail "$2: ${st}" 20 ;;
    esac
    sleep 3
  done
  fail "$2: tx $1 never confirmed" 20
}
node_cli() { # node_cli <args…> — the node binary inside mesh-control, with the rendered config
  docker exec tsi-mesh-control octravpn-node --config=/work/state/members-policy/node.toml "$@"
}
peer_json() { docker exec "$1" tailscale status --json 2>/dev/null; }
peer_ip()   { peer_json "$1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])'; }
peer_key()  { peer_json "$1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["Self"]["PublicKey"])'; }
peer_state() { peer_json "$1" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("BackendState",""))' 2>/dev/null || true; }
# The enforcement assertions only mean something if both peers are actually
# registered and running; a logged-out peer also fails to ping.
require_peers_running() {
  for peer in tsi-peer-a tsi-peer-b; do
    st=$(peer_state "${peer}")
    [[ "${st}" == "Running" ]] || { docker exec "${peer}" tailscale status 2>&1 | head -4 >&2; fail "${peer} is not Running (BackendState=${st:-?}) — registration problem, not a policy verdict" 40; }
  done
  ok "both peers Running"
}
# The probe has to be ICMP: an echo request crosses the receiver's packet
# filter (`filter.RunIn`, src-IP match), whereas disco pings are
# WireGuard-internal and TSMP ping requests are answered by tailscaled
# *before* the filter runs (`tstun.Wrapper.filterPacketInboundFromWireGuard`)
# — a TSMP pong proves reachability, not admission. The policy also prunes
# unrelated peers from the netmap, so "no matching peer" is the deny-all
# outcome as much as "no reply" is.
wire_ping() { docker exec "$1" tailscale ping --icmp --c 3 --timeout 4s "$2" >/dev/null 2>&1; }
expect_ping() { # expect_ping <from> <to-ip> <yes|no> <label>
  local got="no"
  # Give the new netmap a moment to land; poll so a slow /map delivery does
  # not masquerade as an enforcement failure.
  for _ in $(seq 1 12); do
    if wire_ping "$1" "$2"; then got="yes"; else got="no"; fi
    [[ "${got}" == "$3" ]] && break
    sleep 5
  done
  if [[ "${got}" == "$3" ]]; then
    ok "$4: ping $1 → $2 = ${got} (expected $3)"
  else
    echo "    $1 state: $(peer_state "$1"); last ping output:" >&2
    docker exec "$1" tailscale ping --icmp --c 1 --timeout 4s "$2" 2>&1 | tail -2 | sed 's/^/      /' >&2 || true
    fail "$4: ping $1 → $2 = ${got}, expected $3" 60
  fi
}
# tracing colours its key=value fields, so strip ANSI before grepping logs.
mc_logs() { docker logs tsi-mesh-control 2>&1 | perl -pe 's/\e\[[0-9;]*m//g'; }
# Only lines logged after the last `mark_logs` count, so a boot-time
# "matched=1" cannot satisfy a wait issued after a later admit.
LOG_MARK=0
mark_logs() { LOG_MARK=$(mc_logs | wc -l | tr -d ' '); }
wait_policy_log() { # wait_policy_log <matched-count>
  for _ in $(seq 1 24); do
    if mc_logs | tail -n +"$((LOG_MARK + 1))" | command grep -E 'members policy applied' | command grep -qE "matched=$1\b"; then
      ok "mesh-control applied a policy with matched=$1"; return 0
    fi
    sleep 5
  done
  fail "mesh-control never logged a policy with matched=$1" 30
}
cleanup() {
  if [[ "${KEEP_STACK:-0}" == "1" ]]; then echo "KEEP_STACK=1; leaving the stack up" >&2; return; fi
  "${COMPOSE[@]}" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "0/ preflight"
[[ -x "${OCTRA_BIN}" ]] || fail "octra binary missing: ${OCTRA_BIN}" 10
[[ -x "${NODE_BIN}" ]]  || fail "linux octravpn-node missing: ${NODE_BIN} (demo/lib/build-linux-binaries.sh)" 10
[[ -s "${OPERATOR_KEY}" && -s "${OPERATOR_WG_KEY}" ]] || fail "operator keys missing" 10
rpc '{"jsonrpc":"2.0","id":1,"method":"node_status","params":[]}' | command grep -q '"result"' || fail "RPC not answering at ${RPC_HOST}" 10
[[ "$(view get_circle_active "[\"${V4}\"]")" != "" ]] || fail "main-v4 at ${V4} is not answering views" 10
OPERATOR_ADDR=$("${OCTRA_BIN}" cast wallet addr --key "${OPERATOR_KEY}")
ok "rpc ${RPC_HOST} (containers: ${RPC_CONTAINER}); program ${V4}; operator ${OPERATOR_ADDR}"

step "1/ native circle (deploy once, reuse across runs)"
mkdir -p "${MP}" "${SCRIPT_DIR}/state/tailscale-wire"
CIRCLE=""
if [[ -s "${MP}/circle.id" ]]; then
  CIRCLE=$(tr -d '[:space:]' <"${MP}/circle.id")
  if "${OCTRA_BIN}" cast circle info "${CIRCLE}" --rpc-url "${RPC_HOST}" >/dev/null 2>&1; then
    ok "reusing circle ${CIRCLE}"
  else
    CIRCLE=""
  fi
fi
if [[ -z "${CIRCLE}" ]]; then
  DEPLOY=$("${OCTRA_BIN}" cast circle deploy --key "${OPERATOR_KEY}" --rpc-url "${RPC_HOST}")
  CIRCLE=$(printf '%s' "${DEPLOY}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["circle_id"])')
  TX=$(printf '%s' "${DEPLOY}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["submit"]["tx_hash"])')
  wait_tx "${TX}" "deploy_circle ${CIRCLE}"
  printf '%s\n' "${CIRCLE}" >"${MP}/circle.id"
fi
export MEMBERS_POLICY_CIRCLE="${CIRCLE}"

step "2/ render the operator config the daemon + CLI share"
cp "${OPERATOR_KEY}" "${MP}/wallet.key"; cp "${OPERATOR_WG_KEY}" "${MP}/wg.key"; chmod 600 "${MP}"/*.key
cat >"${MP}/node.toml" <<TOML
# Generated by run-members-policy.sh — chain side of the members-policy proof.
[chain]
rpc_url             = "${RPC_CONTAINER}"
program_addr        = "${V4}"
validator_addr      = "${OPERATOR_ADDR}"
wallet_secret_path  = "/work/state/members-policy/wallet.key"
circle_id           = "${CIRCLE}"

[tunnel]
public_endpoint     = "tsi-mesh-control:51820"
listen              = "0.0.0.0:51820"
wg_secret_path      = "/work/state/members-policy/wg.key"

[pricing]
price_per_mb        = 100
region              = "interop"

[control]
listen              = "0.0.0.0:51821"
audit_dir           = "/work/state/members-policy/audit"

[control.relay]
enabled             = false

[attestation]
poll_interval_secs  = 60
TOML
ok "wrote ${MP#"${REPO_ROOT}"/}/node.toml (circle ${CIRCLE})"

step "3/ mesh-control up (chain-aware) — and the circle's first anchor"
"${COMPOSE[@]}" down >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d >&2 || fail "compose up" 30
for _ in $(seq 1 20); do docker exec tsi-mesh-control test -x /usr/local/bin/octravpn-node >/dev/null 2>&1 && break; sleep 1; done
sleep 3
docker ps --format '{{.Names}}' | command grep -q '^tsi-mesh-control$' || { docker logs tsi-mesh-control >&2 || true; fail "mesh-control exited (bad [chain] / passphrase?)" 30; }
BOOT=$(node_cli circle bootstrap --circle "${CIRCLE}" 2>&1 || true)
printf '%s\n' "${BOOT}" | sed 's/^/    /' >&2
if printf '%s' "${BOOT}" | command grep -q 'state-root readable: true'; then
  ok "circle already bootstrapped"
else
  node_cli circle bootstrap --circle "${CIRCLE}" --commit 2>&1 | sed 's/^/    /' >&2 || fail "circle bootstrap --commit" 20
  READABLE=""
  for _ in $(seq 1 30); do
    if node_cli circle bootstrap --circle "${CIRCLE}" 2>/dev/null | command grep -q 'state-root readable: true'; then READABLE=1; break; fi
    sleep 4
  done
  [[ -n "${READABLE}" ]] || fail "state-root never became readable after bootstrap (anchor + sealed blob)" 20
  ok "circle bootstrapped: registered + sealed /state-root.json reads back"
fi
# Start from an empty anchored set — a previous run's admits persist on
# chain — so the deny-all assertion below is real.
LISTING=$(node_cli auth --circle "${CIRCLE}" members list 2>&1)
ok "members before the proof: $(printf '%s' "${LISTING}" | head -1)"
STALE=$(printf '%s\n' "${LISTING}" | awk '/^  oct/ {print $1}')
if [[ -n "${STALE}" ]]; then
  mark_logs
  while IFS= read -r w; do
    [[ -n "${w}" ]] || continue
    node_cli auth --circle "${CIRCLE}" members evict --wallet "${w}" 2>&1 | command grep -vE 'INFO|DEBUG' | sed 's/^/    /' >&2
  done <<<"${STALE}"
fi
wait_policy_log 0

step "4/ stock tailscale peers join"
HTTP_BODY=$(curl -fsS --max-time 5 -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
  -d '{"user":"interop-test","reusable":true}' http://127.0.0.1:51821/admin/preauth 2>/dev/null || true)
PREAUTH_KEY=$(printf '%s' "${HTTP_BODY}" | sed -nE 's/.*"key"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')
[[ -n "${PREAUTH_KEY}" ]] || fail "no preauth key from /admin/preauth: ${HTTP_BODY:-(empty)}" 40
for _ in $(seq 1 30); do [[ -s "${SCRIPT_DIR}/state/tailscale-wire/tls.crt" ]] && break; sleep 1; done
for peer in tsi-peer-a tsi-peer-b; do
  docker exec "${peer}" sh -c 'mkdir -p /usr/local/share/ca-certificates && cp /mnt/mesh-control-state/tailscale-wire/tls.crt /usr/local/share/ca-certificates/octravpn-mesh-control.crt && (update-ca-certificates >/dev/null 2>&1 || true)' || true
  docker exec "${peer}" sh -c "/usr/bin/timeout 90 tailscale --socket=/var/run/tailscale/tailscaled.sock up --login-server '${LOGIN_SERVER}' --authkey '${PREAUTH_KEY}' --hostname ${peer} --accept-routes --reset" \
    >"/tmp/tsi-mp-up-${peer}.log" 2>&1 || { tail -n 20 "/tmp/tsi-mp-up-${peer}.log" >&2; fail "tailscale up on ${peer}" 40; }
done
IP_A=""; IP_B=""
for _ in $(seq 1 30); do IP_A=$(peer_ip tsi-peer-a 2>/dev/null || true); IP_B=$(peer_ip tsi-peer-b 2>/dev/null || true); [[ -n "${IP_A}" && -n "${IP_B}" ]] && break; sleep 1; done
[[ -n "${IP_A}" && -n "${IP_B}" ]] || fail "peers never got tailnet IPs" 40
KEY_A=$(peer_key tsi-peer-a); KEY_B=$(peer_key tsi-peer-b)
ok "peer-a ${IP_A} ${KEY_A}"; ok "peer-b ${IP_B} ${KEY_B}"

step "5/ no members anchored ⇒ the wire is closed"
require_peers_running
expect_ping tsi-peer-a "${IP_B}" no "deny-all"
expect_ping tsi-peer-b "${IP_A}" no "deny-all"

step "6/ admit peer-a ⇒ a→b opens, b→a stays closed"
mark_logs
node_cli auth --circle "${CIRCLE}" members admit --wallet "${OPERATOR_ADDR}" --node-key "${KEY_A}" 2>&1 | sed 's/^/    /' >&2
wait_policy_log 1
expect_ping tsi-peer-a "${IP_B}" yes "member a → non-member b"
expect_ping tsi-peer-b "${IP_A}" no  "non-member b → member a"

step "7/ admit peer-b ⇒ both directions open"
mark_logs
node_cli auth --circle "${CIRCLE}" members admit --wallet "${MEMBER_WALLET_B}" --node-key "${KEY_B}" 2>&1 | sed 's/^/    /' >&2
wait_policy_log 2
expect_ping tsi-peer-a "${IP_B}" yes "member a → member b"
expect_ping tsi-peer-b "${IP_A}" yes "member b → member a"

step "8/ evict peer-a ⇒ a→b closes again"
mark_logs
node_cli auth --circle "${CIRCLE}" members evict --wallet "${OPERATOR_ADDR}" 2>&1 | sed 's/^/    /' >&2
wait_policy_log 1
expect_ping tsi-peer-a "${IP_B}" no  "evicted a → member b"
expect_ping tsi-peer-b "${IP_A}" yes "member b → evicted a (b is still a member)"

step "final anchored set"
node_cli auth --circle "${CIRCLE}" members list 2>&1 | sed 's/^/    /' >&2
echo >&2; echo "MEMBERS-POLICY PROOF: PASS (circle ${CIRCLE})" >&2
