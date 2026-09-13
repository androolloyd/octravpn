#!/usr/bin/env bash
# lib-members-policy.sh — shared setup for the two members-policy proofs.
#
#   run-members-policy.sh        packet-filter posture (enforce_registration = false)
#   run-members-registration.sh  admission posture     (enforce_registration = true)
#
# Both drive a real lite_node (sequence 12) + the deployed main-v4 through
# `mesh serve --members-policy-circle`, so everything up to "mesh-control is
# up, the circle is anchored and the member set is empty" is identical. Only
# the assertions differ. Source this, call `mp_setup <true|false>`, then
# assert.
#
# Exit codes (shared, so a CI reader needs one table):
#   0   all assertions held
#   10  preflight (RPC / program / binaries / keys)
#   20  chain setup (circle deploy or bootstrap never became readable)
#   30  mesh-control did not come up / policy never applied
#   40  tailscale up / convergence
#   60  an enforcement assertion failed
#
# Env knobs: OCTRA_RPC_URL_HOST (host-side RPC), OCTRA_RPC_URL (in-container
# RPC), V4_PROGRAM_ADDR, OPERATOR_KEY, OPERATOR_WG_KEY, MEMBER_WALLET_B,
# OCTRAVPN_SEALED_PASSPHRASE, MP_RESET_REGISTRATIONS=1 (wipe machines.sqlite
# before boot), KEEP_STACK=1 (leave containers up).

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
WIRE_STATE="${SCRIPT_DIR}/state/tailscale-wire"
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
peer_json()  { docker exec "$1" tailscale status --json 2>/dev/null; }
peer_ip()    { peer_json "$1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])'; }
peer_key()   { peer_json "$1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["Self"]["PublicKey"])'; }
peer_state() { peer_json "$1" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("BackendState",""))' 2>/dev/null || true; }
# Hostnames of the peers this node currently sees in its netmap, sorted.
peer_names() {
  peer_json "$1" | python3 -c 'import sys,json
d = json.load(sys.stdin)
print(" ".join(sorted(p.get("HostName","?") for p in (d.get("Peer") or {}).values())))' 2>/dev/null || true
}
# The enforcement assertions only mean something if both peers are actually
# registered and running; a logged-out peer also fails to ping.
require_peers_running() {
  local peer st
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
expect_peers() { # expect_peers <peer> <expected space-separated hostnames|-> <label>
  local want="$2" got
  [[ "${want}" == "-" ]] && want=""
  for _ in $(seq 1 12); do
    got=$(peer_names "$1")
    [[ "${got}" == "${want}" ]] && break
    sleep 5
  done
  if [[ "${got}" == "${want}" ]]; then
    ok "$3: $1 sees [${got:-none}]"
  else
    fail "$3: $1 sees [${got:-none}], expected [${want:-none}]" 60
  fi
}
# tracing colours its key=value fields, so strip ANSI before grepping logs.
mc_logs() { docker logs tsi-mesh-control 2>&1 | perl -pe 's/\e\[[0-9;]*m//g'; }
# Only lines logged after the last `mark_logs` count, so a boot-time
# "matched=1" cannot satisfy a wait issued after a later admit.
LOG_MARK=0
mark_logs() { LOG_MARK=$(mc_logs | wc -l | tr -d ' '); }
mc_logs_since_mark() { mc_logs | tail -n +"$((LOG_MARK + 1))"; }
wait_policy_log() { # wait_policy_log <matched-count>
  for _ in $(seq 1 24); do
    if mc_logs_since_mark | command grep -E 'members policy applied' | command grep -qE "matched=$1\b"; then
      ok "mesh-control applied a policy with matched=$1"; return 0
    fi
    sleep 5
  done
  fail "mesh-control never logged a policy with matched=$1" 30
}
# The gate admits from the membership snapshot the sync publishes, so a join
# may only be retried once the daemon has actually re-read the anchor — the
# admit tx itself lands an epoch earlier. This waits for that read.
wait_members_loaded() { # wait_members_loaded <member-count>
  for _ in $(seq 1 24); do
    if mc_logs_since_mark | command grep -E 'anchored member set loaded' | command grep -qE "members=$1\b"; then
      ok "the daemon re-read the anchor: $1 member(s)"; return 0
    fi
    sleep 5
  done
  fail "the daemon never re-read the anchor at $1 member(s)" 30
}

# Machine key of the last registration the gate refused for this hostname —
# the identity an operator can act on. A refused *node* key is already dead:
# a 200-with-error register response burns it and the client retries with a
# fresh one (observed: a new node key every ~15-25s), while the machine key
# is the device's long-lived noise identity and survives re-auth. `hostname`
# is recorded with Debug so tracing quotes it; the keys are Display and bare.
# Never fails: an empty answer is the caller's to interpret (a grep miss
# under `set -e` would otherwise kill the harness).
refused_machine_key() { # refused_machine_key <hostname>
  mc_logs | command grep 'registration refused by the admission gate' \
    | command grep -E "hostname=\"?$1\"?" | tail -1 \
    | sed -nE 's/.*machine_key=([0-9a-fA-F]{64}).*/\1/p' || true
}

# Wait for a peer's own retry loop to complete the login. After an admit the
# client finishes on its own; re-running `tailscale up` would rotate its node
# key, and an operator must not have to.
wait_peer_running() { # wait_peer_running <peer> [seconds]
  local peer="$1" secs="${2:-120}" waited=0
  while (( waited < secs )); do
    [[ "$(peer_state "${peer}")" == "Running" ]] && { ok "${peer} came up on its own retry (${waited}s)"; return 0; }
    sleep 5; waited=$((waited + 5))
  done
  docker exec "${peer}" tailscale status 2>&1 | head -4 >&2
  fail "${peer} never reached Running after being admitted" 40
}

cleanup() {
  if [[ "${KEEP_STACK:-0}" == "1" ]]; then echo "KEEP_STACK=1; leaving the stack up" >&2; return; fi
  "${COMPOSE[@]}" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

mp_preflight() {
  step "0/ preflight"
  [[ -x "${OCTRA_BIN}" ]] || fail "octra binary missing: ${OCTRA_BIN}" 10
  [[ -x "${NODE_BIN}" ]]  || fail "linux octravpn-node missing: ${NODE_BIN} (demo/lib/build-linux-binaries.sh)" 10
  [[ -s "${OPERATOR_KEY}" && -s "${OPERATOR_WG_KEY}" ]] || fail "operator keys missing" 10
  rpc '{"jsonrpc":"2.0","id":1,"method":"node_status","params":[]}' | command grep -q '"result"' || fail "RPC not answering at ${RPC_HOST}" 10
  [[ "$(view get_circle_active "[\"${V4}\"]")" != "" ]] || fail "main-v4 at ${V4} is not answering views" 10
  OPERATOR_ADDR=$("${OCTRA_BIN}" cast wallet addr --key "${OPERATOR_KEY}")
  ok "rpc ${RPC_HOST} (containers: ${RPC_CONTAINER}); program ${V4}; operator ${OPERATOR_ADDR}"
}

mp_circle() {
  step "1/ native circle (deploy once, reuse across runs)"
  mkdir -p "${MP}" "${WIRE_STATE}"
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
    local deploy tx
    deploy=$("${OCTRA_BIN}" cast circle deploy --key "${OPERATOR_KEY}" --rpc-url "${RPC_HOST}")
    CIRCLE=$(printf '%s' "${deploy}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["circle_id"])')
    tx=$(printf '%s' "${deploy}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["submit"]["tx_hash"])')
    wait_tx "${tx}" "deploy_circle ${CIRCLE}"
    printf '%s\n' "${CIRCLE}" >"${MP}/circle.id"
  fi
  export MEMBERS_POLICY_CIRCLE="${CIRCLE}"
}

mp_render_config() { # mp_render_config <enforce_registration: true|false>
  step "2/ render the operator config the daemon + CLI share"
  cp "${OPERATOR_KEY}" "${MP}/wallet.key"; cp "${OPERATOR_WG_KEY}" "${MP}/wg.key"; chmod 600 "${MP}"/*.key
  cat >"${MP}/node.toml" <<TOML
# Generated by the members-policy harness — chain side of the proof.
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

[control.members_policy]
# false ⇒ every key may register and the packet filter decides what it can
# reach (visible-but-mute non-members). true ⇒ membership is admission: a
# non-member cannot register and a removed one loses its registration.
enforce_registration = $1

[control.relay]
enabled             = false

[attestation]
poll_interval_secs  = 60
TOML
  ok "wrote ${MP#"${REPO_ROOT}"/}/node.toml (circle ${CIRCLE}, enforce_registration = $1)"
}

mp_up() {
  step "3/ mesh-control up (chain-aware) — and the circle's first anchor"
  "${COMPOSE[@]}" down >/dev/null 2>&1 || true
  if [[ "${MP_RESET_REGISTRATIONS:-0}" == "1" ]]; then
    rm -f "${WIRE_STATE}"/machines.sqlite*
    ok "wiped the durable registration store — every peer starts unregistered"
  fi
  "${COMPOSE[@]}" up -d >&2 || fail "compose up" 30
  for _ in $(seq 1 20); do docker exec tsi-mesh-control test -x /usr/local/bin/octravpn-node >/dev/null 2>&1 && break; sleep 1; done
  sleep 3
  docker ps --format '{{.Names}}' | command grep -q '^tsi-mesh-control$' \
    || { docker logs tsi-mesh-control >&2 || true; fail "mesh-control exited (bad [chain] / passphrase?)" 30; }
}

mp_bootstrap() {
  local boot readable=""
  boot=$(node_cli circle bootstrap --circle "${CIRCLE}" 2>&1 || true)
  printf '%s\n' "${boot}" | sed 's/^/    /' >&2
  if printf '%s' "${boot}" | command grep -q 'state-root readable: true'; then
    ok "circle already bootstrapped"
    return 0
  fi
  node_cli circle bootstrap --circle "${CIRCLE}" --commit 2>&1 | sed 's/^/    /' >&2 || fail "circle bootstrap --commit" 20
  for _ in $(seq 1 30); do
    if node_cli circle bootstrap --circle "${CIRCLE}" 2>/dev/null | command grep -q 'state-root readable: true'; then readable=1; break; fi
    sleep 4
  done
  [[ -n "${readable}" ]] || fail "state-root never became readable after bootstrap (anchor + sealed blob)" 20
  ok "circle bootstrapped: registered + sealed /state-root.json reads back"
}

mp_clear_members() {
  # Start from an empty anchored set — a previous run's admits persist on
  # chain — so the deny-all assertions below are real.
  local listing stale w
  listing=$(node_cli auth --circle "${CIRCLE}" members list 2>&1)
  ok "members before the proof: $(printf '%s' "${listing}" | head -1)"
  stale=$(printf '%s\n' "${listing}" | awk '/^  oct/ {print $1}')
  if [[ -n "${stale}" ]]; then
    mark_logs
    while IFS= read -r w; do
      [[ -n "${w}" ]] || continue
      node_cli auth --circle "${CIRCLE}" members evict --wallet "${w}" 2>&1 | command grep -vE 'INFO|DEBUG' | sed 's/^/    /' >&2
    done <<<"${stale}"
  fi
  wait_policy_log 0
}

mp_setup() { # mp_setup <enforce_registration: true|false>
  mp_preflight
  mp_circle
  mp_render_config "$1"
  mp_up
  mp_bootstrap
  mp_clear_members
}

mp_preauth_key() {
  local body key
  body=$(curl -fsS --max-time 5 -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d '{"user":"interop-test","reusable":true}' http://127.0.0.1:51821/admin/preauth 2>/dev/null || true)
  key=$(printf '%s' "${body}" | sed -nE 's/.*"key"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')
  [[ -n "${key}" ]] || fail "no preauth key from /admin/preauth: ${body:-(empty)}" 40
  printf '%s' "${key}"
}

mp_install_cert() { # mp_install_cert <peer>
  for _ in $(seq 1 30); do [[ -s "${WIRE_STATE}/tls.crt" ]] && break; sleep 1; done
  docker exec "$1" sh -c 'mkdir -p /usr/local/share/ca-certificates && cp /mnt/mesh-control-state/tailscale-wire/tls.crt /usr/local/share/ca-certificates/octravpn-mesh-control.crt && (update-ca-certificates >/dev/null 2>&1 || true)' || true
}

# `tailscale up` on one peer. Returns its exit status instead of failing, so a
# caller can assert a refusal; the client's output lands in $MP_UP_LOG.
#
# `--force-reauth` is load-bearing for the admission proof: a client that
# still believes it is logged in returns success from `up` without talking to
# the control plane, so without it a refusal assertion can pass on stale
# local state.
mp_try_join() { # mp_try_join <peer> <preauth-key> [timeout-secs]
  local peer="$1" key="$2" secs="${3:-60}"
  MP_UP_LOG="/tmp/tsi-mp-up-${peer}.log"
  mp_install_cert "${peer}"
  docker exec "${peer}" sh -c "/usr/bin/timeout ${secs} tailscale --socket=/var/run/tailscale/tailscaled.sock up \
      --login-server '${LOGIN_SERVER}' --authkey '${key}' --hostname ${peer} --accept-routes --reset --force-reauth" \
    >"${MP_UP_LOG}" 2>&1
}

# Log every peer out and wait for it to leave Running, so a later refusal
# assertion cannot be satisfied by a peer that simply never re-registered.
mp_logout_peers() {
  local peer st
  for peer in tsi-peer-a tsi-peer-b; do
    mp_install_cert "${peer}"
    docker exec "${peer}" tailscale logout >/dev/null 2>&1 || true
    for _ in $(seq 1 15); do
      st=$(peer_state "${peer}")
      [[ "${st}" != "Running" ]] && break
      sleep 2
    done
    st=$(peer_state "${peer}")
    [[ "${st}" != "Running" ]] || fail "${peer} is still Running after logout (state=${st})" 40
    ok "${peer} logged out (state=${st:-?})"
  done
}

mp_join_or_fail() { # mp_join_or_fail <peer> <preauth-key>
  mp_try_join "$1" "$2" 90 || { tail -n 20 "${MP_UP_LOG}" >&2; fail "tailscale up on $1" 40; }
}

# Start `tailscale up` and return immediately. The client keeps retrying in
# the background, which is what makes admit-during-the-attempt work.
mp_start_join() { # mp_start_join <peer> <preauth-key>
  local peer="$1" key="$2"
  mp_install_cert "${peer}"
  docker exec -d "${peer}" sh -c "tailscale --socket=/var/run/tailscale/tailscaled.sock up \
      --login-server '${LOGIN_SERVER}' --authkey '${key}' --hostname ${peer} --accept-routes --reset --force-reauth \
      >/tmp/up.log 2>&1"
}

mp_wait_ips() { # sets IP_A / IP_B
  IP_A=""; IP_B=""
  for _ in $(seq 1 30); do
    IP_A=$(peer_ip tsi-peer-a 2>/dev/null || true)
    IP_B=$(peer_ip tsi-peer-b 2>/dev/null || true)
    [[ -n "${IP_A}" && -n "${IP_B}" ]] && break
    sleep 1
  done
  [[ -n "${IP_A}" && -n "${IP_B}" ]] || fail "peers never got tailnet IPs" 40
}
