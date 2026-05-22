#!/usr/bin/env bash
# devnet-circle-deploy.sh
#
# Idempotent deploy of the *one* canonical demo circle used by tapes
# 02 / 15 / 16 / 19 / 00 against the live Octra devnet
# (https://devnet.octrascan.io/rpc).
#
# Behaviour:
#   1. If `demo/state/devnet/circle-id.txt` exists AND `cast circle info
#      <id>` succeeds, exits 0 READY and prints the id.
#   2. Otherwise deploys a fresh circle owned by the devnet deployer
#      wallet (docker/devnet/state/deployer.key), persists the id, and
#      seeds 5 sealed assets (all with the shared passphrase `demo`).
#
# The 5 seeded paths share one passphrase so a single tape can show one
# unseal operation surfacing the whole asset set:
#
#   /policy.json   — v3 policy JSON
#   /index.html    — landing page (HTML)
#   /style.css     — minimal CSS
#   /raw.bin       — 256B random bytes
#   /sealed.json   — sensitive-looking JSON
#
# Why sealed-only: the live devnet chain enforces
# `resource_mode = sealed_read` on every circle as of 2026-05; plaintext
# puts are rejected with `circle_mode_invalid: sealed_read circles
# require encrypted asset updates`. The wire-correct plaintext `cast
# circle put` is in octra-foundry and ready to use the day the chain
# enables a non-sealed resource_mode.
#
# Exit codes:
#   0   READY — circle exists + has assets; id is the last stdout line.
#   10  preflight (binary / wallet / RPC) failed.
#   20  deploy failed.
#   30  asset upload failed.
#
# Env overrides (all optional):
#   OCTRA_BIN       — path to `octra` (default: octra-foundry target).
#   OCTRA_RPC_URL   — RPC endpoint (default: devnet.octrascan.io).
#   DEPLOYER_KEY    — wallet key file (default: docker/devnet/state/deployer.key).
#   FORCE_REDEPLOY  — when set to `1`, ignore the cached id and redeploy.
#
# Stdout (consumer-facing): a single line with the circle id. Anything
# else goes to stderr so the caller can `CIRCLE_ID=$(... bringup.sh)`.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)

STATE_DIR="${REPO_ROOT}/demo/state/devnet"
ID_FILE="${STATE_DIR}/circle-id.txt"
mkdir -p "${STATE_DIR}"

OCTRA_BIN="${OCTRA_BIN:-${REPO_ROOT}/../octra-foundry/target/release/octra}"
if [[ ! -x "${OCTRA_BIN}" ]]; then
    OCTRA_BIN="${REPO_ROOT}/../octra-foundry/target/debug/octra"
fi
OCTRA_RPC_URL="${OCTRA_RPC_URL:-https://devnet.octrascan.io/rpc}"
DEPLOYER_KEY="${DEPLOYER_KEY:-${REPO_ROOT}/docker/devnet/state/deployer.key}"
PASSPHRASE="${OCTRAVPN_SEALED_PASSPHRASE:-demo}"

# Preflight -----------------------------------------------------------
if [[ ! -x "${OCTRA_BIN}" ]]; then
    echo "devnet-circle-deploy: octra binary not found at ${OCTRA_BIN}" >&2
    echo "  build via: (cd ../octra-foundry && cargo build --release -p octra-cli --bin octra)" >&2
    exit 10
fi
if [[ ! -f "${DEPLOYER_KEY}" ]]; then
    echo "devnet-circle-deploy: deployer key missing: ${DEPLOYER_KEY}" >&2
    exit 10
fi
if ! curl -fsS -m 5 -X POST -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"node_status","params":[],"id":1}' \
        "${OCTRA_RPC_URL}" >/dev/null 2>&1; then
    # Some devnet nodes don't expose node_status; try octra_balance as
    # a fallback liveness probe.
    if ! curl -fsS -m 5 -X POST -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","method":"octra_balance","params":["oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm"],"id":1}' \
            "${OCTRA_RPC_URL}" >/dev/null 2>&1; then
        echo "devnet-circle-deploy: RPC unreachable: ${OCTRA_RPC_URL}" >&2
        exit 10
    fi
fi

log() { echo "[devnet-circle-deploy] $*" >&2; }

# Returns 0 if `circle_info <id>` succeeds; 1 otherwise.
circle_alive() {
    local id="$1"
    "${OCTRA_BIN}" cast circle info "${id}" --rpc-url "${OCTRA_RPC_URL}" 2>/dev/null \
        | grep -q '"circle_id"'
}

# Returns 0 if the circle's `assets_root` is non-zero (i.e. at least
# one asset has been written).
circle_has_assets() {
    local id="$1"
    local root
    root=$("${OCTRA_BIN}" cast circle info "${id}" --rpc-url "${OCTRA_RPC_URL}" 2>/dev/null \
        | sed -nE 's/.*"assets_root":[[:space:]]*"([0-9a-fA-F]+)".*/\1/p')
    if [[ -z "${root}" ]]; then
        return 1
    fi
    # All zeroes = empty tree.
    [[ "${root}" =~ ^0+$ ]] && return 1
    return 0
}

# Returns 0 if the named asset exists on-chain at `<id>:<path>`.
asset_exists() {
    local id="$1" path="$2" rk
    rk=$("${OCTRA_BIN}" cast circle key "${id}" "${path}" 2>/dev/null)
    [[ -z "${rk}" ]] && return 1
    "${OCTRA_BIN}" cast circle asset-key "${id}" "${rk}" \
        --rpc-url "${OCTRA_RPC_URL}" 2>/dev/null \
        | grep -q '"ciphertext_b64"'
}

# Returns 0 if all 5 canonical demo assets exist.
circle_fully_seeded() {
    local id="$1"
    for p in /policy.json /index.html /style.css /raw.bin /sealed.json; do
        asset_exists "${id}" "${p}" || return 1
    done
    return 0
}

# Stage 1: reuse cached id if it's still live + fully seeded.
if [[ -z "${FORCE_REDEPLOY:-}" && -f "${ID_FILE}" ]]; then
    CACHED_ID=$(tr -d ' \r\n' < "${ID_FILE}")
    if [[ -n "${CACHED_ID}" ]] && circle_alive "${CACHED_ID}"; then
        if circle_fully_seeded "${CACHED_ID}"; then
            log "reusing existing circle: ${CACHED_ID} (all 5 assets present)"
            echo "${CACHED_ID}"
            exit 0
        fi
        log "circle ${CACHED_ID} exists; resuming asset seed"
        CIRCLE_ID="${CACHED_ID}"
    else
        log "cached id ${CACHED_ID} no longer resolves — deploying fresh"
        CIRCLE_ID=""
    fi
else
    CIRCLE_ID=""
fi

# Stage 2: also probe the previous-agent's known circle as a fallback
# before deploying a new one.
if [[ -z "${CIRCLE_ID}" ]]; then
    KNOWN_CIRCLE="octEY88M6UifvMVR5bDmsjJPYakVoLVomZW7KuLpw8PWv3b"
    if circle_alive "${KNOWN_CIRCLE}"; then
        log "adopting prior-agent circle ${KNOWN_CIRCLE} (alive)"
        CIRCLE_ID="${KNOWN_CIRCLE}"
        printf '%s\n' "${CIRCLE_ID}" > "${ID_FILE}"
    fi
fi

# Stage 3: deploy fresh if neither cache nor known-id worked.
if [[ -z "${CIRCLE_ID}" ]]; then
    log "deploying new circle on ${OCTRA_RPC_URL}"
    DEPLOY_OUT=$("${OCTRA_BIN}" cast circle deploy \
        --key "${DEPLOYER_KEY}" \
        --rpc-url "${OCTRA_RPC_URL}" 2>&1) || {
            echo "devnet-circle-deploy: deploy failed:" >&2
            echo "${DEPLOY_OUT}" >&2
            exit 20
        }
    CIRCLE_ID=$(printf '%s\n' "${DEPLOY_OUT}" \
        | sed -nE 's/.*"circle_id":[[:space:]]*"(oct[A-Za-z0-9]+)".*/\1/p' \
        | head -1)
    if [[ -z "${CIRCLE_ID}" ]]; then
        echo "devnet-circle-deploy: could not parse circle_id from deploy output:" >&2
        echo "${DEPLOY_OUT}" >&2
        exit 20
    fi
    log "deployed circle: ${CIRCLE_ID}"
    printf '%s\n' "${CIRCLE_ID}" > "${ID_FILE}"
    # Wait a few seconds for the circle to settle on-chain before we
    # try writing assets to it.
    sleep 8
fi

# Stage 4: seed the 5 canonical sealed assets (skip ones already on-chain).
if circle_fully_seeded "${CIRCLE_ID}"; then
    log "circle ${CIRCLE_ID} already has all 5 assets — done"
    echo "${CIRCLE_ID}"
    exit 0
fi

log "seeding sealed assets under passphrase '${PASSPHRASE}' (skipping already-on-chain paths)"
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

cat > "${TMP}/policy.json" <<'JSON'
{
  "version": 1,
  "rules": [
    { "action": "accept", "src": ["*"] }
  ]
}
JSON

cat > "${TMP}/index.html" <<'HTML'
<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>octravpn sealed demo</title>
    <link rel="stylesheet" href="/style.css"></head>
  <body>
    <h1>Sealed by default.</h1>
    <p>Every asset under this circle is encrypted at rest on-chain.</p>
  </body>
</html>
HTML

cat > "${TMP}/style.css" <<'CSS'
body { font: 16px/1.4 system-ui, sans-serif; margin: 3rem; color: #222; }
h1   { color: #5a3; }
CSS

# 256B of (deterministic-ish) random for reproducibility.
dd if=/dev/urandom of="${TMP}/raw.bin" bs=256 count=1 status=none

cat > "${TMP}/sealed.json" <<'JSON'
{
  "type": "sealed-demo",
  "secret_token": "this-asset-was-encrypted-on-chain",
  "issued_at": "2026-05-20T00:00:00Z",
  "audience": "demo"
}
JSON

# Look up the current confirmed nonce for the deployer wallet. Devnet's
# `pending_nonce` doesn't tick until tx confirmation, so we bump our
# local counter explicitly across the 5 put-encrypted submits to avoid
# `duplicate nonce` errors.
deployer_addr() {
    "${OCTRA_BIN}" cast wallet addr --key "${DEPLOYER_KEY}" 2>/dev/null \
        | tr -d ' \r\n' || true
}

DEPLOYER_ADDR=$(deployer_addr || true)
if [[ -z "${DEPLOYER_ADDR}" || "${DEPLOYER_ADDR}" != oct* ]]; then
    # Fall back to the public address baked into the previous-agent record.
    DEPLOYER_ADDR="oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm"
fi

current_nonce() {
    curl -s -m 8 -X POST -H 'Content-Type: application/json' \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"octra_balance\",\"params\":[\"${DEPLOYER_ADDR}\"],\"id\":1}" \
            "${OCTRA_RPC_URL}" \
        | sed -nE 's/.*"pending_nonce":[[:space:]]*([0-9]+).*/\1/p' \
        | head -1
}

START_NONCE=$(current_nonce)
if ! [[ "${START_NONCE}" =~ ^[0-9]+$ ]]; then
    echo "devnet-circle-deploy: could not read pending_nonce for ${DEPLOYER_ADDR}" >&2
    exit 30
fi
log "starting nonce sequence at $((START_NONCE + 1))"
LOCAL_NONCE=$((START_NONCE + 1))

put_one() {
    local path="$1" file="$2" ct="$3"
    if asset_exists "${CIRCLE_ID}" "${path}"; then
        log "  skip ${path} — already on-chain"
        return 0
    fi
    log "  put-encrypted ${path} (${ct}) nonce=${LOCAL_NONCE}"
    if ! "${OCTRA_BIN}" cast circle put-encrypted \
            "${CIRCLE_ID}" "${path}" "${file}" \
            --passphrase "${PASSPHRASE}" \
            --content-type "${ct}" \
            --key "${DEPLOYER_KEY}" \
            --nonce "${LOCAL_NONCE}" \
            --rpc-url "${OCTRA_RPC_URL}" 1>&2; then
        echo "devnet-circle-deploy: put-encrypted ${path} failed" >&2
        return 1
    fi
    LOCAL_NONCE=$((LOCAL_NONCE + 1))
    # Wait until the nonce actually rolls forward on-chain. Devnet's
    # mempool rejects back-to-back submits with `duplicate nonce` when
    # the prior tx hasn't confirmed yet — poll until pending_nonce
    # advances or 30s elapse.
    local deadline=$(( $(date +%s) + 30 ))
    while (( $(date +%s) < deadline )); do
        local pn
        pn=$(current_nonce)
        if [[ "${pn}" =~ ^[0-9]+$ ]] && (( pn >= LOCAL_NONCE - 1 )); then
            break
        fi
        sleep 2
    done
    sleep 2
}

put_one /policy.json "${TMP}/policy.json"  "application/json" || exit 30
put_one /index.html  "${TMP}/index.html"   "text/html"        || exit 30
put_one /style.css   "${TMP}/style.css"    "text/css"         || exit 30
put_one /raw.bin     "${TMP}/raw.bin"      "application/octet-stream" || exit 30
put_one /sealed.json "${TMP}/sealed.json"  "application/json" || exit 30

log "circle ready: ${CIRCLE_ID}"
echo "${CIRCLE_ID}"
exit 0
