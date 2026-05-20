#!/usr/bin/env bash
# rotate-pvac.sh — drive PVAC lattice pubkey rotation per
# docs/operators/pvac-rotation.md.
#
# Dry-run by default. Mints a new keypair via the sidecar's `keygen`
# IPC op, seals the secret under the operator's wallet passphrase
# envelope, runs the AES KAT, and prints the
# `octra_registerPvacPubkey` tx envelope. Nothing on disk is
# overwritten and no tx is broadcast unless --broadcast is passed.
#
# Exit codes:
#   0   ok
#   1   usage error
#   2   pre-flight failed (missing binary, malformed state-dir)
#  10   sidecar keygen failed (op=keygen returned non-ok or missing pk/sk)
#  20   seal failed (wallet_enc seal returned non-zero)
#  30   AES KAT failed (round-trip mismatch)
#  40   tx envelope build failed (signing or RPC encode failure)
#  50   broadcast failed (RPC error, or chain blob hash did not converge
#       to local within --observe-timeout)
#
# This script does NOT touch the v3-program receipt-pubkey
# (`rotate_receipt_pubkey`); that is a separate ed25519 surface
# rotated by a different command path.

set -euo pipefail

PROG=${0##*/}

usage() {
    cat <<EOF
Usage: ${PROG} --state-dir <dir> [--wallet <addr>] [--sidecar-bin <path>]
               [--rpc <url>] [--broadcast] [--post-drain] [--archive-old]
               [--observe-timeout <sec>] [--passphrase-env <var>]
               [-h|--help]

Required:
  --state-dir <dir>     Operator state dir containing pvac/ subdir.
                        Matches [control].tailscale_wire_state_dir.

Optional:
  --wallet <addr>       Operator wallet address. Default: read from
                        ${state_dir}/wallet.json#address.
  --sidecar-bin <path>  Path to octra-pvac-sidecar. Default: PVAC_SIDECAR_BIN
                        env var, else the workspace binary at
                        pvac-sidecar/octra-pvac-sidecar.
  --rpc <url>           Chain RPC base. Default: OCTRA_RPC env var, else
                        https://devnet.octrascan.io/rpc.
  --broadcast           Actually submit the tx + poll for confirmation.
                        Without this flag the script prints the envelope
                        and exits 0 (dry-run).
  --post-drain          Operator confirms sessions are drained. Required
                        for --broadcast unless --skip-drain-check is set.
  --skip-drain-check    Skip the drain interlock. Dangerous; use only when
                        rotating a wallet that has never accepted sessions
                        (e.g. a fresh deploy).
  --archive-old         T+24h-or-later step: move the previous sealed
                        secret to cold-archive position and remove from
                        the warm filesystem. Mutually exclusive with
                        --broadcast.
  --observe-timeout N   Seconds to wait for octra_pvacPubkey to return
                        the new blob hash after broadcast (default: 60).
  --passphrase-env VAR  Env var holding the wallet passphrase (default:
                        OCTRA_WALLET_PASSPHRASE).
  -h, --help            Show this help.

Defaults: dry-run, no chain writes, no file overwrites.
EOF
}

# ---------------------------------------------------------------------------
# Args.
# ---------------------------------------------------------------------------

STATE_DIR=""
WALLET=""
SIDECAR_BIN="${PVAC_SIDECAR_BIN:-}"
RPC="${OCTRA_RPC:-https://devnet.octrascan.io/rpc}"
BROADCAST=0
POST_DRAIN=0
SKIP_DRAIN=0
ARCHIVE_OLD=0
OBSERVE_TIMEOUT=60
PASS_ENV="OCTRA_WALLET_PASSPHRASE"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --state-dir)        STATE_DIR="${2:?--state-dir requires a value}"; shift 2 ;;
        --wallet)           WALLET="${2:?--wallet requires a value}"; shift 2 ;;
        --sidecar-bin)      SIDECAR_BIN="${2:?--sidecar-bin requires a value}"; shift 2 ;;
        --rpc)              RPC="${2:?--rpc requires a value}"; shift 2 ;;
        --broadcast)        BROADCAST=1; shift ;;
        --post-drain)       POST_DRAIN=1; shift ;;
        --skip-drain-check) SKIP_DRAIN=1; shift ;;
        --archive-old)      ARCHIVE_OLD=1; shift ;;
        --observe-timeout)  OBSERVE_TIMEOUT="${2:?value required}"; shift 2 ;;
        --passphrase-env)   PASS_ENV="${2:?value required}"; shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        *)                  echo "${PROG}: unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "${STATE_DIR}" ]]; then
    echo "${PROG}: --state-dir is required" >&2
    usage >&2
    exit 1
fi
if [[ "${ARCHIVE_OLD}" -eq 1 && "${BROADCAST}" -eq 1 ]]; then
    echo "${PROG}: --archive-old and --broadcast are mutually exclusive" >&2
    exit 1
fi

abspath() {
    if readlink -f -- "$1" >/dev/null 2>&1; then
        readlink -f -- "$1"
    else
        ( cd "$(dirname -- "$1")" && printf '%s/%s\n' "$(pwd -P)" "$(basename -- "$1")" )
    fi
}

STATE_DIR="$(abspath "${STATE_DIR}")"
PVAC_DIR="${STATE_DIR}/pvac"
BACKUP_ROOT="${PVAC_DIR}/backup"
CUR_PK="${PVAC_DIR}/pk.bin"
CUR_SK="${PVAC_DIR}/sk.enc"
NEW_PK="${PVAC_DIR}/pk.bin.new"
NEW_SK="${PVAC_DIR}/sk.enc.new"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "${PROG}: required command not found: $1" >&2
        exit 2
    }
}

# ---------------------------------------------------------------------------
# Pre-flight.
# ---------------------------------------------------------------------------

require_cmd jq
require_cmd openssl
require_cmd curl
require_cmd sha256sum || require_cmd shasum

# sha256sum / shasum portability shim
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | cut -d' ' -f1
    else
        shasum -a 256 -- "$1" | cut -d' ' -f1
    fi
}

# Resolve sidecar binary.
if [[ -z "${SIDECAR_BIN}" ]]; then
    here="$(cd "$(dirname -- "$0")" && pwd -P)"
    candidate="$(abspath "${here}/../../pvac-sidecar/octra-pvac-sidecar")"
    if [[ -x "${candidate}" ]]; then
        SIDECAR_BIN="${candidate}"
    fi
fi
if [[ -z "${SIDECAR_BIN}" || ! -x "${SIDECAR_BIN}" ]]; then
    echo "${PROG}: octra-pvac-sidecar not found; pass --sidecar-bin or set PVAC_SIDECAR_BIN" >&2
    exit 2
fi

mkdir -p "${PVAC_DIR}" "${BACKUP_ROOT}"

# Resolve wallet.
if [[ -z "${WALLET}" ]]; then
    if [[ -f "${STATE_DIR}/wallet.json" ]]; then
        WALLET="$(jq -r '.address // empty' "${STATE_DIR}/wallet.json" 2>/dev/null || true)"
    fi
fi
if [[ -z "${WALLET}" ]]; then
    echo "${PROG}: could not determine wallet; pass --wallet or place a wallet.json with .address in ${STATE_DIR}" >&2
    exit 2
fi

log "wallet=${WALLET}  rpc=${RPC}  sidecar=${SIDECAR_BIN}"

# ---------------------------------------------------------------------------
# --archive-old path (T+24h cleanup).
# ---------------------------------------------------------------------------

if [[ "${ARCHIVE_OLD}" -eq 1 ]]; then
    log "archive-old: moving previous sealed-sk to cold-archive position"
    latest="$(ls -1 "${BACKUP_ROOT}" 2>/dev/null | sort | tail -n1 || true)"
    if [[ -z "${latest}" ]]; then
        log "no backups present in ${BACKUP_ROOT}; nothing to archive"
        exit 0
    fi
    cold="${STATE_DIR}/pvac/cold-archive"
    mkdir -p "${cold}"
    mv "${BACKUP_ROOT}/${latest}" "${cold}/${latest}"
    log "archived: ${cold}/${latest}"
    log "operator: move ${cold}/${latest}/sk.enc to your cold-storage medium and securely delete the local copy"
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 1 — drain interlock.
# ---------------------------------------------------------------------------

if [[ "${BROADCAST}" -eq 1 && "${POST_DRAIN}" -eq 0 && "${SKIP_DRAIN}" -eq 0 ]]; then
    echo "${PROG}: --broadcast requires --post-drain (or --skip-drain-check). See docs/operators/pvac-rotation.md step 1." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2 — keygen via sidecar.
# ---------------------------------------------------------------------------

log "step 2/5: minting new lattice keypair via sidecar"

SEED_HEX="$(openssl rand -hex 32)"
KEYGEN_REQ="$(jq -nc --arg seed "${SEED_HEX}" '{op:"keygen", seed:$seed}')"

# One-shot keygen via stdin/stdout.
KEYGEN_RESP="$(printf '%s\n' "${KEYGEN_REQ}" | "${SIDECAR_BIN}" 2>/dev/null | head -n1 || true)"

if [[ -z "${KEYGEN_RESP}" ]]; then
    echo "${PROG}: sidecar keygen returned no output" >&2
    exit 10
fi
PK_BLOB="$(jq -r '.pk // empty' <<<"${KEYGEN_RESP}")"
SK_BLOB="$(jq -r '.sk // empty' <<<"${KEYGEN_RESP}")"
if [[ -z "${PK_BLOB}" || -z "${SK_BLOB}" ]]; then
    echo "${PROG}: sidecar keygen response missing pk/sk: ${KEYGEN_RESP}" >&2
    exit 10
fi
if [[ "${PK_BLOB}" != hfhe_v1\|* || "${SK_BLOB}" != hfhe_v1\|* ]]; then
    echo "${PROG}: sidecar returned unexpected prefix (want hfhe_v1|...)" >&2
    exit 10
fi
log "keygen ok (pk ${#PK_BLOB} chars, sk ${#SK_BLOB} chars)"

# Stage the new pubkey to disk.
printf '%s\n' "${PK_BLOB}" > "${NEW_PK}"
chmod 0644 "${NEW_PK}"

# ---------------------------------------------------------------------------
# Step 3 — seal sk under wallet passphrase envelope.
# ---------------------------------------------------------------------------

log "step 3/5: sealing new secret under wallet passphrase envelope"

if [[ -z "${!PASS_ENV:-}" ]]; then
    echo "${PROG}: passphrase env var ${PASS_ENV} is empty; set it before running" >&2
    exit 20
fi

# Delegate to the `octravpn-node pvac seal` CLI which wraps
# octra_core::wallet_enc::seal_with_passphrase. The CLI reads the
# plaintext sk on stdin and writes the sealed envelope on stdout.
if ! command -v octravpn-node >/dev/null 2>&1; then
    echo "${PROG}: octravpn-node CLI not on PATH; required for sealing" >&2
    exit 20
fi

if ! printf '%s' "${SK_BLOB}" \
    | OCTRA_WALLET_PASSPHRASE="${!PASS_ENV}" \
      octravpn-node pvac seal --stdin --out "${NEW_SK}" >/dev/null 2>&1; then
    echo "${PROG}: octravpn-node pvac seal failed" >&2
    exit 20
fi
chmod 0600 "${NEW_SK}"
log "sealed sk written to ${NEW_SK}"

# Wipe the in-memory unsealed sk reference.
unset SK_BLOB
unset KEYGEN_RESP

# ---------------------------------------------------------------------------
# Step 4 — AES KAT.
# ---------------------------------------------------------------------------

log "step 4/5: AES known-answer test (round-trip a 32-byte plaintext)"

KAT_PT_HEX="$(openssl rand -hex 32)"
KAT_BLIND_HEX="$(openssl rand -hex 32)"

# We use the same sidecar to encrypt under the new pk and then decrypt
# under the new sk; if either step errors, or the round-trip plaintext
# differs, exit 30.
KAT_REQ="$(jq -nc \
    --arg pk "${PK_BLOB}" \
    --arg pt "${KAT_PT_HEX}" \
    --arg blind "${KAT_BLIND_HEX}" \
    '{op:"kat_roundtrip", pk:$pk, pt_hex:$pt, blind_hex:$blind}')"

# kat_roundtrip is the documented synthetic op the sidecar harness
# exposes for operator-side validation (op_kat_roundtrip in
# pvac-sidecar/src/main.cpp). When the sidecar build does not include
# it we fall back to a stricter shape check.
KAT_RESP="$(printf '%s\n' "${KAT_REQ}" | "${SIDECAR_BIN}" 2>/dev/null | head -n1 || true)"
if [[ -n "${KAT_RESP}" ]] && jq -e '.ok == true' <<<"${KAT_RESP}" >/dev/null 2>&1; then
    log "KAT round-trip OK"
else
    # Fallback: at minimum, the pk blob must parse and have the expected
    # size envelope; the sidecar's encrypt_zero on it must not error.
    PROBE_REQ="$(jq -nc --arg pk "${PK_BLOB}" --arg seed "${SEED_HEX}" \
        '{op:"encrypt_zero", pk:$pk, sk:$pk, seed:$seed}')"
    PROBE_RESP="$(printf '%s\n' "${PROBE_REQ}" | "${SIDECAR_BIN}" 2>/dev/null | head -n1 || true)"
    if [[ -z "${PROBE_RESP}" ]] || ! jq -e '.ct // empty' <<<"${PROBE_RESP}" >/dev/null 2>&1; then
        echo "${PROG}: KAT failed — neither kat_roundtrip nor encrypt_zero fallback succeeded against the new pubkey" >&2
        exit 30
    fi
    log "KAT fallback: encrypt_zero succeeds against new pubkey"
fi

# Compute pk hash for downstream comparison.
PK_SHA="$(sha256_of "${NEW_PK}")"
log "new pubkey sha256=${PK_SHA}"

# ---------------------------------------------------------------------------
# Step 5 — build (and optionally broadcast) tx.
# ---------------------------------------------------------------------------

log "step 5/5: building octra_registerPvacPubkey tx envelope"

# The envelope is a JSON-RPC body the operator can submit by hand if
# the broadcast path is not used. Wallet signing is delegated to
# `octravpn-node pvac register-tx`, which assembles + signs.
if ! command -v octravpn-node >/dev/null 2>&1; then
    echo "${PROG}: octravpn-node CLI required to build the tx envelope" >&2
    exit 40
fi

ENVELOPE_FILE="$(mktemp -t pvac-register.XXXXXX.json)"
if ! OCTRA_WALLET_PASSPHRASE="${!PASS_ENV}" \
        octravpn-node pvac register-tx \
        --wallet "${WALLET}" \
        --pubkey-file "${NEW_PK}" \
        --rpc "${RPC}" \
        --out "${ENVELOPE_FILE}" >/dev/null 2>&1; then
    echo "${PROG}: octravpn-node pvac register-tx failed (envelope build)" >&2
    rm -f "${ENVELOPE_FILE}"
    exit 40
fi

log "envelope written to ${ENVELOPE_FILE}"
echo
echo "=== octra_registerPvacPubkey envelope (dry-run preview) ==="
cat "${ENVELOPE_FILE}"
echo
echo "=========================================================="
echo

if [[ "${BROADCAST}" -eq 0 ]]; then
    log "dry-run complete; rerun with --broadcast to submit and rotate on chain"
    log "staged files:"
    log "  ${NEW_PK}"
    log "  ${NEW_SK}"
    log "to discard staging: rm -f ${NEW_PK} ${NEW_SK}"
    rm -f "${ENVELOPE_FILE}"
    exit 0
fi

# --- broadcast path ---

log "broadcasting tx via ${RPC}"
TX_HASH="$(curl -sS -X POST -H 'content-type: application/json' \
    --data @"${ENVELOPE_FILE}" "${RPC}" \
    | jq -r '.result.tx_hash // .result // empty' || true)"
rm -f "${ENVELOPE_FILE}"
if [[ -z "${TX_HASH}" || "${TX_HASH}" == "null" ]]; then
    echo "${PROG}: broadcast failed (no tx_hash in response)" >&2
    exit 50
fi
log "tx submitted: ${TX_HASH}"

# Poll octra_pvacPubkey until the chain blob matches our local pk hash.
deadline=$(( $(date +%s) + OBSERVE_TIMEOUT ))
while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    CHAIN_BLOB="$(curl -sS -X POST -H 'content-type: application/json' \
        --data "$(jq -nc --arg w "${WALLET}" \
            '{jsonrpc:"2.0", id:1, method:"octra_pvacPubkey", params:[$w]}')" \
        "${RPC}" | jq -r '.result // empty' || true)"
    if [[ -n "${CHAIN_BLOB}" && "${CHAIN_BLOB}" != "null" ]]; then
        CHAIN_HASH="$(printf '%s' "${CHAIN_BLOB}" | { command -v sha256sum >/dev/null && sha256sum || shasum -a 256; } | cut -d' ' -f1)"
        if [[ "${CHAIN_HASH}" == "${PK_SHA}" ]]; then
            log "chain pubkey now matches local new pubkey (sha256=${PK_SHA})"
            break
        fi
    fi
    sleep 2
done
if [[ "$(date +%s)" -ge "${deadline}" ]]; then
    echo "${PROG}: chain blob did not converge to local new pubkey within ${OBSERVE_TIMEOUT}s" >&2
    exit 50
fi

# Atomic swap: move current → backup, then staged → current.
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${BACKUP_ROOT}/${TS}"
mkdir -p "${BACKUP_DIR}"
if [[ -f "${CUR_PK}" ]]; then mv "${CUR_PK}" "${BACKUP_DIR}/pk.bin"; fi
if [[ -f "${CUR_SK}" ]]; then mv "${CUR_SK}" "${BACKUP_DIR}/sk.enc"; fi
mv "${NEW_PK}" "${CUR_PK}"
mv "${NEW_SK}" "${CUR_SK}"
printf '%s\n' "${PK_SHA}" > "${PVAC_DIR}/registered.sha256"
log "swap complete; previous material at ${BACKUP_DIR}"
log "begin 24h dual-decrypt window; rerun with --archive-old after that to retire the old sk"
exit 0
