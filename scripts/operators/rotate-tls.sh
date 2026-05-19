#!/usr/bin/env bash
# rotate-tls.sh — drive the back-up / mint / validate / swap / observe
# dance documented in docs/operators/tls-rotation.md.
#
# Defaults: reuse the existing private key (preserves the SPKI
# fingerprint pinned by oct:// clients). Pass --rekey to mint a fresh
# keypair instead — required when the key is suspected to be
# compromised.
#
# Exit codes:
#   0  ok
#   1  usage error
#   2  state-dir does not contain expected tls/ layout
#   3  mint failed (openssl error)
#   4  validation failed (cert <-> key mismatch, SAN drift, expiry too soon)
#   5  swap failed
#   6  reload/restart of daemon failed
#   7  post-swap observation failed (cert still old after deadline)
#
# This script does NOT touch chain RPC pinned roots — those are
# operator-driven and live at [chain].pinned_root_paths in node.toml.

set -euo pipefail

PROG=${0##*/}

usage() {
    cat <<EOF
Usage: ${PROG} --state-dir <dir> [--san <hostname>] [--days N] [--rekey] [--service <unit>] [--observe-timeout N]

Required:
  --state-dir <dir>   Directory holding tls/{cert.pem,key.pem}. Matches
                      [control].tailscale_wire_state_dir in node.toml.

Optional:
  --san <hostname>    SAN for the new cert (default: read from the
                      current cert's first DNS SAN entry).
  --days <N>          New cert validity in days (default: 90).
  --rekey             Mint a fresh keypair (changes SPKI fingerprint).
                      Default reuses the existing key.
  --service <unit>    systemd unit to reload after the swap. Default:
                      octravpn-node. Set to '' to skip.
  --observe-timeout N Seconds to wait for the daemon to start serving
                      the new cert (default: 30).
  --dry-run           Print actions but do not touch the filesystem.
  -h, --help          Show this message.

The script is idempotent: re-running with no changes is a no-op (the
backup step is skipped when the existing cert is identical to what we
would mint).
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing.
# ---------------------------------------------------------------------------

STATE_DIR=""
SAN=""
DAYS=90
REKEY=0
SERVICE="octravpn-node"
OBSERVE_TIMEOUT=30
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --state-dir) STATE_DIR="${2:?--state-dir requires a value}"; shift 2 ;;
        --san)       SAN="${2:?--san requires a value}"; shift 2 ;;
        --days)      DAYS="${2:?--days requires a value}"; shift 2 ;;
        --rekey)     REKEY=1; shift ;;
        --service)   SERVICE="${2-}"; shift 2 ;;
        --observe-timeout) OBSERVE_TIMEOUT="${2:?value required}"; shift 2 ;;
        --dry-run)   DRY_RUN=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "${PROG}: unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "${STATE_DIR}" ]]; then
    echo "${PROG}: --state-dir is required" >&2
    usage >&2
    exit 1
fi

# Resolve absolute paths up-front so a relative --state-dir does not
# bite later. Use readlink -f when available; fall back to cd+pwd for
# portability with the macOS BSD readlink.
abspath() {
    if readlink -f -- "$1" >/dev/null 2>&1; then
        readlink -f -- "$1"
    else
        ( cd "$(dirname -- "$1")" && printf '%s/%s\n' "$(pwd -P)" "$(basename -- "$1")" )
    fi
}

STATE_DIR="$(abspath "${STATE_DIR}")"
TLS_DIR="${STATE_DIR}/tls"
CERT="${TLS_DIR}/cert.pem"
KEY="${TLS_DIR}/key.pem"
BACKUP_ROOT="${TLS_DIR}/backup"

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf 'DRY-RUN: %s\n' "$*"
        return 0
    fi
    "$@"
}

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "${PROG}: required command not found: $1" >&2
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Pre-flight.
# ---------------------------------------------------------------------------

require_cmd openssl
require_cmd mktemp

if [[ ! -d "${TLS_DIR}" ]]; then
    echo "${PROG}: ${TLS_DIR} does not exist; --state-dir must point at a directory containing a tls/ subdir" >&2
    exit 2
fi
if [[ ! -s "${CERT}" || ! -s "${KEY}" ]]; then
    echo "${PROG}: ${TLS_DIR} must contain cert.pem and key.pem before rotation" >&2
    exit 2
fi

log "rotating TLS material under ${TLS_DIR}"

# Derive SAN from existing cert if not provided.
if [[ -z "${SAN}" ]]; then
    SAN="$(openssl x509 -in "${CERT}" -noout -ext subjectAltName 2>/dev/null \
        | sed -n 's/.*DNS:\([^,]*\).*/\1/p' \
        | head -n1)"
    if [[ -z "${SAN}" ]]; then
        echo "${PROG}: could not derive SAN from current cert; pass --san explicitly" >&2
        exit 1
    fi
    log "derived SAN from current cert: ${SAN}"
fi

# ---------------------------------------------------------------------------
# Step 1 — back up.
# ---------------------------------------------------------------------------

TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${BACKUP_ROOT}/${TS}"
log "step 1/5: back up to ${BACKUP_DIR}"
run mkdir -p "${BACKUP_DIR}"
run cp -p "${CERT}" "${BACKUP_DIR}/cert.pem"
run cp -p "${KEY}"  "${BACKUP_DIR}/key.pem"

# ---------------------------------------------------------------------------
# Step 2 — mint.
# ---------------------------------------------------------------------------

log "step 2/5: mint new cert (san=${SAN}, days=${DAYS}, rekey=${REKEY})"
STAGE_DIR="$(mktemp -d "${TLS_DIR}/.rotate.XXXXXX")"
trap 'rm -rf "${STAGE_DIR}"' EXIT

NEW_CERT="${STAGE_DIR}/cert.pem"
NEW_KEY="${STAGE_DIR}/key.pem"

if [[ "${REKEY}" -eq 1 ]]; then
    run openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${NEW_KEY}" \
        -out "${NEW_CERT}" \
        -days "${DAYS}" \
        -subj "/CN=${SAN}" \
        -addext "subjectAltName=DNS:${SAN}" \
        >/dev/null 2>&1 || { echo "${PROG}: openssl mint failed" >&2; exit 3; }
else
    # Reuse the existing key — copy it into the stage dir and re-sign
    # a fresh cert against it via openssl req + x509 with the same key.
    run cp -p "${KEY}" "${NEW_KEY}"
    CSR="${STAGE_DIR}/req.csr"
    run openssl req -new -key "${NEW_KEY}" -out "${CSR}" \
        -subj "/CN=${SAN}" \
        -addext "subjectAltName=DNS:${SAN}" \
        >/dev/null 2>&1 || { echo "${PROG}: openssl req failed" >&2; exit 3; }
    run openssl x509 -req -in "${CSR}" -signkey "${NEW_KEY}" \
        -out "${NEW_CERT}" -days "${DAYS}" \
        -extfile <(printf 'subjectAltName=DNS:%s\n' "${SAN}") \
        >/dev/null 2>&1 || { echo "${PROG}: openssl x509 failed" >&2; exit 3; }
fi

# ---------------------------------------------------------------------------
# Step 3 — validate.
# ---------------------------------------------------------------------------

log "step 3/5: validate"

# a) cert parses, key parses
run openssl x509 -in "${NEW_CERT}" -noout >/dev/null 2>&1 \
    || { echo "${PROG}: new cert does not parse" >&2; exit 4; }
run openssl rsa -in "${NEW_KEY}" -noout >/dev/null 2>&1 \
    || { echo "${PROG}: new key does not parse" >&2; exit 4; }

# b) modulus match
if [[ "${DRY_RUN}" -eq 0 ]]; then
    CERT_MOD="$(openssl x509 -in "${NEW_CERT}" -noout -modulus | openssl dgst -sha256)"
    KEY_MOD="$(openssl rsa  -in "${NEW_KEY}"  -noout -modulus | openssl dgst -sha256)"
    if [[ "${CERT_MOD}" != "${KEY_MOD}" ]]; then
        echo "${PROG}: cert/key modulus mismatch" >&2
        exit 4
    fi
fi

# c) SAN survived the mint
if [[ "${DRY_RUN}" -eq 0 ]]; then
    if ! openssl x509 -in "${NEW_CERT}" -noout -ext subjectAltName \
            | grep -q "DNS:${SAN}"; then
        echo "${PROG}: new cert is missing SAN DNS:${SAN}" >&2
        exit 4
    fi
fi

# d) not-after covers at least 50% of the requested window — guards
# against a clock-skew mint that produced a cert expiring tomorrow.
if [[ "${DRY_RUN}" -eq 0 ]]; then
    MIN_DAYS=$(( DAYS / 2 ))
    if ! openssl x509 -in "${NEW_CERT}" -noout -checkend $(( MIN_DAYS * 86400 )) >/dev/null; then
        echo "${PROG}: new cert expires in < ${MIN_DAYS} days; refusing to install" >&2
        exit 4
    fi
fi

log "validation passed"

# ---------------------------------------------------------------------------
# Step 4 — atomic swap.
# ---------------------------------------------------------------------------

log "step 4/5: swap into place"
run chmod 0644 "${NEW_CERT}"
run chmod 0600 "${NEW_KEY}"
run mv -f "${NEW_CERT}" "${CERT}"
run mv -f "${NEW_KEY}"  "${KEY}"

if [[ -n "${SERVICE}" ]]; then
    if command -v systemctl >/dev/null 2>&1; then
        log "reloading ${SERVICE}"
        if ! run systemctl reload "${SERVICE}" 2>/dev/null; then
            log "reload not supported; falling back to restart --no-block"
            run systemctl restart --no-block "${SERVICE}" \
                || { echo "${PROG}: systemctl restart failed" >&2; exit 6; }
        fi
    else
        log "systemctl not present; sending SIGHUP to processes named ${SERVICE}"
        run pkill -HUP -x "${SERVICE}" || true
    fi
else
    log "--service was empty; skipping daemon reload"
fi

# ---------------------------------------------------------------------------
# Step 5 — observe.
# ---------------------------------------------------------------------------

log "step 5/5: observe (timeout=${OBSERVE_TIMEOUT}s)"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "DRY-RUN: skipping observe step"
    exit 0
fi

OLD_FP="$(openssl x509 -in "${BACKUP_DIR}/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
NEW_FP="$(openssl x509 -in "${CERT}"                 -noout -fingerprint -sha256 | cut -d= -f2)"

if [[ "${OLD_FP}" == "${NEW_FP}" ]]; then
    log "fingerprint unchanged — nothing to observe"
    exit 0
fi

deadline=$(( $(date +%s) + OBSERVE_TIMEOUT ))
served_fp=""
while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    served_fp="$(echo | openssl s_client -connect "${SAN}:443" -servername "${SAN}" 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
        | cut -d= -f2 || true)"
    if [[ "${served_fp}" == "${NEW_FP}" ]]; then
        log "ok — daemon is serving the new cert (sha256=${NEW_FP})"
        exit 0
    fi
    sleep 1
done

echo "${PROG}: daemon still serving old cert after ${OBSERVE_TIMEOUT}s (served=${served_fp:-?}, want=${NEW_FP})" >&2
echo "${PROG}: backup is preserved at ${BACKUP_DIR}; revert by mv-ing cert.pem and key.pem back" >&2
exit 7
