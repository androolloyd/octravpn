#!/usr/bin/env bash
# OctraVPN testnet — operator join flow.
#
# A new operator runs this from their own host AFTER receiving a
# preauth key from an existing operator (issued via mesh-control's
# /v1/preauth endpoint, which the operator multisig signed).
#
# Steps:
#   1. Verify the preauth key is a valid base32 token.
#   2. POST to mesh-control /v1/join with the preauth key + the
#      operator's wallet pubkey (from a freshly-generated sealed key).
#   3. mesh-control verifies the preauth signature on chain and the
#      validator-bond, then returns a signed roster envelope.
#   4. We write the roster + the new node config to ./operator-state/
#      and print "JOINED <validator_addr>" on success.
#
# On error: prints a structured `JOIN_ERROR: <code> <message>` line
# and exits non-zero. Codes:
#   E_PREAUTH_MISSING       --preauth-key not supplied
#   E_CONTROL_UNREACHABLE   mesh-control URL did not respond
#   E_PREAUTH_INVALID       mesh-control rejected the preauth key
#   E_BOND_INSUFFICIENT     validator bond below min_endpoint_stake
#   E_ROSTER_BAD_SIG        roster signature did not verify
#   E_UNKNOWN               anything else

set -euo pipefail

usage() {
  cat <<'EOF'
usage: join.sh --preauth-key KEY --control-url URL \
               [--wallet-key PATH] [--endpoint HOST:PORT] [--out DIR]

required:
  --preauth-key   KEY        Base32 preauth token issued by an operator.
  --control-url   URL        Mesh-control endpoint, e.g. https://mesh.testnet.example.com

optional:
  --wallet-key    PATH       Path to the new operator's sealed wallet key.
                             If absent, the script generates one with
                             `octravpn keygen` under --out.
  --endpoint      HOST:PORT  Publicly-reachable WireGuard endpoint of
                             the joining node. Required for a signing
                             role; omittable for observer-only.
  --out           DIR        Where to write operator-state (default
                             ./operator-state).
  --dry-run                  Walk the steps but don't POST.
EOF
}

PREAUTH_KEY=""
CONTROL_URL=""
WALLET_KEY=""
ENDPOINT=""
OUT_DIR="./operator-state"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preauth-key) PREAUTH_KEY="$2"; shift 2 ;;
    --control-url) CONTROL_URL="$2"; shift 2 ;;
    --wallet-key)  WALLET_KEY="$2"; shift 2 ;;
    --endpoint)    ENDPOINT="$2"; shift 2 ;;
    --out)         OUT_DIR="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) printf 'JOIN_ERROR: E_UNKNOWN unrecognised arg: %s\n' "$1" >&2; exit 2 ;;
  esac
done

err() { printf 'JOIN_ERROR: %s %s\n' "$1" "$2" >&2; exit 2; }

[[ -n "$PREAUTH_KEY" ]] || err E_PREAUTH_MISSING "--preauth-key is required (ask an existing operator to issue one)"
[[ -n "$CONTROL_URL" ]] || err E_PREAUTH_MISSING "--control-url is required"

# Sanity: preauth keys are base32, 32 chars (160 bits) — reject
# obviously malformed input before we hit the network.
if ! [[ "$PREAUTH_KEY" =~ ^[A-Z2-7]{32}$ ]]; then
  err E_PREAUTH_INVALID "preauth key must be 32-char base32 (got: ${#PREAUTH_KEY} chars)"
fi

# Check control-plane reachability.
if (( ! DRY_RUN )); then
  if ! curl --silent --fail --max-time 10 "$CONTROL_URL/v1/health" >/dev/null; then
    err E_CONTROL_UNREACHABLE "GET $CONTROL_URL/v1/health failed"
  fi
fi

mkdir -p "$OUT_DIR"

# Generate a wallet if the operator didn't provide one.
if [[ -z "$WALLET_KEY" ]]; then
  WALLET_KEY="$OUT_DIR/wallet.key.sealed"
  if [[ ! -f "$WALLET_KEY" ]]; then
    if (( DRY_RUN )); then
      printf '    [dry-run] would generate %s via octravpn keygen --seal\n' "$WALLET_KEY"
    else
      if ! command -v octravpn >/dev/null; then
        err E_UNKNOWN "octravpn binary not on PATH — install it or pass --wallet-key"
      fi
      octravpn keygen --seal --out "$WALLET_KEY"
    fi
  fi
fi

# Read the pubkey out of the sealed bundle. The bundle format
# carries a plaintext pubkey header so we can do this without
# unsealing the secret half.
if (( DRY_RUN )); then
  PUBKEY="<dry-run-pubkey>"
else
  PUBKEY=$(octravpn keygen --print-pubkey "$WALLET_KEY" 2>/dev/null \
    || err E_UNKNOWN "could not read pubkey from $WALLET_KEY")
fi

printf '\033[1;36m==>\033[0m posting join request to %s\n' "$CONTROL_URL/v1/join"
printf '    pubkey   = %s\n' "$PUBKEY"
printf '    endpoint = %s\n' "${ENDPOINT:-<observer-only>}"

if (( DRY_RUN )); then
  printf 'JOINED %s (dry-run, no chain side effect)\n' "$PUBKEY"
  exit 0
fi

# Build the join payload. mesh-control verifies:
#   - preauth signature (chain side)
#   - operator pubkey is novel (not already a redeemed join)
#   - if `endpoint` is set, the operator is bonded with at least
#     min_endpoint_stake.
PAYLOAD=$(cat <<EOF
{
  "preauth_key": "$PREAUTH_KEY",
  "pubkey":      "$PUBKEY",
  "endpoint":    "$ENDPOINT"
}
EOF
)

# POST, capture body + status.
TMP_BODY=$(mktemp)
trap 'rm -f "$TMP_BODY"' EXIT
HTTP_STATUS=$(curl --silent --max-time 30 \
  -o "$TMP_BODY" \
  -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -X POST \
  --data "$PAYLOAD" \
  "$CONTROL_URL/v1/join" || echo "000")

case "$HTTP_STATUS" in
  200) ;;
  401|403)
    code=$(grep -oE '"code"[[:space:]]*:[[:space:]]*"[^"]+"' "$TMP_BODY" \
            | head -n1 | sed 's/.*"\([^"]*\)"$/\1/')
    err "${code:-E_PREAUTH_INVALID}" "mesh-control rejected join (HTTP $HTTP_STATUS): $(cat "$TMP_BODY")"
    ;;
  409)
    err E_BOND_INSUFFICIENT "bond check failed: $(cat "$TMP_BODY")"
    ;;
  000)
    err E_CONTROL_UNREACHABLE "curl could not reach $CONTROL_URL/v1/join"
    ;;
  *)
    err E_UNKNOWN "HTTP $HTTP_STATUS: $(cat "$TMP_BODY")"
    ;;
esac

# Persist the roster envelope. It's a JWS-style structure with a
# `signature` field over a canonical-JSON `roster`. We don't verify
# the sig here in bash; the validator binary verifies it on start.
cp "$TMP_BODY" "$OUT_DIR/roster.json"
printf 'JOINED %s\n' "$PUBKEY"
printf '\nNext: drop %s alongside your sealed wallet key and start your validator container.\n' "$OUT_DIR/roster.json"
