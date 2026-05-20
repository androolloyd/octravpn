#!/usr/bin/env bash
# deploy-fronting.sh — mint a Worker HMAC key, deploy the
# domain-fronting DERP Worker, and print the node.toml snippet the
# operator needs to drop into `[tun.derp.front]`.
#
# Usage:
#   ./scripts/operators/deploy-fronting.sh \
#     --real-host derp.example.org \
#     [--name octravpn-front] \
#     [--skip-deploy] \
#     [--skip-smoke]
#
# Requires `wrangler` (Cloudflare CLI) on PATH and a Cloudflare
# account already authenticated via `wrangler login`.  We deliberately
# do NOT bake credentials into this script.
#
# Full walkthrough + threat model: docs/operators/derp-fronting.md.

set -euo pipefail

# ─── arg parsing ────────────────────────────────────────────────────
REAL_HOST=""
WORKER_NAME="octravpn-front"
SKIP_DEPLOY=0
SKIP_SMOKE=0

usage() {
  cat <<EOF
deploy-fronting.sh — deploy a Cloudflare Worker that fronts an
operator-run DERP relay.

Required:
  --real-host HOST     The operator's real DERP origin
                       (e.g. derp.octravpn.example.org).

Optional:
  --name NAME          Worker name (default: octravpn-front).
  --skip-deploy        Just mint a key + print the snippet, don't
                       actually call wrangler.  Useful for dry-runs.
  --skip-smoke         Skip the post-deploy curl smoke test.
  -h, --help           This help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --real-host) REAL_HOST="$2"; shift 2;;
    --name)      WORKER_NAME="$2"; shift 2;;
    --skip-deploy) SKIP_DEPLOY=1; shift;;
    --skip-smoke)  SKIP_SMOKE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

if [[ -z "$REAL_HOST" ]]; then
  echo "error: --real-host is required" >&2
  usage
  exit 2
fi

# ─── workspace layout ───────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FRONT_DIR="$REPO_ROOT/deploy/fronting"

if [[ ! -f "$FRONT_DIR/derp-front.js" ]]; then
  echo "error: $FRONT_DIR/derp-front.js missing — wrong checkout?" >&2
  exit 1
fi

# ─── mint HMAC key (32 bytes, hex-encoded) ──────────────────────────
echo "[1/4] minting 32-byte HMAC key…"
HMAC_HEX="$(openssl rand -hex 32)"
if [[ -z "$HMAC_HEX" || "${#HMAC_HEX}" -ne 64 ]]; then
  echo "error: openssl rand failed (got ${#HMAC_HEX} hex chars)" >&2
  exit 1
fi
echo "      key minted (sha256-prefix: $(echo -n "$HMAC_HEX" | sha256sum | cut -c1-12))"

# ─── deploy ─────────────────────────────────────────────────────────
FRONT_HOST=""
if [[ "$SKIP_DEPLOY" -eq 0 ]]; then
  if ! command -v wrangler >/dev/null 2>&1; then
    echo "error: wrangler not on PATH — install with 'npm i -g wrangler'" >&2
    exit 1
  fi
  echo "[2/4] uploading HMAC key as Worker secret…"
  ( cd "$FRONT_DIR" && \
    echo "$HMAC_HEX" | wrangler secret put OCTRA_FRONT_KEY --name "$WORKER_NAME" )

  echo "[3/4] deploying Worker '$WORKER_NAME'…"
  ( cd "$FRONT_DIR" && wrangler deploy --name "$WORKER_NAME" )

  # wrangler prints `Published octravpn-front (1.23 sec)` followed by
  # the hostname.  Parse it from the most recent deployment list.
  FRONT_HOST="$( ( cd "$FRONT_DIR" && \
    wrangler deployments list --name "$WORKER_NAME" 2>/dev/null \
      | grep -oE '[a-z0-9-]+\.workers\.dev' | head -n1 ) )"
  if [[ -z "$FRONT_HOST" ]]; then
    # Fallback: guess the default Cloudflare hostname pattern.
    FRONT_HOST="${WORKER_NAME}.workers.dev"
    echo "      (couldn't read deployed hostname; assuming $FRONT_HOST)"
  fi
else
  echo "[2/4] (skipped: --skip-deploy)"
  echo "[3/4] (skipped: --skip-deploy)"
  FRONT_HOST="${WORKER_NAME}.workers.dev"
fi

# ─── smoke test ─────────────────────────────────────────────────────
if [[ "$SKIP_SMOKE" -eq 0 && "$SKIP_DEPLOY" -eq 0 ]]; then
  echo "[4/4] smoke testing $FRONT_HOST…"

  # (a) no auth header → expect 404 (Worker pretends to be a stale
  # site).  This proves the Worker is at least reachable.
  CODE_NOAUTH="$(curl -s -o /dev/null -w '%{http_code}' \
    "https://$FRONT_HOST/derp" || echo "000")"
  if [[ "$CODE_NOAUTH" != "404" ]]; then
    echo "      WARN: expected 404 without auth, got $CODE_NOAUTH"
    echo "      (could be Cloudflare cache, transient — investigate)"
  else
    echo "      ok: unauth request → 404"
  fi

  # (b) wrong key → still 404.  We can't easily produce a *valid*
  # request from bash without re-implementing the HMAC, but we can
  # at least confirm that a request carrying garbage gets the same
  # opaque 404.
  CODE_GARBAGE="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "x-octra-front-auth: $(printf '%064d' 0)" \
    -H "x-octra-front-ts: $(date +%s)" \
    -H "host: $REAL_HOST" \
    "https://$FRONT_HOST/derp" || echo "000")"
  if [[ "$CODE_GARBAGE" != "404" ]]; then
    echo "      WARN: expected 404 with wrong key, got $CODE_GARBAGE"
  else
    echo "      ok: wrong key → 404"
  fi
  # A "valid" 200 smoke test requires generating the HMAC; that
  # belongs in `octravpn-node front-test` (TODO; out of scope here).
else
  echo "[4/4] (skipped)"
fi

# ─── emit node.toml snippet ─────────────────────────────────────────
cat <<EOF

────────────────────────────────────────────────────────────────────
  Fronting deploy complete.  Drop the snippet below into node.toml
  on every octravpn-node that should use this Worker as a censor-
  resistant DERP fallback.
────────────────────────────────────────────────────────────────────

[tun.derp.front]
enabled = true
front_host = "$FRONT_HOST"
real_host = "$REAL_HOST"
front_hmac_key = "$HMAC_HEX"

# Reminder: the same HMAC key MUST be present on the Worker side as
# the OCTRA_FRONT_KEY secret.  If you lose this script's output,
# rotate by re-running deploy-fronting.sh.

EOF
