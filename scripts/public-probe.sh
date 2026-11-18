#!/usr/bin/env bash
# public-probe.sh — is the public front door serving, and if not, which
# layer is the one that is down?
#
# The deployment is a public relay (TLS + reverse proxy) in front of a node
# and its Circle gateway. Those fail differently, and the HTTP status says
# which one failed:
#
#   serving        200            the gateway answered from canonical state
#   synchronizing  503 + the gateway's "Node is synchronizing" body: the node
#                                 is up but not at head, so it refuses to serve
#   origin_down    502 / 504      the relay's proxy answered; nothing behind
#                                 it did (node, gateway or the tunnel to them)
#   unreachable    no response    DNS, TLS or the relay itself
#   unexpected     anything else
#
# A site that is down was invisible from October 21 until someone happened
# to curl it; this exists so that the state is reported, not discovered.
#
# Usage:
#   scripts/public-probe.sh                 # probes https://octra.to/
#   PROBE_URL=... PROBE_ATTEMPTS=1 scripts/public-probe.sh
#
# Outputs key=value lines (appended to $GITHUB_OUTPUT when set, and always
# printed): state, http_code, detail, tls_days_left, devnet_epoch, checked_at.
#
# Exit code is 0 for every state — "down" is a result, not a script failure.
# It is 2 only when the probe itself cannot run (missing tool, bad usage).
set -euo pipefail

URL="${PROBE_URL:-https://octra.to/}"
ATTEMPTS="${PROBE_ATTEMPTS:-3}"
PAUSE="${PROBE_PAUSE_SECONDS:-20}"
DEVNET_RPC="${PROBE_DEVNET_RPC:-https://devnet.octrascan.io/rpc}"

for tool in curl python3 openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "public-probe: missing '$tool'" >&2; exit 2; }
done

body="$(mktemp)"
trap 'rm -f "$body"' EXIT

classify() { # classify <http_code> <body-file>
  case "$1" in
    200) echo serving ;;
    503)
      if grep -q 'Node is synchronizing' "$2" 2>/dev/null; then echo synchronizing; else echo unexpected; fi ;;
    502|504) echo origin_down ;;
    000) echo unreachable ;;
    *) echo unexpected ;;
  esac
}

# A transient blip is not an outage: only report "not serving" when every
# attempt agrees. One good answer is enough to call it serving.
state=unreachable
code=000
attempt=1
while (( attempt <= ATTEMPTS )); do
  code="$(curl -sS --max-time 15 -o "$body" -w '%{http_code}' "$URL" 2>/dev/null || true)"
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  state="$(classify "$code" "$body")"
  [[ "$state" == serving ]] && break
  (( attempt < ATTEMPTS )) && sleep "$PAUSE"
  attempt=$(( attempt + 1 ))
done

case "$state" in
  serving)       detail="the gateway answered" ;;
  synchronizing) detail="the node is up but not at head; it refuses to serve until it is" ;;
  origin_down)   detail="the relay's proxy answered HTTP ${code}; the node or gateway behind it did not" ;;
  unreachable)   detail="no HTTP response: DNS, TLS or the relay itself" ;;
  *)             detail="unexpected HTTP ${code}" ;;
esac

# Days until the certificate the relay presents expires. Unknown when there
# is no TLS endpoint to ask, or the URL is not https.
tls_days_left=unknown
if [[ "$URL" == https://* ]]; then
  host="${URL#https://}"; host="${host%%/*}"
  port=443
  [[ "$host" == *:* ]] && { port="${host##*:}"; host="${host%%:*}"; }
  not_after="$( (echo | openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//') || true)"
  if [[ -n "$not_after" ]]; then
    tls_days_left="$(python3 - "$not_after" <<'PY' || echo unknown
import datetime, sys
expires = datetime.datetime.strptime(sys.argv[1].strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
print((expires - datetime.datetime.now(datetime.timezone.utc)).days)
PY
)"
  fi
fi

# Reference point: where the chain itself is. Best effort — the reference
# RPC being down must not change the verdict about our own deployment.
devnet_epoch="$(curl -sS --max-time 10 "$DEVNET_RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"node_status","params":[]}' 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["epoch"])' 2>/dev/null || echo unknown)"

emit() {
  printf '%s\n' "$1"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then printf '%s\n' "$1" >> "$GITHUB_OUTPUT"; fi
}
emit "state=${state}"
emit "http_code=${code}"
emit "detail=${detail}"
emit "tls_days_left=${tls_days_left}"
emit "devnet_epoch=${devnet_epoch}"
emit "checked_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
