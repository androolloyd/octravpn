#!/usr/bin/env bash
# octra-release-canary.sh — fetch + verify the signed Octra devnet release
# marker and diff it against the committed baseline.
#
# octra-labs ships MANDATORY, epoch-gated node releases roughly weekly, and
# consensus rules change under us without any notification on our side. Our
# devnet fixtures (crates/octravpn-core/tests/devnet_rpc_contract.rs and the
# docker/devnet e2e suites) are frozen snapshots of chain behavior, so they
# rot silently when source_commit / consensus_rules_id move. This script is
# the detector; .github/workflows/octra-release-canary.yml is the alarm.
#
# The verification is a faithful port of the upstream node operator tooling
# (lite_node controls/lib/release.py — validate() + verify() + decode()),
# NOT a loose "did the JSON parse" check:
#   * exact field set, schema/key_id/chain_id pinning, enum + regex checks
#   * signing payload = compact JSON ARRAY of the 14 field values in
#     declaration order (separators (",",":"), ensure_ascii=False)
#   * raw ed25519 verify via `openssl pkeyutl -rawin` against the pinned
#     release key
#   * freshness: issued_at <= now+5min, expires_at > now, and the
#     issued->expires window capped at 72h (upstream re-signs ~3x/week)
#   * anti-rollback vs the baseline: sequence must not decrease, and an
#     equal sequence must be byte-identical (mirrors release.py trusted())
# An unverified canary is worse than none — it invites trusting a spoofed
# response — so any verification failure is a hard error, never a "skip".
#
# The baseline file is the last marker we ACCEPTED, verbatim, so it stays
# re-verifiable by this same code path (signature included; validated with
# fresh=false since it will usually be past its 72h expiry). Update it only
# after the re-verification checklist in the drift issue is done.
#
# Usage:
#   scripts/octra-release-canary.sh                       # default baseline
#   scripts/octra-release-canary.sh --baseline FILE \
#       --marker-out /tmp/marker.json                     # CI invocation
#   OCTRA_RELEASE_URL=... scripts/octra-release-canary.sh # test override
#
# Outputs: key=value lines appended to $GITHUB_OUTPUT when set (else stdout):
#   outcome, sequence, action, notice_code, source_commit,
#   consensus_rules_id, consensus_profile, issued_at, expires_at,
#   baseline_sequence, baseline_source_commit, baseline_consensus_rules_id,
#   changed_fields (csv, drift only)
#
# Exit codes:
#   0  — marker verified; source_commit and consensus_rules_id match baseline
#   10 — marker verified; DRIFT from baseline (fixtures need re-verification),
#        or no baseline is committed yet (outcome=unseeded)
#   2  — fetch / verification / environment failure (fail the CI job)
#
set -euo pipefail

log() { printf '\033[1;34m[canary]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[canary] error:\033[0m %s\n' "$*" >&2; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
octra_root="$(cd "${script_dir}/.." && pwd)"

URL="${OCTRA_RELEASE_URL:-https://releases.octra.network/v1/devnet/latest.json}"
baseline="${octra_root}/docs/audit/octra-release-baseline.json"
marker_out=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline)   baseline="$2";   shift 2 ;;
    --marker-out) marker_out="$2"; shift 2 ;;
    *) err "unknown argument: $1"; exit 2 ;;
  esac
done

# Tool preflight. openssl is required by the verifier itself (release.py
# raises the same way); report everything missing at once.
missing=0
for tool in curl python3 openssl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "missing '$tool'"
    missing=1
  fi
done
(( missing )) && exit 2

tmp="$(mktemp -d "${TMPDIR:-/tmp}/octra-canary.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Fetch. curl does not follow redirects unless told to, and we deliberately
# do NOT pass -L: release.py refuses redirects outright (NoRedirect), so a
# 30x lands here as a non-200 and is treated as an origin failure. The size
# cap mirrors the upstream 16 KiB limit (curl aborts a touch above it; the
# verifier enforces the exact 16384-byte cap).
log "fetching ${URL}"
http_code="$(curl -sS --max-time 15 --max-filesize 20480 \
  -H 'Accept: application/json' -H 'User-Agent: octra-release-canary/1' \
  -o "$tmp/marker.raw" -w '%{http_code}' "$URL")" || {
  err "release marker origin is unavailable"
  exit 2
}
if [[ "$http_code" != "200" ]]; then
  err "release marker fetch returned HTTP ${http_code} (redirects are refused)"
  exit 2
fi

# Verify + compare. Ported from lite_node controls/lib/release.py; keep the
# checks and their error strings aligned with upstream so a divergence in
# behavior is easy to spot when they revise their tooling.
out_kv="$tmp/outputs.kv"
set +e
python3 - "$tmp/marker.raw" "$baseline" "$out_kv" "${marker_out:-}" <<'PYEOF'
import base64, binascii, datetime, json, re, subprocess, sys, tempfile
from pathlib import Path

raw_path, baseline_path, out_kv, marker_out = sys.argv[1:5]

KEY_ID = "devnet-release-f912b4891be62acc"
CHAIN = "octra-devnet-9871-cluster"
KEY = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA3csWqO5Eoat2ZtlmcclQ1LuCCafYPKv2uo9CwZv0Mzs=
-----END PUBLIC KEY-----
"""
FIELDS = (
    "schema",
    "chain_id",
    "key_id",
    "sequence",
    "action",
    "notice_code",
    "public_commit",
    "source_commit",
    "network_sha256",
    "runtime_profile_hash",
    "consensus_profile",
    "consensus_rules_id",
    "issued_at",
    "expires_at",
)
ACTIONS = frozenset({"current", "recommended", "required", "hold"})
NOTICES = frozenset({
    "consensus_recovery",
    "routine_update",
    "release_hold",
    "release_current",
})
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ValidatorError(Exception):
    pass


def release_time(raw):
    if not isinstance(raw, str):
        raise ValidatorError("release marker time is invalid")
    try:
        value = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidatorError("release marker time is invalid") from error
    if value.tzinfo is None:
        raise ValidatorError("release marker time is invalid")
    return value.astimezone(datetime.timezone.utc)


def payload(value):
    return json.dumps(
        [value[field] for field in FIELDS],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def validate(value, fresh=True):
    if not isinstance(value, dict) or set(value) != {*FIELDS, "signature"}:
        raise ValidatorError("release marker fields are invalid")
    if value["schema"] != "octra-devnet-release-v2":
        raise ValidatorError("release marker schema is invalid")
    if value["key_id"] != KEY_ID:
        raise ValidatorError("release marker key id is invalid")
    if value["chain_id"] != CHAIN:
        raise ValidatorError("release marker chain is invalid")
    if value["action"] not in ACTIONS:
        raise ValidatorError("release marker action is invalid")
    if value["notice_code"] not in NOTICES:
        raise ValidatorError("release marker notice code is invalid")
    sequence = value["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ValidatorError("release marker sequence is invalid")
    for field in ("public_commit", "source_commit"):
        if not isinstance(value[field], str) or not HEX40.fullmatch(value[field]):
            raise ValidatorError(f"release marker {field} is invalid")
    if value["public_commit"] == "0" * 40:
        raise ValidatorError("release marker public commit is not published")
    for field in ("network_sha256", "runtime_profile_hash"):
        if not isinstance(value[field], str) or not HEX64.fullmatch(value[field]):
            raise ValidatorError(f"release marker {field} is invalid")
    profile = value["consensus_profile"]
    if not isinstance(profile, int) or isinstance(profile, bool) or profile < 1:
        raise ValidatorError("release marker consensus profile is invalid")
    rules = value["consensus_rules_id"]
    if not isinstance(rules, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", rules):
        raise ValidatorError("release marker consensus rules id is invalid")
    signature = value["signature"]
    if not isinstance(signature, str) or not re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature):
        raise ValidatorError("release marker signature encoding is invalid")
    issued = release_time(value["issued_at"])
    expires = release_time(value["expires_at"])
    clock = datetime.datetime.now(datetime.timezone.utc)
    if issued > clock + datetime.timedelta(minutes=5):
        raise ValidatorError("release marker was issued in the future")
    if fresh and expires <= clock:
        raise ValidatorError("release marker is expired")
    if issued >= expires or expires - issued > datetime.timedelta(hours=72):
        raise ValidatorError("release marker time range is invalid")


def verify(value):
    try:
        signature = base64.b64decode(value["signature"], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValidatorError("release marker signature is invalid") from error
    if len(signature) != 64:
        raise ValidatorError("release marker signature is invalid")
    with tempfile.TemporaryDirectory(prefix="octra-release-") as directory:
        root = Path(directory)
        data = root / "payload"
        signed = root / "signature"
        public = root / "public.pem"
        data.write_bytes(payload(value))
        signed.write_bytes(signature)
        public.write_bytes(KEY)
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(public), "-rawin",
                "-in", str(data), "-sigfile", str(signed),
            ],
            check=False,
            capture_output=True,
        )
    if result.returncode != 0:
        raise ValidatorError("release marker signature verification failed")


def decode(raw, fresh=True):
    if len(raw) > 16_384:
        raise ValidatorError("release marker exceeds size limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidatorError("release marker is not valid JSON") from error
    validate(value, fresh=fresh)
    verify(value)
    return value


def emit(handle, **fields):
    for key, value in fields.items():
        handle.write(f"{key}={value}\n")


try:
    marker = decode(Path(raw_path).read_bytes(), fresh=True)

    # The baseline is the last marker we accepted. It is normally past its
    # own 72h expiry, so validate with fresh=False — exactly how release.py
    # treats its on-disk cache — but its signature must still verify: a
    # tampered baseline would silently mask drift.
    baseline = None
    if Path(baseline_path).exists():
        baseline = decode(Path(baseline_path).read_bytes(), fresh=False)
        if marker["sequence"] < baseline["sequence"]:
            raise ValidatorError("release marker sequence would roll back")
        if marker["sequence"] == baseline["sequence"] and marker != baseline:
            raise ValidatorError("release marker sequence was reused")

    if marker_out:
        Path(marker_out).write_text(
            json.dumps(marker, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    # The two fields our frozen fixtures actually depend on. Anything else
    # (network_sha256, runtime_profile_hash, ...) matters to node OPERATORS,
    # not to RPC/consensus-contract consumers like us — but they still ride
    # along in the outputs for the issue body.
    watched = ("source_commit", "consensus_rules_id")
    changed = [
        field for field in watched
        if baseline is not None and marker[field] != baseline[field]
    ]
    if changed:
        outcome = "drift"
    elif baseline is None:
        # Verified fine, but there is no committed baseline to compare
        # against. Reported as its own outcome (and exits like drift) so
        # the missing seed cannot be mistaken for a green result.
        outcome = "unseeded"
    else:
        outcome = "in_sync"

    with open(out_kv, "w", encoding="utf-8") as handle:
        emit(
            handle,
            sequence=marker["sequence"],
            action=marker["action"],
            notice_code=marker["notice_code"],
            public_commit=marker["public_commit"],
            source_commit=marker["source_commit"],
            consensus_rules_id=marker["consensus_rules_id"],
            consensus_profile=marker["consensus_profile"],
            issued_at=marker["issued_at"],
            expires_at=marker["expires_at"],
            baseline_sequence=baseline["sequence"] if baseline else "none",
            baseline_source_commit=baseline["source_commit"] if baseline else "none",
            baseline_consensus_rules_id=baseline["consensus_rules_id"] if baseline else "none",
            changed_fields=",".join(changed),
            outcome=outcome,
        )

    sys.exit(0 if outcome == "in_sync" else 10)
except ValidatorError as error:
    print(f"[canary] verification refused: {error}", file=sys.stderr)
    sys.exit(2)
PYEOF
rc=$?
set -e

if [[ $rc -ne 0 && $rc -ne 10 ]]; then
  err "release marker did not verify (exit $rc)"
  exit 2
fi

# Surface the outputs: to $GITHUB_OUTPUT under Actions, stdout otherwise.
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  cat "$out_kv" >> "$GITHUB_OUTPUT"
fi
cat "$out_kv"

if [[ $rc -eq 10 ]]; then
  if grep -q '^outcome=unseeded$' "$out_kv"; then
    err "no baseline committed at ${baseline} — seed it from this verified marker"
  else
    err "DRIFT: baseline no longer matches the signed release marker"
  fi
  exit 10
fi
log "in sync with baseline ($(basename "$baseline"))"
exit 0
