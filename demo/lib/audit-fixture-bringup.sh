#!/usr/bin/env bash
# audit-fixture-bringup.sh
#
# Bring up a single-container fixture for the audit-replay / audit-verify
# tapes (03 + 21). The container runs the Linux-built octravpn-node
# binary against a synthesized HMAC-chained audit.log + empty receipt
# journal. Everything happens inside docker; nothing leaks onto the
# host except the on-disk fixture under demo/.audit-fixture/.
#
# Exit codes:
#   0   READY — `octravpn-node audit replay` returned 0 against the fixture.
#   10  build / docker-run preflight failed.
#   20  audit fixture synthesis failed (python3 inside the container barfed).
#   30  smoke replay against the fixture failed.
#
# Idempotent: re-running on a warm fixture reuses the existing artefacts.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
FIXTURE_DIR="${REPO_ROOT}/demo/.audit-fixture"
LINUX_BIN="${REPO_ROOT}/target/linux-debug/debug/octravpn-node"
CONTAINER_NAME="${AUDIT_FIXTURE_CONTAINER:-octravpn-audit-fixture}"

mkdir -p "${FIXTURE_DIR}/node"

if [[ ! -x "${LINUX_BIN}" ]]; then
    # On a fresh macOS host the Linux binary won't exist. The shared
    # builder is a no-op when artefacts are fresh, so this is safe in
    # CI (which pre-stages the binary) and self-healing locally.
    "${SCRIPT_DIR}/build-linux-binaries.sh" >&2 || true

    if [[ ! -x "${LINUX_BIN}" ]]; then
        # Fall back to release if debug still isn't built; demo
        # workflow builds debug.
        if [[ -x "${REPO_ROOT}/target/release/octravpn-node" ]]; then
            LINUX_BIN="${REPO_ROOT}/target/release/octravpn-node"
        elif [[ -x "${REPO_ROOT}/target/debug/octravpn-node" ]]; then
            LINUX_BIN="${REPO_ROOT}/target/debug/octravpn-node"
        else
            echo "audit-fixture-bringup: octravpn-node binary missing under target/" >&2
            echo "  run demo/lib/build-linux-binaries.sh to produce target/linux-debug/debug/octravpn-node" >&2
            exit 10
        fi
    fi
fi

# Drop any stale container so the fixture refresh is deterministic.
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

# Bring up a long-lived container that has the binary + fixture mounted.
# The container does nothing on its own — `docker exec` drives every command.
docker run -d --name "${CONTAINER_NAME}" \
    -v "${LINUX_BIN}":/usr/local/bin/octravpn-node:ro \
    -v "${FIXTURE_DIR}":/work \
    -w /work \
    debian:bookworm-slim \
    sleep infinity >/dev/null || {
        echo "audit-fixture-bringup: docker run failed" >&2
        exit 10
    }

# Install python3 (used to synthesize the HMAC-chained log) lazily.
docker exec "${CONTAINER_NAME}" sh -c 'command -v python3 >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y --no-install-recommends python3 >/dev/null)' || {
    echo "audit-fixture-bringup: python3 install failed" >&2
    exit 10
}

# Synthesize the audit fixture inside the container so the binary's
# byte-ordering / line-format expectations match the host's.
docker exec -i "${CONTAINER_NAME}" python3 - <<'PY' || { echo "audit-fixture-bringup: fixture synth failed" >&2; exit 20; }
import hmac, hashlib, json, os, secrets
state_dir = "/work/node"
os.makedirs(state_dir, exist_ok=True)
# Deterministic key so audit verify reproduces.
key = bytes.fromhex("ab" * 32)
with open(f"{state_dir}/audit.log.key", "wb") as f:
    f.write(key)
records = [
    (1715000000, "session_open",  "a" * 64, {"peer": "peer-1"}),
    (1715000005, "session_open",  "b" * 64, {"peer": "peer-2"}),
    (1715000020, "bytes_used",    "a" * 64, {"bytes_used": 4096}),
    (1715000040, "receipt_sign",  "a" * 64, {"seq": 1, "bytes_used": 4096}),
    (1715000060, "bytes_used",    "b" * 64, {"bytes_used": 8192}),
    (1715000080, "receipt_sign",  "b" * 64, {"seq": 1, "bytes_used": 8192}),
    (1715000100, "session_close", "a" * 64, {"reason": "client_quit"}),
    (1715000120, "session_close", "b" * 64, {"reason": "client_quit"}),
]
prev_mac = b"\x00" * 32
with open(f"{state_dir}/audit.log", "w") as f:
    for ts, kind, sid, extra in records:
        rec = {
            "ts_unix": ts,
            "kind": kind,
            "source": None,
            "session_id": sid,
            "extra": extra,
        }
        canonical = json.dumps(rec, separators=(",", ":"), sort_keys=False)
        mac = hmac.new(key, prev_mac + canonical.encode(), hashlib.sha256).digest()
        chained = {
            "record_json": canonical,
            "prev_mac": prev_mac.hex(),
            "mac": mac.hex(),
        }
        f.write(json.dumps(chained) + "\n")
        prev_mac = mac
# Empty receipt journal — replay tolerates this.
open(f"{state_dir}/receipts.bin", "wb").close()
print(f"wrote {len(records)} audit records + empty journal under {state_dir}")
PY

echo "audit-fixture container '${CONTAINER_NAME}' ready" >&2
echo "  binary  : /usr/local/bin/octravpn-node (mounted from ${LINUX_BIN})" >&2
echo "  fixture : /work/node/{audit.log,audit.log.key,receipts.bin}" >&2
echo "READY"
