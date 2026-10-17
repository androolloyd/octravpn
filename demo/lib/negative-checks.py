#!/usr/bin/env python3
"""Exact negative controls for demo tapes 02/16/21; no generic nonzero acceptance."""

import argparse
import re
import subprocess
import sys


DECRYPT_ERROR = "octravpn fetch: decrypt failed (wrong passphrase / key_id / corrupt envelope)"
AUDIT = "octravpn-audit-fixture"
PORTAL = "octravpn-portal-demo"
MUTATE_RECORD = '''import json
from pathlib import Path
source = Path("/work/node/audit.log")
lines = source.read_text().splitlines()
if not lines:
    raise SystemExit("empty audit fixture")
outer = json.loads(lines[0])
record = json.loads(outer["record_json"])
if record["kind"] != "session_open":
    raise SystemExit("unexpected fixture record")
record["kind"] = "tampered_demo"
outer["record_json"] = json.dumps(record, separators=(",", ":"))
lines[0] = json.dumps(outer)
Path("/tmp/audit.tampered.log").write_text("\\n".join(lines) + "\\n")
print("modified record_json at line 1; original MAC retained")
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def call(arguments):
    return subprocess.run(arguments, capture_output=True, text=True, check=False, timeout=90)


def sealed():
    identity = call(["docker", "exec", PORTAL, "printenv", "OCTRAVPN_DEMO_CIRCLE_ID"])
    circle = identity.stdout.strip()
    require(identity.returncode == 0 and re.fullmatch(r"oct[A-Za-z0-9]{40,50}", circle),
            "fixture Circle ID is unavailable or malformed")
    url = f"oct://{circle}/sealed.json"
    def fetch(passphrase):
        return call(["docker", "exec", "-e", f"OCTRAVPN_SEALED_PASSPHRASE={passphrase}", PORTAL,
                     "octravpn", "--config", "/etc/octravpn/config.toml", "fetch", url])
    good = fetch("demo")
    require(good.returncode == 0 and good.stdout, "correct-passphrase control did not fetch the asset")
    print("correct-passphrase control: fetched the target asset")
    wrong = fetch("wrong")
    require(wrong.returncode == 5, f"expected decrypt exit 5, got {wrong.returncode}")
    require(not wrong.stdout, "wrong-passphrase request emitted unexpected plaintext")
    require(DECRYPT_ERROR in wrong.stderr.splitlines(), "missing exact decrypt-failure diagnostic")
    print("wrong-passphrase control: exit=5, decrypt rejected, no plaintext")


def audit():
    def verify(path):
        return call(["docker", "exec", AUDIT, "octravpn-node", "audit", "verify",
                     "--audit-path", path, "--journal-path", "/work/node/receipts.bin",
                     "--hmac-key", "/work/node/audit.log.key"])
    clean = verify("/work/node/audit.log")
    require(clean.returncode == 0 and "verification PASSED" in clean.stdout.splitlines()
            and "8 entries, HMAC chain valid" in clean.stdout,
            "clean eight-record audit control failed")
    print("clean audit control: exit=0, eight HMAC-linked records verified")
    mutation = call(["docker", "exec", AUDIT, "python3", "-c", MUTATE_RECORD])
    require(mutation.returncode == 0, "valid-JSON audit mutation failed")
    print("modified record_json at line 1; original MAC retained")
    tampered = verify("/tmp/audit.tampered.log")
    require(tampered.returncode == 1, f"expected verification exit 1, got {tampered.returncode}")
    require("verification FAILED" in tampered.stdout.splitlines()
            and re.search(r"^audit log:\s+FAIL\s+[^\n]*MAC mismatch at line 1:", tampered.stdout, re.M),
            "expected a line-one MAC mismatch, not an unrelated failure")
    print("tampered audit control: exit=1, MAC mismatch at line 1")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("sealed", "audit"))
    args = parser.parse_args()
    (sealed if args.check == "sealed" else audit)()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"negative control failed: {error}", file=sys.stderr)
        sys.exit(1)
