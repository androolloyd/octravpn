#!/usr/bin/env python3
"""Verify adopted native sources and the reviewable Rust host API patch."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--upstream", type=pathlib.Path)
    mode.add_argument("--vendored-only", action="store_true",
                      help="check local provenance hashes without independently reproducing the upstream patch")
    args = parser.parse_args()
    pin = json.loads((ROOT / "docs/rust-node/upstream.json").read_text())["commit"]
    if args.upstream:
        actual = subprocess.check_output(["git", "-C", str(args.upstream), "rev-parse", "HEAD"], text=True).strip()
        if actual != pin: raise SystemExit("upstream pin mismatch")
    pvac = ROOT / "vendor/octra-pvac"
    report = json.loads((pvac / "PROVENANCE.json").read_text())
    if report["commit"] != pin: raise SystemExit("PVAC pin mismatch")
    for name, expected in report["source_sha256"].items():
        if digest(pvac / name) != expected:
            raise SystemExit(f"modified PVAC source: {name}")
        if args.upstream:
            raw = subprocess.check_output(["git", "-C", str(args.upstream), "show", f"HEAD:{name}"])
            if hashlib.sha256(raw).hexdigest() != expected:
                raise SystemExit(f"upstream PVAC hash mismatch: {name}")
    engine = ROOT / "vendor/octra-circle-wasm-host"
    report = json.loads((engine / "PROVENANCE.json").read_text())
    patch = ROOT / "scripts/node-port/circle-host-rust-api.patch"
    if report["commit"] != pin or digest(patch) != report["patch_sha256"]:
        raise SystemExit("Circle host pin or patch mismatch")
    for name, expected in report["adapted_sha256"].items():
        if digest(engine / name) != expected:
            raise SystemExit(f"unreviewed Circle engine adaptation: {name}")
    if args.vendored_only:
        print("PASS: vendored PVAC and Circle host match recorded provenance hashes")
        return
    with tempfile.TemporaryDirectory(prefix="octra-native-source-check-") as temp:
        fresh = pathlib.Path(temp)
        for name, expected in report["upstream_sha256"].items():
            raw = subprocess.check_output(["git", "-C", str(args.upstream), "show", f"HEAD:{report['source_directory']}/{name}"])
            if hashlib.sha256(raw).hexdigest() != expected: raise SystemExit(f"upstream host hash mismatch: {name}")
            path = fresh / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        subprocess.run(["patch", "--batch", "--silent", "-p1", "-i", str(patch)], cwd=fresh, check=True)
        for name, expected in report["adapted_sha256"].items():
            if digest(engine / name) != expected or digest(fresh / name) != expected:
                raise SystemExit(f"unreviewed Circle engine adaptation: {name}")
    print("PASS: pinned PVAC sources and exactly reproduced Rust Circle API patch")


if __name__ == "__main__": main()
