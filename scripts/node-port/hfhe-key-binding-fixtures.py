#!/usr/bin/env python3
"""Generate c49 keyed proof vectors from verified, committed native headers."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PIN = "c49de45cf49ebbc2e5c0697eb956cbcada5845e7"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    git = ["git", "-C", str(args.upstream)]
    paths = subprocess.check_output(git + ["ls-tree", "-r", "--name-only", PIN, "pvac", "pvac_ffi"], text=True).splitlines()
    hashes = {}
    for path in paths:
        committed = subprocess.check_output(git + ["show", f"{PIN}:{path}"])
        if (args.upstream / path).read_bytes() != committed:
            raise SystemExit(f"modified native oracle input: {path}")
        hashes[path] = hashlib.sha256(committed).hexdigest()
    oracle = ROOT / "scripts/node-port/hfhe-key-binding-oracle.cpp"
    cases = []
    for profile in [1, 2]:
        for rule in [0, 1]:
            for operation in ["zero", "bound", "range", "key_switch", "migration"]:
                # Wrapped zero is also the new registration ownership proof input.
                cases.append(dict(profile=profile, rule=rule, operation=operation,
                    variant=1, value=0, amount=0, prove=profile == 2 and rule == 1,
                    entropy_seed=20261112))
    flags = ["-march=armv8-a+crypto"] if platform.machine() in ("arm64", "aarch64") else ["-maes", "-msse2", "-mpclmul"]
    with tempfile.TemporaryDirectory(prefix="octra-key-binding-") as tmp:
        binary = str(Path(tmp) / "oracle")
        subprocess.run(["clang++", "-std=c++17", "-O2", *flags, "-I", str(args.upstream / "pvac/include"), "-I", str(args.upstream / "pvac_ffi"), str(oracle), "-o", binary], check=True)
        lines = [" ".join(str(c[k]) if k != "prove" else str(int(c[k])) for k in ["profile", "rule", "operation", "variant", "value", "amount", "prove", "entropy_seed"]) for c in cases]
        raw = subprocess.check_output([binary], input="\n".join(lines) + "\n", text=True, timeout=600)
    results = [json.loads(line) for line in raw.splitlines()]
    assert len(results) == len(cases)
    for case, result in zip(cases, results):
        if "error" in result:
            raise SystemExit(f"native oracle refused {case}: {result}")
        case["expected"] = result
    report = dict(upstream_commit=PIN, source_sha256=hashes,
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(), cases=cases)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Generated {len(cases)} native keyed cases; {sum(c['prove'] for c in cases)} complete proofs")


if __name__ == "__main__":
    main()
