#!/usr/bin/env python3
"""Pin every runtime source file; implementation coverage is a separate gate."""
import argparse, collections, hashlib, json, pathlib, subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
SUFFIXES = {".ml", ".mli", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp", ".proto", ".mjs"}
COMPONENTS = {"bin", "lib", "node_runtime", "circle_runtime", "net", "proto", "pvac", "pvac_ffi", "zk_ffi", "crypto_guard", "mcl", "logging"}

def snapshot(upstream):
    pin = json.loads((ROOT / "docs/rust-node/upstream.json").read_text())
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != pin["commit"]: raise SystemExit("upstream commit differs from pin")
    if subprocess.run(["git", "-C", str(upstream), "diff", "--quiet", "HEAD", "--", *sorted(COMPONENTS)]).returncode:
        raise SystemExit("modified upstream runtime source")
    files = subprocess.check_output(["git", "-C", str(upstream), "ls-files", "-z"]).decode().split("\0")
    hashes = {}
    counts = collections.Counter()
    for name in files:
        path = pathlib.PurePosixPath(name)
        if not name or path.parts[0] not in COMPONENTS or path.suffix not in SUFFIXES: continue
        body = (upstream / name).read_bytes()
        for prior in pin.get("source_equivalent_commits", []):
            prior_body = subprocess.check_output(["git", "-C", str(upstream), "show", f"{prior}:{name}"])
            if prior_body != body: raise SystemExit(f"source-equivalent revision differs: {prior}:{name}")
        hashes[name] = hashlib.sha256(body).hexdigest()
        component = "/".join(path.parts[:2]) if path.parts[0] == "lib" else path.parts[0]
        counts[component] += 1
    return {"upstream_commit": commit, "scope": "source inventory, not behavior or port completeness", "components": dict(sorted(counts.items())), "files": hashes, "source_equivalent_commits": pin.get("source_equivalent_commits", [])}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, default=ROOT / "docs/rust-node/source-map.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = snapshot(args.upstream)
    if args.check:
        if json.loads(args.out.read_text()) != report: raise SystemExit("source map mismatch")
    else:
        if args.out.exists(): raise SystemExit("refusing to replace source map; review and explicitly remove the old snapshot")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(report['files'])} pinned runtime source files")

if __name__ == "__main__": main()
