#!/usr/bin/env python3
"""Generate byte-exact field fixtures from the pinned native implementation."""
import argparse, hashlib, json, pathlib, random, subprocess, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[2]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    pin = json.loads((ROOT / "docs/rust-node/upstream.json").read_text())["commit"]
    if args.out.exists(): raise SystemExit("use a fresh fixture path")
    actual = subprocess.check_output(["git","-C",str(args.upstream),"rev-parse","HEAD"],text=True).strip()
    source = "pvac/include/pvac/core/field.hpp"
    raw = subprocess.check_output(["git","-C",str(args.upstream),"show",f"HEAD:{source}"])
    if actual != pin or (args.upstream/source).read_bytes() != raw: raise SystemExit("modified or unpinned oracle")
    mask = (1<<64)-1
    boundary = [(0,0),(1,0),(mask,0),(mask,(1<<63)-1),(mask-1,(1<<63)-1),(mask,mask),
        (0,1<<63),(0,mask),(1<<63,0),(mask, (1<<63)-2),(1,1)]
    cases = [[*a,*b, exponent] for a in boundary for b in boundary for exponent in [0,1,2,63,mask]]
    rng=random.Random(20261012)
    cases += [[rng.getrandbits(64) for _ in range(5)] for _ in range(1024)]
    with tempfile.TemporaryDirectory(prefix="octra-hfhe-field-") as temp:
        executable = pathlib.Path(temp)/"oracle"
        subprocess.run(["clang++","-std=c++17","-O2","-I",str(args.upstream/"pvac/include"),str(ROOT/"scripts/node-port/hfhe-field-oracle.cpp"),"-o",str(executable)],check=True)
        output=subprocess.check_output([str(executable)],input=''.join(' '.join(map(str,row))+'\n' for row in cases),text=True)
    lines=output.splitlines()
    if len(lines)!=len(cases): raise SystemExit("oracle output count mismatch")
    report={"upstream_commit":pin,"source":source,"source_sha256":hashlib.sha256(raw).hexdigest(),
        "scope":"field words, arithmetic and little-endian bytes; not complete HFHE parity",
        "cases":[{"input":[str(value) for value in row],"expected":line.split()} for row,line in zip(cases,lines)]}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f"Generated {len(cases)} byte-exact field cases")

if __name__ == "__main__": main()
