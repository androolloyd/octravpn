#!/usr/bin/env python3
"""Actual native Compute_pool with exact PVAC capacity/queue/burst settings."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BUILDER="sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
def fixtures():
    rows=[]
    def step(kind,ident,priority="required",fail=False):return dict(kind=kind,id=ident,priority=priority,fail=fail)
    for capacity in [1,2]:
        def case(steps):return dict(capacity=capacity,required=128,speculative=6,burst=4,steps=steps)
        starts=[step("start",i) for i in range(capacity)]
        queued=[step("start",10+i,"required" if i%3 else "speculative") for i in range(12)]
        rows.append(case(starts+queued+[step("resolve",i) for _ in range(3) for i in list(range(capacity))+list(range(10,22))]))
        rows.append(case(starts+[step("start",10),step("cancel",10),step("start",11,"speculative"),step("cancel",11),step("try",12,"speculative")]+[step("resolve",i,fail=i==0) for i in range(capacity)]+[step("try",13)]))
        # Exact native queue limits, followed by queue cancellation and bounded
        # cleanup. All identifiers remain unique even for refused admissions.
        rows.append(case(starts+[step("start",10+i) for i in range(129)]+[step("start",200+i,"speculative") for i in range(7)]+[step("cancel",10+i) for i in range(129)]+[step("cancel",200+i) for i in range(7)]+[step("resolve",i) for i in range(capacity)]+[step("try",300,"speculative")]))
        rows.append(case(starts+[step("cancel",i) for i in range(capacity)]+[step("try",10,"speculative"),step("start",11)]+[step("resolve",i) for i in range(capacity)]+[step("resolve",11),step("try",12,"speculative")]))
    return rows
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--upstream",type=Path,required=True);parser.add_argument("--out",type=Path,required=True);args=parser.parse_args()
    if args.out.exists():raise SystemExit("require fresh output")
    spec=importlib.util.spec_from_file_location("native",ROOT/"scripts/node-port/native-oracle.py");native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    inputs=fixtures()
    report=native.run(args.upstream,BUILDER,ROOT/"scripts/node-port/pvac-admission-oracle.ml",inputs,"octra_core yojson lwt.unix")
    report["input_sha256"]=hashlib.sha256(json.dumps(inputs,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    report["generator_sha256"]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report["scope"]="Unchanged native Compute_pool with exact adopted PVAC capacity1/2, required128/speculative6/burst4 (checked against native Resource_lanes by oracle); controlled job queue/cancel/failure traces. Actual packaged-worker contention is a separate regression."
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+"\n")
    print(f"Generated {len(inputs)} exact native PVAC admission traces: {args.out}")
if __name__=="__main__":main()
