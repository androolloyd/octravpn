#!/usr/bin/env python3
"""Generate native seeded product graph bytes, profile behavior and refusals."""
import argparse
import hashlib
import json
import pathlib
import platform
import random
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('use a fresh fixture path')
    pin = json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    actual = subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip()
    if actual != pin:
        raise SystemExit('upstream pin mismatch')
    hashes = {}
    adopted = json.loads((ROOT/'docs/rust-node/source-map.json').read_text())['files']
    sources = subprocess.check_output(['git','-C',str(args.upstream),'ls-files','pvac','pvac_ffi/pvac_serialize.hpp'],text=True).splitlines()
    for source in sources:
        raw = subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{source}'])
        if (args.upstream/source).read_bytes() != raw:
            raise SystemExit(f'modified native source: {source}')
        digest = hashlib.sha256(raw).hexdigest()
        if source in adopted:
            if adopted[source] != digest:
                raise SystemExit(f'adopted source map mismatch: {source}')
            hashes[source] = digest
    cases = []
    rng = random.Random(2026101304)
    def add(mode, a, b, slots=1, math=False, repack=8, draw=0, budget=1200000, rounds=1, right_slots=None, error_weight=2):
        cases.append({'mode':mode,'left_kind':a,'right_kind':b,'slots':slots,
            'right_slots':slots if right_slots is None else right_slots,'math':math,
            'repack_slots':repack,'draw_factor':draw,'edge_budget':budget,'rounds':rounds,
            'seed':rng.randbytes(32).hex(),'error_weight':error_weight})
    for mode in ['mul','square']:
        for math in [False,True]:
            for slots in [1,2,8]:
                for a,b in [(0,0),(1,0),(2,1),(3,0),(0,3),(3,3),(4,0),(5,0),(6,0),(9,0)]:
                    add(mode,a,b,slots,math,repack=[0,1,3,8][(a+b)%4])
            for repack in [0,1,2,8,21,22,65537]:
                add(mode,0,1,math=math,repack=repack)
            for budget in [0,1,8]:
                add(mode,1,2,math=math,budget=budget)
            for a,b in [(7,0),(0,7),(8,0),(0,8)]:
                add(mode,a,b,math=math)
            for a,b in [(0,0),(1,1),(2,2)]:
                add(mode,a,b,math=math,repack=3,rounds=2)
    for draw in [1,2,8,(1<<64)-1]:
        for _ in range(5):
            add('mul',0,1,draw=draw)
    for _ in range(24):
        add('mul',0,0,repack=1,error_weight=-1)
    for math in [False,True]:
        add('mul',0,0,math=math,right_slots=2)
    architecture = platform.machine()
    flags = ['-march=armv8-a+crypto'] if architecture in ('arm64','aarch64') else ['-maes','-msse2']
    oracle = ROOT/'scripts/node-port/hfhe-product-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-product-') as temp:
        executable=pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2',*flags,'-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        lines = [f'{c["mode"]} {c["seed"]} '+ ' '.join(str(c[key]) for key in
            ['slots','right_slots','left_kind','right_kind'])+f' {int(c["math"])} '+
            ' '.join(str(c[key]) for key in ['repack_slots','draw_factor','edge_budget','rounds','error_weight']) for c in cases]
        output=subprocess.check_output([str(executable)],input='\n'.join(lines)+'\n',text=True)
    results=[json.loads(line) for line in output.splitlines()]
    if len(results)!=len(cases):
        raise SystemExit('native oracle output count mismatch')
    # Store repeated native inputs once; ciphertext outputs retain all wire bytes.
    inputs={}
    for case,result in zip(cases,results):
        for field in ['public','left','right']:
            raw=bytes.fromhex(result[field]);key=hashlib.sha256(raw).hexdigest()
            inputs[key]=result.pop(field);case[field]=key
        case.update(result)
    report={'upstream_commit':pin,'source_sha256':hashes,'architecture':architecture,
        'oracle_sha256':hashlib.sha256(oracle.read_bytes()).hexdigest(),
        'scope':'Seeded multiplication and squaring graph bytes, math profiles and refusals; no proof/backend qualification',
        'inputs':inputs,'cases':cases}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {len(cases)} native product cases')


if __name__=='__main__':
    main()
