#!/usr/bin/env python3
"""Qualify proof gadget constraints and selected full proofs against pristine native headers.

Only the platform entropy call is redirected inside this test translation unit.
No native source is edited and no real proving secrets enter these fixtures.
"""
import argparse
import hashlib
import json
import pathlib
import platform
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
    source_map = json.loads((ROOT/'docs/rust-node/source-map.json').read_text())['files']
    sources = sorted(str(path.relative_to(args.upstream)) for path in (args.upstream/'pvac/include').rglob('*.hpp'))
    sources.append('pvac_ffi/pvac_serialize.hpp')
    hashes = {}
    for source in sources:
        original = subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{source}'])
        digest = hashlib.sha256(original).hexdigest()
        if (args.upstream/source).read_bytes() != original:
            raise SystemExit(f'modified native source: {source}')
        if source_map[source] != digest:
            raise SystemExit(f'adopted source map mismatch: {source}')
        hashes[source] = digest
    cases=[]
    for profile in [1,2]:
        for operation in [0,1,2,3,4]:
            for slots in [0,1,3]:
                for depth,noise in [(0,0),(0,120),(3,120)]:
                    cases.append(dict(profile=profile,operation=operation,slots=slots,depth=depth,noise=noise,value=17,entropy_seed=173+len(cases)))
    lines=[' '.join(map(str,[case['profile'],case['depth'],case['operation'],case['slots'],case['value'],case['entropy_seed'],case['noise']])) for case in cases]
    oracle = ROOT/'scripts/node-port/hfhe-random-encrypt-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-random-encrypt-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2','-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        output = subprocess.check_output([str(executable)],input='\n'.join(lines)+'\n',text=True)
    results=output.splitlines()
    if len(results)!=len(cases): raise SystemExit('native oracle output count mismatch')
    for case,result in zip(cases,results): case['expected']=json.loads(result)
    report=dict(upstream_commit=pin,source_sha256=hashes,architecture=platform.machine(),
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
        scope='Complete unseeded encryption bytes and entropy consumption using a test-only deterministic stream; not complete backend parity',cases=cases)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f"Generated {len(cases)} native unseeded encryptions")


if __name__=='__main__': main()
