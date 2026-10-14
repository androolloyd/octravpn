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
    keys=['count','terms','alpha','row','target','slots','query','bits','flags','cert','mutation','budget']
    def add(**kwargs):
        case=dict(count=3,terms=3,alpha=8,row=8,target=2,slots=1,query=0,bits=128,flags=13,cert=1,mutation=0,budget=0)
        case.update(kwargs);cases.append({key:str(value) for key,value in case.items()})
    maximum=(1<<64)-1
    for mutation in range(47):
        for slots in [1,3]: add(mutation=mutation,slots=slots)
    for flags in range(16):
        for cert in [0,1,255]:add(flags=flags,cert=cert)
    for terms in [0,1,2,3,4,maximum]:
        for alpha,row in [(0,0),(8,8),(63,63),(127,124),(127,125),(128,127),(maximum,1),(maximum,maximum)]:
            add(terms=terms,alpha=alpha,row=row)
    for budget in range(6):
        for bits in [0,127,128,129,256,maximum//1000,maximum]:add(bits=bits,budget=budget)
    for count in [0,1,3]:
        for target,slots in [(0,1),(1,0),(1,1),(3,4)]:add(count=count,target=target,slots=slots)
    for query in [0,63,64,maximum]:add(query=query)
    lines=[' '.join(case[key] for key in keys) for case in cases]
    oracle = ROOT/'scripts/node-port/hfhe-hidden-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-hidden-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2','-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        output = subprocess.check_output([str(executable)],input='\n'.join(lines)+'\n',text=True)
    results=output.splitlines()
    if len(results)!=len(cases): raise SystemExit('native oracle output count mismatch')
    for case,result in zip(cases,results): case['expected']=json.loads(result)
    report=dict(upstream_commit=pin,source_sha256=hashes,architecture=platform.machine(),
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
        scope='Native hidden coefficient and chosen reset digests and policy decisions, including mutation and resource bounds; not complete backend parity',cases=cases)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f"Generated {len(cases)} native hidden coefficient cases")


if __name__=='__main__': main()
