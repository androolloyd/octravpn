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
    rng = random.Random(2026101312)
    modulus = (1<<127)-1
    encode = lambda value: value.to_bytes(32,'little').hex()
    cases = []
    def add(kind,rule,a,b=0,bits=1,canonical=False,prove=False):
        size = 512 if kind=='mul' else 256 if kind in ['decompose','bind'] else max(1,bits)
        padded = 1 << (size-1).bit_length()
        tape = rng.randbytes((2*padded+8)*64) if prove else b'\0'
        cases.append(dict(kind=kind,rule=rule,left=encode(a),right=encode(b),bits=bits,
                          canonical=canonical,prove=prove,tape=tape.hex()))
    for rule in [0,1]:
        for bits in [1,2,8,63,64,65,127,128,251,252]:
            for value in [0,1,(1<<bits)-1,1<<bits]:
                add('range',rule,value,bits=bits,prove=bits<=8)
        for value in [0,1,modulus-1,modulus,modulus+1,(1<<256)-1]:
            add('alias',rule,value,prove=True)
            for canonical in [False,True]:
                add('decompose',rule,value,canonical=canonical,prove=value==1 and canonical)
        for a,b in [(0,0),(1,1),(modulus-1,modulus-1),(modulus,1),((1<<127)+3,(1<<128)-1),((1<<256)-1,(1<<256)-1)]:
            for canonical in [False,True]:
                add('mul',rule,a,b,canonical=canonical,prove=a==modulus-1 and canonical)
        for kind in ['cube','fifth']:
            for canonical in [False,True]:
                add(kind,rule,7,canonical=canonical)
        for value in [0,1,modulus//2,modulus//2+1,modulus-1]:
            signed=value if value<=modulus//2 else ((1<<252)+27742317777372353535851937790883648493)-(modulus-value)
            add('bind',rule,signed,value,canonical=True)
            add('fold',rule,value,rng.randrange(modulus),canonical=True)
    lines=[]
    for case in cases:
        lines.append(' '.join(map(str,[case['kind'],case['rule'],int(case['canonical']),case['bits'],int(case['prove']),case['left'],case['right'],case['tape']])))
    oracle = ROOT/'scripts/node-port/hfhe-gadgets-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-gadgets-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2','-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        output = subprocess.check_output([str(executable)],input='\n'.join(lines)+'\n',text=True)
    results=output.splitlines()
    if len(results)!=len(cases): raise SystemExit('native oracle output count mismatch')
    for case,result in zip(cases,results): case['expected']=json.loads(result)
    report=dict(upstream_commit=pin,source_sha256=hashes,architecture=platform.machine(),
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
        scope='Exact gadget constraint/output encodings plus selected complete R1CS proofs and verifier outcomes; not complete backend parity',cases=cases)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {len(cases)} native gadget constructions, {sum(case["prove"] for case in cases)} full proofs')


if __name__=='__main__': main()
