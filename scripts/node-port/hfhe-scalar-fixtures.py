#!/usr/bin/env python3
"""Generate raw scalar arithmetic and both native 512-bit reduction profiles.

Public deterministic fixtures deliberately include noncanonical raw scalars.
Prior's retained high-limb truncation must not be replaced by modular math.
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
SOURCES = [
    'pvac/include/pvac/crypto/ristretto255.hpp',
    'pvac/include/pvac/core/field.hpp',
    'pvac/include/pvac/core/hash.hpp',
    'pvac/include/pvac/core/random.hpp',
]


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
    sources = json.loads((ROOT/'docs/rust-node/source-map.json').read_text())['files']
    hashes = {}
    for source in SOURCES:
        original = subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{source}'])
        digest = hashlib.sha256(original).hexdigest()
        if (args.upstream/source).read_bytes() != original:
            raise SystemExit(f'modified native source: {source}')
        if sources[source] != digest:
            raise SystemExit(f'adopted source map mismatch: {source}')
        hashes[source] = digest
    rng = random.Random(2026101305)
    order = (1<<252) + 27742317777372353535851937790883648493
    prime = (1<<127)-1
    raw_mask = (1<<512)-1
    reductions = {0,raw_mask}
    for bit in range(512):
        for delta in [-1,0,1]:
            reductions.add(((1<<bit)+delta)&raw_mask)
    reductions = sorted(reductions) + [rng.getrandbits(512) for _ in range(512)]
    boundaries = sorted(set([0,1,2,order-2,order-1,order,order+1,2*order-1,2*order,
        (1<<252)-1,1<<252,(1<<255)-1,1<<255,(1<<256)-1]))
    pairs = [(a,b) for a in boundaries for b in boundaries]
    pairs += [(rng.getrandbits(256),rng.getrandbits(256)) for _ in range(256)]
    pairs += [(rng.randrange(order),rng.randrange(order)) for _ in range(128)]
    fields = [0,1,2,(1<<63)-1,1<<63,(1<<64)-1,1<<64,prime//2,prime//2+1,prime-1]
    fields += [rng.randrange(prime) for _ in range(128)]
    encode = lambda value,size: value.to_bytes(size,'little').hex()
    cases = {'reduction':[{'input':encode(value,64)} for value in reductions],
             'arithmetic':[{'left':encode(a,32),'right':encode(b,32)} for a,b in pairs],
             'field':[{'input':encode(value,16)} for value in fields]}
    lines = ['reduce '+case['input'] for case in cases['reduction']]
    lines += ['arithmetic '+case['left']+' '+case['right'] for case in cases['arithmetic']]
    lines += ['field '+case['input'] for case in cases['field']]
    oracle = ROOT/'scripts/node-port/hfhe-scalar-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-scalar-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2','-I',str(args.upstream/'pvac/include'),
                        str(oracle),'-o',str(executable)],check=True)
        output = subprocess.check_output([str(executable)],input='\n'.join(lines)+'\n',text=True)
    results = output.splitlines()
    if len(results) != len(lines):
        raise SystemExit('native oracle output count mismatch')
    results = iter(results)
    for case in cases['reduction']:
        prior,wide = next(results).split();case.update(prior=prior,wide=wide)
    names = ['left_canonical','right_canonical','add','sub','neg','mul_prior','mul_wide',
             'inverse_prior','inverse_wide','reduce256']
    for case in cases['arithmetic']:
        expected = next(results).split()
        if len(expected) != len(names):
            raise SystemExit('native arithmetic field count mismatch')
        case['expected'] = dict(zip(names,expected))
    for case in cases['field']:
        unsigned,signed = next(results).split();case.update(unsigned=unsigned,signed=signed)
    report = {'upstream_commit':pin,'source_sha256':hashes,'architecture':platform.machine(),
        'oracle_sha256':hashlib.sha256(oracle.read_bytes()).hexdigest(),
        'scope':'Native raw scalar arithmetic and Prior/Wide reduction; not complete proof/backend parity',
        **cases}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print('Generated native scalar vectors: '+', '.join(f'{name}={len(items)}' for name,items in cases.items()))


if __name__ == '__main__':
    main()
