#!/usr/bin/env python3
"""Generate exact seeded ciphertext bytes from the pristine native implementation."""
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
        raise SystemExit('use a fresh output path')
    manifest = json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
    pin = manifest['upstream_commit']
    if subprocess.check_output(['git', '-C', str(args.upstream), 'rev-parse', 'HEAD'], text=True).strip() != pin:
        raise SystemExit('upstream pin mismatch')
    hashes = {}
    for path, expected in manifest['files'].items():
        if not path.startswith('pvac/') and path != 'pvac_ffi/pvac_serialize.hpp':
            continue
        raw = subprocess.check_output(['git', '-C', str(args.upstream), 'show', f'HEAD:{path}'])
        hashes[path] = hashlib.sha256(raw).hexdigest()
        if hashes[path] != expected or raw != (args.upstream/path).read_bytes():
            raise SystemExit(f'oracle source mismatch: {path}')
    rng = random.Random(2026101313)
    cases = []
    maximum = (1 << 64)-1
    for i in range(48):
        operation = ['value', 'value_depth', 'values', 'zero', 'raw', 'values'][i % 6]
        values = [[0], [maximum], [0, 1, maximum, 1 << 63], [0], [1, 3], []][i % 6]
        if i % 6 == 5 and i % 12 == 11:
            values = [rng.getrandbits(64) for _ in range(8)]
        cases.append(dict(operation=operation, key_seed=rng.randbytes(32).hex(), seed=rng.randbytes(32).hex(),
            full=False, profile=1+(i//6)%2, basis=[337,9,7][(i//12)%3], depth=[-3,0,1,7][(i//6)%4],
            entropy=[0,120,32,64][(i//6)%4], fraction=[0,0.55,1][(i//6)%3], budget=[0,1200000][i%2],
            values=[str(v) for v in values]))
    for i in range(2):
        cases.append(dict(operation='values', key_seed=rng.randbytes(32).hex(), seed=rng.randbytes(32).hex(),
            full=True, profile=1+i, basis=337, depth=0, entropy=120, fraction=0.55, budget=1200000,
            values=['0',str(maximum)]))
    for i in range(4):
        cases.append(dict(operation='pipeline', key_seed=rng.randbytes(32).hex(), seed=rng.randbytes(32).hex(),
            full=False, profile=1+i%2, basis=337, depth=0, entropy=[0,120][i//2], fraction=0.55, budget=[0,1200000][i%2],
            values=['0','1',str(maximum)]))
    architecture = platform.machine()
    flags = ['-march=armv8-a+crypto'] if architecture in ('arm64', 'aarch64') else ['-maes','-msse2','-mpclmul']
    oracle = ROOT/'scripts/node-port/hfhe-encrypt-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-encrypt-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2',*flags,'-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        lines = [' '.join(map(str,[c['operation'],c['key_seed'],c['seed'],int(c['full']),c['profile'],c['basis'],c['depth'],
            c['entropy'],c['fraction'],c['budget'],len(c['values']),*c['values']])) for c in cases]
        output = subprocess.check_output([str(executable)],input='\n'.join(lines)+'\n',text=True)
    results = [json.loads(line) for line in output.splitlines()]
    assert len(results) == len(cases)
    for case, result in zip(cases,results):
        case['expected'] = result
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(dict(upstream_commit=pin,source_sha256=hashes,architecture=architecture,
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
        scope='Seeded encryption bytes and refusals; not complete HFHE backend parity',cases=cases),indent=2)+'\n')
    print(f'Generated {len(cases)} seeded encryption vectors')


if __name__ == '__main__':
    main()
