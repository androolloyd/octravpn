#!/usr/bin/env python3
"""Generate retained LPN and both native Toeplitz implementation fixtures."""
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
    if args.out.exists(): raise SystemExit('use a fresh fixture path')
    pin = json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    if subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip() != pin:
        raise SystemExit('upstream pin mismatch')
    hashes = {}
    files = json.loads((ROOT/'docs/rust-node/source-map.json').read_text())['files']
    for source in files:
        if not source.startswith('pvac/'): continue
        raw = subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{source}'])
        if (args.upstream/source).read_bytes() != raw: raise SystemExit(f'modified oracle source: {source}')
        hashes[source] = hashlib.sha256(raw).hexdigest()
    rng = random.Random(20261013)
    lpn = []
    for i in range(18):
        n,t = [(1,1),(63,63),(65,127),(129,257),(4096,16384)][i%5]
        if i >= 15: n,t = [(1,129),(65,1),(127,63)][i-15]
        lpn.append({'seed':rng.randbytes(32).hex(),'n':n,'t':t,'num':[-1,0,1,8,9][(i//5+i+1)%5],
            'den':8,'tag':str(rng.getrandbits(64)),'nonce':[str(rng.getrandbits(64)),str((1<<64)-1 if i%2==0 else 0)]})
    toep = [{'top':['0'],'y':['0']},{'top':[str((1<<64)-1),str((1<<63)-1)],'y':['1']},
        {'top':['1'],'y':[str((1<<64)-1),str((1<<64)-1)]}]
    for _ in range(127):
        toep.append({'top':[str(rng.getrandbits(64)) for _ in range(rng.choice([1,2,3,64,129]))],
            'y':[str(rng.getrandbits(64)) for _ in range(rng.choice([1,2,3,64,129]))]})
    architecture = platform.machine()
    flags = ['-march=armv8-a+crypto'] if architecture in ('arm64','aarch64') else ['-maes','-msse2','-mpclmul']
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-lpn-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2',*flags,'-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(ROOT/'scripts/node-port/hfhe-key-oracle.cpp'),'-o',str(executable)],check=True)
        lines = ['lpn '+case['seed']+' '+' '.join(map(str,[case['n'],case['t'],case['num'],case['den'],case['tag'],*case['nonce']])) for case in lpn]
        lines += ['toep '+' '.join(map(str,[len(case['top']),len(case['y']),*case['top'],*case['y']])) for case in toep]
        output = subprocess.check_output([str(executable)],input=''.join(line+'\n' for line in lines),text=True)
    expected = [json.loads(line) for line in output.splitlines()]
    assert len(expected) == len(lines)
    for case,result in zip(lpn+toep,expected): case['expected'] = result
    report = {'upstream_commit':pin,'source_sha256':hashes,'architecture':architecture,
        'scope':'Retained LPN PRF, scalar and hardware Toeplitz output; not complete HFHE parity',
        'lpn':lpn,'toeplitz':toep}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {len(lpn)} LPN and {len(toep)} native scalar/hardware Toeplitz cases')


if __name__ == '__main__': main()
