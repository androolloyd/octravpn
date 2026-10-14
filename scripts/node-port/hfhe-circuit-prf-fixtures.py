#!/usr/bin/env python3
"""Generate active v6/v7 masks, layer transcripts, LPN-v2 and delta fixtures."""
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
    if subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip() != pin:
        raise SystemExit('upstream pin mismatch')
    hashes = {}
    files = json.loads((ROOT/'docs/rust-node/source-map.json').read_text())['files']
    for source, expected in files.items():
        if not source.startswith('pvac/') and source != 'pvac_ffi/pvac_serialize.hpp':
            continue
        raw = subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{source}'])
        if (args.upstream/source).read_bytes() != raw:
            raise SystemExit(f'modified oracle source: {source}')
        hashes[source] = hashlib.sha256(raw).hexdigest()
        if hashes[source] != expected:
            raise SystemExit(f'source manifest mismatch: {source}')
    rng = random.Random(2026101307)
    maximum = (1 << 64)-1
    rounds = []
    for profile in (1,2):
        for index, round_number in enumerate([*range(91),127,255,maximum]):
            lo,hi = [(0,0),(1,0),(maximum-1,maximum>>1),(maximum,maximum>>1),
                (1,1<<62),(0,1<<63)][index % 6]
            rounds.append({'profile':profile, 'round':str(round_number), 'value':[str(lo),str(hi)]})
    cases = []
    for i in range(24):
        n,t = [(1,1),(63,64),(65,127),(129,257),(127,129),(65,1)][i%6]
        if i in (22,23): n,t = 4096,16384
        cases.append({'seed':rng.randbytes(32).hex(), 'profile':1+i%2, 'n':n,'t':t,
            'num':[-1,0,1,8,9][i%5], 'den':8, 'tag':str([0,maximum,rng.getrandbits(64)][i%3]),
            'nonce':[str(rng.getrandbits(64)),str([0,maximum][i%2])],
            'count':[0,1,2,5,10][i%5], 'index':str([0,1,maximum,rng.getrandbits(64)][i%4]),
            'gid':[0,1,(1<<32)-1,rng.getrandbits(32)][i%4], 'kind':[0,1,255][i%3]})
    toeplitz = []
    for bits in [1,2,63,64,65,127,128,129,257,1024,16384]:
        for style in range(4):
            word = lambda: [0,1,maximum,rng.getrandbits(64)][style]
            toeplitz.append({'bits':bits,'top':[str(word()) for _ in range((bits+126+63)//64)],
                'y':[str(word()) for _ in range((bits+63)//64)]})
    toeplitz.extend([{'bits':0,'top':[],'y':[]},{'bits':1,'top':['0'],'y':['0']},
        {'bits':64,'top':['0']*3,'y':[]},{'bits':65,'top':['0']*4,'y':['0']*2}])
    architecture = platform.machine()
    flags = ['-march=armv8-a+crypto'] if architecture in ('arm64','aarch64') else ['-maes','-msse2','-mpclmul']
    oracle = ROOT/'scripts/node-port/hfhe-circuit-prf-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-circuit-prf-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2',*flags,'-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        lines = ['round '+' '.join(map(str,[case['profile'],case['round'],*case['value']])) for case in rounds]
        lines += ['case '+' '.join(map(str,[case['seed'],case['profile'],case['n'],case['t'],case['num'],case['den'],
            case['tag'],*case['nonce'],case['count'],case['index'],case['gid'],case['kind']])) for case in cases]
        lines += ['toep '+' '.join(map(str,[case['bits'],len(case['top']),len(case['y']),*case['top'],*case['y']])) for case in toeplitz]
        output = subprocess.check_output([str(executable)],input=''.join(line+'\n' for line in lines),text=True)
    results = [json.loads(line) for line in output.splitlines()]
    assert len(results) == len(lines)
    for case,result in zip(rounds+cases+toeplitz,results):
        case['expected'] = result
    report = {'upstream_commit':pin, 'source_sha256':hashes, 'architecture':architecture,
        'oracle_sha256':hashlib.sha256(oracle.read_bytes()).hexdigest(),
        'scope':'Active circuit PRFs, layer commitments and LPN-v2 noise; not complete HFHE parity',
        'rounds':rounds,'cases':cases,'toeplitz':toeplitz}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {len(rounds)} round/power, {len(cases)} active mask/noise/commitment and {len(toeplitz)} full Toeplitz cases')


if __name__ == '__main__':
    main()
