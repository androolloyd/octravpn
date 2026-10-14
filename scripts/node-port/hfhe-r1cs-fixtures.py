#!/usr/bin/env python3
"""Qualify R1CS against pristine native headers with an explicit test entropy tape.

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
    rng = random.Random(2026101311)
    order = (1<<252) + 27742317777372353535851937790883648493
    encode = lambda value: value.to_bytes(32,'little').hex()
    cases = []
    def case(rule,variant,n,m,mode=0,tape_mode=0,error=0):
        def scalar(index):
            if mode == 1:
                return encode(rng.randrange(order))
            if mode == 2:
                return encode([0,1,order-1,order,order+1,(1<<255),(1<<256)-1][index%7])
            return encode(rng.randrange(1,24))
        commits = [[scalar(i),scalar(i+3)] for i in range(m)]
        gates = [[scalar(i+1),scalar(i+4)] for i in range(n)]
        padded = 1 << max(0,(max(1,n)-1).bit_length())
        tape_size = (2*padded+8)*64
        tape = rng.randbytes(tape_size) if tape_mode==0 else bytes([0 if tape_mode==1 else 255])*tape_size
        if error == 4:
            tape = tape[:72]
        item = dict(rule=rule,variant=variant,error_case=error,committed=commits,gates=gates,tape=tape.hex())
        cases.append(item)
    for rule in [0,1]:
        for variant in range(6):
            for n in [0,1,2,3,5,8]:
                case(rule,variant,n,(n+variant)%3)
        for mode in [1,2]:
            for variant in [0,1,3]:
                case(rule,variant,3,2,mode=mode)
        for tape_mode in [1,2]:
            case(rule,1,3,2,tape_mode=tape_mode)
        for error in [1,2,3,4]:
            case(rule,0,1,0,error=error)
    lines = []
    for item in cases:
        fields = [item['rule'],item['variant'],item['error_case'],len(item['gates']),len(item['committed'])]
        fields += [v for pair in item['committed']+item['gates'] for v in pair]
        fields += [item['tape']]
        lines.append(' '.join(map(str,fields)))
    oracle = ROOT/'scripts/node-port/hfhe-r1cs-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-r1cs-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2','-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        output = subprocess.check_output([str(executable)],input='\n'.join(lines)+'\n',text=True)
    results = output.splitlines()
    if len(results) != len(cases):
        raise SystemExit('native oracle output count mismatch')
    for item,result in zip(cases,results):
        item['expected'] = json.loads(result)
    report = dict(upstream_commit=pin,source_sha256=hashes,architecture=platform.machine(),
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
        entropy_adapter='Platform arc4random_buf/getrandom redirected to a public test tape; native headers unchanged',
        scope='R1CS full raw proof bytes, proving transcript, entropy bytes/calls, and 22 verifier variants per proof; not complete backend parity',
        cases=cases)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    proved = [item for item in cases if 'proof' in item['expected']]
    accepted = sum(item['expected']['verify'][0]['accepted'] for item in proved)
    print(f'Generated {len(proved)} native R1CS proofs ({accepted} accepted), {22*len(proved)} verifier outcomes, {len(cases)-len(proved)} proving refusals')


if __name__ == '__main__':
    main()
