#!/usr/bin/env python3
"""Generate decryption policy fixtures from native constructed ciphertexts."""
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
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream',type=pathlib.Path,required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args=parser.parse_args()
    if args.out.exists():raise SystemExit('use a fresh fixture path')
    pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    if subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip()!=pin:
        raise SystemExit('upstream pin mismatch')
    hashes={}
    for path,expected in json.loads((ROOT/'docs/rust-node/source-map.json').read_text())['files'].items():
        if not path.startswith('pvac/') and path!='pvac_ffi/pvac_serialize.hpp':continue
        raw=subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{path}'])
        if (args.upstream/path).read_bytes()!=raw:raise SystemExit(f'modified oracle source: {path}')
        hashes[path]=hashlib.sha256(raw).hexdigest()
        if hashes[path]!=expected:raise SystemExit(f'source manifest mismatch: {path}')
    rng=random.Random(2026101317)
    kinds=['empty','clear','active','legacy','native','native_unused','product','native_product','nested',
        'pc_only','r_pc_only','native_tag_flip','implicit_zero','wrong_sigma','wrong_index',
        'bad_parent','bad_sign','bad_weights','bad_c0']
    cases=[]
    for profile in [1,2]:
        for index,kind in enumerate(kinds):
            for slots in [1,3]:
                cases.append({'seed':rng.randbytes(32).hex(),'profile':profile,'slots':slots,'kind':kind,
                    'nonce':[str(rng.getrandbits(64)),str([0,(1<<64)-1][index%2])]})
    architecture=platform.machine()
    flags=['-march=armv8-a+crypto'] if architecture in ('arm64','aarch64') else ['-maes','-msse2','-mpclmul']
    oracle=ROOT/'scripts/node-port/hfhe-decrypt-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-decrypt-') as temp:
        executable=pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2',*flags,'-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        lines=[' '.join(map(str,[case['seed'],case['profile'],case['slots'],case['kind'],*case['nonce']])) for case in cases]
        output=subprocess.check_output([str(executable)],input=''.join(line+'\n' for line in lines),text=True)
    results=[json.loads(line) for line in output.splitlines()]
    assert len(results)==len(cases)
    for case,result in zip(cases,results):case['expected']=result
    report={'upstream_commit':pin,'source_sha256':hashes,'architecture':architecture,
        'oracle_sha256':hashlib.sha256(oracle.read_bytes()).hexdigest(),
        'scope':'Decryption policy, native sources, legacy/active/product masks and malformed inputs; not complete HFHE parity',
        'cases':cases}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {len(cases)} native ciphertexts under all three decryption policies')


if __name__=='__main__':main()
