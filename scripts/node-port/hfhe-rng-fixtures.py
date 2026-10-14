#!/usr/bin/env python3
"""Generate native seeded RNG draw/transcript fixtures."""
import argparse, hashlib, json, pathlib, platform, random, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream',type=pathlib.Path,required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args=parser.parse_args()
    pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    if args.out.exists(): raise SystemExit('use a fresh fixture path')
    if subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip()!=pin: raise SystemExit('upstream pin mismatch')
    hashes={}
    for name in ['pvac/include/pvac/core/seedable_rng.hpp','pvac/include/pvac/crypto/lpn.hpp']:
        raw=subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{name}'])
        if (args.upstream/name).read_bytes()!=raw: raise SystemExit('modified RNG source')
        hashes[name]=hashlib.sha256(raw).hexdigest()
    seeds=[bytes(32),bytes([255])*32,bytes(range(32))]
    rng=random.Random(20261012)
    seeds += [rng.randbytes(32) for _ in range(32)]
    cases=[[seed.hex(),str(nonce)] for seed in seeds for nonce in [0,1,(1<<64)-2,(1<<64)-1]]
    architecture=platform.machine()
    flags=['-march=armv8-a+crypto'] if architecture in ('arm64','aarch64') else ['-maes','-msse2']
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-rng-') as temp:
        executable=pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2',*flags,'-I',str(args.upstream/'pvac/include'),str(ROOT/'scripts/node-port/hfhe-rng-oracle.cpp'),'-o',str(executable)],check=True)
        output=subprocess.check_output([str(executable)],input=''.join(' '.join(row)+'\n' for row in cases),text=True)
    lines=output.splitlines()
    assert len(lines)==len(cases)
    report={'upstream_commit':pin,'source_sha256':hashes,'architecture':architecture,
        'scope':'AES-256 counter stream, bounded draw consumption and PRF-key transcript; not full HFHE parity',
        'cases':[{'input':row,'expected':line.split()} for row,line in zip(cases,lines)]}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {len(cases)} native seeded RNG cases')
if __name__=='__main__': main()
