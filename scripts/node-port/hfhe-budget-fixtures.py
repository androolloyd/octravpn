#!/usr/bin/env python3
"""Qualify native floating budgets on this host, or both Darwin CPU targets."""
import argparse
import hashlib
import json
import math
import pathlib
import platform
import random
import struct
import subprocess
import tempfile

ROOT=pathlib.Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream',type=pathlib.Path,required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    parser.add_argument('--mode',choices=['native','darwin-dual'],
        help='default: darwin-dual on arm64 macOS, otherwise native')
    parser.add_argument('--compiler',default='clang++',help='native C++ compiler (default: clang++)')
    args=parser.parse_args()
    if args.out.exists():raise SystemExit('use a fresh fixture path')
    pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    if subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip()!=pin:
        raise SystemExit('upstream pin mismatch')
    hashes={}
    sources=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())['files']
    for source,expected in sources.items():
        if not source.startswith('pvac/') and source not in ('pvac_ffi/pvac_serialize.hpp','pvac_ffi/dune'):continue
        raw=subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{source}'])
        if (args.upstream/source).read_bytes()!=raw:raise SystemExit(f'modified oracle source: {source}')
        hashes[source]=hashlib.sha256(raw).hexdigest()
        if hashes[source]!=expected:raise SystemExit(f'source manifest mismatch: {source}')
    cases=[]
    for sign in [-1,1]:
        for depth in [10,100,1000]:
            for fraction in [0.0,0.55,1.0]:
                slope=sign*0.1*2**60
                entropy=-(slope*depth)
                for noise in [math.nextafter(entropy,-math.inf),entropy,math.nextafter(entropy,math.inf)]:
                    cases.append({'basis':337,'entropy':noise,'slope':slope,'depth':depth,'fraction':fraction,'kind':'cancellation'})
    for basis in [3,7,9,337]:
        for fraction in [0.55,1.0]:
            for count in [0,1,2,3,7,31]:
                boundary=2*math.log2(basis)*count/fraction
                for noise in [math.nextafter(boundary,-math.inf),boundary,math.nextafter(boundary,math.inf)]:
                    cases.append({'basis':basis,'entropy':noise,'slope':16.0,'depth':0,'fraction':fraction,'kind':'floor_boundary'})
    rng=random.Random(2026101337)
    for _ in range(128):
        cases.append({'basis':rng.choice([3,7,9,337]),'entropy':rng.uniform(-100,1000),
            'slope':rng.uniform(-10,100),'depth':rng.choice([-100,-1,0,1,10,32767]),
            'fraction':rng.choice([0.0,0.55,1.0,rng.uniform(-1,2)]),'kind':'random_defined'})
    architecture=platform.machine()
    system=platform.system()
    if system not in ('Darwin','Linux'):
        raise SystemExit('supported native hosts are macOS and Linux')
    host_os={'Darwin':'macos','Linux':'linux'}[system]
    target_arch={'arm64':'aarch64','aarch64':'aarch64','x86_64':'x86_64'}.get(architecture)
    if target_arch is None:raise SystemExit(f'unsupported native architecture: {architecture}')
    mode=args.mode or ('darwin-dual' if system=='Darwin' and target_arch=='aarch64' else 'native')
    if mode=='darwin-dual':
        if system!='Darwin' or target_arch!='aarch64':
            raise SystemExit('darwin-dual requires arm64 macOS with Rosetta x86_64 execution')
        subprocess.run(['arch','-x86_64','/usr/bin/true'],check=True)
        builds=[('aarch64',['-arch','arm64','-march=armv8-a+crypto'],'native arm64',[]),
            ('x86_64',['-arch','x86_64','-maes','-msse2'],'Rosetta x86_64 translation',['arch','-x86_64'])]
    else:
        flags=['-march=armv8-a+crypto'] if target_arch=='aarch64' else ['-maes','-msse2']
        builds=[(target_arch,flags,f'native {architecture}',[])]
    for case in cases:
        for name in ['entropy','slope','fraction']:
            case[name+'_bits']=struct.pack('>d',case[name]).hex()
        case['expected']={}
    # These arithmetic-relevant flags match pvac_ffi/dune; platform-specific
    # unwind emission does not affect this standalone calculation.
    compiler=subprocess.check_output([args.compiler,'--version'],text=True).strip()
    oracle=ROOT/'scripts/node-port/hfhe-budget-oracle.cpp'
    targets={}
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-budget-') as temp:
        for target,arch_flags,execution,launcher in builds:
            flags=['-std=c++17','-O2','-fPIC',*arch_flags]
            executable=pathlib.Path(temp)/target
            subprocess.run([args.compiler,*flags,'-I',str(args.upstream/'pvac/include'),'-I',str(args.upstream/'pvac_ffi'),
                str(oracle),'-o',str(executable)],check=True)
            lines=[' '.join(map(str,[case['basis'],case['entropy_bits'],case['slope_bits'],case['depth'],case['fraction_bits']])) for case in cases]
            command=[*launcher,str(executable)]
            output=subprocess.check_output(command,input=''.join(line+'\n' for line in lines),text=True)
            results=[json.loads(line) for line in output.splitlines()]
            assert len(results)==len(cases)
            for case,result in zip(cases,results):case['expected'][target]=result
            differing=[result for result in results if result['split_cap_bits']!=result['fused_cap_bits']]
            assert differing,'fixture failed to exercise contraction-sensitive cases'
            targets[target]={'operating_system':host_os,'compiler_flags':flags,'execution':execution,'contraction_sensitive_cases':len(differing),
                'native_matches_fused_in_sensitive_cases':all(case['cap_bits']==case['fused_cap_bits'] for case in differing),
                'native_matches_split_in_sensitive_cases':all(case['cap_bits']==case['split_cap_bits'] for case in differing)}
    report={'upstream_commit':pin,'source_sha256':hashes,'host_architecture':architecture,'host_os':host_os,'compiler':compiler,'targets':targets,
        'oracle_sha256':hashlib.sha256(oracle.read_bytes()).hexdigest(),
        'scope':'Defined integer-conversion budgets for the recorded host OS, compiler and target execution modes; other platforms and toolchains remain unqualified',
        'cases':cases}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {len(cases)} budget cases for {len(targets)} target(s) on {host_os}')


if __name__=='__main__':main()
