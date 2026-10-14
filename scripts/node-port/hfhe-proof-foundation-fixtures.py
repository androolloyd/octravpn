#!/usr/bin/env python3
"""Generate exact native proof transcript, generator and group-operation fixtures."""
import argparse
import hashlib
import json
import pathlib
import platform
import random
import subprocess
import tempfile

ROOT=pathlib.Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream',type=pathlib.Path,required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args=parser.parse_args()
    if args.out.exists():raise SystemExit('use a fresh fixture path')
    pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    if subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip()!=pin:raise SystemExit('upstream pin mismatch')
    hashes={}
    for path,expected in json.loads((ROOT/'docs/rust-node/source-map.json').read_text())['files'].items():
        if not path.startswith('pvac/') and path!='pvac_ffi/pvac_serialize.hpp':continue
        raw=subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{path}'])
        if (args.upstream/path).read_bytes()!=raw:raise SystemExit(f'modified oracle source: {path}')
        hashes[path]=hashlib.sha256(raw).hexdigest()
        if hashes[path]!=expected:raise SystemExit(f'source manifest mismatch: {path}')
    rng=random.Random(20261013107)
    maximum=(1<<64)-1
    hashes_cases=[]
    for domain in [b'',b'pvac.bp.gen.G',b'pvac.bp.gen.H',b'custom\0ignored',bytes(range(1,128))]:
        for index in [0,1,2,31,(1<<20)-1,1<<20,maximum,rng.getrandbits(64)]:
            hashes_cases.append({'domain':domain.hex(),'index':str(index)})
    tables=[]
    for op in ['g','h','g_vec','h_vec','precompute']:
        for n in [0,1,7,32,1<<20,(1<<20)+1,maximum]:
            if n==1<<20 and op not in ['g','h']:continue # Do not allocate a million points in a unit fixture.
            tables.append({'op':op,'n':str(n)})
    sizes=[{'op':op,'n':str(n)} for op in ['next','log2'] for n in [0,1,2,3,4,7,8,9,1023,1024,(1<<20)-1,1<<20,(1<<20)+1,maximum]]
    transcripts=[]
    domains=[b'',b'pvac.range_proof.aggregated',b'pvac.verify_zero.key_bound',b'proof\0ignored',bytes(range(1,256))]
    for rule in [0,1]:
        for i in range(24):
            domain=domains[i%len(domains)]
            ops=[{'op':'c','label':'initial'.encode().hex()},{'op':'m','label':'empty'.encode().hex(),'data':''},
                {'op':'c','label':'challenge'.encode().hex()}]
            for j in range(8):
                op=['m','p','u','s'][j%4]
                item={'op':op,'label':[b'',b'tag\0suffix',bytes(range(1,33)),b'value'][j%4].hex()}
                if op=='u':item['data']=str([0,1,maximum,rng.getrandbits(64)][i%4])
                elif op=='m':item['data']=rng.randbytes([0,1,31,32,64,136,257][i%7]).hex()
                else:item['data']=(b'\xff'*32 if i%5==0 else rng.randbytes(32)).hex()
                ops.extend([item,{'op':'c','label':b'challenge'.hex()}])
            transcripts.append({'domain':domain.hex(),'rule':rule,'ops':ops})
    architecture=platform.machine()
    flags=['-march=armv8-a+crypto'] if architecture in ('arm64','aarch64') else ['-maes','-msse2','-mpclmul']
    oracle=ROOT/'scripts/node-port/hfhe-proof-foundation-oracle.cpp'
    enc=lambda value:value or '-'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-proof-foundation-') as temp:
        executable=pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2',*flags,'-I',str(args.upstream/'pvac/include'),'-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        def run(lines):
            output=subprocess.check_output([str(executable)],input=''.join(line+'\n' for line in lines),text=True)
            results=[json.loads(line) for line in output.splitlines()]
            assert len(results)==len(lines)
            return results
        for case,result in zip(hashes_cases,run(['hash '+enc(c['domain'])+' '+c['index'] for c in hashes_cases])):case['expected']=result
        points=[case['expected']['point'] for case in hashes_cases]+['00'*32]
        groups=[]
        for i in range(48):
            a=rng.choice(points) if i<24 else ([b'\xff'*32,bytes([1])+bytes(31),rng.randbytes(32)][i%3]).hex()
            groups.append({'a':a,'b':rng.choice(points),'scalar':([0,1,(1<<256)-1][i%3]).to_bytes(32,'little').hex() if i<12 else rng.randbytes(32).hex(),'blind':rng.randbytes(32).hex()})
        msms=[]
        for n in [0,1,2,3,4,8,16,32]:
            for bad in [False,True]:
                if bad and n==0:continue
                entries=[{'scalar':rng.randbytes(32).hex(),'point':rng.choice(points)} for _ in range(n)]
                if bad:entries[-1]['point']='ff'*32
                msms.append({'entries':entries})
        lines=['table '+c['op']+' '+c['n'] for c in tables]+['size '+c['op']+' '+c['n'] for c in sizes]
        for c in transcripts:
            line='transcript '+enc(c['domain'])+' '+str(c['rule'])+' '+str(len(c['ops']))
            for op in c['ops']:
                line+=' '+op['op']+' '+enc(op['label'])
                if op['op']!='c':line+=' '+enc(op['data'])
            lines.append(line)
        lines+=['group '+' '.join(c[k] for k in ['a','b','scalar','blind']) for c in groups]
        lines+=['msm '+str(len(c['entries']))+''.join(' '+e['scalar']+' '+e['point'] for e in c['entries']) for c in msms]
        for case,result in zip(tables+sizes+transcripts+groups+msms,run(lines)):case['expected']=result
    report={'upstream_commit':pin,'source_sha256':hashes,'architecture':architecture,'oracle_sha256':hashlib.sha256(oracle.read_bytes()).hexdigest(),
        'scope':'Proof transcripts, generators, group operations and rejection boundaries; complete proof/backend parity remains open',
        'hashes':hashes_cases,'tables':tables,'sizes':sizes,'transcripts':transcripts,'groups':groups,'msms':msms}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {sum(len(report[k]) for k in ["hashes","tables","sizes","transcripts","groups","msms"])} proof foundation cases')


if __name__=='__main__':main()
