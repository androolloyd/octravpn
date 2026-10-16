#!/usr/bin/env python3
"""Read-proof vectors from unmodified Octra and its pinned Irmin dependencies."""
import argparse,base64,hashlib,importlib.util,json,random,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PACKAGES=['irmin','irmin-pack','repr','irmin-containers']
def b64(v):return base64.b64encode(v).decode()
def sha(v):return hashlib.sha256(v).hexdigest()
def cases():
    out=[];rng=random.Random(0x111F)
    def add(entries,query,reads=(),adversarial=True):
        out.append(dict(entries=[dict(path=[b64(p) for p in path],value=b64(v)) for path,v in entries],query=[b64(p) for p in query],reads=[[b64(p) for p in path] for path in reads],adversarial=adversarial))
    for count in [1,2,31,32,33,127,128,255,256,257,512,1025]:
        entries=[([f'key-{i:05}'.encode()],rng.randbytes(i%39)) for i in range(count)]
        add(entries,entries[0][0],[[],[b'absent'],entries[-1][0],entries[0][0]+[b'child']])
        add(entries,[b'absent'],[entries[0][0]],False)
    for depth in [1,2,10,40,200]:
        key=[b'branch']*depth+[b'leaf'];entries=[(key,b'payload'),([b'other'],b'payload')]
        add(entries,key,[key[:-1],[b'other'],[b'absent']])
    for key,value in [(b'',b''),(b'\0',b'\xff'),(b'\xff',bytes(range(256))),(b'key',b'x'*16384)]:
        add([([key],value),([b'other'],value)],[key],[[b'other']])
    # Hash-bits collisions force deeper inodes and extender compression.
    keys=[];i=0
    while len(keys)<260:
        key=f'collision-{i}'.encode();i+=1;h=hashlib.blake2b(key).digest()
        if h[0]==0 and h[1]>>6==0:keys.append(key)
    entries=[([key],b'value') for key in keys]
    add(entries,[keys[0]],[[keys[-1]],[b'absent']])
    for _ in range(25):
        entries=[([rng.choice([b'a',b'b',b'\xff',b'',b'meta']) for _ in range(rng.randrange(1,5))],rng.randbytes(rng.randrange(0,65))) for _ in range(80)]
        query=rng.choice(entries)[0];add(entries,query,[rng.choice(entries)[0] for _ in range(4)],False)
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    image=subprocess.check_output(['docker','image','inspect',a.builder_image,'--format','{{.Id}}'],text=True).strip()
    source="""import pathlib,hashlib,json
root=pathlib.Path('/home/opam/.opam/4.14.2/lib')
print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for name in ['irmin','irmin-pack','repr','irmin-containers'] for p in (root/name).rglob('*') if p.is_file() and p.suffix in ['.ml','.mli']}))
"""
    dependencies=json.loads(subprocess.check_output(['docker','run','--rm','--network','none',image,'python3','-c',source],text=True))
    prior=json.loads((ROOT/'crates/octra-node-runtime/tests/fixtures/irmin-storage.json').read_text())['dependencies']['source_sha256']
    pinned={k:v for k,v in prior.items() if k.split('/')[0] in PACKAGES}
    if dependencies!=pinned:raise SystemExit('Installed Irmin dependency source differs from adopted storage provenance')
    spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    report=native.run(a.upstream,image,ROOT/'scripts/node-port/irmin-proof-oracle.ml',cases(),'octra_core lwt.unix yojson base64 irmin')
    report['dependency_source_sha256']=dependencies;report['generator_sha256']=sha(Path(__file__).read_bytes())
    report['scope']='Native Irmin read proofs, authenticated inclusion/absence and blinded-path rejection; no public snapshot import.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',sum(len(c['checks']) for c in report['cases']),'native Irmin proof checks')
if __name__=='__main__':main()
