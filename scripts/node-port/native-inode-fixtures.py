#!/usr/bin/env python3
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json
ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description='Generate native roots for physical inode persistence qualification.')
parser.add_argument('--upstream',type=Path,required=True)
parser.add_argument('--builder-image',required=True)
parser.add_argument('--out',type=Path,required=True)
args=parser.parse_args()
if args.out.exists():raise SystemExit('require a fresh output')
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b(value):return base64.b64encode(value).decode()
def set_(key,value,path=None):return {'op':'set','path':[b(x) for x in ([b'accounts',key] if path is None else path)],'value':b(value)}
def remove(key):return {'op':'remove','path':[b(b'accounts'),b(key)]}
inputs=[]
for count in [257,1025]:
    keys=[i.to_bytes(4,'big') for i in range(count)]
    operations=[set_(key,b'value-'+i.to_bytes(4,'little')) for i,key in enumerate(keys)]
    operations += [set_(keys[0],b'changed'),set_(keys[-1],b'changed-last'),remove(b'absent'),set_(b'\x00\xff',b'binary'),remove(b'\x00\xff')]
    operations += [remove(key) for key in reversed(keys)]
    inputs.append({'op':'tree','operations':operations})
keys=[];index=0
while len(keys)<260:
    key=f'collision-{index}'.encode();index+=1;digest=hashlib.blake2b(key).digest()
    if digest[0]==0 and digest[1]>>6==0:keys.append(key)
inputs.append({'op':'tree','operations':[set_(key,b'shared') for key in keys]+[set_(keys[100],b'changed')]+[remove(key) for key in reversed(keys)]+[set_(b'',b'empty-name'),set_(b'\xff',b'high-name'),set_(b'',b'replaced'),remove(b''),remove(b'\xff')]})
output=native.run(args.upstream,args.builder_image,ROOT/'scripts/node-port/storage-oracle.ml',inputs,'octra_core lwt.unix yojson base64 irmin')
output['generator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();p=args.out;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(output,indent=2)+'\n');print(json.dumps({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'cases':len(inputs),'operations':sum(len(i['operations']) for i in inputs)}))
