#!/usr/bin/env python3
"""Native transaction gossip wire and inventory/request planner."""
import argparse,base64,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b(v):return base64.b64encode(v if isinstance(v,bytes) else str(v).encode()).decode()
def fixtures():
 out=[]
 for kind in ['inv','get','tx']:
  base=dict(op='encode',kind=kind,hash=b('A'*64),hashes=[b('A'*64),b('ab'*32)],length=17,byte=255,append=b(''))
  out.append(base)
  for op in ['decode','plan']:
   row=dict(base,op=op,known=[b('a'*64)],requests=256,replies=64)
   for cut in range(150):out.append(dict(row,cut=cut))
   for offset in [0,1,2,3,4,5]:
    for replacement in [0,1,2,3,127,128,255]:out.append(dict(row,offset=offset,replacement=replacement))
   out.append(dict(row,append=b('x')))
  for hashes in [[],[b('0'*64)]*512,[b('0'*64)]*513,[b('0'*63)],[b('0'*65)],[b('G'*64)],[b(b'\xff'*64)]]:out.append(dict(base,hashes=hashes))
  for hash in [b('0'*63),b('0'*65),b('G'*64),b('aB'*32)]:out.append(dict(base,hash=hash))
  if kind=='tx':
   for length in [0,1,5000000,5000001]:
    for op in ['encode','decode']:out.append(dict(base,op=op,length=length))
 for kind in ['inv','get']:
  for maximum in [0,1,2,64,256,512]:
   for known in [[],[b('a'*64)],[b('a'*64),b('b'*64)]]:
    out.append(dict(op='plan',kind=kind,hashes=[b('A'*64),b('a'*64),b('b'*64),b('c'*64)],known=known,requests=maximum,replies=maximum,append=b('')))
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/tx-gossip-oracle.ml',fixtures(),'octra_net octra_node_runtime yojson base64 digestif')
 report['scope']='Unmodified native inventory/request/transaction wire codecs and legacy fallback planning, independent of transaction admission'
 a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native gossip cases: {a.out}")
if __name__=='__main__':main()
