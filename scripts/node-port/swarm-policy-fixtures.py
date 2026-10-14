#!/usr/bin/env python3
"""Native transport upgrade schedules and swarm admission decisions."""
import argparse,base64,hashlib,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b(v):return base64.b64encode(v if isinstance(v,bytes) else str(v).encode()).decode()
def node(key):return hashlib.sha256(b'octra:node_id:v1\x00'+key).hexdigest().encode()
def fixtures():
 out=[];a=bytes([1])*32;c=bytes([2])*32;d=bytes([3])*32
 for plan in [None,dict(epoch='10',binary=b(c),config=b(d)),dict(epoch='10',binary=b(c),config=b(d),rollback=dict(epoch='20',binary=b(a),config=b(a)))]:
  for epoch in [-(1<<63),-1,0,9,10,19,20,(1<<63)-1]:
   for required in [False,True]:
    for config,binary in [(a,a),(d,c),(a,c),(d,a)]:out.append(dict(op='upgrade',plan=plan,epoch=str(epoch),required=required,config=b(config),binary=b(binary)))
 for raw in [a,b' '+a+b' ',b'1'*31,b'1'*33,b'00'*32,b'FF'*32,b'aB'*32,b'1_'*32,b'_1'*32,b'++'*32,b'  '+b'FF'*32+b'\t',b'\v'+b'FF'*32,b'\x00'*64,b'0x'*32]:out.append(dict(op='normalize',value=b(raw)))
 for now in [-1.,0.,1.,30.,31.]:
  for due in [None,-1.,0.,1.,30.,31.]:
   for active in [0,1,3,4,5]:out.append(dict(op='retry',now=now,due=due,active=active))
 for maximum in [-1,0,1,8,64]:
  for validators in [0,1,8,64]:
   for observers in [0,1,7,8,9]:
    for validator in [False,True]:out.append(dict(op='capacity',maximum=maximum,validators=validators,observers=observers,validator=validator))
 for current in [a,c]:
  for offered in [None,a,c]:out.append(dict(op='keep',target=b(a),current=b(current),offered=None if offered is None else b(offered)))
 for keys in [None,[],[b(a)],[b(a),b(c)],[b(c)]]:
  for peer in [node(a),node(c),b'']:
   for public in [a,c,d]:
    for update in [None,[],[b(a)],[b(c)],[b(a),b(a)],[b(a),b('short')]]:out.append(dict(op='roles',keys=keys,peer_id=b(peer),local_id=b(node(a)),public=b(public),update=update))
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/swarm-policy-oracle.ml',fixtures(),'octra_net yojson base64')
 report['scope']='Native upgrade/rollback hashes, readiness, active validator roles, capacity, profile retention and peer discovery retries'
 a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native swarm policy cases: {a.out}")
if __name__=='__main__':main()
