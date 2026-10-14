#!/usr/bin/env python3
"""Native bounded transaction retry cache and peer gossip quotas."""
import argparse,base64,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b(v):return base64.b64encode(v if isinstance(v,bytes) else str(v).encode()).decode()
def fixtures():
 out=[];rng=random.Random(251)
 for now in ['0','-0','-1','1','nan','inf','-inf','1e300']:
  steps=[]
  for t in ['0',now,'0.999999','1','1.000001','-1','0','2']:
   for key in ['a','b','a']:
    for remember in [False,True,False]:steps.append(dict(now=t,key=b(key),remember=remember))
  out.append(dict(op='seen',steps=steps))
 for _ in range(80):
  steps=[];now=0.
  for _ in range(100):
   now+=rng.choice([-1,0,0,0.0001,0.9,1,2]);steps.append(dict(now=str(now),key=b(bytes([rng.randrange(8)])),remember=rng.choice([True,False])))
  out.append(dict(op='seen',steps=steps))
 steps=[dict(now='0',key=b(f'{i:05}'),remember=True) for i in range(4100)]
 steps.extend(dict(now='0.5',key=b(f'{i:05}'),remember=False) for i in [0,1,2,3,4,5,4095,4096,4099]);steps.extend([dict(now='1',key=b('new'),remember=True),dict(now='1',key=b('04099'),remember=False)])
 out.append(dict(op='seen',steps=steps))
 cfg=dict(window='60',messages=4096,bytes=64*1024*1024,payload=5004096)
 for config in [cfg,dict(cfg,messages=2,bytes=10,payload=5),dict(cfg,messages=0),dict(cfg,bytes=0),dict(cfg,window='0'),dict(cfg,messages=-1),dict(cfg,payload=-1),dict(cfg,bytes=(1<<62)-1,payload=(1<<62)-1)]:
  steps=[]
  for t in ['0','59.9999','60','60.0001','-1','300','600.001']:
   for size in [-1,0,1,5,6,5004096,5004097,(1<<62)-1]:steps.append(dict(now=t,key=b('peer'),bytes=size))
  out.append(dict(op='guard',config=config,steps=steps))
 for _ in range(60):
  steps=[];now=0.
  for _ in range(70):
   now+=rng.choice([-10,0,0.01,1,59,60,300]);steps.append(dict(now=str(now),key=b(bytes([rng.randrange(8)])),bytes=rng.randrange(-1,30),prune=rng.choice([False,False,True]),ttl=str(rng.choice([0,300])),maximum=rng.randrange(5)))
  out.append(dict(op='guard',config=dict(cfg,messages=3,bytes=50,payload=20),steps=steps))
 steps=[dict(now='0',key=b(f'{i:05}'),bytes=0) for i in range(4100)]+[dict(now='0',prune=True,ttl='300',maximum=3)]
 out.append(dict(op='guard',config=cfg,steps=steps));return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/gossip-guard-oracle.ml',fixtures(),'octra_net yojson base64')
 report['scope']='Native bounded retry cache, clock rollback/nonfinite handling, gossip rate/byte quotas and pruning'
 a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native gossip guard traces: {a.out}")
if __name__=='__main__':main()
