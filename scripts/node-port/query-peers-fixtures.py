#!/usr/bin/env python3
"""Native peer rotation/waves with driver ordering inputs made explicit."""
import argparse,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def fixtures():
 rng=random.Random(2026101318);out=[]
 for count in [0,1,2,4,6,7,32,4096]:
  for n in [0,1,4,7]:
   for size in [0,1,15,16,17,32]:
    connected=[rng.randrange(1,10)if rng.randrange(3)else rng.randbytes(32).hex() for _ in range(rng.randrange(20))]
    out.append(dict(seed=rng.randbytes(size).hex(),validators=n,count=count,connected=connected))
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh report')
 r=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/query-peers-oracle.ml',fixtures(),'octra_consensus octra_net yojson mirage-crypto-ec')
 r['scope']='Unmodified native offset, rotation and bundle-wave functions. The driver ordering expression is evaluated with explicit connected and active peer IDs, without a live swarm.'
 a.out.write_text(json.dumps(r,indent=2)+'\n');print('PASS',len(r['cases']),'native peer query plans')
if __name__=='__main__':main()
