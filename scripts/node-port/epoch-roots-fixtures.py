#!/usr/bin/env python3
"""Native epoch-root query source agreement and weighted quorum policy."""
import argparse,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def fixtures():
    out=[];rng=random.Random(2026101317)
    for chain in ['octra-mainnet','octra-devnet-9871-cluster','root-fixture']:
     for epoch in [1,1306546,1306547]:
      for weights in [[1],[1]*4,[1000,1,1,1],[10,3,2,1,1,1,1]]:
       for weighted in [False,True]:
        for _ in range(10):
         records=[dict(addr='v'+str(i+1),root=rng.choice([None,'root-a','root-b']))for i in rng.sample(range(len(weights)),rng.randrange(len(weights)+1))]
         out.append(dict(chain=chain,epoch=str(epoch),height='1',local=1,weights=list(map(str,weights)),weighted=weighted,records=records))
    return out
def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh report')
 r=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/epoch-roots-oracle.ml',fixtures(),'octra_consensus octra_net yojson lwt.unix mirage-crypto-ec')
 r['scope']='Unmodified native driver source-agreement and consensus-quorum decisions at historical activation boundaries. Transport and cancellation are separately tested.'
 a.out.write_text(json.dumps(r,indent=2)+'\n');print(f"PASS: {len(r['cases'])} native epoch-root query decisions")
if __name__=='__main__':main()
