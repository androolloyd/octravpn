#!/usr/bin/env python3
"""Native startup pending-record decisions and ordered host effects."""
import argparse,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def fixtures():
    def record(epoch=1,round=0,root='03'*32):return dict(epoch=epoch,round=round,root=root)
    def case(**kw):return dict(head=0,pending=[record()],restore='legacy',validators=4,quorum=2,responses=['03'*32]*2,after=1,fault='',read_fault=0)|kw
    out=[]
    for pending in [[],[record(0)],[record(1)],[record(2)],[record(0),record(1)],[record(1),record(2)],[record(1,2),record(1,0),record(1,1)],[record(1,2),record(1,2)], [record(root='AB'*32)]]:
      for restore in ['lock','invalid','legacy']:
       for fault in ['','head','query','catchup','delete']:
        out.append(case(pending=pending,restore=restore,fault=fault))
    for read_fault in [1,2,3]:out.append(case(read_fault=read_fault))
    rng=random.Random(2026101316)
    for _ in range(300):
      out.append(case(validators=rng.randrange(1,9),quorum=rng.randrange(0,6),responses=[rng.choice([None,'03'*32,'04'*32])for _ in range(rng.randrange(9))],after=rng.randrange(-1,3),pending=[record(1,rng.randrange(4),rng.choice(['03'*32,'bad']))for _ in range(rng.randrange(1,5))]))
    return out
def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh report')
 r=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/pending-reconciliation-oracle.ml',fixtures(),'octra_node_runtime octra_core octra_consensus yojson lwt.unix')
 r['scope']='Unmodified native pending recovery orchestration and ordered host effects. Host query and canonical catch-up callbacks are controlled, not live-chain sync.'
 a.out.write_text(json.dumps(r,indent=2)+'\n');print(f"PASS: {len(r['cases'])} native pending reconciliation traces")
if __name__=='__main__':main()
