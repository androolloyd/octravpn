#!/usr/bin/env python3
"""Native local vote recovery and precommit durability barrier traces."""
import argparse, importlib.util, itertools, json, pathlib, random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
CHAIN=b'vote-guard-fixture'.hex()
def fixtures():
    def vote(**kw):return dict(chain=CHAIN,epoch='1',round=0,type=2,pid='bound',signer=1,corrupt=False,proposal='present')|kw
    def prepare(wires=None,**kw):return dict(op='prepare',wires=wires or [],restore_error=None)|kw
    def save(v=None,persist=True):return dict(op='save',vote=v or vote(),persist=persist)
    def flags(**kw):return dict(op='flags',running=False,role=True,ready=True,finality=False)|kw
    def floor(n):return dict(op='floor',epoch=str(n))
    out=[]
    for local,height,start in itertools.product([1,9],[0,1,2,41],[None,-1,0,1,41,42]):
        steps=[]if start is None else[floor(start)]
        out.append(dict(local=local,height=str(height),steps=steps+[prepare(),flags(running=True),prepare(),flags(),prepare()]))
    for kind,pid,proposal,signer in itertools.product([1,2],['nil','bound','other'],['present','missing','round','chain','header'],[1,2]):
        v=vote(type=kind,pid=pid,proposal=proposal,signer=signer)
        out.append(dict(local=1,height='1',steps=[prepare(),save(v,False),save(v),save(v),flags(finality=True),save(v),flags(),save(vote())]))
    for v in [vote(),vote(type=1),vote(round=999999),vote(round=1000000),vote(epoch='2'),vote(chain=b'other'.hex()),vote(signer=2),vote(corrupt=True),{'raw':''},{'raw':'00'}]:
        out.append(dict(local=1,height='1',steps=[prepare([v]),save(),prepare(),save(),floor(1),prepare()]))
    out.append(dict(local=9,height='1',steps=[prepare([vote(signer=9)]),prepare(),flags(role=False),save(vote(signer=9))]))
    out.append(dict(local=1,height='1',steps=[prepare(restore_error='host recovery failed'),save(),prepare(),save(),save(vote(pid='other')),prepare(),save(),flags(role=False),flags(ready=False),flags(finality=True)]))
    for proof,role,ready in itertools.product([False,True],repeat=3):out.append(dict(local=1,height='1',steps=[prepare(),flags(finality=proof,role=role,ready=ready),save(persist=False)]))
    rng=random.Random(2026101313)
    for _ in range(36):
        steps=[]
        for n in range(50):
            op=rng.choice(['save']*5+['prepare','flags','floor'])
            v=vote(round=rng.randrange(5),type=rng.choice([1,2]),pid=rng.choice(['nil','bound','other']),signer=rng.choice([1,1,2]),proposal=rng.choice(['present','present','missing','round']))
            steps.append(save(v,rng.choice([True,False]))if op=='save'else prepare([v]if rng.randrange(3)==0 else[])if op=='prepare'else floor(rng.randrange(3))if op=='floor'else flags(running=rng.randrange(4)==0,role=rng.choice([True,False]),ready=rng.choice([True,False]),finality=rng.choice([True,False])))
        out.append(dict(local=1,height='1',steps=steps))
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh report')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/driver-votes-oracle.ml',fixtures(),'octra_consensus octra_net yojson mirage-crypto-ec lwt.unix')
    report['scope']='Unmodified C_driver local vote startup, recovery, readiness and saved_vote durability barrier with real disk vote journal and controlled host precommit callback. No full consensus driver or public-chain qualification.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native vote guard traces")
if __name__=='__main__':main()
