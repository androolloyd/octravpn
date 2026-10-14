#!/usr/bin/env python3
"""Native epoch reward and emission plans, weighted attribution and activation."""
import argparse,base64,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v if isinstance(v,bytes) else str(v).encode()).decode()
MAX=10**15;DURATION=47304000
def fixtures():
    out=[];rng=random.Random(913)
    base=dict(op='plan',active=False,retired='0',base=None,count=4,remaining='1000000',fees='1000',supply='10000')
    for field,values in dict(active=[False,True],retired=['-1','0',str(MAX-1010000)],base=[None,'-1','0','1','9999','1000000','1000001'],count=[-1,0,1,2,4,127,4096],remaining=['-1','0','1','9999','10000',str(MAX),str(MAX+1)],fees=['-1','0','1','4','5','6','1000',str(MAX),str(2**128)],supply=['-1','0','1',str(MAX-1000000),str(MAX),str(MAX+1)]).items():
        for value in values:out.append(dict(base,**{field:value}))
    for _ in range(250):
        supply=rng.randrange(MAX);remaining=rng.randrange(MAX-supply+1)
        out.append(dict(base,active=rng.choice([True,False]),retired=str(MAX-supply-remaining),remaining=str(remaining),supply=str(supply),fees=str(rng.randrange(1000001)),count=rng.randrange(1,4097)))
    for total in [0,1,2,3,4,5,9,10,11,13,1000,2**128]:
        for validators in [[],[(b'a',1)],[(b'a',1),(b'a',2)],[(b'b',1),(b'a',1)],[(b'a',0)],[(b'a',-1)],[(b'a',1),(b'b',10),(b'\xff',2**128)],[(b'b',7),(b'a',3),(b'\x00',5)]]:
            for proposer in [b'a',b'p']:
                out.append(dict(base,op='credits',fees=str(total),remaining='0',count=max(1,len(validators)),proposer=b64(proposer),validators=[dict(address=b64(a),weight=str(w)) for a,w in validators]))
    binding=dict(op='binding',activation=10,epoch=10,remaining='1000',headroom='2000',standard=None,stored_activation=None,initial=None,stored_retired=None)
    for activation in [None,0,10]:
        for epoch in [0,9,10,11,(1<<62)-1]:
            for mask in range(16):
                row=dict(binding,activation=activation,epoch=epoch)
                for n,(k,v) in enumerate([('standard','security_curve'),('stored_activation','10'),('initial','1000'),('stored_retired','1000')]):
                    if mask&(1<<n):row[k]=b64(v)
                out.append(row)
    full=dict(binding,standard=b64('security_curve'),stored_activation=b64('10'),initial=b64('1000'),stored_retired=b64('1000'))
    for field in ['standard','stored_activation','initial','stored_retired']:
        for value in [b'',b'bad',b'-1',b'0xA',b'10_',b' 10',b'1000',b'1001',b'0',b'\xff',str(1<<62).encode()]:out.append(dict(full,**{field:b64(value)}))
    for field in ['remaining','headroom']:
        for value in [-1,0,1,999,1000,1001,2000,2001]:
            for initial in [binding,full]:out.append(dict(initial,**{field:str(value)}))
    for initial in [-1,0,1,1000,MAX,2**128]:
        for elapsed in [-1,0,1,2,DURATION//2,DURATION-1,DURATION,DURATION+1,(1<<62)-1]:
            out.append(dict(op='cumulative',initial=str(initial),elapsed=elapsed))
            bounded=max(0,min(DURATION,elapsed));issued=initial*(17*DURATION*bounded-7*bounded*bounded)//(10*DURATION*DURATION)
            for change in [0,1]:out.append(dict(op='reward',activation=0,epoch=elapsed,initial=str(initial),remaining=str(initial-issued+change)))
    out.append(dict(op='reward',activation=None,epoch=1,initial='1000',remaining='1'))
    return out
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/reward-oracle.ml',fixtures(),'octra_core yojson base64')
    report['scope']='Unmodified native epoch reward plan, weighted credit distribution and emission schedule binding; no policy activation inferred from peers'
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native reward and emission cases: {a.out}")
if __name__=='__main__':main()
