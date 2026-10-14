#!/usr/bin/env python3
"""Native consensus-driver scheduling and round-history traces."""
import argparse, copy, importlib.util, itertools, json, pathlib, random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
CHAIN=b'octra-devnet-9871-cluster'.hex()
MAX=2**62-1;MIN=-2**62
CLOCK='module Unix = struct include Unix let gettimeofday () = float_of_string (Sys.getenv "OCTRA_ROUND_POOL_ORACLE_TIME") end\n'
def fixtures():
    rng=random.Random(2026101307); out=[]
    for sequence in itertools.product(['request','complete','fail'],repeat=5):out.append(dict(kind='actor',steps=list(sequence)))
    def work(op,**kw):return dict(op=op,job=1,id=0,reply=2,active=True)|kw
    out.append(dict(kind='work',steps=[work('submit'),work('submit',job=2),work('finish'),work('submit',job=3),work('take'),work('take'),work('submit',job=4),work('finish',active=False,id=0),work('close'),work('open'),work('finish'),work('submit',job=5),work('finish'),work('take')]))
    for _ in range(64):out.append(dict(kind='work',steps=[work(rng.choice(['submit','submit','finish','finish','take','close','open']),job=rng.randrange(-9,10),reply=rng.randrange(-9,10),id=rng.randrange(12),active=rng.choice([True,False]))for _ in range(100)]))
    def relay(op,**kw):return dict(op=op,generation=0,now='0',key='00',value=0,expires='2',active=True,id=1,outcome='sent',reason='')|kw
    fill=[relay('offer',key=bytes([i]).hex(),value=i)for i in range(7)]
    drain=[relay('finish',outcome=o,reason='ff00657272')for o in ['sent','expired','failed','cancelled','sent']]
    for serial in [0,MAX-1,MAX,MIN]:out.append(dict(kind='relay',serial=serial,steps=fill+drain+[relay('offer'),relay('advance',generation=1),relay('finish',active=False,id=serial+1 if serial<MAX else MIN),relay('close'),relay('offer',generation=2),relay('open',generation=-1),relay('offer',generation=-1)]))
    for now,expires in itertools.product(['-inf','-1','0','1','2','3','inf','nan'],repeat=2):out.append(dict(kind='relay',serial=0,steps=[relay('offer',now=now,expires=expires),relay('offer',now=now,key='01',expires=expires),relay('advance',now=now),relay('finish',now=now),relay('advance',now='inf')]))
    out.append(dict(kind='relay',serial=0,steps=sum(([relay('offer',key=bytes([i]).hex()),relay('finish')]for i in range(70)),[])+[relay('offer',key='00'),relay('offer',key='05'),relay('offer',key='06')]))
    for _ in range(64):
        steps=[]
        for n in range(100):steps.append(relay(rng.choice(['offer']*5+['finish']*3+['advance','close','open']),generation=rng.choice([-1,0,1,2,3]),now=str(n//10),expires=str(n//10+rng.choice([-1,0,1,2,3])),key=bytes([rng.randrange(12)]).hex(),value=rng.randrange(100),id=rng.randrange(20),active=rng.choice([True,False]),outcome=rng.choice(['sent','expired','failed','cancelled']),reason='657272'))
        out.append(dict(kind='relay',serial=0,steps=steps))
    def address(i):return f'validator-{i}'.encode().hex()
    def sync(**kw):return dict(chain=CHAIN,epoch='1380000',round=2,step=1,request=False,validator=address(0),signature='00')|kw
    def query(**kw):return dict(chain=CHAIN,epoch='1380000',after=-1,through=MAX,validator=address(0))|kw
    def action(op,sy=None,**kw):return dict(op=op,sync=sy or sync(),current=2,now='1',queries=[query()])|kw
    def pool(steps,weighted=True,weights=None):return dict(kind='pool',weighted=weighted,validators=[dict(address=address(i),weight=str(w))for i,w in enumerate(weights or [1,2,3,4,5,6,7])],steps=steps)
    for a,b,c,d in itertools.product([False,True],[False,True],[1,2,3],[1,2,3]):
        out.append(pool([action('add',sync(step=c,request=a)),action('add',sync(step=d,request=b,signature='01'),now='2'),action('local',sync(step=d,request=b,signature='02'),now='3'),action('clear'),action('add',sync(epoch='1379999')),action('local',sync(epoch='1380001'),queries=[query(epoch='1380001')])]))
    for weighted,epoch in itertools.product([False,True],['1379999','1380000','1380001']):
        steps=[action('add',sync(epoch=epoch,validator=address(i)),queries=[query(epoch=epoch)])for i in range(7)]
        steps+=[action('observe',queries=[query(epoch=epoch,chain=b'other'.hex()),query(epoch=epoch,after=2),query(epoch=epoch,through=1)])]
        out.append(pool(steps,weighted=weighted,weights=[100,1,1,1,1,1,1]))
    for current in [MIN,-1025,-1,0,1,1023,1024,1025,MAX-1024,MAX-1,MAX]:
        rounds=sorted(set([MIN,-1,0,1,MAX,current,max(MIN,current-1025),max(MIN,current-1024),min(MAX,current+1024),min(MAX,current+1025)]))
        out.append(pool([action('add_at',sync(round=r,validator=address(i%7)),current=current,queries=[query(validator=address(i%7),after=MIN)])for i,r in enumerate(rounds)]+[action('local',sync(round=r),queries=[query(after=MIN)])for r in reversed(rounds)]))
    for trace in range(80):
        steps=[]
        for j in range(80):
            epoch=rng.choice(['1379999','1380000','1380001','1380002']);round=rng.choice([-1,0,1,2,3,64,1023,1024,1025,2048,2049]);validator=address(rng.randrange(9))
            sy=sync(epoch=epoch,round=round,validator=validator,step=rng.randrange(1,4),request=rng.choice([False,True]),signature=bytes([j]).hex())
            queries=[query(epoch=e,validator=validator,through=rng.choice([2,64,1024,MAX]),after=rng.choice([-1,0,1,2,1024]))for e in ['1379999','1380000','1380001','1380002']]
            steps.append(action(rng.choice(['add','add','local','local','add_at','observe','clear']),sy,current=rng.choice([0,1,1024,2048,MAX]),now=str(j),queries=queries))
        out.append(pool(steps,weighted=trace%2==0,weights=[rng.randrange(1,1000000)for _ in range(7)]))
    def gate(op,id='a',**kw):return dict(op=op,id=id,value=1,error=False)|kw
    out.append(dict(kind='gate',steps=[gate('enqueue'),gate('enqueue','b'),gate('enqueue','c'),gate('cancel','b'),gate('relevant',value=False),gate('resolve'),gate('relevant',value=True),gate('enqueue','d'),gate('resolve','d')]))
    out.append(dict(kind='gate',steps=[gate('enqueue'),gate('enqueue','b'),gate('cancel'),gate('resolve','b',error=True),gate('enqueue','c'),gate('resolve','c')]))
    for trace in range(80):
        steps=[];ids=[]
        for n in range(80):
            op=rng.choice(['enqueue','enqueue','cancel','resolve','resolve','relevant','observe'])
            if op=='enqueue':id=f'w{n}';ids.append(id)
            else:id=rng.choice(ids)if ids else 'absent'
            steps.append(gate(op,id,value=rng.choice([True,False])if op=='relevant'else rng.randrange(100),error=rng.randrange(5)==0))
        out.append(dict(kind='gate',steps=steps))
    def ar(op,**kw):return dict(op=op,generation=0,key='00',value=0,index=0,error=False,now='0')|kw
    out.append(dict(kind='async_relay',steps=[ar('offer'),ar('offer'),ar('offer',key='01',value=1),ar('progress',generation=1),ar('offer',generation=1,key='02',value=2),ar('close'),ar('open',generation=1),ar('offer',generation=1,key='03',value=3),ar('clock',now='3'),ar('expire',index=2),ar('offer',generation=1,key='04',value=4),ar('offer',generation=1,key='05',value=5),ar('resolve',index=3,error=True),ar('resolve',index=4),ar('offer',generation=1,key='05',value=5)]))
    out.append(dict(kind='async_relay',steps=[ar('offer',key=bytes([i]).hex(),value=i)for i in range(8)]+[ar('clock',now='2'),ar('resolve'),ar('offer'),ar('resolve',index=1),ar('offer'),ar('open',generation=-1),ar('offer',generation=-1),ar('close')]))
    for trace in range(96):
        steps=[]
        for n in range(100):
            op=rng.choice(['offer']*8+['resolve']*3+['expire','clock','close','open','progress'])
            steps.append(ar(op,generation=rng.randrange(-1,4),key=bytes([rng.randrange(8)]).hex(),value=n,index=rng.randrange(12),error=rng.randrange(4)==0,now=str(n/10)))
        out.append(dict(kind='async_relay',steps=steps))
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/driver-work-oracle.ml',fixtures(),'octra_consensus yojson lwt.unix',prefixes={'lib/consensus/c_round_pool.ml':CLOCK})
    report['scope']='Native output actor, proposal worker slot, asynchronous proposal gate and relay, relay state/effects and round-sync history/witnesses. Only the round-pool wall clock is injected. Signatures, the complete driver and public-peer operation remain separate.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native driver-work traces: {a.out}")
if __name__=='__main__':main()
