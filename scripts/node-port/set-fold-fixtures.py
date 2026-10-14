"""Pinned native finalized duty, persistence and readiness policy traces."""
import argparse, base64, copy, importlib.util, json, pathlib, random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v.encode() if isinstance(v,str) else v).decode()
STANDARD=dict(window='96',challenge='16',rejoin='64',gap='8',cadence='64',delay='64',max=200,share=None)
PART=dict(STANDARD,window='32',cadence='4',delay='8',share=dict(n=1,d=2))
SMALL=dict(STANDARD,window='8',challenge='2',rejoin='4',gap='2',cadence='1',delay='1',max=4)
CHAIN=b64(b'duty\x00chain');ACTIVE=[b64('v'+str(i)) for i in range(1,5)]
def parent(epoch=5,**kw):return dict(chain=CHAIN,epoch=str(epoch),round=1,members=4,signers=[1,2,3],**kw)
def step(op,at=1,**kw):return dict(op=op,at=str(at),source=str(at),**kw)
def final(at,active=ACTIVE,signers=ACTIVE):return step('final',at,active=active,signers=signers,final=dict(epoch=str(at-1),pid=b64(bytes([at%256])*32),set=b64(bytes([2])*32)))
def fixtures():
    cases=[];rng=random.Random(2026101319)
    def trace(steps,cfg=STANDARD,probes=None,initial=None,start=1):
        cases.append(dict(kind='trace',cfg=cfg,start=str(start),probes=probes or ACTIVE+[b64('unknown'),b64(b'\xff\x00')],initial=None if initial is None else b64(json.dumps(initial)),steps=steps))
    for cfg in [STANDARD,PART,SMALL]:
        cases.append(dict(kind='config',cfg=cfg))
        # Consecutive finality crosses warmup, challenge and retention boundaries.
        steps=[step('set',0,active=ACTIVE),step('lock',0,active=ACTIVE)]
        for at in range(1,181):
            steps.append(final(at,signers=ACTIVE[:(at%5)]))
            if at%7==0:steps.append(step('reload',at))
        trace(steps,cfg)
        steps=[]
        for at in range(1,100):
            steps.extend([step('pulse',at,address=b64('unknown'),active=False,credit=str(max(0,at-1))),step('pulse',at,address=b64('unknown'),active=False,credit=str(at))])
        steps += [step('query',n) for n in [-1,0,99,100,108,109,200]]
        steps += [step('set',201,active=[b64('unknown')]),step('set',202,active=[]),step('reload',202)]
        trace(steps,cfg)
    for field,values in dict(window=[-1,0,7,8,128,129,2**63-1],challenge=[-1,0,1,95,96],rejoin=[-1,0,1,128,129],gap=[-1,0,1,64,65],cadence=[-1,0,1,2**63-1],delay=[-1,0,1,2**63-1],max=[-1,0,3,4,200,201],share=[dict(n=n,d=d) for n,d in [(0,0),(0,1),(1,0),(-1,2),(3,2),(2,2),(2**62-1,2**62-1)]]).items():
        for v in values:
            cfg=dict(STANDARD);cfg[field]=v if field in ['max','share'] else str(v);cases.append(dict(kind='config',cfg=cfg))
    for _ in range(80):
        cfg=rng.choice([STANDARD,PART,SMALL]);steps=[step('set',0,active=ACTIVE)]
        for _ in range(45):
            at=rng.choice([-1,0,1,2,3,5,8,10,18,32,64,130,260,2**63-1]);op=rng.choice(['set','final','pulse','lock','delay','query','reload'])
            if op=='set':s=step(op,at,active=rng.choice([[],ACTIVE,ACTIVE[::-1]+ACTIVE,[b64(b'\xff\x00')]]))
            elif op=='final':s=final(at,active=rng.choice([ACTIVE,ACTIVE[:2],[]]),signers=rng.choice([[],ACTIVE,ACTIVE+ACTIVE,[b64('unknown')]]))
            elif op=='pulse':s=step(op,at,address=rng.choice(ACTIVE+[b64(''),b64('unknown')]),active=rng.choice([True,False]),credit=rng.choice([None,'0','1',str(at),str(at+1) if at<2**63-1 else '0']))
            elif op=='lock':s=step(op,at,active=rng.choice([[],ACTIVE,ACTIVE+ACTIVE,[b64('v'+str(i)) for i in range(205)]]))
            else:s=step(op,at)
            s['prune']=rng.choice([True,False]);s['source']=str(rng.choice([-1,0,1,32,64,260,1000000]));steps.append(s)
        trace(steps,cfg,probes=ACTIVE+ACTIVE[:1]+[b64('unknown'),b64(b'\xff\x00')])
    # Overflow pruning, tie breaks and retained live members.
    for cfg in [SMALL,STANDARD]:
        addresses=[b64(f'm{i:04}') for i in range(cfg['max']*4+2)]
        for prune in [False,True]:
            initial=dict(standard='octra-validator-duty',safe_after='0',applied=None,finals=[],members=[dict(address=f'm{i:04}',phase=dict(kind='shadow',pulse=dict(first='1',last='1',count=1)),marks=[]) for i in range(cfg['max']*4)])
            trace([step('pulse',1,address=a,active=False,credit=None,prune=prune) for a in addresses[-2:]]+[step('reload',1)],cfg,probes=[addresses[0],addresses[-1]],initial=initial)
    trace([step('set',1,active=[b64(f'm{i}') for i in range(17)]),step('lock',1,active=ACTIVE)],SMALL)
    for active in [True,False]:
        for credit in [None,'0','1','2','-1','10']:
            trace([step('pulse',n,address=b64('unknown'),active=active,credit=credit) for n in [1,1,2,3,1,12,13]],SMALL)
    # Real independently signed parent commits and duty proofs.
    for variant in ['ok','future','expired','missing','pid','set','chain','owner','type','epoch','round','vote_pid','signer','signature','commit','quorum','outsider']:
        p=parent();v=dict(chain=CHAIN,epoch='5',round=1,type=2,owner=b64('v1'),signer=1);proof=step('proof',6,chain=CHAIN,address=b64('v1'),active=True,parent=p,vote=v)
        record=step('parent_final',6,active=ACTIVE,parent=parent(),signers=[b64('v2')])
        if variant=='future':proof['at']='4'
        if variant=='expired':proof['at']='22'
        if variant=='pid':p['round']=2;v['round']=2
        if variant=='set':p['members']=5
        if variant=='chain':v['chain']=b64('wrong')
        if variant=='owner':proof['address']=b64('v2')
        if variant=='type':v['type']=1
        if variant=='epoch':v['epoch']='4'
        if variant=='round':v['round']=2
        if variant=='vote_pid':v['other_pid']=True
        if variant=='signer':v['signer']=2
        if variant=='signature':v['corrupt']=True
        if variant=='commit':p['corrupt']=True
        if variant=='quorum':p['signers']=[1]
        if variant=='outsider':v['owner']=b64('v5');v['signer']=5;proof['address']=b64('v5')
        trace(([] if variant=='missing' else [record])+[proof,copy.deepcopy(proof),step('reload',6)])
    # Advance replay bypasses parent validation; gaps and held state survive reload.
    trace([step('advance',at,chain=CHAIN,start='6',parent=p) for at,p in [(6,parent()),(6,None),(5,None),(7,parent(6)),(10,parent(9)),(11,parent(8)),(12,None),(12,parent(11,corrupt=True)),(12,parent(11))]]+[step('reload',12)])
    conflict=final(6);trace([conflict,step('advance',6,chain=CHAIN,start='6',parent=parent()),step('reload',6)])
    for p in [None,dict(parent(),chain=b64('wrong')),dict(parent(),signers=[1]),dict(parent(),signers=[1,1,2,3]),dict(parent(),members=17,signers=list(range(1,13)))]:
        trace([step('advance',6,chain=CHAIN,start='6',parent=p),step('reload',6)],SMALL)
    for at,head in [(0,0),(6,-1),(6,6),(6,5),(7,5),(8,5),(9,5)]:
        for proposal in [None,'auto',b64('A'*64),b64('0'*64)]:
            trace([step('parent_final',6,active=ACTIVE,parent=parent(),signers=ACTIVE),step('reference',at,head=str(head),proposal=proposal,parent=parent())])
    for prior in [False,True]:
        for chain in [None,CHAIN,b64('wrong')]:
            for config in [None,b64('config'),b64('wrong')]:
                for catchup in [None,'4','5','6']:
                    cases.append(dict(kind='claim',cfg=STANDARD,chain=CHAIN,config=b64('config'),head='5',claim_chain=chain,claim_config=config,catchup=catchup,prior=prior))
    # Persistence decoder error precedence and exact byte output.
    state=dict(standard='octra-validator-duty',safe_after='0',applied=None,members=[],finals=[])
    member=dict(address='v1',phase=dict(kind='live',since='0'),marks=['0','1'])
    f=dict(epoch='1',proposal_id=b64(bytes(32)),set_hash=b64(bytes(32)))
    def decode(v):cases.append(dict(kind='decode',cfg=STANDARD,raw=b64(json.dumps(v))))
    for v in [None,[],{},state,dict(state,members=[member,member]),dict(state,finals=[f,f]),dict(state,members=[member],finals=[f])]:decode(v)
    for field in state:
        for v in [None,[],0,-1,'','bad','-1','0x8000000000000000','9223372036854775808']:
            d=copy.deepcopy(state);d[field]=v;decode(d)
        d=copy.deepcopy(state);del d[field];decode(d)
    for field in member:
        for v in [None,[],{},0,'', ['0','256'],['0','255'],['1','1'],['-1'],dict(kind='shadow'),dict(kind='shadow',pulse=None),dict(kind='live',since='-1')]:
            m=copy.deepcopy(member);m[field]=v;decode(dict(state,members=[m]))
    for field in f:
        for v in [None,0,'','-1','bad',b64(bytes(31)),b64(bytes(33)),b64(bytes(32)).rstrip('=')]:
            item=dict(f);item[field]=v;decode(dict(state,finals=[item]))
    for field in ['first','last','count']:
        for v in [None,'0','1','-1',0,1,-1,2**62-1,2**62,'0x7fffffffffffffff']:
            p=dict(first='1',last='2',count=2);p[field]=v;decode(dict(state,members=[dict(member,phase=dict(kind='shadow',pulse=p))]))
    for seats in [None,0,3,4,200,201,'4','0x4',2**62]:decode(dict(state,seats=seats))
    for raw in [b'{',b'{"standard":"octra-validator-duty","standard":"wrong","safe_after":"0","applied":null,"members":[],"finals":[]}',json.dumps(dict(state,members=[member])).encode().replace(b'v1',b'\xff\x00'),json.dumps(state).encode().replace(b'"standard"',b'standard')]:
        cases.append(dict(kind='decode',cfg=STANDARD,raw=b64(raw)))
    # Native Z.testbit raises when the Int64 query offset wraps to negative int63.
    # Preserve the reproducer separately: no defined native result to compare.
    trace([step('set',0,active=ACTIVE),step('query',2**63-1)],SMALL)
    exceptional=cases.pop();cases.append(dict(kind='native_exception',cfg=SMALL,trace=exceptional))
    return cases
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/set-fold-oracle.ml',fixtures(),'octra_core octra_consensus yojson mirage-crypto-ec')
    report['scope']='Finalized duty state, participation, authenticated parent/proof checks, persistence and readiness reference/claim policy. Canonical epoch scheduling and transaction host integration are separate gates.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native set fold cases')
if __name__=='__main__':main()
