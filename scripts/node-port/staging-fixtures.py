#!/usr/bin/env python3
"""Qualify the native queue with an explicit test-only clock injection."""
import argparse,base64,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
CLOCK='(* Oracle-only deterministic wall clock; original source verified before injection. *)\nlet oracle_time = ref 0.\nmodule Unix = struct include Unix let gettimeofday () = !oracle_time end\n'
def b(v):return base64.b64encode(v if isinstance(v,bytes) else str(v).encode()).decode()
def tx(sender='a',nonce=1,**kw):return dict(dict(**{'from':b(sender),'to':b('recipient')},amount='1',nonce=nonce,ou='1000',timestamp='100',signature=b(f'sig-{sender}-{nonce}'),op='standard'),**kw)
def step(kind='add',index=0,**kw):return dict(dict(kind=kind,index=index,now='100',head=None,capacity='5000',exclude=[],limit='10000000000',count=100000,indices=[]),**kw)
def case(txs,steps,**kw):
 senders=sorted({t['from'] for t in txs});return dict(dict(mode='pool',transactions=txs,accounts=[dict(sender=s,balance='1000000000000000',nonce=0) for s in senders],minimum='5000',steps=steps),**kw)
def fixtures():
 out=[];rng=random.Random(92017)
 # Preview refusal saturation, advancement, stale epochs and ready-vs-check.
 for limit in [0,1,2,5]:
  for _ in range(16):
   steps=[]
   for _ in range(70):
    head=rng.choice([-1,0,1,2,3,4]);kind=rng.choice(['check','ready','hold','refuse'])
    steps.append(dict(kind=kind,head=None if kind in ['check','ready'] and rng.randrange(4)==0 else str(head),epoch=str(head+rng.choice([0,1,1,2])),hash=b(rng.randrange(7))))
   out.append(dict(mode='preview',limit=limit,steps=steps))
 txs=[tx('a',1),tx('a',2),tx('a',3),tx('b',1,ou='2000'),tx('a',1,ou='1099'),tx('a',1,ou='1100'),tx('a',1,ou='2000')]
 for limit,count in [('3000',3),('2000',10),('1000',1),('5000',2),('0',3),('1000',0),('-1',-1),('999',10)]:
  out.append(case(txs,[step(index=i,limit=limit,count=count,now=str(100+n/8)) for n,i in enumerate([0,1,2,4,5,6,3])]+[step('remove',index=0),step('processed',indices=[1,3]),step('inspect')]))
 for balance in ['0','1000','1001','1100','1101','2001','3003']:
  out.append(case(txs,[step(index=i) for i in [0,1,4,5,6,3,2]],accounts=[dict(sender=b(s),balance=balance,nonce=0) for s in ['a','b']]))
 out.append(case(txs,[step(index=0,head='1'),step('hold',head='1',epoch='2'),step('check',head='1'),step('ready',head='1'),step('clear'),step(head='1'),step('refuse',head='2',epoch='3'),step('clear'),step(head='2'),step(head='3')]))
 for confirmed in [-1,0,1,2,999,(1<<62)-2,(1<<62)-1,-(1<<62)]:
  ts=[tx('a',n) for n in [-1,0,1,2,1000,1001,(1<<62)-2,(1<<62)-1]]
  out.append(case(ts,[step(index=i) for i in range(len(ts))]+[step('expire',now='700'),step('expire',now='700.0001'),step('cleanup',now='1300.0002')],accounts=[dict(sender=b('a'),balance='1000000',nonce=confirmed)]))
 for operation in ['standard','decrypt','claim','stealth','private','program_deploy','deploy_circle','circle_call','multi_exec','compute_settle','circle_asset_put']:
  ts=[tx('a',1,op=operation,ou='1000000',encrypted=b('x'*1500)),tx('a',2),tx('b',1,ou='10000')]
  out.append(case(ts,[step(index=i) for i in [0,1,2]]+[step('inspect',capacity=str(cap)) for cap in [0,999,1000,1999,2000,3000,199999,200000,10000000]]))
 for minimum in ['1000','5000','7999999999','8000000000','9499999999','9500000000','10000000000']:
  ts=[tx('a',1,op='stealth',ou='20000000000'),tx('a',2),tx('b',1,ou='30000000000',op='private')]
  out.append(case(ts,[step(),step('inspect'),step(index=1),step(index=2)],minimum=minimum))
 duty=[tx('a',1,op='validator_ready',message=b(json.dumps({'consensus_pubkey':'key','head_epoch':str(h),'state_root':'a'*64,**({'head_proposal_id':'b'*64} if proposal else {})})),ou='1000') for h in [8,9,10,11] for proposal in [False,True]]
 duty.append(tx('a',1,op='validator_ready',message=b('bad')))
 for active in [False,True]:
  for i in range(len(duty)):
   out.append(case(duty,[step(index=i),step('duty',index=i,head='11',active=active)]))
 for _ in range(85):
  ts=[tx(rng.choice(['a','b','c']),rng.randrange(1,6),ou=str(rng.choice([999,1000,1099,1100,2000,4000,10000])),timestamp=str(rng.choice([99,100,101])),op=rng.choice(['standard','standard','decrypt','circle_call']),signature=b(f'sig{i}')) for i in range(12)]
  steps=[];now=100.
  for _ in range(35):
   kind=rng.choice(['add']*8+['remove','processed','expire','clear','drop_preview','account','inspect','hold','refuse','check','ready'])
   now+=rng.choice([0,0.125,1,599,600]);head=rng.choice([0,1,2,3])
   steps.append(step(kind,index=rng.randrange(len(ts)),now=str(now),capacity=str(rng.choice([0,999,1000,2500,5000,10000])),exclude=rng.sample(list(range(len(ts))),2),limit=str(rng.choice([1000,3000,10000])),count=rng.choice([1,3,10]),indices=rng.sample(list(range(len(ts))),3),head=str(head),epoch=str(head+1),sender=b(rng.choice(['a','b','c'])),balance=rng.choice([None,'1000','3000','1000000']),nonce=rng.randrange(4)))
  out.append(case(ts,steps))
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/staging-oracle.ml',fixtures(),'octra_core yojson base64',prefixes={'lib/core/tx_staging.ml':CLOCK})
 report['scope']='Native staging, replacement, eviction, nonce/balance accounting, preview state, readiness/fee ordering and expiry. Only wall clock injected after pin verification. Non-consensus expiry output is sorted by hash; equal-time bounded drop-cache eviction is not parity-qualified. Authentication and preverification are separate host boundaries.'
 a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native staging traces: {a.out}")
if __name__=='__main__':main()
