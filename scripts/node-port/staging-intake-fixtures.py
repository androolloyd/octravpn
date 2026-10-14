#!/usr/bin/env python3
"""Native normalized RPC/peer staging facade, with explicit clock and worker boundaries."""
import argparse,base64,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
def load(name):
 spec=importlib.util.spec_from_file_location(name,ROOT/f'scripts/node-port/{name}.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
native=load('native-oracle');staging=load('staging-fixtures')
def b(v):return base64.b64encode(v.encode()).decode()
def tx(**kw):return dict(dict(seed=42,amount='1',nonce=1,ou='1000',timestamp='1000',op='standard',public='valid',signature='valid'),**kw)
def step(**kw):return dict(dict(route='rpc',index=0,now='1000',minimum='5000',profile='devnet_full_v1',bft=True,observer=False,window=32,compute=True,settle=True,proof=True,duty=None,head='0',refuse=None),**kw)
def case(txs,steps,**kw):return dict(dict(transactions=txs,steps=steps,accounts=[dict(seed=42,balance='100000000000000',nonce=0,key='valid',exists=True)]),**kw)
def fixtures():
 out=[];templates=[tx()]
 for field,values in dict(public=['none','empty','other'],signature=['zero','empty','newline'],timestamp=['0','699.9','700','1300','1300.1'],nonce=[-1,0,2,32,33,1000,1001],amount=['0','-1'],ou=['0','1','999','-1'],message=[b('hello'),b('x'*257)],**{'from':[b('bad')],'to':[b('bad')]}).items():
  for value in values:templates.append(tx(**{field:value}))
 for t in templates:
  for key in ['valid','none','wrong']:
   out.append(case([t],[step(),step(route='stage'),step(),step(refuse='pre_verify_busy queue full')],accounts=[dict(seed=42,balance='1000000',nonce=0,key=key,exists=True)]))
 for operation in ['circle_call','call','program_exec','multi_exec','validator_ready','compute_fund','compute_return','compute_settle','program_deploy','deploy_circle','stealth']:
  for fee in ['1000','200000','10000001','20000001']:
   t=tx(op=operation,amount='0' if operation not in ['compute_fund'] else '1',ou=fee,message=b('[]'),encrypted=b('method'))
   out.append(case([t],[step(route='stage',profile=profile,proof=proof,compute=compute,settle=settle) for profile,proof,compute,settle in [('off',False,False,False),('devnet_full_v1',False,False,False),('devnet_full_v1',False,True,False),('devnet_full_v1',True,True,True)]]))
 replacements=[tx(),tx(ou='1100'),tx(ou='1210'),tx(nonce=2),tx(nonce=3)]
 out.append(case(replacements,[step(),step(index=3),step(index=1,refuse='pre_verify_busy queue full'),step(index=2),step(route='hold',index=2),step(index=2),step(route='clear'),step(route='refuse',index=2),step(index=2),step(index=2,head='1')]))
 for balance in ['0','1000','1001','2001','2102']:
  out.append(case(replacements,[step(index=i) for i in [0,3,1,2,4]],accounts=[dict(seed=42,balance=balance,nonce=0,key='valid',exists=True)]))
 out.append(case([tx()],[step(observer=True),step()],accounts=[dict(seed=42,balance='1000000',nonce=0,key='valid',exists=False)]))
 for proposal in [False,True]:
  for h in [8,10,11,26,27]:
   t=tx(op='validator_ready',amount='0',message=b(json.dumps({'consensus_pubkey':'key','head_epoch':str(h),'state_root':'a'*64,**({'head_proposal_id':'b'*64} if proposal else {})})))
   out.append(case([t,dict(t,nonce=2)],[step(route='stage',duty=dict(head='10',active=active),index=index) for active,index in [(False,0),(False,0),(True,0),(False,1)]]))
 rng=random.Random(12802)
 for _ in range(30):
  txs=[tx(nonce=rng.randrange(1,5),ou=str(rng.choice([999,1000,1099,1100,2000,3000])),seed=rng.choice([42,43])) for _ in range(8)]
  steps=[step(index=rng.randrange(len(txs)),route=rng.choice(['rpc','stage','hold','refuse','clear']),head=str(rng.randrange(3)),bft=rng.choice([False,True]),refuse=rng.choice([None,None,'pre_verify_busy queue full','pre_verify_unavailable worker exited'])) for _ in range(25)]
  out.append(case(txs,steps,accounts=[dict(seed=s,balance='20000',nonce=0,key='valid',exists=True) for s in [42,43]]))
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh output')
 prefixes={'lib/core/tx_staging.ml':staging.CLOCK,'node_runtime/node_rest_facade.ml':'(* Oracle-only clock shared with the instrumented queue. *)\nmodule Unix = struct include Unix let gettimeofday () = !(Octra_core.Tx_staging.oracle_time) end\n'}
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/staging-intake-oracle.ml',fixtures(),'octra_core octra_node_runtime yojson base64 mirage-crypto-ec',prefixes=prefixes)
 report['scope']='Real native RPC and normalized staging facade with native ledger, public fixture keys, injected wall clock and observable preverification callbacks. Worker execution, durable pending storage, live head synchronization and full-node consensus are not exercised.'
 a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native staging intake traces: {a.out}")
if __name__=='__main__':main()
