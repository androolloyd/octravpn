#!/usr/bin/env python3
"""Native signed gossip normalization/admission, retries and queue effects."""
import argparse,base64,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b(v):return base64.b64encode(v if isinstance(v,bytes) else str(v).encode()).decode()
def fixtures():
 base=dict(seed=42,amount='1',nonce=1,ou='1000',timestamp='1000',op='standard',public='valid',signature='valid');out=[]
 def step(kind='tx',**kwargs):return dict(dict(kind=kind,index=0,indices=[0,0,1],key='carried',now='1000',refuse=False,append=b('')),**kwargs)
 templates=[base]
 for field,values in dict(public=['none','empty','other'],signature=['zero','empty','newline'],timestamp=['0','939.9','940','1060','1060.1'],nonce=[0,1,2,-1],amount=['0','-1','1'],ou=['0','1','-1'],message=[b('hello'),b('x'*257)],encrypted=[b('x')],**{'from':[b('bad')],'to':[b('bad'),b('stealth'),b('multi_exec')]}).items():
  for value in values:templates.append(dict(base,**{field:value}))
 for op in ['circle_call','call','multi_exec','validator_ready','stealth','compute_fund']:
  for message in [None,b('[]'),b('["<script>"]')]:templates.append(dict(base,op=op,message=message,encrypted=b('increment')))
 for tx in templates:
  for key in ['carried','none','account','wrong']:
   out.append(dict(transactions=[tx,dict(base,nonce=2)],known=[],drift='60',steps=[step('inv'),step(key=key,refuse=True),step('inv',now='1000.5'),step(key=key,now='1000.999'),step(key=key,now='1001'),step('get'),step('legacy',key=key,append=b('trailing')),step(wrong_hash=True,index=1)]))
 rng=random.Random(718)
 for _ in range(30):
  steps=[]
  for _ in range(30):steps.append(step(rng.choice(['inv','get','tx','legacy']),index=rng.randrange(2),indices=[rng.randrange(2) for _ in range(5)],key=rng.choice(['carried','none','account']),now=str(1000+rng.choice([0,.5,.999,1,2,61])),refuse=rng.choice([True,False])))
  out.append(dict(transactions=[base,dict(base,nonce=2,public='none')],known=rng.choice([[],[0]]),drift='60',steps=steps))
 out.append(dict(transactions=[base,dict(base,nonce=2)],known=[],drift='60',steps=[step('raw',raw=b(raw)) for raw in [b'',b'\x00',b'\x01\xff',b'\xff'*10]]+[step('large',length=5004097)]))
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/p2p-transaction-oracle.ml',fixtures(),'octra_node_runtime octra_core octra_net yojson base64 mirage-crypto-ec')
 report['scope']='Real native gossip handler and admission with public development keys and an instrumented queue boundary; host staging policy, consensus execution and funded VPN are not exercised'
 a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native transaction receiver traces: {a.out}")
if __name__=='__main__':main()
