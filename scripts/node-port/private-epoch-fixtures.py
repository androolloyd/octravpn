import argparse,base64,hashlib,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
def b64(v):return base64.b64encode(v).decode()
def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--material',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--oracle',type=pathlib.Path,required=True);a=p.parse_args()
 m={k:bytes.fromhex(v)for k,v in json.loads(a.material.read_text()).items()}
 payload=dict(cipher='hfhe_v1|'+b64(m['delta']),zero_proof='zkzp_v2|'+b64(m['proof']),amount_commitment=b64(m['commitment']),blinding=b64(m['blinding']),range_proof_balance='rp_v1|'+b64(m['range']))
 def encoded(v):return b64(json.dumps(v,separators=(',',':')).encode())
 default=dict(active=True,unique=True,withdraw=False,bound=True,self=True,max_fhe=2,warmup="none",gate='none',public=b64(m['public']),current=b64(('hfhe_v1|'+b64(m['current'])).encode()),payload=encoded(payload))
 cases=[]
 def add(name,**kw):cases.append(default|dict(name=name)|kw)
 for withdraw in [False,True]:
  add('direct proof',withdraw=withdraw)
  for gate in ['match','wrong']:
   for active in [False,True]:add('valid receipt '+gate,withdraw=withdraw,gate=gate,active=active)
  for gate in ['empty','unbound','bound','wrong','match']:
   # Every gate/profile combination uses an invalid proof. Only the historical
   # matching certified transition bypasses proof verification.
   for active in [False,True]:add('receipt '+gate,withdraw=withdraw,gate=gate,active=active,payload=encoded(payload|{'zero_proof':'invalid'}))
  for name,changes in [('cap',dict(max_fhe=0)),('key',dict(bound=False)),('target',dict(self=False))]:
   add('guard '+name,withdraw=withdraw,gate='empty',**changes)
 for withdraw in [False,True]:
  add('prior operation consumes cap',withdraw=withdraw,max_fhe=1,warmup='encrypt')
 add('one encrypted debit per sender',withdraw=True,warmup='decrypt')
 add('historical receipt without range',withdraw=True,active=False,gate='match',payload=encoded({k:v for k,v in payload.items() if k!='range_proof_balance'}))
 for op in ['private','recrypt']:add('disabled '+op,operation=op)
 for fault in ['missing','corrupt']:
  add('key blob '+fault,key_fault=fault)
  add('payload failure before key blob '+fault,key_fault=fault,payload=encoded({}))
  add('receipt failure before key blob '+fault,key_fault=fault,gate='empty')
 spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
 d=native.run(a.upstream,'octra-vpn-latest-builder-20261012:latest',a.oracle,cases,'octra_core yojson lwt.unix');d['generator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest();d['material_sha256']=hashlib.sha256(a.material.read_bytes()).hexdigest();a.out.write_text(json.dumps(d,indent=2)+'\n');print('Generated',len(cases),'native private epoch cases')
if __name__=='__main__':main()
