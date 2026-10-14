import argparse,base64,hashlib,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
def b64(v):return base64.b64encode(v if isinstance(v,bytes) else v.encode()).decode()
def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 cases=[]
 def add(name,state=[],operations=[],ids=[0,1],since=0):cases.append(dict(name=name,state=state,operations=operations,ids=ids,since=since))
 def row(key,value):return dict(key=key,value=b64(value))
 def stored(raw):return [row(['stealth','0'],raw)]
 def js(v):return json.dumps(v,separators=(',',':'))
 output=dict(id=0,stealth_tag='tag',eph_pub='ephemeral',enc_amount='encrypted',amount='7',epoch_id=5,tx_hash='a'*64,sender_addr='sender',claimed=0,claim_pub='claim',delta_cipher_stored='delta',amount_hash='pvac_key_bound_output_v1',amount_commitment='commitment')
 insert=dict(operation='insert',epoch=5,**{k:b64(v)for k,v in dict(tag='tag',ephemeral='ephemeral',encrypted='encrypted',amount='7',hash='a'*64,sender='sender',claim='claim',delta='delta',amount_hash='pvac_key_bound_output_v1',commitment='commitment').items()})
 claim=dict(operation='claim',id=0,hash=b64('c'*64))
 add('empty');add('insert',operations=[insert]);add('insert claim replay',operations=[insert,claim,claim]);add('missing claim',operations=[claim])
 for counter in ['0','1','-1','0x10','0b10','01','1_0','bad','',str(2**63-1),str(-2**63),str(2**63)]:
  add('counter '+counter,state=[row(['index','stealth_counter'],counter)],operations=[insert],ids=[-1,0,1,2,10,16])
 for name,value in [('ordinary',output),('already claimed',output|dict(claimed=1)),('negative claim',output|dict(claimed=-1)),('claim text',output|dict(claimed='0')),('missing claim',{k:v for k,v in output.items()if k!='claimed'}),('missing id',{k:v for k,v in output.items()if k!='id'}),('large id',output|dict(id=2**62)),('list',[]),('null',None)]:
  add('row '+name,state=stored(js(value)),operations=[claim])
 for field in output:
  add('missing '+field,state=stored(js({k:v for k,v in output.items()if k!=field})))
 for raw in ['{','{"claimed":0,"claimed":2}',js(output)[:-1]+',"claimed":2}',js(output|dict(claim_tx_hash='before'))[:-1]+',"claim_tx_hash":"duplicate"}',js(output|dict(amount='-5')),js(output|dict(amount='0x10')),js(output|dict(amount='bad'))]:
  add('raw row',state=stored(raw),operations=[claim])
 for raw in ['NaN','Infinity','-Infinity','1e100','-0.0','1.0000000000000002','[null,true,{"x":1,"x":2}]']:
  add('extra JSON '+raw,state=stored(js(output)[:-1]+',"extra":'+raw+'}'),operations=[claim])
 add('arbitrary byte fields',operations=[insert|dict(tag=b64(b'\xff\x00\n'))])
 add('epoch selection',state=[row(['stealth',str(i)],js(output|dict(id=i,epoch_id=i)))for i in [2,10,1]],ids=[10,2,1],since=2)
 spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
 oracle=ROOT/'scripts/node-port/private-output-oracle.ml'
 data=native.run(a.upstream,'octra-vpn-latest-builder-20261012:latest',oracle,cases,'octra_core yojson lwt.unix');data['generator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest();a.out.write_text(json.dumps(data,indent=2)+'\n');print('Generated',len(cases),'native private output cases')
if __name__=='__main__':main()
