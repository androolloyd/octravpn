#!/usr/bin/env python3
"""Qualify native account ciphertext chunks, strict loading and canonical storage."""
import argparse,base64,copy,hashlib,json,pathlib,random,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
enc=lambda v:base64.b64encode(v).decode()
def account(cipher=None,**changes):
 v=dict(balance='11',nonce='2',public_key=enc(b'key\0\xff'),encrypted_balance=None if cipher is None else enc(cipher),decrypt_allowance='3');v.update(changes);return v
def image(cipher=None,**changes):return dict(kind='image',account=account(cipher,**changes))
def hash(tag,raw):return hashlib.sha256(tag+b'\0'+raw).hexdigest().encode()
def cases():
 rng=random.Random(81013);result=[]
 for size in [0,1,4095,4096,4097,65535,65536,65537,131072,200001]:
  for raw in [b'x'*size,rng.randbytes(size)]:
   result+=[image(raw),image(b'hfhe_v1|'+base64.b64encode(raw))]
 result+=[image(),image(b'hfhe_v1|AA=='),image(b'hfhe_v1|AB=='),image(b'hfhe_v1|AA'),image(b'hfhe_v1|'),image(b'0',balance='-5',nonce='-1')]
 raw_account={'balance':'1','nonce':0,'public_key':None,'encrypted_balance':None,'decrypt_allowance':'0'}
 data=[json.dumps(raw_account).encode(),b'not json',b'null',b'{}']
 for key in raw_account:
  for value in [None,True,0,'bad','-+1','',{},[],str(1<<200)]:
   a=copy.deepcopy(raw_account);a[key]=value;data.append(json.dumps(a).encode())
  a=copy.deepcopy(raw_account);del a[key];data.append(json.dumps(a).encode())
 data.append(b'{"balance":"1","nonce":0,"public_key":null,"encrypted_balance":null,"nonce":1}')
 for layout in ['parts','x',None]:
  a={'layout':layout,'balance':'1','nonce':0,'public_key':None,'cipher_id':'x','decrypt_allowance':'0'};data.append(json.dumps(a).encode())
 result +=[dict(kind='data',raw=enc(v))for v in data]
 raw=b'abcdef';part=hash(b'octra.account.part',raw);blob=hash(b'octra.account.blob',raw);cid=hash(b'octra.account.cipher',b'text\0'+raw)
 meta=dict(form='text',size=6,id=cid.decode(),blob=blob.decode(),parts=[part.decode()]);metas=[json.dumps(meta).encode(),b'null',b'bad',b'{}']
 for key in meta:
  for value in [None,True,-1,0,'bad','A'*64,[],['f'*64],['bad']]:
   m=copy.deepcopy(meta);m[key]=value;metas.append(json.dumps(m).encode())
  m=copy.deepcopy(meta);del m[key];metas.append(json.dumps(m).encode())
 result +=[dict(kind='meta',raw=enc(v))for v in metas]
 for size in [0,1,5,6,7,4096]:
  for id in [blob,b'bad']:
   for parts in [[],[[enc(part),enc(raw)]],[[enc(b'bad'),enc(raw)]],[[enc(part),enc(raw+b'x')]]]:result.append(dict(kind='join',size=str(size),id=enc(id),parts=parts))
 addr=b'account\0\xff';path=lambda *v:[enc(b'accounts'),enc(addr)]+[enc(x)for x in v]
 def set_step(cipher,active=True,**changes):return dict(op='set',active=active,account=account(cipher,**changes))
 def store(steps):return dict(kind='store',address=enc(addr),steps=steps)
 result.append(store([set_step(None),set_step(raw),set_step(raw,balance='21'),set_step(b'hfhe_v1|'+base64.b64encode(rng.randbytes(200001))),set_step(b'0',False),set_step(None)]))
 for removal in [path(b'cipher'),path(b'cipher',b'meta'),path(b'cipher',b'parts'),path(b'cipher',b'parts',part)]:
  result.append(store([set_step(raw),dict(op='remove',path=removal),set_step(raw,balance='30'),set_step(raw+b'x'),set_step(None)]))
 for bad_meta in [b'bad',json.dumps(dict(meta,id='f'*64)).encode(),json.dumps(dict(meta,blob='f'*64)).encode()]:
  result.append(store([set_step(raw),dict(op='write',path=path(b'cipher',b'meta'),raw=enc(bad_meta)),set_step(raw,balance='30'),set_step(None)]))
 result.append(store([dict(op='write',path=path(b'data'),raw=enc(b'bad')),set_step(raw),set_step(None)]))
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
 if subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()!=pin or a.out.exists():raise SystemExit('require pristine pin and fresh output')
 sources=['lib/core/account_pack.ml','lib/core/blob_chunk.ml','lib/core/store_irmin.ml','lib/core/ledger_types.ml'];hashes={};inputs=cases()
 with tempfile.TemporaryDirectory(prefix='octra-account-oracle-')as temp:
  f=pathlib.Path(temp);(f/'cases.json').write_text(json.dumps(inputs));checks=[]
  for i,path in enumerate(sources):
   source=subprocess.check_output(['git','-C',str(a.upstream),'show',f'HEAD:{path}']);assert source==(a.upstream/path).read_bytes();hashes[path]=hashlib.sha256(source).hexdigest();(f/f'source-{i}').write_bytes(source);checks.append(f'cmp {path} /fixture/source-{i}')
  (f/'native_pack.ml').write_text('open Octra_core\n'+(a.upstream/'lib/core/account_pack.ml').read_text());shutil.copyfile(ROOT/'scripts/node-port/account-pack-oracle.ml',f/'main.ml');(f/'dune').write_text('(executable (name main) (libraries octra_core yojson base64 lwt.unix irmin))\n')
  command=' && '.join(checks+['mkdir vpn_account_oracle','cp /fixture/main.ml /fixture/native_pack.ml /fixture/dune vpn_account_oracle/','opam exec -- dune exec ./vpn_account_oracle/main.exe -- /fixture/cases.json'])
  output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={f},target=/fixture,readonly',a.builder_image,'bash','-lc',command],text=True)
 payload=json.loads(next(line.removeprefix('ORACLE_RESULT=')for line in output.splitlines()if line.startswith('ORACLE_RESULT=')));a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(dict(upstream_commit=pin,sources=hashes,cases=payload),indent=2)+'\n');print(f'Generated {len(inputs)} native cases: {a.out}')
if __name__=='__main__':main()
