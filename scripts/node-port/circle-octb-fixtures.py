"""Production Circle legacy OCTB deployment/update, including refusal precedence."""
import argparse,base64,copy,hashlib,importlib.util,json,pathlib,struct
ROOT=pathlib.Path(__file__).resolve().parents[2]
def module(name):
 spec=importlib.util.spec_from_file_location(name,ROOT/'scripts/node-port'/name);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
native=module('native-oracle.py');code=module('circle-code-fixtures.py')
def b64(v):return base64.b64encode(v if isinstance(v,bytes) else v.encode()).decode()
def bytecode(text,count=1,consts=()):return b'OCTB\x01\x00'+struct.pack('<HI',len(consts),count)+b''.join(bytes([t])+struct.pack('<I',len(v))+v for t,v in consts)+text
def fixtures():
 base=code.fixtures();deploy=next(v for v in base if v['name']=='deploy wasm');update=next(v for v in base if v['name']=='update wasm');out=[]
 programs={
  'stop':bytecode(b'\x17'),'integer':bytecode(b'\x0b\0\0\0\x17',2,[(0,b'0x2a')]),
  'state metadata':bytecode(b'\x17',consts=[(2,b'\0OCTRA_STATE_V1\0AAA=')]),
  'invalid state metadata':bytecode(b'\x17',consts=[(2,b'\0OCTRA_STATE_V1\0bad')]),
  'public write':bytecode(b'\x0e\0\0\x01',consts=[(2,b'counter')]),
  'reserved write':bytecode(b'\x0e\0\0\xff',consts=[(2,b'\0owner')]),
  'capability':bytecode(b'\x89\0\0\x01',consts=[(0,b'0')]),
  'point op':bytecode(b'\x5f\0'),'float op':bytecode(b'\x62\0\x01'),
  'program op':bytecode(b'\x7c\0\x01'),'bad register':bytecode(b'\x19\xff'),
  'missing label':bytecode(b'\x14\x01\0\0\0'),
  'duplicate label':bytecode(b'\x16\0\0\0\0\x16\0\0\0\0',2),
  'empty':bytecode(b'',0),'trailing':bytecode(b'\x17\0'),'unknown':bytecode(b'\xff'),
  'short':b'OCTB','wrong magic':b'WASM'+b'\0'*20,
 }
 for proof in [False,True]:
  for storage in [False,True]:
   rules=dict(proof=proof,storage_proof=storage)
   for name,raw in programs.items():
    for template in [deploy,update]:
     v=copy.deepcopy(template)|rules;v['name']='octb '+v['name']+' '+name
     tx=v['transactions'][0];p=json.loads(base64.b64decode(tx['params']));p['code_b64']=b64(raw)
     if tx['op']=='deploy':p['runtime']='octb'
     else:
      for e in v['entries']:
       if base64.b64decode(e['path'][-1])==b'runtime':e['value']=b64('octb')
     tx['params']=b64(json.dumps(p,separators=(',',':')));out.append(v)
   for raw in ['','!','====','a','YWJjZA']:
    v=copy.deepcopy(out[-1]);v['name']='octb invalid base64 '+repr(raw);p=json.loads(base64.b64decode(v['transactions'][0]['params']));p['code_b64']=raw;v['transactions'][0]['params']=b64(json.dumps(p));out.append(v)
   valid=next(v for v in out if v['name']=='octb deploy wasm stop' and v['proof']==proof and v['storage_proof']==storage)
   for violation in ['wrong recipient','exists','budget','negative limit','invalid limits','balance']:
    for bytecode_name in ['stop','short']:
     v=copy.deepcopy(valid);v['name']='deploy precedence '+violation+' '+bytecode_name
     t=v['transactions'][0];p=json.loads(base64.b64decode(t['params']));p['code_b64']=b64(programs[bytecode_name])
     if violation=='wrong recipient':t['to']=b64('wrong')
     if violation=='exists':v['entries']=[dict(path=list(map(b64,['circles','$circle','runtime'])),value=b64('octb'))]
     if violation=='budget':p['limits']['max_wasm_bytes']='1'
     if violation=='negative limit':p['limits']['max_wasm_bytes']='-1'
     if violation=='invalid limits':p['limits']['max_wasm_bytes']='bad'
     if violation=='balance':v['accounts'][0]['balance']='0'
     t['params']=b64(json.dumps(p,separators=(',',':')));out.append(v)
   for violation in ['owner','budget','missing','balance']:
    for bytecode_name in ['stop','short']:
     v=copy.deepcopy(next(v for v in out if v['name']=='octb update wasm stop' and v['proof']==proof and v['storage_proof']==storage));v['name']='update precedence '+violation+' '+bytecode_name
     t=v['transactions'][0];t['params']=b64(json.dumps(dict(code_b64=b64(programs[bytecode_name]))))
     for e in v['entries']:
      leaf=base64.b64decode(e['path'][-1])
      if violation=='owner' and leaf==b'owner':e['value']=b64('other')
      if violation=='budget' and leaf==b'max_wasm_bytes':e['value']=b64('1')
     if violation=='missing':v['entries']=[]
     if violation=='balance':v['accounts'][0]['balance']='0'
     out.append(v)
   v=copy.deepcopy(valid);v['name']='deploy then reject update then update';t=copy.deepcopy(update['transactions'][0]);t.update(to=b64('$previous'),nonce=2);t['params']=b64(json.dumps(dict(code_b64=b64(programs['short']))));u=copy.deepcopy(t);u['params']=b64(json.dumps(dict(code_b64=b64(programs['integer']))));v['transactions'] += [t,u];out.append(v)
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
 if a.out.exists():raise SystemExit('Require fresh output')
 counter=json.loads((ROOT/'crates/octra-node-runtime/tests/fixtures/circle-view.json').read_text())
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/circle-code-oracle.ml',dict(wasm_b64=counter['wasm_b64'],cases=fixtures()),'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix str')
 report.update(wasm_b64=counter['wasm_b64'],wasm_sha256=counter['wasm_sha256'],guest_source_sha256=counter['guest_source_sha256'],generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),generator_dependency_sha256=hashlib.sha256((ROOT/'scripts/node-port/circle-code-fixtures.py').read_bytes()).hexdigest(),scope='Unmodified consensus processor and epoch executor: legacy OCTB Circle deploy/update with exact state roots, fees, accounts, nonce journals and refusals. No OCTB execution or OCPG certificate admission qualification.')
 a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native OCTB Circle epochs')
if __name__=='__main__':main()
