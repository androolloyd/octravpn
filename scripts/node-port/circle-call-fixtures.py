#!/usr/bin/env python3
"""Native Circle method framing, HFHE transcripts, manifests and execution replies."""
import argparse,base64,hashlib,itertools,json,pathlib,random,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
def b64(raw):return base64.b64encode(raw).decode()
def raw(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
def entry(method='fhe_encrypt',result=None):return dict(method=method,request_hash='a'*64,response_hash='b'*64,result=result)
def reply():return dict(success=True,status_code=0,effort_used=7,response_b64=b64(b'OCWS1\x03\0\0\0\x0242'),storage_pairs=[dict(key_b64=b64(b'key\xff'),value_b64=b64(b'value\0'))],events=[],spawns=[],assets=[],encrypted_assets=[],hfhe_receipt_entries=[])
def fixtures():
    out=[];rng=random.Random(814913)
    encoded={b'',b'=',b'==',b'===',b'====',b'A===',b'AAAA====',b'AAAA====='}
    for width in range(1,7):encoded.update(bytes(x) for x in itertools.product(b'A/=!',repeat=width))
    for prefix in [b'',b'AAAA',b'AAAA====',b'YQ==',b'YWJj']:
        encoded.update(prefix+bytes([b])+suffix for b in range(256) for suffix in [b'',b'===',b'AAA',b'===='])
    encoded.update(rng.randbytes(rng.randrange(0,64)) for _ in range(500))
    out.extend(dict(op='base64',bytes=b64(value)) for value in sorted(encoded))
    def case(op,value,**rest):out.append(dict(op=op,json=b64(value if isinstance(value,bytes) else raw(value)),**rest))
    for method in [b'',b'method',b'x\x00\xff',b'a'*65535,b'a'*65536]:
        for params in [[],[None,False,True,0,-1,2**62-1,2**62,2**63-1,2**64,'a\0'],[{}],[[]],[1.0],[1e300],[None,{},[]]]:case('request',params,method=b64(method))
    case('request',b'["\xff",123456789012345678901234567890]',method=b64(b'raw'))
    case('request',[None]*65536,method=b64(b'many'))
    for literal in [b'',b'+1',b'-1',b'0xFFFF',b'0b101',b'0o7',b'01',b'1_2',b'_1',b' 1 ',b'1e2',b'bad',b'\xff',b'9'*600]:out.append(dict(op='literal',method=b64(b'm'),literal=b64(literal)))
    for tag in range(8):
        for payload in [b'',b'42',b'bad',b'\xff\0',b'-9999999999999999999999999']:
            data=b'OCWS1'+bytes([tag])+len(payload).to_bytes(4,'big')+payload
            for v in [data,data+b'x',data[:-1],b'BAD!!'+data[5:],data[:6]+(2**32-1).to_bytes(4,'big')+data[10:]]:out.append(dict(op='response',bytes=b64(v)))
    out.extend(dict(op='response',bytes=b64(rng.randbytes(rng.randrange(0,60))))for _ in range(100))
    vals=[None,False,0,1.5,'',[],{},'bad',2**62,2**63-1]
    transcripts=[[],[entry()],[entry('fhe_verify_zero',False)],[entry('fhe_verify_range',True),entry('fhe_verify_bound',False)],[entry()]*16,[entry()]*17,[entry('fhe_verify_zero',True)]*3]
    for field in entry():
        for value in vals+['A'*64,'a'*63,'a'*65]:transcripts.append([{**entry(),field:value}])
        x=entry();del x[field];transcripts.append([x])
    for value in vals:transcripts.append(value)
    transcripts += [[entry('fhe_verify_zero',None)],[entry('other',True)],[entry('x'*64)],[entry('x'*65)],[entry()]*17+[{}]]
    for value in transcripts:case('transcript',value)
    case('transcript',raw([entry()]).replace(b'fhe_encrypt',b'\xff'))
    exports=[dict(name='octra_query',kind='function'),dict(name='octra_update',kind='function'),dict(name='octra_http_request',kind='function')]
    descriptors=[{},dict(exports=exports),dict(exports=exports,manifest=dict(methods=[]))]
    for field in ['exports','manifest']:
        descriptors += [dict(exports=exports,**{field:value}) if field=='manifest' else {field:value} for value in vals]
    methods=[dict(name='get',view=True),dict(name='set',view=False),dict(name='compute',view=True,execution='compute')]
    for method in methods:descriptors.append(dict(exports=exports,manifest=dict(methods=[method])))
    for field in ['name','view','execution']:
        for value in vals+['standard','compute']:descriptors.append(dict(manifest=dict(methods=[{**methods[0],field:value}])))
    descriptors += [dict(manifest=dict(methods=[dict(name='x',view=False,execution='compute')])),dict(exports=[{'name':'x'}]),dict(exports=[None]),dict(exports=[dict(name='octra_query',kind='global')])]
    for value in descriptors:case('methods',value)
    case('methods',b'{"manifest":{"methods":[{"name":"first","name":"second","view":true}]}}')
    case('methods',b'{"manifest":{"methods":[{"name":"\xff","view":true}]}}')
    before=[[b64(b'prior'),b64(b'old')],[b64(b'prior'),b64(b'new')]]
    cases=[reply(),{**reply(),'storage_pairs':None},{**reply(),'storage_pairs':reply()['storage_pairs']*2},{}]
    for field in reply():
        for value in vals:cases.append({**reply(),field:value})
        x=reply();del x[field];cases.append(x)
    for name in ['key_b64','value_b64']:
        for value in vals+['a','====','a===','aG==','aGVsbG8','aGVsbG8=\n','aGVsbG8=','aGVsbG8===']:
            item=dict(key_b64='YQ==',value_b64='Yg==');item[name]=value
            cases.append({**reply(),'storage_pairs':[item]})
    for name in ['topic_b64','data_b64']:
        for value in vals+['bad','YQ==']:cases.append({**reply(),'events':[{**dict(topic_b64='YQ==',data_b64='Yg=='),name:value}]})
    spawn=dict(circle_id='c',owner_mode='caller',spawn_nonce=0,payload_json='{}')
    asset=dict(circle_id='c',path='/x',content_type='text/plain',body_b64='eA==')
    encrypted=dict(circle_id='c',path='/x',slot_ref=None,state_ref=None,content_type='text/plain',encoding=None,key_id='k',plaintext_hash='h',padding_class=None,activate_after_epoch=None,expire_after_epoch=None,metadata_mode=None,ciphertext_b64='eA==')
    for name,effect in [('spawns',spawn),('assets',asset),('encrypted_assets',encrypted)]:
        cases.append({**reply(),name:[effect]})
        for field in effect:
            for value in vals+['__invalid__','parent','opaque','reveal','0xFFFFFFFFFFFFFFFF','9223372036854775808','bad\0']:
                cases.append({**reply(),name:[{**effect,field:value}]})
            x=dict(effect);del x[field];cases.append({**reply(),name:[x]})
    for transcript in transcripts:cases.append({**reply(),'hfhe_receipt_entries':transcript})
    for root in [None,'a'*64,'A'*64,'a'*63,'',0]:
        for steps in [None,0,1,-1,'0xFFFFFFFFFFFFFFFF','2',2**62,2**63]:cases.append({**reply(),'compute_trace_root':root,'compute_steps':steps,'compute_operations':1})
    for name in ['compute_exit','compute_fault','error','unavailable']:
        for value in vals+[-2**31,2**31-1,2**31,'reason']:cases.append({**reply(),name:value})
    for _ in range(100):
        x=reply()
        for name in rng.sample(list(x),3):x[name]=rng.choice(vals)
        cases.append(x)
    for count in [0,1,16,33,128,257]:
        pairs=[dict(key_b64=b64(f'key{i}'.encode()),value_b64=b64(str(i).encode())) for i in range(count)]
        rng.shuffle(pairs)
        cases.append({**reply(),'storage_pairs':pairs+pairs[::3]})
    for value in cases:case('execution',value,before=before)
    case('execution',raw({**reply(),'error':'raw','unavailable':'later'}).replace(b'raw',b'\xff').replace(b'later',b'\xfe'),before=before)
    case('execution',raw(reply())[:-1]+b',"success":false}',before=before)
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text());pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
    if pin!=inventory['upstream_commit'] or a.out.exists():raise SystemExit('require adopted pin and fresh output')
    for name,h in inventory['files'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=h:raise SystemExit(f'modified upstream: {name}')
    inputs=fixtures();oracle=ROOT/'scripts/node-port/circle-call-oracle.ml'
    with tempfile.TemporaryDirectory(prefix='octra-circle-call-') as temporary:
        work=pathlib.Path(temporary);shutil.copyfile(oracle,work/'main.ml')
        (work/'dune').write_text('(executable (name main) (libraries octra_core octra_circle_runtime lwt.unix yojson base64))\n')
        (work/'input.json').write_text(json.dumps(inputs));(work/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && sha256sum /home/opam/.opam/4.14.2/lib/base64/base64.ml && mkdir vpn_circle_call_oracle && cp /oracle/main.ml /oracle/dune vpn_circle_call_oracle/ && opam exec -- dune exec ./vpn_circle_call_oracle/main.exe < /oracle/input.json'],text=True)
    dependency_sha256=next(line.split()[0]for line in output.splitlines() if line.endswith('/lib/base64/base64.ml'))
    report=dict(upstream_commit=pin,source_sha256=inventory['files'],oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),builder_image=a.builder_image,base64_dependency=dict(version='3.5.2',source_sha256=dependency_sha256),scope='Actual native Circle request/response codec, HFHE receipt, method descriptors and complete execution result decoder; native default Base64 dependency behavior',cases=json.loads(output.splitlines()[-1]))
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'PASS: {len(inputs)} native Circle call cases: {a.out}')
if __name__=='__main__':main()
