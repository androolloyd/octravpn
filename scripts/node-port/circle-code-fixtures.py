"""Native deployment/update epochs with complete roots and exact refusal bytes."""
import argparse, base64, copy, hashlib, importlib.util, json, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
def b64(v): return base64.b64encode(v if isinstance(v, bytes) else v.encode()).decode()
def payload(**fields):
    return dict(runtime='wasm_v1', privacy_class='public', browser_mode='gateway_allowed', resource_mode='public_resources', code_b64='$COUNTER', limits=dict(max_stable_bytes='33554432', max_assets_bytes='33554432', max_inline_value='65536', max_wasm_bytes='33554432')) | fields
def fixtures():
    sender='oct'+'2'*44; out=[]
    def tx(op='deploy', p=None, nonce=1, to='$derive', ou=100, amount=0, **extra):
        return {'from':b64(sender),'to':b64(to),'op':op,'params':None if p is None else b64(p if isinstance(p,str) else json.dumps(p,separators=(',',':'))),'nonce':nonce,'ou':str(ou),'amount':str(amount),'method':None} | extra
    def entry(path,value):return dict(path=list(map(b64,path)),value=b64(value))
    def add(name, transactions, entries=None, balance=10000000, **rules):
        out.append(dict(name=name,transactions=transactions,entries=entries or [],accounts=[dict(address=b64(sender),nonce=0,balance=str(balance))],epoch=3,now=123.5,proof=False,inspect=False,float=False,math=False,storage_proof=False,circle_policy=False,wasm_compute=False)|rules)
    def seeded(**changes):
        fields={'runtime':'wasm_v1','version':'1','owner':sender,'code_hash':'0'*64,'stable_root':'0'*64,'assets_root':'0'*64,'privacy/class':'public','browser/mode':'gateway_allowed','resources/mode':'public_resources','limits/max_stable_bytes':'33554432','limits/max_assets_bytes':'33554432','limits/max_inline_value':'65536','limits/max_wasm_bytes':'33554432','program/code_b64':'$COUNTER','call_code':'preserve'}|changes
        return [entry(['circles','oct'+'3'*44,*k.split('/')],v) for k,v in fields.items() if v is not None]
    for proof in [False,True]:
      for inspect in [False,True]:
       for compute in [False,True]:
        rules=dict(proof=proof,storage_proof=proof,inspect=inspect,wasm_compute=compute)
        add('deploy wasm', [tx(p=payload())], **rules)
        add('update wasm', [tx('update',dict(code_b64='$COUNTER'),to='oct'+'3'*44)], seeded(),**rules)
        add('octb empty', [tx(p=payload(runtime='octb',code_b64=None))], **rules)
        add('deploy missing code', [tx(p=payload(code_b64=None))], **rules)
        for code in ['', 'AAAA', '====', 'a', '!!!!', 'YWJjZA==', 'YWJjZA']:
            add('deploy invalid '+repr(code),[tx(p=payload(code_b64=code))],**rules)
            add('update invalid '+repr(code),[tx('update',dict(code_b64=code),to='oct'+'3'*44)],seeded(),**rules)
    for p in [None, '{}','[]','null',payload(runtime='invalid'),payload(privacy_class='invalid'),payload(browser_mode='invalid'),payload(resource_mode='invalid'),payload(limits={}),payload(limits=None),payload(limits='bad'),payload(code_b64=10),payload(policy_hash=10),payload(members_root=[]),payload(export_policy=False)]:
        add('payload fields',[tx(p=p)])
    for field in ['runtime','privacy_class','browser_mode','resource_mode','limits']:
        p=payload(); del p[field]; add('missing '+field,[tx(p=p)])
    for field,cap in [('max_stable_bytes',33554432),('max_assets_bytes',33554432),('max_inline_value',65536),('max_wasm_bytes',33554432)]:
        for value in [None,0,'-1',str(cap+1),'bad','9223372036854775808','0xffffffffffffffff','0x2_000000','0']:
            p=payload();p['limits'][field]=value;add('limit '+field+' '+str(value),[tx(p=p)])
        p=payload(runtime='wrong');p['limits']={field:'bad'};add('integer precedence '+field,[tx(p=p)])
    add('sealed mode mismatch',[tx(p=payload(resource_mode='sealed_read'))])
    add('sealed valid',[tx(p=payload(resource_mode='sealed_read',browser_mode='native_sealed',privacy_class='sealed',policy_hash='policy',members_root='members',export_policy='export'))])
    add('wrong recipient',[tx(p=payload(),to='missing')])
    add('existing runtime even malformed',[tx(p=payload())],[entry(['circles','$circle','runtime'],'bad')])
    add('partial state optional removed',[tx(p=payload(runtime='octb',code_b64=None))],[entry(['circles','$circle','privacy',k],'stale') for k in ['policy_hash','members_root','export_policy']])
    for balance in [0,99,100,101]:
        add('deploy balance '+str(balance),[tx(p=payload(),amount=12345)],balance=balance)
        add('update balance '+str(balance),[tx('update',dict(code_b64='$COUNTER'),to='oct'+'3'*44,amount=12345)],seeded(),balance=balance)
    for p in [None,'{}','[]','null',dict(code_b64=''),dict(code_b64=None),dict(code_b64=1)]:
        add('update payload',[tx('update',p,to='oct'+'3'*44)],seeded())
    for changes in [dict(owner='other'),dict(runtime=None),dict(version='9223372036854775807'),{'limits/max_wasm_bytes':'-1'},{'limits/max_wasm_bytes':'1'}]:
        add('update metadata '+str(changes),[tx('update',dict(code_b64='$COUNTER'),to='oct'+'3'*44)],seeded(**changes))
    # Use native-derived deploy target for subsequent steps via $previous marker.
    add('deploy then update then call',[tx(p=payload()),tx('call','[]',nonce=2,to='$previous',method=b64('inc'),ou=1000000),tx('update',dict(code_b64='$COUNTER'),nonce=3,to='$previous'),tx('call','[]',nonce=4,to='$previous',method=b64('inc'),ou=1000000)],inspect=True)
    lifecycle = copy.deepcopy(out[-1])
    for proof in [False, True]:
        for inspect in [False, True]:
            for compute in [False, True]:
                if not proof and inspect and not compute: continue
                out.append(lifecycle | dict(proof=proof,storage_proof=proof,inspect=inspect,wasm_compute=compute))
    add('rejected deploy does not consume nonce',[tx(p=payload(),to='wrong'),tx(p=payload())])
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    counter=json.loads((ROOT/'crates/octra-node-runtime/tests/fixtures/circle-view.json').read_text())
    for name,digest in counter['guest_source_sha256'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=digest:raise SystemExit('Guest changed')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/circle-code-oracle.ml',dict(wasm_b64=counter['wasm_b64'],cases=fixtures()),'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix str')
    # Store one guest rather than duplicating its canonical payload per case.
    for case in report['cases']:
        for row in case['expected']['deployments']:
            row[1]=b64(base64.b64decode(row[1]).replace(counter['wasm_b64'].encode(),b'$COUNTER'))
    report.update(wasm_b64=counter['wasm_b64'],wasm_sha256=counter['wasm_sha256'],guest_source_sha256=counter['guest_source_sha256'],scope='Unmodified production VM transition and epoch executor: WASM deploy/update and code-less OCTB metadata, complete roots, fees, nonce/refusal artifacts, canonical payload/address bytes. No OCTB code execution, nested calls, external admission or consensus qualification.')
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native Circle code epochs')
if __name__=='__main__':main()
