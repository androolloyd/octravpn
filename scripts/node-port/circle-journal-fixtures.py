"""Real native nested Circle transactions, value/storage journals and receipts."""
import argparse,base64,copy,hashlib,importlib.util,itertools,json,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v if isinstance(v,bytes) else v.encode()).decode()
def fixtures(digest):
    a='oct'+'3'*44;b='oct'+'5'*44;sender='oct'+'2'*44;dest='oct'+'7'*44
    def entry(path,value):return dict(path=list(map(b64,path)),value=b64(value))
    def seed(address,enabled=True):
        fields={'runtime':'wasm_v1','version':'1','owner':sender,'code_hash':digest,'stable_root':'0'*64,'assets_root':'0'*64,'privacy/class':'public','browser/mode':'gateway_allowed','resources/mode':'public_resources','limits/max_stable_bytes':'33554432','limits/max_assets_bytes':'33554432','limits/max_inline_value':'65536','limits/max_wasm_bytes':'33554432','program/code_b64':'$COUNTER','assets/usage_bytes':'0'}
        if enabled:fields['call_code']=digest
        return [entry(['circles',address,*k.split('/')],v) for k,v in fields.items()]
    out=[]
    def add(name,method,params,amount=0,entries=None,accounts=None,ou=100,**rules):
        out.append(dict(name=name,entries=entries if entries is not None else seed(a)+seed(b),accounts=accounts or [dict(address=b64(addr),nonce=0,balance=str(balance)) for addr,balance in [(sender,100000000),(a,100),(b,40)]],transactions=[{'from':b64(sender),'to':b64(a),'op':'call','params':b64(json.dumps(params,separators=(',',':'))),'method':b64(method),'amount':str(amount),'nonce':1,'ou':str(ou)}],epoch=3,now=123.5,proof=True,storage_proof=True,inspect=False,math=False,float=False,circle_policy=False,wasm_compute=False)|rules)
    for inspect,compute in itertools.product([False,True],repeat=2):
        rules=dict(inspect=inspect,wasm_compute=compute)
        for amount in [-1,0,10,200]:
            for target in [dest,a,sender,'invalid']:
                for transfer in ['-1','0','1','100','1000','9999999999999999999999999999999999']:
                    add('money','money',[target,transfer],amount=amount,**rules)
        for target in [a,b,'missing','oct'+'8'*44]:
            for method,params in [('return',[True]),('return',[False]),('return',[23]),('return',['hello']),('return',[None]),('empty',[]),('money',[dest,'13']),('fail',[dest,'13']),('reserved',[]),('unknown',[])]:
                add('nested '+method,'chain',[target,method,*params],amount=20,**rules)
        for method in ['twice','after_fail']:
            for target in [a,b]:add(method,method,[target,'money',dest,'7'],amount=20,**rules)
        for target in [a,b]:
            add('twice funded fuel','twice',[target,'money',dest,'7'],amount=20,ou=5000000,**rules)
        for depth in [0,1,2,7,8,9]:
            for target in [a,b]:add('reentry '+str(depth),'recurse',[depth,target],**rules)
        for count in [0,126,127,128,254,255,256,257]:
            add('interpreter events '+str(count),'twice',[b,'events',count],**rules)
        for count in [60,61,62,63,64]:
            add('shared events '+str(count),'many',[b,count],ou=10000000,**rules)
        add('disabled child','chain',[b,'return',1],entries=seed(a)+seed(b,False),**rules)
        add('direct failure','fail',[dest,'13'],amount=20,**rules)
        add('direct reserved','reserved',[],**rules)
    # Failed outer calls must restore successful child effects before a later tx.
    for method in ['after_fail','chain']:
        add('failure then success',method,[b,'fail' if method=='chain' else 'money',dest,'13'],amount=20,inspect=True)
        second=copy.deepcopy(out[-1]['transactions'][0]);second.update(nonce=2,method=b64('money'),params=b64(json.dumps([dest,'5'])),amount='0');out[-1]['transactions'].append(second)
    return out

def qualify(report):
    """Prove the shared budget was reached, rather than an earlier WASM limit."""
    counts={}
    for case in report['cases']:
        item=case['input'];name=item['name']
        if name not in ['twice funded fuel',*[f'shared events {n}' for n in range(60,65)]]:continue
        receipts=[json.loads(base64.b64decode(raw)) for _,raw in case['expected']['receipts']]
        assert len(receipts)==1
        receipt=receipts[0]
        if name in ['twice funded fuel','shared events 60','shared events 61']:
            assert receipt['success'] and case['expected']['result']['confirmed']
        elif name=='shared events 62':
            if item['inspect']:
                assert not receipt['success'] and receipt['error']=='circle receipt effort exceeds limit' and not receipt['events']
            else:
                assert receipt['success'] and len(receipt['events'])==258
        else:
            assert not receipt['success'] and receipt['error']=='wasm event cap exceeded'
        counts[name]=counts.get(name,0)+1
    assert counts=={'twice funded fuel':8,**{f'shared events {n}':4 for n in range(60,65)}}
    return counts

def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    source=ROOT/'scripts/node-port/circle-journal-guest.rs';sdk=a.upstream/'contracts/examples/rust_circle_sdk/src/lib.rs'
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
    assert sdk.read_bytes()==subprocess.check_output(['git','-C',str(a.upstream),'show',inventory['upstream_commit']+':contracts/examples/rust_circle_sdk/src/lib.rs'])
    with tempfile.TemporaryDirectory(prefix='octra-journal-guest-') as d:
        d=pathlib.Path(d);common=['rustc','--edition=2021','--target=wasm32-unknown-unknown','-C','panic=abort','-C','opt-level=2','-C','strip=debuginfo']
        subprocess.run(common+['--crate-type=rlib','--crate-name=rust_circle_sdk',str(sdk),'-o',str(d/'libsdk.rlib')],check=True)
        subprocess.run(common+['--crate-type=cdylib','--extern',f'rust_circle_sdk={d}/libsdk.rlib',str(source),'-o',str(d/'journal.wasm')],check=True)
        wasm=(d/'journal.wasm').read_bytes()
    digest=hashlib.sha256(wasm).hexdigest();code=b64(wasm)
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/circle-code-oracle.ml',dict(wasm_b64=code,cases=fixtures(digest)),'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix str')
    report.update(wasm_b64=code,wasm_sha256=digest,guest_source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest(),'contracts/examples/rust_circle_sdk/src/lib.rs':hashlib.sha256(sdk.read_bytes()).hexdigest()},rustc=subprocess.check_output(['rustc','--version'],text=True).strip(),scope='Unmodified native production VM transition and epoch executor; purpose-built WASM guest with pinned native SDK. Value/balance/transfer, nested and reentrant Circle calls, shared event budget, full rollback, state roots, fee/account/nonce results and exact ordered event receipts. No OCTB/HFHE/compute or external admission/consensus qualification.')
    report['budget_coverage']=qualify(report)
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native Circle journal epochs')
if __name__=='__main__':main()
