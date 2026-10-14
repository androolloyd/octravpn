"""Native Circle spawning, public/encrypted asset commits and rollback epochs."""
import argparse,base64,copy,hashlib,importlib.util,itertools,json,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v if isinstance(v,bytes) else v.encode()).decode()
def payload(**kw):
    p=dict(runtime='wasm_v1',privacy_class='public',browser_mode='gateway_allowed',resource_mode='public_resources',code_b64='$COUNTER',limits=dict(max_stable_bytes='33554432',max_assets_bytes='33554432',max_inline_value='65536',max_wasm_bytes='33554432'))
    p.update(kw);return p
def fixtures(digest):
    a='oct'+'3'*44;b='oct'+'5'*44;sender='oct'+'2'*44
    def entry(path,value):return dict(path=list(map(b64,path)),value=b64(value))
    def seed(address,owner=sender,resource='public_resources',limit=33554432,usage='0'):
        fields={'runtime':'wasm_v1','version':'1','owner':owner,'code_hash':digest,'stable_root':'0'*64,'assets_root':'0'*64,'privacy/class':'public','browser/mode':'native_sealed' if resource=='sealed_read' else 'gateway_allowed','resources/mode':resource,'limits/max_stable_bytes':'33554432','limits/max_assets_bytes':str(limit),'limits/max_inline_value':'65536','limits/max_wasm_bytes':'33554432','program/code_b64':'$COUNTER','assets/usage_bytes':usage,'call_code':digest}
        return [entry(['circles',address,*k.split('/')],v) for k,v in fields.items()]
    out=[]
    def add(name,method,params,entries=None,**rules):
        out.append(dict(name=name,entries=entries if entries is not None else seed(a)+seed(b),accounts=[dict(address=b64(sender),nonce=0,balance='100000000')],transactions=[{'from':b64(sender),'to':b64(a),'op':'call','params':b64(json.dumps(params,separators=(',',':'))),'method':b64(method),'amount':'0','nonce':1,'ou':'5000000'}],epoch=3,now=123.5,proof=True,storage_proof=True,inspect=False,math=False,float=False,circle_policy=False,wasm_compute=False)|rules)
    asset=['self','/index.html','text/html',b64('<h1>Native Circle</h1>'),None]
    enc=['self','path','/secret','text/plain',b64(b'ciphertext'),'key','A'*64,None,None,None,None,None]
    public=payload();sealed=payload(resource_mode='sealed_read',browser_mode='native_sealed')
    payloads=[public,sealed,payload(runtime='octb',code_b64=None),payload(runtime='octb',code_b64=b64('not admitted OCTB')),payload(code_b64=None),payload(code_b64=''),payload(code_b64='!'),payload(code_b64=b64('not wasm')),payload(resource_mode='sealed_read'),{},[],payload(runtime='bad')]
    for field,value in [('max_assets_bytes','-1'),('max_wasm_bytes','1'),('max_stable_bytes','1'),('max_inline_value','no')]:
        p=copy.deepcopy(public);p['limits'][field]=value;payloads.append(p)
    for proof,inspect,manifest in itertools.product([False,True],repeat=3):
        rules=dict(proof=proof,inspect=inspect,wasm_compute=manifest)
        for path in ['/index.html','docs/./index','/a//b','../bad','%ff','/a%20b','']:
            for encoding in [None,'gzip']:
                add('public path','assets',['self',path,'text/html',asset[3],encoding],**rules)
        for field,values in [(0,[b,'invalid']),(2,['','\"\\\n']),(3,['','!',b64('abc')])]:
            for value in values:
                p=asset.copy();p[field]=value;add('public field','assets',p,**rules)
        for limit in [0,1,21,22,23]:add('asset limit','assets',asset,entries=seed(a,limit=limit),**rules)
        for usage in ['bad','0','33554432','9223372036854775807','-1']:
            add('asset usage','assets',asset,entries=seed(a,usage=usage),**rules)
        add('wrong owner','assets',asset,entries=seed(a,owner=b),**rules)
        add('public on sealed','assets',asset,entries=seed(a,resource='sealed_read'),**rules)
        for count in [0,2,4,5]:
            p=[]
            for n in range(count):p+=['self',f'/asset{n}','text/plain',b64('abc'),None]
            add('multiple assets '+str(count),'assets',p,**rules)
        add('duplicate paths','assets',asset+['self','//index.html','text/plain',b64('x'),None],**rules)
        add('sum budget','assets',['self','/a','text/plain',b64('abc'),None,'self','/b','text/plain',b64('abc'),None],entries=seed(a,limit=5),**rules)
        add('public failure','fail',asset,**rules)
        for p,owner in itertools.product(payloads,['caller','parent']):
            add('spawn payload','spawn',[json.dumps(p,separators=(',',':')),owner,1],**rules)
        for count in [0,2,4,5]:add('spawn count '+str(count),'spawn',[json.dumps(public),'parent',count],**rules)
        for owner in ['caller','parent']:
            for count in [1,2]:add('spawn with assets','spawn_assets',[json.dumps(public),owner,count,*asset],**rules)
            add('spawn call before commit','spawn_call',[json.dumps(public),owner,1],**rules)
        for kind,ref in [('path','/secret'),('slot',' A'+'B'*63+' '),('state',' A'+'B'*63+' '),('slot','bad'),('state','bad')]:
            e=enc.copy();e[1:3]=[kind,ref]
            add('encrypted locator','encrypted',e,entries=seed(a,resource='sealed_read'),**rules)
            for owner in ['caller','parent']:
                add('spawn encrypted','spawn_encrypted',[json.dumps(sealed),owner,1,*e],**rules)
        for field,values in [(0,[b]),(3,['']),(4,['!',b64('')]),(5,['']),(6,['bad','a'*64]),(7,['gzip']),(8,['pad']),(9,['10','0']),(10,['0','-1']),(11,['opaque','reveal','bad'])]:
            for value in values:
                e=enc.copy();e[field]=value;add('encrypted field','encrypted',e,entries=seed(a,resource='sealed_read'),**rules)
        e=enc.copy();e[9:11]=['3','3'];add('encrypted epoch range','encrypted',e,entries=seed(a,resource='sealed_read'),**rules)
        add('encrypted on public','encrypted',enc,**rules)
        add('duplicate encrypted','encrypted',enc+enc,entries=seed(a,resource='sealed_read'),**rules)
        # Native parent authorizes child asset writes only when it owns the child.
        nested_asset=asset[:-1]+['identity']
        for method in ['chain','after_fail']:
            for owner in [sender,a]:
                add('nested assets '+method,method,[b,'assets',*nested_asset],entries=seed(a)+seed(b,owner=owner),**rules)
            add('nested spawn '+method,method,[b,'spawn_assets',json.dumps(public),'parent',1,*nested_asset],entries=seed(a)+seed(b,owner=a),**rules)
        # Replacement must subtract the committed old size; failed effects cannot
        # leak into the next transaction's metadata or asset usage.
        for method in ['assets','fail']:
            add('replace after '+method,method,asset,entries=seed(a,limit=24),**rules)
            second=copy.deepcopy(out[-1]['transactions'][0]);second.update(nonce=2,method=b64('assets'),params=b64(json.dumps(['self','/index.html','text/plain',b64('abc'),None])))
            out[-1]['transactions'].append(second)
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    source=ROOT/'scripts/node-port/circle-effects-guest.rs';sdk=a.upstream/'contracts/examples/rust_circle_sdk/src/lib.rs'
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
    assert sdk.read_bytes()==subprocess.check_output(['git','-C',str(a.upstream),'show',inventory['upstream_commit']+':contracts/examples/rust_circle_sdk/src/lib.rs'])
    with tempfile.TemporaryDirectory(prefix='octra-effects-guest-') as d:
        d=pathlib.Path(d);common=['rustc','--edition=2021','--target=wasm32-unknown-unknown','-C','panic=abort','-C','opt-level=2','-C','strip=debuginfo']
        subprocess.run(common+['--crate-type=rlib','--crate-name=rust_circle_sdk',str(sdk),'-o',str(d/'libsdk.rlib')],check=True)
        subprocess.run(common+['--crate-type=cdylib','--extern',f'rust_circle_sdk={d}/libsdk.rlib',str(source),'-o',str(d/'effects.wasm')],check=True)
        wasm=(d/'effects.wasm').read_bytes()
    digest=hashlib.sha256(wasm).hexdigest();code=b64(wasm)
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/circle-code-oracle.ml',dict(wasm_b64=code,cases=fixtures(digest)),'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix str')
    report.update(wasm_b64=code,wasm_sha256=digest,guest_source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest(),'contracts/examples/rust_circle_sdk/src/lib.rs':hashlib.sha256(sdk.read_bytes()).hexdigest()},rustc=subprocess.check_output(['rustc','--version'],text=True).strip(),scope='Unmodified native production epoch executor and VM transitions. Spawn admission, owner/origin/marker metadata, public/encrypted assets and locators, usage/replacement, nested effect commit and failure rollback, exact roots/receipts/fees. Public development fixtures; no encrypted decryption or private capability qualification.')
    for name in ['spawn with assets','spawn encrypted','encrypted locator','nested assets chain']:
        for proof,inspect,manifest in itertools.product([False,True],repeat=3):
            if name.startswith('nested') and not proof:continue
            assert any(c['input']['name']==name and c['input']['proof']==proof and c['input']['inspect']==inspect and c['input']['wasm_compute']==manifest and c['expected']['result'].get('confirmed') for c in report['cases']),(name,proof,inspect,manifest)
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native Circle effect epochs')
if __name__=='__main__':main()
