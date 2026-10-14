#!/usr/bin/env python3
"""Generate native canonical Circle state and public-read compatibility cases."""
import argparse, base64, hashlib, importlib.util, json, pathlib, shutil, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('assets',ROOT/'scripts/node-port/circle-assets-fixtures.py')
assets=importlib.util.module_from_spec(spec);spec.loader.exec_module(assets)
b64=assets.b64; raw=assets.raw
CIRCLE=('oct'+'1'*44).encode()
def state():
    values={'runtime':'wasm_v1','version':'1','owner':'owner','code_hash':'a'*64,'stable_root':'b'*64,'assets_root':'c'*64,'privacy/class':'public','browser/mode':'gateway_allowed','resources/mode':'public_resources','limits/max_stable_bytes':'1048576','limits/max_assets_bytes':'1048576','limits/max_inline_value':'4096','limits/max_wasm_bytes':'2097152'}
    return {tuple([b'circles',CIRCLE]+[v.encode() for v in k.split('/')]):v.encode() for k,v in values.items()}
def entry(key,value): return raw(dict(raw_key=key,key_hash=assets.digest(b'octra:stable_key:v1',key.encode()),value={'value_kind':'inline','value_inline':value}))
def encoded(es): return [dict(path=list(map(b64,p)),value=b64(v)) for p,v in es.items()]
def descriptor(reads=None,names=None):
    if names is None:names=['read']
    return dict(manifest=dict(methods=[dict(name=n,view=True,public_reads=reads or []) for n in names]))
def declaration(**kwargs): return dict(circle_id=CIRCLE.decode(),path='/index.html',offset=0,max_bytes=5,**kwargs)
def fixtures():
    cases=[]
    def add(op,es,**kwargs):cases.append(dict(op=op,circle=b64(CIRCLE),entries=encoded(es),**kwargs))
    initial=state();add('info',initial)
    for key in initial:
        missing=dict(initial);del missing[key];add('info',missing)
        for value in [b'',b'bad',b'-1',b'0xFFFFFFFFFFFFFFFF',b'0u18446744073709551615',b'9223372036854775808',b'\xff']:
            add('info',dict(initial,**{})|{key:value})
    for name in ['policy_hash','members_root','export_policy']:
        add('info',initial|{(b'circles',CIRCLE,b'privacy',name.encode()):b'\xff\x00'})
    stable=(b'circles',CIRCLE,b'stable',b'by_hash');key=b'counter';hashkey=assets.digest(b'octra:stable_key:v1',key).encode()
    stable_values=[entry('counter','4'),b'{',b'null',b'{}',entry('other','secret'),raw(dict(raw_key='counter',key_hash='incorrect',value={'value_kind':'inline','value_inline':'4'})),raw(dict(raw_key='counter',key_hash='h',value={'value_kind':'blob_ref','value_blob_hash':'h','value_size':'4'})),raw(dict(raw_key='counter',key_hash='h',value={'value_kind':'blob_ref','value_blob_hash':'h','value_size':'bad'})),entry('counter','value').replace(b'value"}',b'\xff"}')]
    for val in stable_values:
        for op in ['storage','inline']:add(op,initial|{stable+(hashkey,):val},key=b64(key))
    add('storage',initial|{stable+(b'1',):entry('same','first'),stable+(b'2',):entry('same','second'),stable+(b'3',b'nested'):entry('ignored','tree')})
    ds=[{},dict(manifest=None),descriptor(),dict(manifest=[]),dict(manifest={'methods':None}),descriptor(names=['','x']),descriptor(names=['x','x'])]
    good=declaration()
    for name in good:
        for val in [None,{},[],False,'','bad',-1,0,65536,65537,'0x1','0x7fffffffffffffff','4611686018427387904']:
            ds.append(descriptor([good|{name:val}]))
        v=dict(good);del v[name];ds.append(descriptor([v]))
    for path in ['x','//index.html','/%69ndex.html','/../x','/%ff','/%','/index.html','/']:
        ds.append(descriptor([good|dict(path=path)]))
    ds.extend([descriptor([good]*n) for n in [1,2,16,17]])
    ds.extend([descriptor([good|dict(path=f'/{i}',max_bytes=65536) for i in range(n)]) for n in [4,5]])
    for d in ds:cases.append(dict(op='declarations',descriptor=b64(raw(d))))
    meta=assets.meta();meta['resource_key']=assets.digest(b'octra:circle_resource_key:v1',CIRCLE,b'/index.html')
    ap=(b'circles',CIRCLE,b'assets',b'by_hash',meta['path_key'].encode())
    ready=initial|{ap+(b'meta',):raw(meta),ap+(b'body_b64',):b'aGVsbG8='}
    def read(es=ready,read=good,budget=100000,epoch=3,decl=None):
        add('reads',es,descriptor=b64(raw(descriptor([read]) if decl is None else decl)),method=b64(b'read'),budget=budget,epoch=str(epoch))
    for budget in [None,-1,0,1999,2000,2019,2020,100000]:read(budget=budget)
    for offset in [0,1,4,5,6,2**62-1]:read(read=good|dict(offset=offset))
    for key in ready:
        es=dict(ready);del es[key];read(es)
    for privacy in ['public','scoped','sealed','circle']:read(ready|{(b'circles',CIRCLE,b'privacy',b'class'):privacy.encode()})
    for key in meta:
        for value in [None,'bad',-1]:read(ready|{ap+(b'meta',):raw(meta|{key:value})})
    for key,values in [('size_bytes',['-1','0','4','6','1048577']),('body_mode',['sealed_read']),('locator_mode',['opaque_slot']),('metadata_mode',['opaque']),('key_id',['secret']),('activate_after_epoch',['4']),('expire_after_epoch',['3']),('content_type',['text/\u00ff'])]:
        for value in values:read(ready|{ap+(b'meta',):raw(meta|{key:value})})
    for body in [b'%%%%',b'aGVsbG8=====',b'',b'aGVsbG8=']:
        for budget in [None,100000]:read(ready|{ap+(b'body_b64',):body},budget=budget)
    for field in ['activate_after_epoch','expire_after_epoch','tombstone','revoked']:
        for value in ['0','3','4',' YES\n','false','bad']:
            key=f"slot_policy:{meta['path_key']}:{field}";kh=assets.digest(b'octra:stable_key:v1',key.encode()).encode()
            read(ready|{stable+(kh,):entry(key,value)})
    read(decl=descriptor([]));read(decl=descriptor([good],names=['other']))
    return cases
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text());pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
    if a.out.exists() or pin!=inventory['upstream_commit']:raise SystemExit('require adopted pin and fresh output')
    for name,h in inventory['files'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=h:raise SystemExit(f'modified upstream: {name}')
    oracle=ROOT/'scripts/node-port/circle-state-oracle.ml';inputs=fixtures()
    with tempfile.TemporaryDirectory(prefix='octra-circle-state-') as directory:
        work=pathlib.Path(directory);shutil.copyfile(oracle,work/'main.ml')
        (work/'dune').write_text('(executable (name main) (libraries octra_core lwt.unix yojson base64 irmin))\n')
        (work/'input.json').write_text(json.dumps(inputs));(work/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && mkdir vpn_circle_state_oracle && cp /oracle/main.ml /oracle/dune vpn_circle_state_oracle/ && opam exec -- dune exec ./vpn_circle_state_oracle/main.exe < /oracle/input.json'],text=True)
    report=dict(upstream_commit=pin,source_sha256=inventory['files'],oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),builder_image=a.builder_image,scope='Native canonical Circle records, inline storage and snapshot public reads',cases=json.loads(output.splitlines()[-1]))
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'PASS: {len(inputs)} native Circle state cases: {a.out}')
if __name__=='__main__':main()
