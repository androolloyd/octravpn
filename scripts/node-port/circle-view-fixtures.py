#!/usr/bin/env python3
"""Qualify canonical Circle views using the actual upstream counter and OCaml host."""
import argparse,base64,hashlib,importlib.util,json,pathlib,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('state',ROOT/'scripts/node-port/circle-state-fixtures.py');state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
def fixtures():
    es=state.state();es[(b'meta',b'last_epoch')]=b'0';stable=(b'circles',state.CIRCLE,b'stable',b'by_hash');key=state.assets.digest(b'octra:stable_key:v1',b'counter').encode()
    es[stable+(key,)]=state.entry('counter','4');out=[]
    def add(method,params=[],entries=es,**opts):
        out.append(dict(circle=state.CIRCLE.decode(),method=method,params=params,entries=state.encoded(entries),code=True,proof=False,float=False,math=False)|opts)
    for method,params in [('get_counter',[]),('caller_echo',[]),('runtime_guard',[]),('state_path_key_of',['abc']),('inc',[]),('missing',[]),('get_counter',[{}]),('get_counter',[1.5]),('public_asset_undeclared',[])]:
        for proof in [False,True]:add(method,params,proof=proof)
    for value in ['0','-1','9223372036854775807','bad','9']:
        add('get_counter',entries=es|{stable+(key,):state.entry('counter',value)})
    for method in ['get_counter','caller_echo','runtime_guard']:add(method,proof=True,float=True,math=True)
    meta=state.assets.meta(b'/public.bin');meta.update(content_type='application/octet-stream',size_bytes='8',blob_hash=hashlib.sha256(b'abcdefgh').hexdigest(),resource_key=state.assets.digest(b'octra:circle_resource_key:v1',state.CIRCLE,b'/public.bin'))
    ap=(b'circles',state.CIRCLE,b'assets',b'by_hash',meta['path_key'].encode());assets=es|{ap+(b'meta',):state.raw(meta),ap+(b'body_b64',):b'YWJjZGVmZ2g='}
    add('public_asset_read',entries=assets)
    add('public_asset_read',entries=assets,proof=True)
    add('public_asset_read')
    add('public_asset_read',entries=assets|{ap+(b'body_b64',):b'YWJj'})
    return out
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text());pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
    if a.out.exists() or pin!=inventory['upstream_commit']:raise SystemExit('require adopted pin and fresh output')
    for name,h in inventory['files'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=h:raise SystemExit(f'modified upstream: {name}')
    guest_hashes={}
    for crate in ['rust_circle_counter','rust_circle_sdk']:
        for name in ['Cargo.toml',*[str(p.relative_to(a.upstream/'contracts/examples'/crate)) for p in sorted((a.upstream/'contracts/examples'/crate/'src').rglob('*.rs'))]]:
            path=f'contracts/examples/{crate}/{name}';data=subprocess.check_output(['git','-C',str(a.upstream),'show',f'{pin}:{path}'])
            if (a.upstream/path).read_bytes()!=data:raise SystemExit(f'modified guest: {path}')
            guest_hashes[path]=hashlib.sha256(data).hexdigest()
    oracle=ROOT/'scripts/node-port/circle-view-oracle.ml'
    with tempfile.TemporaryDirectory(prefix='octra-circle-view-') as directory:
        work=pathlib.Path(directory)
        subprocess.run(['cargo','build','--offline','--manifest-path',str(a.upstream/'contracts/examples/rust_circle_counter/Cargo.toml'),'--target','wasm32-unknown-unknown','--target-dir',str(work/'target'),'--release'],check=True)
        wasm=(work/'target/wasm32-unknown-unknown/release/rust_circle_counter.wasm').read_bytes();(work/'counter.wasm').write_bytes(wasm)
        shutil.copyfile(oracle,work/'main.ml');(work/'dune').write_text('(executable (name main) (libraries octra_core octra_circle_runtime octra_vm lwt.unix yojson base64 irmin))\n')
        (work/'input.json').write_text(json.dumps(fixtures()));(work/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && mkdir vpn_circle_view_oracle && cp /oracle/main.ml /oracle/dune vpn_circle_view_oracle/ && opam exec -- dune exec ./vpn_circle_view_oracle/main.exe < /oracle/input.json'],text=True)
    cases=json.loads(output.splitlines()[-1])
    if not any(c['expected']['found']=={'result':'4'} for c in cases):raise SystemExit('native engine did not execute counter')
    report=dict(upstream_commit=pin,source_sha256=inventory['files'],guest_source_sha256=guest_hashes,wasm_sha256=hashlib.sha256(wasm).hexdigest(),wasm_b64=state.b64(wasm),oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),builder_image=a.builder_image,scope='Complete OCaml Circle public-view host executing upstream counter, with byte budget and snapshot public reads',cases=cases)
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'PASS: {len(cases)} native Circle view cases: {a.out}')
if __name__=='__main__':main()
