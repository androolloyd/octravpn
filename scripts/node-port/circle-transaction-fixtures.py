#!/usr/bin/env python3
"""Qualify native Circle transactions, fee/value journals and receipt persistence."""
import argparse,base64,copy,hashlib,importlib.util,json,pathlib,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('state',ROOT/'scripts/node-port/circle-state-fixtures.py');state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
spec=importlib.util.spec_from_file_location('view',ROOT/'scripts/node-port/circle-view-fixtures.py');view=importlib.util.module_from_spec(spec);spec.loader.exec_module(view)
def b64(value): return base64.b64encode(value if isinstance(value,bytes) else value.encode()).decode()
def fixtures():
    seed=view.fixtures()[0];out=[];sender='oct'+'2'*44;circle=seed['circle']
    def tx(nonce=1,amount=0,ou=100,method='inc',params='[]',target=circle):
        return dict(from_=b64(sender),to=b64(target),amount=str(amount),nonce=nonce,ou=str(ou),method=None if method is None else b64(method),params=None if params is None else b64(params))
    def add(proof=False,balance=10000000,transactions=None,entries=None):
        transactions=copy.deepcopy(transactions or [tx()])
        for t in transactions:t['from']=t.pop('from_')
        out.append(dict(seed,proof=proof,storage_proof=proof,inspect=True,epoch=3,now=123.5,accounts=[dict(address=b64(sender),balance=str(balance),nonce=0)],transactions=transactions,entries=entries or seed['entries']))
    for proof in [False,True]:
        for balance in [0,1,99,100,101,1000000,1000010]:
            for amount in [0,1,10,balance+1]:
                for ou in [1,100]:add(proof,balance,[tx(amount=amount,ou=ou)])
        for ou in [0,1000000,20000001,(1<<62),(1<<63)]:add(proof,ou+100,[tx(ou=ou)])
        for method in ['missing','get_counter','prepare_room','prepare_register_lane','public_asset_record','kernel_probe']:
            add(proof,transactions=[tx(method=method),tx(nonce=2)])
        for method,params in [(None,'[]'),('inc',None),('inc','{}'),('inc','null'),('inc','[1.5]'),('inc','[{}]')]:
            add(proof,transactions=[tx(method=method,params=params),tx(nonce=2)])
        add(proof,transactions=[tx(target='missing-circle'),tx(nonce=2)])
        add(proof,transactions=[tx(nonce=2),tx(),tx(nonce=3)])
        add(proof,transactions=[tx(),tx(),tx(nonce=2)])
        add(proof,transactions=[tx(amount=10000000),tx(nonce=2)])
        add(proof,transactions=[tx(method=None),tx(),tx(nonce=2)])
        for max_inline,max_stable in [('0','1000000'),('1000000','1')]:
            entries=[dict(e,value=b64(max_inline if e['path'][-1]==b64('max_inline_value') else max_stable)) if e['path'][-1] in [b64('max_inline_value'),b64('max_stable_bytes')] else e for e in seed['entries']]
            add(proof,entries=entries,transactions=[tx(amount=10),tx(nonce=2)])
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
    oracle=ROOT/'scripts/node-port/circle-transaction-oracle.ml'
    with tempfile.TemporaryDirectory(prefix='octra-circle-transaction-') as directory:
        work=pathlib.Path(directory)
        subprocess.run(['cargo','build','--offline','--manifest-path',str(a.upstream/'contracts/examples/rust_circle_counter/Cargo.toml'),'--target','wasm32-unknown-unknown','--target-dir',str(work/'target'),'--release'],check=True)
        wasm=(work/'target/wasm32-unknown-unknown/release/rust_circle_counter.wasm').read_bytes();(work/'counter.wasm').write_bytes(wasm)
        shutil.copyfile(oracle,work/'main.ml');(work/'dune').write_text('(executable (name main) (libraries octra_core octra_circle_runtime octra_vm octra_node_runtime lwt.unix yojson base64 irmin))\n')
        (work/'input.json').write_text(json.dumps(fixtures()));(work/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && mkdir vpn_circle_transaction_oracle && cp /oracle/main.ml /oracle/dune vpn_circle_transaction_oracle/ && opam exec -- dune exec ./vpn_circle_transaction_oracle/main.exe < /oracle/input.json'],text=True)
    cases=json.loads(output.splitlines()[-1])
    if not any(any(e['outcome']=='confirmed' for e in c['expected']['events']) for c in cases):raise SystemExit('native engine did not execute counter')
    report=dict(upstream_commit=pin,source_sha256=inventory['files'],guest_source_sha256=guest_hashes,wasm_sha256=hashlib.sha256(wasm).hexdigest(),wasm_b64=b64(wasm),oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),builder_image=a.builder_image,scope='Native Circle sender loop, fee/value savepoints, WASM execution and auxiliary receipt bytes; caller-supplied transaction admission',cases=cases)
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'PASS: {len(cases)} native Circle transaction cases: {a.out}')
if __name__=='__main__':main()
