#!/usr/bin/env python3
"""Qualify native Circle RPC clocks, profiles and real WASM view boundaries."""
import argparse,base64,hashlib,importlib.util,json,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
native=module('native',ROOT/'scripts/node-port/native-oracle.py')
state=module('state',ROOT/'scripts/node-port/circle-state-fixtures.py')
def build_guest(upstream):
    with tempfile.TemporaryDirectory(prefix='octra-epoch-guest-') as directory:
        work=pathlib.Path(directory)
        (work/'lib.rs').write_bytes((ROOT/'scripts/node-port/epoch-guest.rs').read_bytes())
        sdk=upstream.resolve()/'contracts/examples/rust_circle_sdk'
        (work/'Cargo.toml').write_text('[package]\nname="octra_epoch_guest"\nversion="0.0.0"\nedition="2021"\n[lib]\npath="lib.rs"\ncrate-type=["cdylib"]\n[profile.release]\nopt-level="z"\nlto=true\npanic="abort"\nstrip=true\n[dependencies]\nrust_circle_sdk={path='+json.dumps(str(sdk))+'}\n')
        subprocess.run(['cargo','build','--offline','--manifest-path',str(work/'Cargo.toml'),'--target','wasm32-unknown-unknown','--release'],check=True)
        return (work/'target/wasm32-unknown-unknown/release/octra_epoch_guest.wasm').read_bytes()
def fixtures(upstream):
    counter=json.loads((ROOT/'crates/octra-node-runtime/tests/fixtures/circle-view.json').read_text())
    for name,digest in counter['guest_source_sha256'].items():
        if hashlib.sha256((upstream/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError(f'modified guest: {name}')
    if hashlib.sha256(base64.b64decode(counter['wasm_b64'])).hexdigest()!=counter['wasm_sha256']:
        raise RuntimeError('counter WASM differs')
    b64=lambda raw:base64.b64encode(raw.encode()).decode()
    inputs=[{'kind':'clock','epoch':value} for value in [None,'','bad','-1','0','1','0x10','+5','4_2',str((1<<62)-2),str((1<<62)-1),str(1<<62),str((1<<63)-1)]]
    for chain in ['octra-devnet-9871-cluster','octra-mainnet','local']:
        for epoch in sorted(set([-1,0,1,(1<<62)-1]+[e+d for e in [1380000,1500000,1510000,1614500,1663000] for d in [-1,0,1]])):
            for default in ['good','missing','bad','unreadable']:
                inputs.append(dict(kind='profile',chain=b64(chain),epoch=epoch,default=default,roots={}))
    for anchor in [1353962,1380960,1504440]:
        for default in ['missing','bad','unreadable']:
            inputs.append(dict(kind='profile',chain=b64('octra-devnet-9871-cluster'),epoch=1700000,default='good',roots={str(anchor):default}))
    es=state.state();es[(b'meta',b'last_epoch')]=b'0'
    es[(b'circles',state.CIRCLE,b'program',b'code_b64')]=counter['wasm_b64'].encode()
    es[(b'circles',state.CIRCLE,b'code_hash')]=counter['wasm_sha256'].encode()
    m=state.assets.meta(b'/public.bin');m.update(content_type='application/octet-stream',size_bytes='8',blob_hash=hashlib.sha256(b'abcdefgh').hexdigest(),resource_key=state.assets.digest(b'octra:circle_resource_key:v1',state.CIRCLE,b'/public.bin'))
    ap=(b'circles',state.CIRCLE,b'assets',b'by_hash',m['path_key'].encode())
    for activate in [None,'0','1','2']:
        for expire in [None,'0','1','2']:
            values=es|{ap+(b'meta',):state.raw(m|dict(activate_after_epoch=activate,expire_after_epoch=expire)),ap+(b'body_b64',):b'YWJjZGVmZ2g='}
            inputs.append(dict(kind='view',circle=state.CIRCLE.decode(),method='public_asset_read',params=[],entries=state.encoded(values)))
    guest=build_guest(upstream)
    guest_hash=hashlib.sha256(guest).hexdigest()
    values=es|{(b'circles',state.CIRCLE,b'program',b'code_b64'):base64.b64encode(guest),(b'circles',state.CIRCLE,b'code_hash'):guest_hash.encode()}
    inputs.append(dict(kind='view',circle=state.CIRCLE.decode(),method='epoch',params=[],entries=state.encoded(values)))
    return inputs,counter,guest_hash

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream',required=True,type=pathlib.Path)
    parser.add_argument('--builder-image',required=True)
    parser.add_argument('--out',required=True,type=pathlib.Path)
    args=parser.parse_args()
    if args.out.exists():raise SystemExit('Require fresh output')
    inputs,counter,guest_hash=fixtures(args.upstream)
    report=native.run(args.upstream,args.builder_image,ROOT/'scripts/node-port/circle-rpc-oracle.ml',inputs,'octra_core octra_vm octra_circle_runtime octra_node_runtime lwt.unix yojson irmin')
    report.update(scope='Unmodified Circle RPC snapshot epoch guards, native view-profile fault order, upstream counter public-read activation/expiry boundaries and an SDK epoch guest',guest_source_sha256=counter['guest_source_sha256'],wasm_sha256=counter['wasm_sha256'],epoch_guest_source_sha256=hashlib.sha256((ROOT/'scripts/node-port/epoch-guest.rs').read_bytes()).hexdigest(),epoch_guest_wasm_sha256=guest_hash,generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),rustc=subprocess.check_output(['rustc','--version'],text=True).strip())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(report['cases']),'native Circle RPC cases')
if __name__=='__main__':main()
