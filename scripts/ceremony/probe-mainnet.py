#!/usr/bin/env python3
"""Recheck an unsigned candidate using only a verified local Rust compiler."""
import argparse,datetime,json,pathlib,subprocess
import local_compiler
from importlib.util import module_from_spec,spec_from_file_location
ROOT=pathlib.Path(__file__).resolve().parents[2]
_SPEC=spec_from_file_location('octra_ceremony_target',pathlib.Path(__file__).with_name('target.py'))
targets=module_from_spec(_SPEC);_SPEC.loader.exec_module(targets)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--network',choices=('mainnet','devnet'),default='mainnet')
    p.add_argument('--network-env',type=pathlib.Path)
    p.add_argument('--candidate',type=pathlib.Path,required=True)
    p.add_argument('--rpc-url',help='Execution target assertion; never used for source compilation')
    p.add_argument('--compiler-rpc-url',required=True)
    p.add_argument('--compiler-binding',type=pathlib.Path,required=True)
    p.add_argument('--out',type=pathlib.Path,required=True)
    args=p.parse_args()
    local_compiler.loopback(args.compiler_rpc_url)
    subprocess.run(['python3','-B',str(ROOT/'scripts/ceremony/prepare-candidate.py'),'verify','--out',str(args.candidate)],check=True,capture_output=True)
    intent=json.loads((args.candidate/'intent.json').read_text())
    selected=targets.select(intent['target'],args.network,args.network_env)
    if intent.get('target_binding_sha256')!=targets.digest(selected):raise ValueError('candidate target binding digest mismatch')
    if args.rpc_url is not None and args.rpc_url!=selected['rpc_url']:raise ValueError('RPC override differs from selected candidate target')
    if args.out.exists():raise ValueError('use a fresh output directory')
    manifest=json.loads((args.candidate/'manifest.json').read_text());original=manifest['payload'].get('compiler',{})
    if original.get('kind')!='verified_local_rust_node':raise ValueError('repackage using the verified local Rust compiler before preflight')
    sources={name:local_compiler.read(args.candidate/name) for name in ('main-v5.aml','private-admin-factory.aml')}
    if any(local_compiler.sha(raw)!=manifest['payload']['files'].get(name) for name,raw in sources.items()):raise ValueError('candidate source changed after integrity verification')
    artifacts,observation=local_compiler.compile_bundle(args.compiler_rpc_url,args.compiler_binding,selected,sources)
    for key in ('binding_sha256','binary_sha256','source_manifest_sha256','native_fixture_sha256','native_profiles'):
        if original.get(key)!=observation.get(key):raise ValueError('candidate local compiler binding/profile differs: '+key)
    if any(original['after']['runtime'].get(key)!=observation['before']['runtime'].get(key) for key in local_compiler.PROFILE_FIELDS):
        raise ValueError('candidate compiler runtime profile differs')
    # Compare both complete results and OCTB before creating any success evidence.
    for name,item in artifacts.items():
        if item['code']!=local_compiler.read(args.candidate/(name.removesuffix('.aml')+'.octb')) or item['result_raw']!=local_compiler.member(local_compiler.read(args.candidate/(name+'.compile.json')),'result'):
            raise ValueError('candidate differs from current local compiler output: '+name)
    args.out.mkdir(parents=True)
    report={'rpc_url':selected['rpc_url'],'target':selected,'target_binding_sha256':targets.digest(selected),
            'probed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'read_only':True,
            'source_uploaded':False,'source_sent_to_local_compiler':True,'public_target_preflight':False,'broadcast':False,
            'compiler':original,'recheck':observation,'checks':{},'deploy_ready':False,
            'blockers':['Stateful target execution/finality remains unqualified','Funded relayer wallet not configured']}
    for name,item in artifacts.items():
        raw=item['response'];(args.out/(name+'.compile.json')).write_bytes(raw)
        (args.out/(name+'.octb')).write_bytes(item['code'])
        deployment=local_compiler.encoded(local_compiler.artifact(selected,original,item))+b'\n'
        (args.out/(name+'.artifact.json')).write_bytes(deployment)
        report['checks'][name]={'source_sha256':local_compiler.sha(sources[name]),'artifact_sha256':local_compiler.sha(raw),
                              'bytecode_sha256':local_compiler.sha(item['code']),'deployment_artifact_sha256':local_compiler.sha(deployment)}
    (args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    local_compiler.validate_saved(args.candidate,args.out,selected)
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
