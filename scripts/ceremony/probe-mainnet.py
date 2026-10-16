#!/usr/bin/env python3
"""Read-only RPC identity and exact-source compiler preflight; uploads source, never funds."""
import argparse,base64,collections,datetime,hashlib,json,pathlib,re,subprocess,urllib.request
from importlib.util import module_from_spec, spec_from_file_location
ROOT=pathlib.Path(__file__).resolve().parents[2]
_TARGET_SPEC=spec_from_file_location('octra_ceremony_target',pathlib.Path(__file__).with_name('target.py'))
targets=module_from_spec(_TARGET_SPEC)
_TARGET_SPEC.loader.exec_module(targets)


def rpc(url,method,params):
    data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
    req=urllib.request.Request(url,data=data,headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=30) as response:
        raw=response.read(4*1024*1024+1)
    if len(raw)>4*1024*1024: raise ValueError('RPC response exceeds bound')
    result=json.loads(raw)
    if result.get('id')!=1 or result.get('jsonrpc')!='2.0': raise ValueError('invalid RPC envelope')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--network',choices=('mainnet','devnet'),default='mainnet')
    p.add_argument('--network-env',type=pathlib.Path)
    p.add_argument('--candidate',type=pathlib.Path)
    p.add_argument('--rpc-url')
    p.add_argument('--out',type=pathlib.Path,required=True)
    args=p.parse_args()
    if args.network=='devnet' and args.candidate is None:
        raise ValueError('devnet source preflight requires a verified candidate bundle')
    if args.candidate is not None:
        subprocess.run(['python3',str(ROOT/'scripts/ceremony/prepare-candidate.py'),'verify','--out',str(args.candidate)],check=True,capture_output=True)
        intent=json.loads((args.candidate/'intent.json').read_text())
        selected=targets.select(intent['target'],args.network,args.network_env)
        if intent.get('target_binding_sha256')!=targets.digest(selected):
            raise ValueError('candidate target binding digest mismatch')
        source_root=args.candidate
    else:
        selected=targets.select({'rpc_url':targets.MAINNET_RPC},args.network,args.network_env)
        source_root=ROOT/'program'
    if args.rpc_url is not None and args.rpc_url!=selected['rpc_url']:
        raise ValueError('RPC override differs from selected candidate target')
    if args.out.exists(): raise ValueError('use a fresh output directory')
    # Snapshot both verified sources before contacting the target compiler.
    sources={name:(source_root/name).read_bytes() for name in ['main-v5.aml','private-admin-factory.aml']}
    if args.candidate is not None:
        manifest=json.loads((args.candidate/'manifest.json').read_text())
        if any(hashlib.sha256(raw).hexdigest()!=manifest['payload']['files'].get(name) for name,raw in sources.items()):
            raise ValueError('candidate source changed after integrity verification')
    args.out.mkdir(parents=True)
    report={'rpc_url':selected['rpc_url'],'target':selected,'target_binding_sha256':targets.digest(selected),
            'probed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'read_only':True,'source_uploaded':True,'broadcast':False,'checks':{},'blockers':[],
            'source_scope':'verified candidate bundle' if args.candidate else 'current workspace program sources',
            'authority_scope':'RPC routing and responses do not independently attest network authority or finality'}
    for method in ['octra_runtimeVersion','node_status']:
        result=rpc(selected['rpc_url'],method,[])
        report['checks'][method]=result
    runtime=report['checks']['octra_runtimeVersion'].get('result',{})
    if not runtime.get('chain_id'):
        report['blockers'].append('RPC does not expose a verifiable chain/profile identity; independent network identity remains required')
    elif args.network=='devnet' and runtime['chain_id']!=selected['chain_id']:
        raise ValueError('RPC runtime chain differs from the independently pinned target')
    for file,raw_source in sources.items():
        source=raw_source.decode('utf-8')
        result=rpc(selected['rpc_url'],'octra_compileAml',[source,True])
        artifact=args.out/(file+'.compile.json')
        artifact.write_text(json.dumps(result,indent=2)+'\n')
        compiled=result.get('result',{})
        labels=re.findall(r'^JDEST (\d+)$',compiled.get('disasm',''),re.M)
        duplicates=[label for label,n in collections.Counter(labels).items() if n>1]
        check={'source_sha256':hashlib.sha256(raw_source).hexdigest(),'artifact_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),
               'compiled':bool(compiled.get('bytecode')),'duplicate_jump_labels':duplicates,
               'compiler_version':compiled.get('version'),'certificate':compiled.get('certificate')}
        if check['compiled']:
            code=base64.b64decode(compiled['bytecode'],validate=True)
            (args.out/(file+'.octb')).write_bytes(code)
            check['bytecode_sha256']=hashlib.sha256(code).hexdigest()
        else: report['blockers'].append(file+': target compiler rejected source')
        if duplicates: report['blockers'].append(file+': target compiler has duplicate branch labels')
        report['checks'][file]=check
    report['blockers'].append('Compilation alone cannot establish activated stateful Groth16 verification; target execution rehearsal required')
    report['blockers'].append('Funded relayer wallet not configured')
    report['deploy_ready']=False
    (args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__': main()
