#!/usr/bin/env python3
"""Read-only RPC identity and exact-source compiler preflight; never sends funds."""
import argparse,base64,collections,datetime,hashlib,json,pathlib,re,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[2]

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
    p.add_argument('--rpc-url',default='https://octra.network/rpc')
    p.add_argument('--out',type=pathlib.Path,required=True)
    args=p.parse_args()
    if args.out.exists(): raise ValueError('use a fresh output directory')
    args.out.mkdir(parents=True)
    report={'rpc_url':args.rpc_url,'probed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'read_only':True,'broadcast':False,'checks':{},'blockers':[]}
    for method in ['octra_runtimeVersion','node_status']:
        result=rpc(args.rpc_url,method,[])
        report['checks'][method]=result
    runtime=report['checks']['octra_runtimeVersion'].get('result',{})
    if not runtime.get('chain_id'):
        report['blockers'].append('RPC does not expose a verifiable chain/profile identity; independent network/genesis pin required')
    for file in ['main-v5.aml','private-admin-factory.aml']:
        source=(ROOT/'program'/file).read_text()
        result=rpc(args.rpc_url,'octra_compileAml',[source,True])
        (args.out/(file+'.compile.json')).write_text(json.dumps(result,indent=2)+'\n')
        compiled=result.get('result',{})
        labels=re.findall(r'^JDEST (\d+)$',compiled.get('disasm',''),re.M)
        duplicates=[label for label,n in collections.Counter(labels).items() if n>1]
        check={'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
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
