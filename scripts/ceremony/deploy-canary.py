#!/usr/bin/env python3
"""Bounded mainnet RC qualification. Deploys with zero escrow; never stakes funds.

Default is an offline plan. --broadcast spends at most 1 OCT in declared fees,
records each submission before waiting, and qualifies real stateful private-admin
proofs before the operator funds the contract. A failed/unknown submission stops;
rerunning into the same output directory is refused to avoid duplicate actions.
"""
import argparse,base64,hashlib,json,pathlib,subprocess,time,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[2]
RPC='https://octra.network/rpc'

def command(parts):
    result=subprocess.run([str(p) for p in parts],capture_output=True,text=True)
    if result.returncode: raise RuntimeError(result.stderr[-3000:])
    return result.stdout.strip()

def load(candidate,preflight):
    command(['python3',ROOT/'scripts/ceremony/prepare-candidate.py','verify','--out',candidate])
    intent=json.loads((candidate/'intent.json').read_text())
    if intent.get('economics', {}).get('vpn_protocol_fee_bps') != 0:
        raise ValueError('candidate does not declare zero VPN protocol commission')
    values=intent['constructor_args']
    if intent['target']['rpc_url']!=RPC or len(values)!=9 or values[-1]!=200_000_000 or values[2]!=100_000_000:
        raise ValueError('only the reviewed 200 OCT / 100 OCT stake mainnet canary is allowed')
    if not all(values[5:8]): raise ValueError('private administration must be initialized')
    if values[0]!=1_000_000 or values[1]!=1_000_000: raise ValueError('canary deposits must be 1 OCT')
    artifacts={}
    for name in ['main-v5.aml','private-admin-factory.aml']:
        source=(candidate/name).read_bytes()
        if name=='main-v5.aml':
            import re
            text=source.decode()
            if not re.search(r'const PROTOCOL_FEE_DEFAULT_BPS: uint = 0\b',text) or not re.search(r'require\(new_protocol_fee_bps == 0,',text) or 'total_paid * self.protocol_fee_bps' in text:
                raise ValueError('candidate permits VPN protocol commission')
        item=json.loads((preflight/(name+'.compile.json')).read_text())['result']
        code=base64.b64decode(item['bytecode'],validate=True)
        certificate=item['certificate']
        if certificate['source_hash']!=hashlib.sha256(source).hexdigest() or certificate['bytecode_hash']!=hashlib.sha256(code).hexdigest():
            raise ValueError('target compiler artifact does not match candidate source/code')
        import collections,re
        labels=re.findall(r'^JDEST (\d+)$',item['disasm'],re.M)
        if any(n>1 for n in collections.Counter(labels).values()): raise ValueError('duplicate target jump label')
        if item['verification']['errors']!=0: raise ValueError('target safety verifier errors')
        artifacts[name]=(code,certificate['bytecode_hash'])
    return intent,artifacts

def rpc(method,params):
    req=urllib.request.Request(RPC,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=20) as response: raw=response.read(4*1024*1024+1)
    if len(raw)>4*1024*1024: raise ValueError('RPC response exceeds bound')
    result=json.loads(raw)
    if result.get('id')!=1 or 'error' in result or 'result' not in result: raise RuntimeError(f'{method}: {result}')
    return result['result']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate',type=pathlib.Path,required=True)
    p.add_argument('--preflight',type=pathlib.Path,required=True)
    p.add_argument('--key',type=pathlib.Path)
    p.add_argument('--credential',type=pathlib.Path)
    p.add_argument('--setup',type=pathlib.Path)
    p.add_argument('--out',type=pathlib.Path)
    p.add_argument('--octra',type=pathlib.Path,default=ROOT.parent/'octra-foundry/target/debug/octra')
    p.add_argument('--prover',type=pathlib.Path,default=ROOT/'target/release/octravpn-private-admin')
    p.add_argument('--fee-ou',type=int,default=1000)
    p.add_argument('--broadcast',action='store_true')
    args=p.parse_args()
    intent,artifacts=load(args.candidate,args.preflight)
    if not 1<=args.fee_ou<=10_000: raise ValueError('fee must be within the bounded canary range')
    plan={'rpc_url':RPC,'escrow_deposited':0,'contract_funding_cap_ou':200_000_000,
          'declared_fee_budget_ou':5*args.fee_ou,'private_admin_domain':intent['constructor_args'][7],
          'actions':['deploy factory','spawn VPN via factory','private pause','replay must revert','private unpause'],
          'scope':'RC qualification only; no operator stake, treasury deposit or VPN service activation',
          'independent_review':False,'multiparty_setup_certified':False,'broadcast':args.broadcast}
    if not args.broadcast:
        print(json.dumps(plan,indent=2)); return
    if not all([args.key,args.credential,args.setup,args.out]): raise ValueError('broadcast requires key, credential, setup and fresh output directory')
    # Bind all inputs before submitting anything. Prover enforces regular-file,
    # permission and size checks on the credential; no witness enters this journal.
    setup=json.loads((args.setup/'manifest.json').read_text())
    values=intent['constructor_args']
    if setup['verification_key_b64']!=values[6] or not setup['development_only']:
        raise ValueError('RC requires the matching, explicitly marked development setup')
    relayer=command([args.octra,'cast','wallet','addr','--key',args.key])
    balance=rpc('octra_balance',[relayer])
    available=int(balance['balance_raw'])
    if available<plan['declared_fee_budget_ou']: raise ValueError('relayer is unfunded or below qualification fee budget')
    if args.out.exists(): raise ValueError('use a fresh output directory; inspect previous submission journal before retrying')
    args.out.mkdir(mode=0o700,parents=True)
    journal={'plan':plan,'relayer':relayer,'initial_balance_raw':available,'submissions':[],'qualified':False}
    def save(): (args.out/'journal.json').write_text(json.dumps(journal,indent=2)+'\n')
    def view(program,method):
        result=rpc('contract_call',[program,method,[]])
        if 'result' not in result: raise ValueError(f'{method}: no successful view result')
        return result['result']
    def authorization(program,nonce,paused,label):
        request=args.out/(label+'.request.json'); output=args.out/(label+'.authorization.json')
        request.write_text(json.dumps({'method':'set_paused','params':[paused]})+'\n')
        command([args.prover,'authorize','--credential',args.credential,'--proving-key',args.setup/'proving-key.bin','--request',request,'--domain',values[7],'--program',program,'--nonce',nonce,'--out',output])
        auth=json.loads(output.read_text())
        if auth['commitment']!=values[5] or auth['verification_key_sha256']!=setup['verification_key_sha256']:
            raise ValueError('credential/proving key differs from reviewed candidate')
        return auth
    # Dry proof binds this credential and key before the first paid operation.
    authorization('oct'+'1'*44,0,1,'input-check')
    def wait_receipt(hash):
        until=time.monotonic()+90
        while time.monotonic()<until:
            tx=rpc('octra_transaction',[hash])
            if tx.get('status') in ('rejected','dropped'): raise ValueError(f'transaction rejected: {hash}: {tx}')
            if tx.get('status')=='confirmed': return rpc('contract_receipt',[hash])
            time.sleep(1)
        raise ValueError('confirmation timeout; inspect journal and never blindly resubmit')
    def record(label,result):
        journal.pop('in_flight',None)
        hash=result['tx_hash']
        journal['submissions'].append({'label':label,'tx_hash':hash}); save()
        receipt=wait_receipt(hash)
        journal['submissions'][-1]['receipt']=receipt; save()
        return receipt
    def send(label,address,method,params,expected_success=True):
        # Every call has zero attached value and an explicit bounded fee.
        journal['in_flight']={'label':label,'possible_submission':True};save()
        result=json.loads(command([args.octra,'cast','send','--key',args.key,'--rpc-url',RPC,'--fee',args.fee_ou,'--value',0,address,method,*[json.dumps(x,separators=(',',':')) for x in params]]))
        receipt=record(label,result)
        if receipt.get('success') is not expected_success: raise ValueError(f'{label}: unexpected execution outcome; no escrow has been funded')
        return receipt
    save()
    journal['in_flight']={'label':'deploy factory','possible_submission':True};save()
    factory_result=json.loads(command([args.octra,'forge','create',args.candidate/'private-admin-factory.aml','--key',args.key,'--rpc-url',RPC,'--ou',args.fee_ou,'--no-wait']))
    receipt=record('deploy factory',factory_result)
    if receipt.get('success') is not True: raise ValueError('factory deployment failed')
    factory=receipt.get('contract')
    if not isinstance(factory,str) or len(factory)!=47 or not factory.startswith('oct'): raise ValueError('confirmed receipt lacks factory address')
    if rpc('vm_contract',[factory]).get('code_hash')!=artifacts['private-admin-factory.aml'][1]: raise ValueError('deployed factory code mismatch')
    journal['factory']=factory; save()
    receipt=send('spawn VPN',factory,'deploy_vpn',[base64.b64encode(artifacts['main-v5.aml'][0]).decode(),*values])
    children=[event['values'][0] for event in receipt.get('events',[]) if event.get('event')=='VPNDeployed']
    if len(children)!=1 or not isinstance(children[0],str) or len(children[0])!=47: raise ValueError('confirmed child-address event missing/ambiguous')
    program=children[0];journal['program']=program;save()
    metadata=rpc('vm_contract',[program])
    if metadata.get('code_hash')!=artifacts['main-v5.aml'][1] or metadata.get('owner')!=factory: raise ValueError('child code/native authority mismatch')
    for method,expected in [('get_admin_commitment',values[5]),('get_admin_domain',values[7]),('get_max_locked_value',200_000_000),('get_admin_nonce',0)]:
        if str(view(program,method))!=str(expected): raise ValueError('child initialization mismatch: '+method)
    pause=authorization(program,0,1,'pause')
    send('private pause',program,pause['method'],pause['params'])
    if int(view(program,'get_admin_nonce'))!=1: raise ValueError('stateful proof did not advance nonce')
    receipt=send('replay rejection',program,pause['method'],pause['params'],False)
    reasons=[event.get('values') for event in receipt.get('events',[]) if event.get('event')=='Require']
    if ['admin nonce mismatch'] not in reasons or int(view(program,'get_admin_nonce'))!=1: raise ValueError('replay control failed')
    unpause=authorization(program,1,0,'unpause')
    send('private unpause',program,unpause['method'],unpause['params'])
    if int(view(program,'get_admin_nonce'))!=2: raise ValueError('private unpause failed')
    final=int(rpc('octra_balance',[relayer])['balance_raw'])
    if available-final>plan['declared_fee_budget_ou']: raise ValueError('observed spend exceeds bounded fee plan')
    journal.update(qualified=True,final_balance_raw=final,escrow_deposited=0,
                   scope='stateful proof and replay qualified through official RPC; production network/finality certification still absent')
    save();print(json.dumps({'program':program,'factory':factory,'qualified':True,'escrow_deposited':0,'journal':str(args.out/'journal.json')},indent=2))

if __name__=='__main__':
    try: main()
    except (OSError,ValueError,KeyError,RuntimeError,subprocess.SubprocessError) as error:
        raise SystemExit('Canary STOP: '+str(error))
