#!/usr/bin/env python3
"""Hermetic controls only: no network, compiler, wallet, signing or real proving keys."""
import argparse,base64,contextlib,copy,hashlib,importlib.util,io,json,pathlib,sys,tempfile,tomllib
ROOT=pathlib.Path(__file__).resolve().parents[2]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

module=load('canary',ROOT/'scripts/ceremony/deploy-canary.py')
FACTORY='oct'+'2'*44;PROGRAM='oct'+'3'*44;RELAYER='oct'+'4'*44
commit='a'*64;domain='b'*64;vk=base64.b64encode(b'OG16V1'+b'\0\0\0\6'+bytes(896)).decode()
code=b'OCTBfixture';code_hash=hashlib.sha256(code).hexdigest();key_hash='c'*64
checks=[]

def sha(data):return hashlib.sha256(data).hexdigest()

def fixture(temp):
    candidate=temp/'candidate';preflight=temp/'preflight';setup=temp/'setup'
    for folder in [candidate,preflight,setup]:folder.mkdir()
    # Synthetic public env/authority model; actual adopted bytes are checked
    # separately by the qualification record, never claimed by these mocks.
    authority=json.loads((ROOT/'docs/rust-node/network-authority.json').read_text())
    cp=authority['checkpoint']
    raw='\n'.join([f"OCTRA_CHAIN_ID={authority['chain_id']}",f"OCTRA_CONSENSUS_CONFIG_HASH={authority['config_hash']}",f"OCTRA_CHECKPOINT_EPOCH={cp['epoch']}",f"OCTRA_CHECKPOINT_STATE_ROOT={cp['state_root']}",f"OCTRA_CHECKPOINT_TXID_HI={cp['txid_hi']}"])+'\n'
    network_env=temp/'network.env';network_env.write_text(raw)
    authority['sha256']=sha(raw.encode());authority_file=temp/'authority.json';authority_file.write_text(json.dumps(authority))
    module.targets.AUTHORITY_FILE=authority_file
    target=module.targets.devnet(network_env)
    sources={'main-v5.aml':b'contract Fixture { const PROTOCOL_FEE_DEFAULT_BPS: uint = 0\n require(new_protocol_fee_bps == 0, "protocol fee disabled") }',
             'private-admin-factory.aml':b'contract FixtureFactory {}'}
    compile_files={}
    for name,source in sources.items():
        (candidate/name).write_bytes(source)
        artifact=preflight/(name+'.compile.json')
        artifact.write_text(json.dumps({'result':{'bytecode':base64.b64encode(code).decode(),'disasm':'JDEST 100\n','verification':{'errors':0},'certificate':{'source_hash':sha(source),'bytecode_hash':code_hash}}}))
        compile_files[name]={'artifact_sha256':sha(artifact.read_bytes()),'source_sha256':sha(source),'bytecode_sha256':code_hash}
    (candidate/'manifest.json').write_text(json.dumps({'payload':{'files':{name:sha(source) for name,source in sources.items()}}}))
    (setup/'manifest.json').write_text(json.dumps({'verification_key_b64':vk,'verification_key_sha256':key_hash,'development_only':True}))
    return candidate,preflight,setup,network_env,target,compile_files,authority_file


cases=['valid','unfunded','wrong_child_code','ambiguous_child_event','replay_accepted','wrong_cap','commission_enabled',
       'devnet_valid','mainnet_offline_plan','devnet_offline_plan','mode_mismatch','devnet_requires_mode','devnet_mode_mainnet_candidate',
       'wrong_devnet_rpc','wrong_chain','wrong_config','wrong_checkpoint_kind','wrong_checkpoint_root','wrong_checkpoint_epoch',
       'checkpoint_as_genesis','wrong_env_sha','tampered_env','missing_env','wrong_binding','wrong_preflight_rpc','wrong_preflight_binding',
       'wrong_preflight_target','missing_preflight_report','wrong_preflight_artifact_hash','wrong_preflight_source_hash','wrong_preflight_code_hash','wrong_preflight_runtime_chain','main_source_mismatch','factory_source_mismatch',
       'swapped_compile_files','wrong_certificate_code','duplicate_jump','verifier_error','wrong_admin_binding','wrong_credential',
       'wrong_setup_vk','unknown_submission','fee_out_of_range']
for case in cases:
    with tempfile.TemporaryDirectory(prefix='octra-canary-controls-') as raw:
        temp=pathlib.Path(raw);candidate,preflight,setup,network_env,target,compile_files,authority_file=fixture(temp)
        is_devnet=case.startswith('devnet') or case in ['mode_mismatch','wrong_devnet_rpc','wrong_chain','wrong_config','wrong_checkpoint_kind','wrong_checkpoint_root','wrong_checkpoint_epoch','checkpoint_as_genesis','wrong_env_sha','tampered_env','missing_env','wrong_binding','wrong_preflight_rpc','wrong_preflight_binding','wrong_preflight_target','missing_preflight_report','wrong_preflight_artifact_hash','wrong_preflight_source_hash','wrong_preflight_code_hash','wrong_preflight_runtime_chain','wrong_admin_binding']
        network='devnet' if is_devnet else 'mainnet'
        values=[1_000_000,1_000_000,100_000_000,100,1000,commit,vk,domain,200_000_000]
        intent={'target':copy.deepcopy(target) if is_devnet else {'rpc_url':module.RPC},'constructor_args':values,'economics':{'vpn_protocol_fee_bps':0}}
        if is_devnet:
            intent.update(target_binding_sha256=module.targets.digest(target),private_admin={'commitment':commit,'domain':domain,'verification_key_b64_sha256':sha(vk.encode())})
        report={'rpc_url':target['rpc_url'],'target':copy.deepcopy(target),'target_binding_sha256':module.targets.digest(target),'checks':copy.deepcopy(compile_files)}
        if case=='wrong_cap':values[-1]=0
        if case=='commission_enabled':intent['economics']['vpn_protocol_fee_bps']=50
        if case=='mode_mismatch':network='mainnet'
        if case=='devnet_mode_mainnet_candidate':intent['target']={'rpc_url':module.RPC}
        if case=='wrong_devnet_rpc':intent['target']['rpc_url']=module.RPC
        if case=='wrong_chain':intent['target']['chain_id']='foreign'
        if case=='wrong_config':intent['target']['config_hash']='d'*64
        if case=='wrong_checkpoint_kind':intent['target']['origin']['kind']='genesis'
        if case=='wrong_checkpoint_root':intent['target']['origin']['state_root']='d'*64
        if case=='wrong_checkpoint_epoch':intent['target']['origin']['epoch']+=1
        if case=='checkpoint_as_genesis':intent['target']['genesis_root']=target['origin']['state_root']
        if case=='wrong_env_sha':intent['target']['network_env_sha256']='d'*64
        if case=='tampered_env':network_env.write_text(network_env.read_text()+'# tampered\n')
        if case=='wrong_binding':intent['target_binding_sha256']='d'*64
        if case=='wrong_preflight_rpc':report['rpc_url']=module.RPC
        if case=='wrong_preflight_binding':report['target_binding_sha256']='d'*64
        if case=='wrong_preflight_target':report['target']['config_hash']='d'*64
        if case=='wrong_preflight_artifact_hash':report['checks']['private-admin-factory.aml']['artifact_sha256']='d'*64
        if case=='wrong_preflight_source_hash':report['checks']['main-v5.aml']['source_sha256']='d'*64
        if case=='wrong_preflight_code_hash':report['checks']['private-admin-factory.aml']['bytecode_sha256']='d'*64
        if case=='wrong_preflight_runtime_chain':report['checks']['octra_runtimeVersion']={'result':{'chain_id':'foreign'}}
        if case=='wrong_admin_binding':intent['private_admin']['domain']='d'*64
        if case in ['main_source_mismatch','factory_source_mismatch']:
            name='main-v5.aml' if case=='main_source_mismatch' else 'private-admin-factory.aml'
            (candidate/name).write_bytes((candidate/name).read_bytes()+b'\n# changed')
        if case=='swapped_compile_files':
            a=preflight/'main-v5.aml.compile.json';b=preflight/'private-admin-factory.aml.compile.json';x=a.read_bytes();a.write_bytes(b.read_bytes());b.write_bytes(x)
        if case in ['wrong_certificate_code','duplicate_jump','verifier_error']:
            path=preflight/'private-admin-factory.aml.compile.json';item=json.loads(path.read_text())
            if case=='wrong_certificate_code':item['result']['certificate']['bytecode_hash']='d'*64
            if case=='duplicate_jump':item['result']['disasm']='JDEST 100\nJDEST 100\n'
            if case=='verifier_error':item['result']['verification']['errors']=1
            path.write_text(json.dumps(item))
        if case=='wrong_setup_vk':
            path=setup/'manifest.json';item=json.loads(path.read_text());item['verification_key_b64']='wrong';path.write_text(json.dumps(item))
        (candidate/'intent.json').write_text(json.dumps(intent))
        if is_devnet and case!='missing_preflight_report':(preflight/'report.json').write_text(json.dumps(report))
        nonce=0;paid=[];receipts={};wallet=[];proofs=[];calls=[]
        expected_rpc=target['rpc_url'] if is_devnet else module.RPC
        def command(parts):
            global nonce
            parts=[str(x) for x in parts]
            if parts[0]=='python3':return 'Candidate integrity: PASS'
            if parts[1:4]==['cast','wallet','addr']:wallet.append(parts);return RELAYER
            if parts[1]=='authorize':
                proofs.append(parts);output=pathlib.Path(parts[parts.index('--out')+1]);n=int(parts[parts.index('--nonce')+1])
                request=json.loads(pathlib.Path(parts[parts.index('--request')+1]).read_text())
                output.write_text(json.dumps({'method':'set_paused','params':[request['params'][0],n,'tag','proof'],'commitment':'wrong' if case=='wrong_credential' else commit,'verification_key_sha256':key_hash}))
                return 'Authorization fixture'
            assert parts[1:3] in [['forge','create'],['cast','send']],parts
            paid.append(parts);tx='tx'+str(len(paid));assert parts[parts.index('--rpc-url')+1]==expected_rpc
            if parts[1]=='forge':
                assert '--no-wait' in parts and int(parts[parts.index('--ou')+1])==1000
                if case=='unknown_submission':raise RuntimeError('unknown fixture submission; no hash returned')
                receipt={'success':True,'contract':FACTORY}
            else:
                assert int(parts[parts.index('--value')+1])==0 and int(parts[parts.index('--fee')+1])==1000
                address=parts[parts.index('--value')+2];method=parts[parts.index('--value')+3]
                if method=='deploy_vpn':
                    assert address==FACTORY;event={'event':'VPNDeployed','values':[PROGRAM]}
                    receipt={'success':True,'events':[event]*(2 if case=='ambiguous_child_event' else 1)}
                else:
                    assert address==PROGRAM and method=='set_paused'
                    params=[json.loads(x) for x in parts[parts.index('--value')+4:]]
                    if params[1]==nonce:nonce+=1;receipt={'success':True}
                    elif case=='replay_accepted':receipt={'success':True}
                    else:receipt={'success':False,'events':[{'event':'Require','values':['admin nonce mismatch']}]}
            receipts[tx]=receipt;return json.dumps({'tx_hash':tx,'address':'untrusted prediction'})
        def rpc(url,method,params):
            assert url==expected_rpc;calls.append(method)
            if method=='octra_balance':
                if case=='unfunded':raise RuntimeError('sender not found')
                return {'balance_raw':str(20_000-1000*len(paid))}
            if method=='octra_transaction':return {'status':'confirmed'}
            if method=='contract_receipt':return receipts[params[0]]
            if method=='vm_contract':return {'code_hash':'wrong' if case=='wrong_child_code' and params[0]==PROGRAM else code_hash,'owner':FACTORY}
            if method=='contract_call':return {'result':{'get_admin_commitment':commit,'get_admin_domain':domain,'get_max_locked_value':200_000_000,'get_admin_nonce':nonce}[params[1]]}
            raise AssertionError(method)
        module.command=command;module.rpc=rpc;out=temp/'run'
        offline=case.endswith('offline_plan');argv=['deploy-canary.py','--candidate',str(candidate),'--preflight',str(preflight)]
        if case!='devnet_requires_mode':argv+=['--network',network]
        if is_devnet and case!='missing_env':argv+=['--network-env',str(network_env)]
        if not offline:argv+=['--key','fixture.key','--credential','fixture.credential','--setup',str(setup),'--out',str(out),'--broadcast']
        if case=='fee_out_of_range':argv+=['--fee-ou','10001']
        sys.argv=argv;success=case in ['valid','devnet_valid','mainnet_offline_plan','devnet_offline_plan']
        try:
            with contextlib.redirect_stdout(io.StringIO()) as stream:module.main()
            assert success,case
            result=json.loads(stream.getvalue())
            if offline:
                assert result['broadcast'] is False and result['escrow_deposited']==0 and not wallet and not proofs and not calls and not paid
                assert result['declared_fee_budget_ou']<=1_000_000
                if is_devnet:assert result['target']['origin']['kind']=='checkpoint' and 'genesis_root' not in result['target']
            else:assert result['qualified'] is True and nonce==2 and len(paid)==5
        except (ValueError,RuntimeError):
            assert not success,case
            journal_path=out/'journal.json'
            journal=json.loads(journal_path.read_text()) if journal_path.is_file() else {}
            assert journal.get('qualified') is not True
        early=cases.index(case)>=cases.index('mode_mismatch') and case not in ['wrong_credential','unknown_submission','wrong_setup_vk']
        if early:assert not wallet and not proofs and not calls and not paid,case
        if case in ['unfunded','wrong_cap','commission_enabled','wrong_setup_vk']:assert not paid,case
        if case=='wrong_credential':assert len(proofs)==1 and not paid,case
        if case=='unknown_submission':
            journal=json.loads((out/'journal.json').read_text());assert journal['in_flight']['possible_submission'] is True and len(paid)==1
            try:module.main();raise AssertionError('existing journal must refuse resubmission')
            except ValueError:pass
            assert len(paid)==1
        assert len(paid)<=5;checks.append(case)

# Target preflight is tested only with fake responses and subprocesses.
probe=load('probe',ROOT/'scripts/ceremony/probe-mainnet.py')
for case in ['devnet_bound_sources','mainnet_legacy_default','rpc_override_mismatch','runtime_chain_mismatch','changed_main_before_upload','changed_factory_before_upload']:
    with tempfile.TemporaryDirectory(prefix='octra-canary-probe-controls-') as raw:
        temp=pathlib.Path(raw);candidate,preflight,setup,network_env,target,compile_files,authority_file=fixture(temp);probe.targets.AUTHORITY_FILE=authority_file
        intent={'target':target,'target_binding_sha256':probe.targets.digest(target)};(candidate/'intent.json').write_text(json.dumps(intent));out=temp/'probe'
        requests=[]
        def verify_fixture(*args,**kwargs):
            if case.startswith('changed_'):
                name='main-v5.aml' if case=='changed_main_before_upload' else 'private-admin-factory.aml'
                (candidate/name).write_bytes((candidate/name).read_bytes()+b'changed')
            return None
        probe.subprocess.run=verify_fixture
        def rpc_fixture(url,method,params):
            assert url==(probe.targets.MAINNET_RPC if case=='mainnet_legacy_default' else probe.targets.DEVNET_RPC);requests.append((method,params))
            if method=='octra_runtimeVersion':return {'result':{'chain_id':'foreign' if case=='runtime_chain_mismatch' else target['chain_id']}}
            if method=='node_status':return {'result':{}}
            assert method=='octra_compileAml'
            name=next(name for name in ['main-v5.aml','private-admin-factory.aml'] if params[0]==(candidate/name).read_text())
            return json.loads((preflight/(name+'.compile.json')).read_text())
        probe.rpc=rpc_fixture
        argv=['probe-mainnet.py','--out',str(out)]
        if case=='mainnet_legacy_default':
            probe.ROOT=temp;shutil_source=temp/'program';shutil_source.mkdir()
            for name in ['main-v5.aml','private-admin-factory.aml']:(shutil_source/name).write_bytes((candidate/name).read_bytes())
        else:argv+=['--network','devnet','--candidate',str(candidate),'--network-env',str(network_env)]
        if case=='rpc_override_mismatch':argv+=['--rpc-url',probe.targets.MAINNET_RPC]
        sys.argv=argv
        try:
            with contextlib.redirect_stdout(io.StringIO()):probe.main()
            assert case in ['devnet_bound_sources','mainnet_legacy_default'],case
            report=json.loads((out/'report.json').read_text());assert report['deploy_ready'] is False and report['broadcast'] is False
            assert len([m for m,p in requests if m=='octra_compileAml'])==2
            for name in ['main-v5.aml','private-admin-factory.aml']:
                assert report['checks'][name]['artifact_sha256']==sha((out/(name+'.compile.json')).read_bytes())
                assert report['checks'][name]['source_sha256']==sha((candidate/name).read_bytes())
        except ValueError:
            assert case not in ['devnet_bound_sources','mainnet_legacy_default'],case
            assert not any(m=='octra_compileAml' for m,p in requests),case
        checks.append('probe_'+case)

# Real packager logic uses a fake local compiler and fake public repository
# snapshots; this certifies metadata/integrity plumbing, never native compilation.
prepare=load('prepare',ROOT/'scripts/ceremony/prepare-candidate.py')
for case in ['compiler_unknown','compiler_declared','compiler_invalid','mainnet_package','mainnet_legacy_integrity']:
    with tempfile.TemporaryDirectory(prefix='octra-canary-package-controls-') as raw:
        temp=pathlib.Path(raw);candidate,preflight,setup,network_env,target,compile_files,authority_file=fixture(temp);prepare.targets.AUTHORITY_FILE=authority_file
        prepare.ROOT=temp;program=temp/'program';program.mkdir()
        for name in ['main-v5.aml','private-admin-factory.aml']:(program/name).write_bytes((candidate/name).read_bytes())
        mainnet=case.startswith('mainnet_')
        params_target={'rpc_url':module.RPC,'chain_id':'','genesis_root':''} if mainnet else target
        target_text='[target]\n'+''.join(f'{key} = {json.dumps(value)}\n' for key,value in params_target.items() if key not in ['origin','authority','rpc_provenance'])
        if not mainnet:target_text+='\n[target.origin]\n'+''.join(f'{key} = {json.dumps(value)}\n' for key,value in target['origin'].items())
        params=temp/'params.toml';params.write_text(target_text+'\n[private_admin]\n'+''.join(f'{key} = {json.dumps(value)}\n' for key,value in {'commitment':commit,'verification_key_b64':vk,'domain':domain}.items())+'\n[constructor]\nmin_session_deposit=1000000\nmin_tailnet_deposit=1000000\nmin_circle_stake=100000000\nsession_grace_epochs=100\nunbond_grace_epochs=1000\nmax_locked_value=200000000\n')
        compiler=temp/'fixture-compiler';compiler.write_bytes(b'hermetic compiler model; never executed')
        def compile_fixture(args,cwd=None):
            if args[1]=='compile':pathlib.Path(args[args.index('--out')+1]).write_bytes(code);return b'status = pass fixture\n'
            if args[1]=='abi':return b'{"functions":[{"name":"fixture"}]}'
            assert args[1]=='version';return b'fixture compiler\n'
        prepare.command=compile_fixture;prepare.snapshot=lambda repo:{'head':'fixture','tree_sha256':'0'*64,'dirty':True}
        declared=None if case=='compiler_unknown' else ('invalid' if case=='compiler_invalid' else '7f9be4489870645cfcc95439638cde40f5da9f50')
        args=argparse.Namespace(out=temp/'compiled',params=params,amlc=compiler,program_version=5,network='mainnet' if mainnet else 'devnet',network_env=None if mainnet else network_env,compiler_patch=[],compiler_upstream_commit=declared)
        try:
            with contextlib.redirect_stdout(io.StringIO()):prepare.compile_candidate(args)
            assert case!='compiler_invalid'
            manifest=json.loads((args.out/'manifest.json').read_text());intent=json.loads((args.out/'intent.json').read_text())
            assert manifest['payload']['compiler']['upstream_commit']==declared
            if mainnet:
                assert intent['target']['rpc_url']==module.RPC and manifest['unmet_prerequisites']==list(prepare.PRIVATE_REQUIRED)
            else:
                assert intent['target']['origin']['kind']=='checkpoint' and 'genesis_root' not in intent['target']
                assert manifest['unmet_prerequisites'][0]=='target_network_and_checkpoint_origin'
            if case=='mainnet_legacy_integrity':
                intent['target'].pop('network');intent.pop('target_binding_sha256')
                (args.out/'intent.json').write_text(json.dumps(intent)+'\n')
                manifest['payload']['files']['intent.json']=sha((args.out/'intent.json').read_bytes())
                manifest['candidate_id']=sha(prepare.encoded(manifest['payload']))
                (args.out/'manifest.json').write_text(json.dumps(manifest)+'\n')
            with contextlib.redirect_stdout(io.StringIO()):assert prepare.verify(argparse.Namespace(out=args.out,require_ready=False))==0
        except ValueError:assert case=='compiler_invalid'
        checks.append('packager_'+case)
print(json.dumps({'status':'PASS','controls':len(checks),'cases':checks,'scope':'Hermetic mocked controls only; no actual RPC/source upload/wallet/signing/compiler/proof execution or public deployment.'},indent=2))
