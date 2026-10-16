#!/usr/bin/env python3
"""Hermetic controls only: no network, compiler, wallet, signing or real proving keys."""
import argparse,base64,contextlib,copy,hashlib,importlib.util,io,json,pathlib,sys,tempfile,tomllib,unittest.mock
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/ceremony'))

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

module=load('canary',ROOT/'scripts/ceremony/deploy-canary.py')
transport_rpc=module.rpc
FACTORY='oct'+'2'*44;PROGRAM='oct'+'3'*44;RELAYER='oct'+'4'*44
commit='a'*64;domain='b'*64;vk=base64.b64encode(b'OG16V1'+b'\0\0\0\6'+bytes(896)).decode()
code=b'OCTBfixture';code_hash=hashlib.sha256(code).hexdigest();key_hash='c'*64
runtime_profile='e'*64;consensus_standard='f'*64
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
       'wrong_preflight_target','missing_preflight_report','wrong_preflight_artifact_hash','wrong_preflight_source_hash','wrong_preflight_code_hash','wrong_preflight_runtime_chain','wrong_live_chain','wrong_live_profile','wrong_live_consensus','wrong_live_shape','main_source_mismatch','factory_source_mismatch',
       'swapped_compile_files','wrong_certificate_code','duplicate_jump','verifier_error','wrong_admin_binding','wrong_credential',
       'wrong_setup_vk','unknown_submission','fee_out_of_range','deployment_too_low','deployment_negative','deployment_exceeds_ceiling','budget_exceeded','fee_budget_exact','custom_deployment','replay_rejected','devnet_replay_rejected','devnet_replay_native_no_receipt','devnet_resume_after_replay','devnet_resume_tampered_journal','replay_wrong_reason','replay_wrong_error','replay_successful_receipt','replay_missing_receipt','replay_dropped','unexpected_rejection_factory','unexpected_rejection_spawn','unexpected_rejection_pause','replay_nonce_changed','fee_depletion']
for case in cases:
    with tempfile.TemporaryDirectory(prefix='octra-canary-controls-') as raw:
        temp=pathlib.Path(raw);candidate,preflight,setup,network_env,target,compile_files,authority_file=fixture(temp)
        is_devnet=case.startswith('devnet') or case in ['mode_mismatch','wrong_devnet_rpc','wrong_chain','wrong_config','wrong_checkpoint_kind','wrong_checkpoint_root','wrong_checkpoint_epoch','checkpoint_as_genesis','wrong_env_sha','tampered_env','missing_env','wrong_binding','wrong_preflight_rpc','wrong_preflight_binding','wrong_preflight_target','missing_preflight_report','wrong_preflight_artifact_hash','wrong_preflight_source_hash','wrong_preflight_code_hash','wrong_preflight_runtime_chain','wrong_live_chain','wrong_live_profile','wrong_live_consensus','wrong_live_shape','wrong_admin_binding']
        network='devnet' if is_devnet else 'mainnet'
        deployment_ou=960_000 if case=='fee_budget_exact' else (300_000 if case=='custom_deployment' else 200_000)
        call_fee=10_000 if case=='fee_budget_exact' else 1000
        values=[1_000_000,1_000_000,100_000_000,100,1000,commit,vk,domain,200_000_000]
        intent={'target':copy.deepcopy(target) if is_devnet else {'rpc_url':module.RPC},'constructor_args':values,'economics':{'vpn_protocol_fee_bps':0}}
        if is_devnet:
            intent.update(target_binding_sha256=module.targets.digest(target),private_admin={'commitment':commit,'domain':domain,'verification_key_b64_sha256':sha(vk.encode())})
        report={'compiler':{'kind':'verified_local_rust_node'},'rpc_url':target['rpc_url'],'target':copy.deepcopy(target),'target_binding_sha256':module.targets.digest(target),'checks':copy.deepcopy(compile_files)}
        if not is_devnet:report={'compiler':{'kind':'verified_local_rust_node'},'rpc_url':module.RPC}
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
        if case!='missing_preflight_report':(preflight/'report.json').write_text(json.dumps(report))
        nonce=0;paid=[];receipts={};wallet=[];proofs=[];calls=[];resume_mode=False
        expected_rpc=target['rpc_url'] if is_devnet else module.RPC
        def command(parts):
            global nonce
            parts=[str(x) for x in parts]
            if parts[0]=='python3':return 'Candidate integrity: PASS'
            if parts[1:4]==['cast','wallet','addr']:wallet.append(parts);return RELAYER
            if parts[1]=='authorize':
                proofs.append(parts);output=pathlib.Path(parts[parts.index('--out')+1]);n=int(parts[parts.index('--nonce')+1])
                if output.exists():raise RuntimeError('authorization output already exists')
                request=json.loads(pathlib.Path(parts[parts.index('--request')+1]).read_text())
                output.write_text(json.dumps({'method':'set_paused','params':[request['params'][0],n,'tag','proof'],'commitment':'wrong' if case=='wrong_credential' else commit,'verification_key_sha256':key_hash}))
                return 'Authorization fixture'
            assert parts[1:3] in [['forge','create'],['cast','send']],parts
            paid.append(parts);tx='tx'+str(len(paid));assert parts[parts.index('--rpc-url')+1]==expected_rpc
            if parts[1]=='forge':
                assert '--compiled-artifact' in parts and '--artifact-sha256' in parts
                assert parts[parts.index('--artifact-sha256')+1]=='a'*64
                assert '--no-wait' in parts and int(parts[parts.index('--ou')+1])==deployment_ou
                if case=='unknown_submission':raise RuntimeError('unknown fixture submission; no hash returned')
                receipt={'success':True,'contract':FACTORY}
            else:
                assert int(parts[parts.index('--value')+1])==0 and int(parts[parts.index('--fee')+1])==call_fee
                address=parts[parts.index('--value')+2];method=parts[parts.index('--value')+3]
                if method=='deploy_vpn':
                    assert address==FACTORY;event={'event':'VPNDeployed','values':[PROGRAM]}
                    receipt={'success':True,'events':[event]*(2 if case=='ambiguous_child_event' else 1)}
                else:
                    assert address==PROGRAM and method=='set_paused'
                    params=[json.loads(x) for x in parts[parts.index('--value')+4:]]
                    if params[1]==nonce:nonce+=1;receipt={'success':True}
                    elif case=='replay_accepted':receipt={'success':True}
                    else:
                        receipt={'success':False,'error':'execution reverted','events':[{'event':'Require','values':['admin nonce mismatch']}]}
                        if case=='replay_wrong_reason':receipt['events'][0]['values']=['different failure']
                        if case=='replay_wrong_error':receipt['error']='different error'
                        if case=='replay_successful_receipt':receipt['success']=True
                        if case=='replay_nonce_changed':nonce+=1
            receipts[tx]=receipt;return json.dumps({'tx_hash':tx,'address':'untrusted prediction'})
        def rpc(url,method,params):
            assert url==expected_rpc;calls.append(method)
            if method=='octra_runtimeVersion':
                if case=='wrong_live_shape':return []
                return {'chain_id':'foreign' if case=='wrong_live_chain' else target['chain_id'],
                        'runtime_profile_hash':'0'*64 if case=='wrong_live_profile' else runtime_profile,
                        'consensus_standard_hash':'0'*64 if case=='wrong_live_consensus' else consensus_standard}
            if method=='octra_balance':
                if case=='unfunded':raise RuntimeError('sender not found')
                charged=sum(int(parts[parts.index('--ou')+1]) if parts[1]=='forge' else int(parts[parts.index('--fee')+1]) for parts in paid)
                return {'balance_raw':str(1_000_000-charged-(1 if case=='fee_depletion' and len(paid)==5 else 0))}
            if method=='octra_transaction':
                index=int(params[0].removeprefix('tx'))
                if case=='unexpected_rejection_factory' and index==1 or case=='unexpected_rejection_spawn' and index==2 or case=='unexpected_rejection_pause' and index==3:return {'status':'rejected','tx_hash':params[0]}
                if index==4 and case in ['devnet_resume_after_replay','devnet_resume_tampered_journal'] and not resume_mode:raise RuntimeError('public replay still pending')
                if index==4 and case in ['replay_rejected','devnet_replay_rejected','devnet_replay_native_no_receipt','devnet_resume_after_replay','devnet_resume_tampered_journal','replay_wrong_reason','replay_wrong_error','replay_successful_receipt','replay_missing_receipt','replay_nonce_changed']:
                    reason='execution reverted [unrelated]' if case=='replay_missing_receipt' else 'execution reverted [admin nonce mismatch]'
                    return {'status':'rejected','tx_hash':params[0],'error':{'reason':reason}}
                if index==4 and case=='replay_dropped':return {'status':'dropped','tx_hash':params[0]}
                return {'status':'confirmed','tx_hash':params[0]}
            if method=='contract_receipt':
                if case in ['replay_missing_receipt','devnet_replay_native_no_receipt'] and params[0]=='tx4':raise RuntimeError('receipt unavailable')
                return receipts[params[0]]
            if method=='vm_contract':return {'code_hash':'wrong' if case=='wrong_child_code' and params[0]==PROGRAM else code_hash,'owner':FACTORY}
            if method=='contract_call':return {'result':{'get_admin_commitment':commit,'get_admin_domain':domain,'get_max_locked_value':200_000_000,'get_admin_nonce':nonce}[params[1]]}
            raise AssertionError(method)
        module.command=command;module.rpc=rpc;out=temp/'run'
        # The real offline artifact validator has dedicated native-fixture controls.
        # This suite isolates the existing financial/journal/prover ordering.
        module.local_compiler.validate_saved=lambda *args: {'checks':{'private-admin-factory.aml':{'deployment_artifact_sha256':'a'*64}},'recheck':{'before':{'runtime':{'runtime_profile_hash':runtime_profile,'consensus_standard_hash':consensus_standard}}}}
        offline=case.endswith('offline_plan');argv=['deploy-canary.py','--candidate',str(candidate),'--preflight',str(preflight)]
        if case!='devnet_requires_mode':argv+=['--network',network]
        if is_devnet and case!='missing_env':argv+=['--network-env',str(network_env)]
        if not offline:argv+=['--key','fixture.key','--credential','fixture.credential','--setup',str(setup),'--out',str(out),'--broadcast']
        if case=='fee_out_of_range':argv+=['--fee-ou','10001']
        if case=='fee_budget_exact':argv+=['--fee-ou',str(call_fee)]
        requested_deployment={'deployment_too_low':199999,'deployment_negative':-1,'deployment_exceeds_ceiling':1000001,'budget_exceeded':1000000}.get(case,deployment_ou)
        argv+=['--deployment-ou',str(requested_deployment)]
        sys.argv=argv;success=case in ['valid','devnet_valid','mainnet_offline_plan','devnet_offline_plan','fee_budget_exact','custom_deployment','replay_rejected','devnet_replay_rejected','devnet_replay_native_no_receipt']
        try:
            with contextlib.redirect_stdout(io.StringIO()) as stream:module.main()
            assert success,case
            result=json.loads(stream.getvalue())
            if offline:
                assert result['broadcast'] is False and result['escrow_deposited']==0 and not wallet and not proofs and not calls and not paid
                assert result['declared_fee_budget_ou']==deployment_ou+4*call_fee<=1_000_000
                if is_devnet:assert result['target']['origin']['kind']=='checkpoint' and 'genesis_root' not in result['target']
            else:assert result['qualified'] is True and nonce==2 and len(paid)==5
        except (ValueError,RuntimeError):
            assert not success,case
            journal_path=out/'journal.json'
            journal=json.loads(journal_path.read_text()) if journal_path.is_file() else {}
            assert journal.get('qualified') is not True
        if case in ['devnet_resume_after_replay','devnet_resume_tampered_journal']:
            journal_path=out/'journal.json';journal=json.loads(journal_path.read_text())
            assert [entry['label'] for entry in journal['submissions']]==['deploy factory','spawn VPN','private pause','replay rejection']
            assert 'receipt' not in journal['submissions'][-1] and len(paid)==4
            if case=='devnet_resume_tampered_journal':
                journal['relayer']=PROGRAM;journal_path.write_text(json.dumps(journal))
            resume_mode=True;sys.argv=argv+['--resume']
            try:
                with contextlib.redirect_stdout(io.StringIO()) as stream:module.main()
                assert case=='devnet_resume_after_replay'
                assert json.loads(stream.getvalue())['qualified'] is True and len(paid)==5 and nonce==2
            except ValueError:
                assert case=='devnet_resume_tampered_journal' and len(paid)==4
        early=cases.index(case)>=cases.index('mode_mismatch') and case not in ['wrong_credential','unknown_submission','wrong_setup_vk','fee_budget_exact','custom_deployment','replay_rejected','devnet_replay_rejected','devnet_replay_native_no_receipt','devnet_resume_after_replay','devnet_resume_tampered_journal','replay_wrong_reason','replay_wrong_error','replay_successful_receipt','replay_missing_receipt','replay_dropped','unexpected_rejection_factory','unexpected_rejection_spawn','unexpected_rejection_pause','replay_nonce_changed','fee_depletion']
        if early and case not in ['wrong_live_chain','wrong_live_profile','wrong_live_consensus','wrong_live_shape']:assert not wallet and not proofs and not calls and not paid,case
        if case in ['wrong_live_chain','wrong_live_profile','wrong_live_consensus','wrong_live_shape']:assert calls==['octra_runtimeVersion'] and not wallet and not proofs and not paid,case
        if case in ['unfunded','wrong_cap','commission_enabled','wrong_setup_vk']:assert not paid,case
        if case=='wrong_credential':assert len(proofs)==1 and not paid,case
        if case=='unknown_submission':
            journal=json.loads((out/'journal.json').read_text());assert journal['in_flight']['possible_submission'] is True and len(paid)==1
            try:module.main();raise AssertionError('existing journal must refuse resubmission')
            except ValueError:pass
            assert len(paid)==1
        if case.startswith('replay_') and case not in ['replay_accepted','replay_rejected']:
            assert len(paid)==4 and nonce in (1,2),case
        if case.startswith('unexpected_rejection_'):
            assert len(paid)=={'unexpected_rejection_factory':1,'unexpected_rejection_spawn':2,'unexpected_rejection_pause':3}[case],case
        assert len(paid)<=5;checks.append(case)

# Local compiler/profile/source/artifact controls are exercised separately by
# test-local-compiler.py against the full pinned native result fixture.
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
        args=argparse.Namespace(compiler_rpc_url=None,compiler_binding=None,out=temp/'compiled',params=params,amlc=compiler,program_version=5,network='mainnet' if mainnet else 'devnet',network_env=None if mainnet else network_env,compiler_patch=[],compiler_upstream_commit=declared)
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
class DirectEndpoint:
    def open(self,request,timeout):
        assert request.full_url=='https://devnet.octrascan.io/rpc' and timeout==20
        assert request.get_header('User-agent')=='octra-canary/1.0'
        assert json.loads(request.data)['method']=='octra_balance'
        return io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":{"balance_raw":"7"}}')
def direct_only(*handlers):
    assert len(handlers)==2
    assert isinstance(handlers[0],module.urllib.request.ProxyHandler) and handlers[0].proxies=={}
    assert isinstance(handlers[1],module._NoRedirect)
    assert handlers[1].redirect_request(None,None,302,'Found',{},'https://elsewhere.invalid/') is None
    return DirectEndpoint()
with unittest.mock.patch.object(module.urllib.request,'build_opener',direct_only):
    assert transport_rpc('https://devnet.octrascan.io/rpc','octra_balance',['oct'+'4'*44])=={'balance_raw':'7'}
checks.append('strict_direct_rpc_transport')
class RateLimitedEndpoint(DirectEndpoint):
    def __init__(self,failures):self.failures=failures;self.calls=0
    def open(self,request,timeout):
        self.calls+=1
        if self.calls<=self.failures:
            raise module.urllib.error.HTTPError(request.full_url,429,'Too Many Requests',{'Retry-After':'1'},None)
        return super().open(request,timeout)
endpoint=RateLimitedEndpoint(2)
with unittest.mock.patch.object(module.urllib.request,'build_opener',lambda *handlers:endpoint),unittest.mock.patch.object(module.time,'sleep') as sleep:
    assert transport_rpc('https://devnet.octrascan.io/rpc','octra_balance',['oct'+'4'*44])=={'balance_raw':'7'}
    assert endpoint.calls==3 and [call.args[0] for call in sleep.call_args_list]==[1,2]
checks.append('bounded_read_only_rate_limit_retry')
endpoint=RateLimitedEndpoint(6)
with unittest.mock.patch.object(module.urllib.request,'build_opener',lambda *handlers:endpoint),unittest.mock.patch.object(module.time,'sleep') as sleep:
    try:transport_rpc('https://devnet.octrascan.io/rpc','octra_balance',['oct'+'4'*44]);raise AssertionError('sixth rate limit must stop')
    except module.urllib.error.HTTPError as error:assert error.code==429
    assert endpoint.calls==6 and sleep.call_count==5
checks.append('rate_limit_exhaustion_stops')
print(json.dumps({'status':'PASS','controls':len(checks),'cases':checks,'scope':'Hermetic mocked controls only; no actual RPC/source upload/wallet/signing/compiler/proof execution or public deployment.'},indent=2))
