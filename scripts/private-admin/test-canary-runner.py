#!/usr/bin/env python3
"""Hermetic runner controls, not a replacement for native/public proof execution."""
import base64,contextlib,hashlib,importlib.util,io,json,pathlib,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('canary',ROOT/'scripts/ceremony/deploy-canary.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
FACTORY='oct'+'2'*44;PROGRAM='oct'+'3'*44;RELAYER='oct'+'4'*44
commit='a'*64;domain='b'*64;vk=base64.b64encode(b'OG16V1'+b'\0\0\0\6'+bytes(896)).decode()
code=b'OCTBfixture';code_hash=hashlib.sha256(code).hexdigest();key_hash='c'*64
checks=[]
with tempfile.TemporaryDirectory(prefix='octra-canary-controls-') as raw:
    temp=pathlib.Path(raw);candidate=temp/'candidate';preflight=temp/'preflight';setup=temp/'setup'
    for folder in [candidate,preflight,setup]:folder.mkdir()
    values=[1_000_000,1_000_000,100_000_000,100,1000,commit,vk,domain,200_000_000]
    intent={'target':{'rpc_url':module.RPC},'constructor_args':values,'economics':{'vpn_protocol_fee_bps':0}}
    (candidate/'intent.json').write_text(json.dumps(intent))
    for name in ['main-v5.aml','private-admin-factory.aml']:
        source=b'contract Fixture { const PROTOCOL_FEE_DEFAULT_BPS: uint = 0\n require(new_protocol_fee_bps == 0, "protocol fee disabled") }';(candidate/name).write_bytes(source)
        (preflight/(name+'.compile.json')).write_text(json.dumps({'result':{'bytecode':base64.b64encode(code).decode(),'disasm':'JDEST 100\n','verification':{'errors':0},'certificate':{'source_hash':hashlib.sha256(source).hexdigest(),'bytecode_hash':code_hash}}}))
    (setup/'manifest.json').write_text(json.dumps({'verification_key_b64':vk,'verification_key_sha256':key_hash,'development_only':True}))
    for case in ['valid','unfunded','wrong_child_code','ambiguous_child_event','replay_accepted','wrong_cap','commission_enabled']:
        nonce=0;paid=[];receipts={}
        values[-1]=0 if case=='wrong_cap' else 200_000_000
        intent['economics']['vpn_protocol_fee_bps']=50 if case=='commission_enabled' else 0
        (candidate/'intent.json').write_text(json.dumps(intent))
        def command(parts):
            global nonce
            parts=[str(x) for x in parts]
            if parts[0]=='python3': return 'Candidate integrity: PASS'
            if parts[1:4]==['cast','wallet','addr']: return RELAYER
            if parts[1]=='authorize':
                output=pathlib.Path(parts[parts.index('--out')+1]);n=int(parts[parts.index('--nonce')+1])
                request=json.loads(pathlib.Path(parts[parts.index('--request')+1]).read_text())
                output.write_text(json.dumps({'method':'set_paused','params':[request['params'][0],n,'tag','proof'],'commitment':commit,'verification_key_sha256':key_hash}))
                return 'Authorization created'
            assert parts[1:3] in [['forge','create'],['cast','send']],parts
            paid.append(parts);tx='tx'+str(len(paid))
            assert '--key' in parts and '--rpc-url' in parts
            if parts[1]=='forge':
                assert '--no-wait' in parts and int(parts[parts.index('--ou')+1])==1000
                receipt={'success':True,'contract':FACTORY}
            else:
                assert int(parts[parts.index('--value')+1])==0
                assert int(parts[parts.index('--fee')+1])==1000
                address=parts[parts.index('--value')+2];method=parts[parts.index('--value')+3]
                if method=='deploy_vpn':
                    assert address==FACTORY
                    event={'event':'VPNDeployed','values':[PROGRAM]}
                    receipt={'success':True,'events':[event]* (2 if case=='ambiguous_child_event' else 1)}
                else:
                    assert address==PROGRAM and method=='set_paused'
                    params=[json.loads(x) for x in parts[parts.index('--value')+4:]]
                    if params[1]==nonce:nonce+=1;receipt={'success':True}
                    elif case=='replay_accepted':receipt={'success':True}
                    else:receipt={'success':False,'events':[{'event':'Require','values':['admin nonce mismatch']}]}
            receipts[tx]=receipt
            return json.dumps({'tx_hash':tx,'address':'untrusted prediction'})
        def rpc(method,params):
            if method=='octra_balance':
                if case=='unfunded': raise RuntimeError('sender not found')
                return {'balance_raw':str(20_000-1000*len(paid))}
            if method=='octra_transaction':return {'status':'confirmed'}
            if method=='contract_receipt':return receipts[params[0]]
            if method=='vm_contract':return {'code_hash':'wrong' if case=='wrong_child_code' and params[0]==PROGRAM else code_hash,'owner':FACTORY}
            if method=='contract_call':
                fields={'get_admin_commitment':commit,'get_admin_domain':domain,'get_max_locked_value':200_000_000,'get_admin_nonce':nonce}
                return {'result':fields[params[1]]}
            raise AssertionError(method)
        module.command=command;module.rpc=rpc
        out=temp/('run-'+case)
        sys.argv=['deploy-canary.py','--candidate',str(candidate),'--preflight',str(preflight),'--key','fixture.key','--credential','fixture.credential','--setup',str(setup),'--out',str(out),'--broadcast']
        try:
            with contextlib.redirect_stdout(io.StringIO()) as stream:module.main()
            assert case=='valid',case
            assert json.loads(stream.getvalue())['qualified'] is True and nonce==2 and len(paid)==5
        except (ValueError,RuntimeError):
            assert case!='valid',case
            journal=json.loads((out/'journal.json').read_text()) if out.exists() else {}
            assert journal.get('qualified') is not True
        if case in ['unfunded','wrong_cap','commission_enabled']:assert not paid
        assert len(paid)<=5
        checks.append(case)
print('PASS: seven canary runner controls; zero commission, bounded fees, zero attached value, failed qualification never reports ready')
