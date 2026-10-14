#!/usr/bin/env python3
"""Native validator-control parsing and admission differential vectors."""
import argparse,base64,hashlib,importlib.util,json,pathlib,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2];enc=lambda v:base64.b64encode(v).decode()
def cases():
    spec=importlib.util.spec_from_file_location('state',ROOT/'scripts/node-port/transaction-state-fixtures.py');state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
    raw=lambda value:json.dumps(value,separators=(',',':')).encode();result=[]
    nums=['','+','-','-+1','-+0','-+0x1','0x','1_','_1','0u18446744073709551615','0U10','0xffffffffffffffff','0x7fffffffffffffff','0x8000000000000000','-0xffffffffffffffff','18446744073709551615','-9223372036854775808','9223372036854775808','4611686018427387904','-4611686018427387904','-0x8000000000000000','+0xffffffffffffffff','0b10','0o10',' 1','1\0']
    for op in ['int64','int63']:result +=[dict(operation=op,message=enc(v.encode()))for v in nums]
    entry={'address':state.ADDR.decode(),'pubkey':state.PUB.decode()};update={'activate_epoch':'100','validators':[entry]};weighted=update|{'weighted':True,'source_epoch':'2','standard':'bonded_stake','validators':[entry|{'weight':'15'}]}
    updates=[update,weighted,{},None,[],update|{'validators':[]},weighted|{'source_epoch':'100'},weighted|{'standard':'wrong'},update|{'source_epoch':None},update|{'standard':'bonded_stake'},update|{'weighted':None},update|{'fingerprint':3},update|{'fingerprint':'x'},update|{'validators':[entry,entry]}]
    for name in ['activate_epoch','source_epoch','weighted','standard','validators']:
        updates.append({k:v for k,v in weighted.items()if k!=name})
    for value in [0,1,-1,'','0x1','-+0','-+1','_1','1_','not a number',None,{},True]:
        updates.append(weighted|{'validators':[entry|{'weight':value}]})
    for name in ['address','pubkey','weight']:
        for value in ['',None,'invalid',state.ADDR.decode(),state.PUB.decode()]:updates.append(weighted|{'validators':[entry|{'weight':'5',name:value}]})
    for value in nums:updates.append(update|{'activate_epoch':value});updates.append(weighted|{'source_epoch':value})
    legacy={'fingerprint':'f'*64,'head_epoch':'1','state_root':'a'*64};bonded={'consensus_pubkey':'key','head_epoch':'1','state_root':'root'};readies=[legacy,bonded,legacy|bonded]
    for base in [legacy,bonded]:
        for name in list(base)+['chain_id','binary_hash','config_hash','catchup_head_epoch','shadow_epochs','head_proposal_id']:
            for value in [None,'','x','a'*64,'A'*64,'f'*128,0,-1,'-1','0x7fffffffffffffff','0xffffffffffffffff',[],True]:readies.append(base|{name:value})
        for value in nums:readies.append(base|{'head_epoch':value})
    for value in updates:result.append(dict(operation='update',message=enc(raw(value))))
    for value in readies:
        for op in ['legacy_ready','bonded_ready']:result.append(dict(operation=op,message=enc(raw(value))))
    for value in [None,{},[],{'consensus_pubkey':'','proof':''},{'consensus_pubkey':3,'proof':''},{'consensus_pubkey':'key','proof':'proof','unused':7}]:result.append(dict(operation='bond',message=enc(raw(value))))
    for op in ['update','legacy_ready','bonded_ready','bond','evidence']:
        result.append(dict(operation=op,message=None))
        for value in [b'',b'{',b'null',b'[]',b'{}',b'{evidence:"AA=="}',b'{"evidence":"AB=="}',b'{"evidence":"bad"}',b'{"evidence":"","extra":0}',b'x'*8193]:result.append(dict(operation=op,message=enc(value),compare_error=False))
    for case in list(result):
        name={'update':'validator_set_update','legacy_ready':'validator_ready','bonded_ready':'validator_ready','bond':'validator_bond','evidence':'validator_evidence'}.get(case['operation'])
        if name:result.append(case|{'operation':'admit','op_type':name})
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    if subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()!=pin or a.out.exists():raise SystemExit('require pristine pin and fresh output')
    sources=['lib/core/validator_set_update.ml','lib/core/validator_registry.ml','lib/core/validator_evidence.ml','lib/core/bft_control_admission.ml','lib/core/validator_policy.ml'];hashes={};inputs=cases()
    with tempfile.TemporaryDirectory(prefix='octra-control-oracle-')as temp:
        f=pathlib.Path(temp);(f/'cases.json').write_text(json.dumps(inputs));checks=[]
        for i,path in enumerate(sources):
            source=subprocess.check_output(['git','-C',str(a.upstream),'show',f'HEAD:{path}']);assert source==(a.upstream/path).read_bytes();hashes[path]=hashlib.sha256(source).hexdigest();(f/f'source-{i}').write_bytes(source);checks.append(f'cmp {path} /fixture/source-{i}')
        shutil.copyfile(ROOT/'scripts/node-port/control-payload-oracle.ml',f/'main.ml');(f/'dune').write_text('(executable (name main) (libraries octra_core octra_consensus yojson base64))\n')
        command=' && '.join(checks+['mkdir vpn_control_oracle','cp /fixture/main.ml /fixture/dune vpn_control_oracle/','opam exec -- dune exec ./vpn_control_oracle/main.exe -- /fixture/cases.json'])
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={f},target=/fixture,readonly',a.builder_image,'bash','-lc',command],text=True)
    payload=next(line.removeprefix('ORACLE_RESULT=')for line in output.splitlines()if line.startswith('ORACLE_RESULT='));a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(dict(upstream_commit=pin,sources=hashes,oracle='native validator-control payloads in isolated builder',cases=json.loads(payload)),indent=2)+'\n');print(f'Generated {len(inputs)} native cases: {a.out}')
if __name__=='__main__':main()
