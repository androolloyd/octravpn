#!/usr/bin/env python3
"""Qualify native submission admission, profiles, fees and program wire decoding."""
import argparse,base64,copy,hashlib,importlib.util,json,pathlib,random,shutil,struct,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('transactions',ROOT/'scripts/node-port/transaction-state-fixtures.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
enc=old.enc
bits=lambda f:struct.pack('>d',f).hex()
def context(**changes):
 value=dict(release=None,crypto=None,ops=None,stealth_min=None,now_bits='41d954fc40000000',drift_bits=bits(300.),observer=False,bft=False,head=None,active=False,confirmed='0',window='32',capacity=True,pending='0',pending_max='16',sender_exists=True,account_key=None,relay_fee='1000',encrypted_limit='50000000',message_limit='256',zkp_limit='50000',validator_limit='16384',program_limit='10000000');value.update(changes);return value
def case(tx=None,**cfg):return dict(kind='transaction',tx=tx or old.tx(),context=context(**cfg),seed=None)
def package(main=b'main.aml',sources=None,envelope=None,version=1,profile=1):
 if sources is None:sources=[(main,b'fn main() {}')]
 if envelope is None:envelope=b'OCPG'+struct.pack('<HHII',2,0,0,0)
 raw=b'OCPS'+struct.pack('<HHH',version,profile,len(main))+main+struct.pack('<H',len(sources))
 for path,body in sources:raw+=struct.pack('<H',len(path))+path+struct.pack('<I',len(body))+body
 return raw+struct.pack('<I',len(envelope))+envelope

def cases():
 result=[];ops=list(dict.fromkeys(c['input']['op_type']for c in json.loads((ROOT/'crates/octra-node-protocol/tests/fixtures/transaction-state.json').read_text())['cases']if c['input']['operation']=='transaction'))
 profiles=[{},dict(bft=True),dict(bft=True,release=enc(b'devnet_private_v1')),dict(bft=True,release=enc(b'devnet_full_v1')),dict(bft=True,crypto=enc(b'private_v1')),dict(bft=True,ops=enc(b'circle_noncall, circle_call, standard,stealth')),dict(bft=True,ops=enc(b' deploy_circle\v,circle_call'))]
 for op in ops:
  for profile in profiles:
   for amount in ['-1','0','1']:
    value=case(old.tx(op_type=op,amount=amount,ou='1000'),**profile);result.append(value)
  for ou in ['-1','0','999','10000000']:
   result.append(case(old.tx(op_type=op,ou=ou,amount='0'),sender_exists=False))
 for alias in [None,b'',b'bad',old.PUB,base64.b64encode(bytes(32))]:
  value=case();value['seed']=enc(old.SEED);value['context']['account_key']=None if alias is None else enc(alias);result.append(value)
 for sender in [b'',b'oct'+b'0'*44,old.ADDR]:
  for receiver in [sender,b'',b'stealth',b'multi_exec',b'oct'+b'1'*44]:
   for op in ['standard','private','encrypt','decrypt','claim','stealth','recrypt','key_switch','op01_burn','multi_exec']:
    result.append(case(old.tx(**{'from':enc(sender),'to':enc(receiver)},op_type=op,amount='0')))
 for stamp in [0.,1700000000.,1700000300.,1700000300.5,1700000301.5,float('inf'),float('-inf'),float('nan')]:
  for observer in [False,True]:result.append(case(old.tx(timestamp_bits=bits(stamp)),observer=observer))
 for name in ['message','encrypted_data']:
  for size in [0,1,255,256,257,8192,8193,16384,16385]:
   for op in ['standard','circle_asset_put','validator_ready','compute_return','compute_fund','program_deploy']:
    result.append(case(old.tx(op_type=op,**{name:enc(b'x'*size)})))
 for raw in [b'[]',b'["<html>"]',b'["<1>"]',b'["</"]',b'["<!"]',b'[["<x>"]]',b'{"calls":["<html>"]}',b'["\xff<x>"]',b'bad',b'[1,2,3]',b'{"calls":[]}',b'{"calls":[1,2]}']:
  for op in ['call','multi_exec','deploy','circle_call','standard']:result.append(case(old.tx(op_type=op,message=enc(raw))))
 for minimum in [b'-+1',b'0',b'1',b'10000000000',b'10000000001',b'bad',b'0x1388']:
  result.append(case(old.tx(op_type='stealth',amount='0',ou='3'),stealth_min=enc(minimum)))
 for confirmed in [str(-(1<<62)),str((1<<62)-1),'0','32']:
  for window in ['-1','0','32',str((1<<62)-1)]:
   result.append(case(old.tx(nonce='1',op_type='stealth',encrypted_data=enc(b'{}')),bft=True,confirmed=confirmed,window=window,capacity=False))
 for head in [-1,0,1,16,18,20,(1<<63)-1]:
  for reference in [-1,0,1,16,18,20,(1<<63)-1]:
   for active in [False,True]:
    payload=dict(head_epoch=str(reference),head_proposal_id='a'*64,consensus_pubkey='',state_root='')
    result.append(case(old.tx(op_type='validator_ready',amount='0',timestamp_bits=bits(0.),message=enc(json.dumps(payload).encode())),bft=True,head=str(head),active=active))
 for mutation in [{'head_proposal_id':None},{'duty_vote':'bad'},{'duty_vote':1,'duty_commit':1},{'duty_vote':'','duty_commit':''}]:
  payload=dict(head_epoch='20',head_proposal_id='a'*64,consensus_pubkey='',state_root='');payload.update(mutation);result.append(case(old.tx(op_type='validator_ready',timestamp_bits=bits(0.),message=enc(json.dumps(payload).encode())),bft=True,head='20',active=True))
 raw=package();programs=[raw[:i]for i in range(len(raw))]+[raw,raw+b'x',package(version=2),package(profile=2),package(main=b'/bad'),package(main=b'foo/../bar'),package(sources=[]),package(sources=[(b'z',b''),(b'main.aml',b'')]),package(sources=[(b'other',b'')]),package(sources=[(b'main.aml',b''),(b'main.aml',b'')]),package(sources=[(b'main.aml',b'x'*65537)]),package(envelope=b'no'),package(envelope=b'OCPG'+struct.pack('<HHII',3,0,0,0))]
 for raw in programs:
  encoded=base64.b64encode(raw);result.append(dict(kind='program',raw=enc(encoded)));result.append(case(old.tx(op_type='program_deploy',encrypted_data=enc(encoded))))
 envelope=b'OCPG'+struct.pack('<HHII',2,0,4,3)+b'codecrt'
 for raw in [envelope[:i]for i in range(len(envelope))]+[envelope,envelope+b'x']+[b'OCPG'+struct.pack('<HHII',v,f,c,s)for v,f,c,s in [(3,0,0,0),(2,1,0,0),(2,0,16777217,0),(2,0,0,1048577),(3,1,0,0)]]:result.append(dict(kind='envelope',raw=enc(raw)))
 for fuel in [0,1,5000000,5000001,0x80000000]:
  for count in [0,1,64,65]:
   raw=struct.pack('>IH',fuel,count)+b''.join(struct.pack('>I',1)+b'x'for _ in range(count));result.append(dict(kind='compute',raw=enc(base64.b64encode(raw))));result.append(dict(kind='compute',raw=enc(base64.b64encode(raw[:6]))))
 for op in ['encrypt','decrypt','stealth','claim','key_switch']:
  for raw in [None,b'',b'{}',b'null',b'[]',b'{"version":5}',b'{"cipher":"bad","amount_commitment":"","zero_proof":"","blinding":""}',b'{"new_pubkey":"","aes_kat":""}']:
   result.append(case(old.tx(op_type=op,encrypted_data=None if raw is None else enc(raw))))
 cipher_cases=json.loads((ROOT/'crates/octra-hfhe/tests/fixtures/cipher-wire.json').read_text())['cases']
 proof_cases=json.loads((ROOT/'crates/octra-hfhe/tests/fixtures/proof_wire.json').read_text())['cases']
 valid_cipher=next(v['input'] for v in cipher_cases if 'bytes' in v['expected'] and v['strict'] and not v['zero_fill'])
 valid_proof=next(v['input'][12:] for v in proof_cases if 'bytes' in v['expected'])
 ct='hfhe_v1|'+enc(bytes.fromhex(valid_cipher));zp='zkzp_v2|'+enc(bytes.fromhex(valid_proof));commit=enc(bytes(32))
 for raw in [v['input'] for v in cipher_cases if not v['zero_fill']][:40]+[valid_cipher+'00','']:
  payload=dict(cipher='hfhe_v1|'+enc(bytes.fromhex(raw)),amount_commitment=commit,zero_proof=zp,blinding=commit)
  result.append(case(old.tx(op_type='encrypt',encrypted_data=enc(json.dumps(payload).encode()))))
 for raw in [v['input'][12:] for v in proof_cases][:50]+[valid_proof+'00','']:
  payload=dict(cipher=ct,amount_commitment=commit,zero_proof='zkzp_v2|'+enc(bytes.fromhex(raw)),blinding=commit)
  result.append(case(old.tx(op_type='decrypt',encrypted_data=enc(json.dumps(payload).encode()))))
 for field,values in [('claim_pub',['a'*64,'a'*63,'z'*64]),('stealth_tag',['f'*32,'f'*31]),('send_zero_proof',['',zp,'bad']),('range_proof_delta',['rp_v1|AA==','rp_v1|','rp_v1|AB==']),('enc_amount',['',42])]:
  for value in values:
   payload=dict(version=5,delta_cipher=ct,commitment=commit,range_proof_delta='rp_v1|AA==',range_proof_balance='rp_v1|AA==',eph_pub='x',stealth_tag='f'*32,enc_amount='',claim_pub='a'*64,amount_commitment=commit);payload[field]=value
   result.append(case(old.tx(op_type='stealth',encrypted_data=enc(json.dumps(payload).encode()))))
 for output in [-1,0,1]:
  payload=dict(version=5,output_id=output,claim_cipher=ct,commitment=commit,claim_secret='a'*64,zero_proof=zp)
  result.append(case(old.tx(op_type='claim',encrypted_data=enc(json.dumps(payload).encode()))))
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
 if subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()!=pin or a.out.exists():raise SystemExit('require pristine pin and fresh output')
 sources=['node_runtime/tx_view.ml','lib/core/transaction.ml','lib/core/tx_payload.ml','lib/core/bft_control_admission.ml','lib/core/compute_bill.ml','lib/core/crypto.ml','lib/core/set_fold.ml','lib/core/tx_staging.ml','lib/core/validator_ready_policy.ml','lib/core/pvac_registry.ml','lib/core/pvac_verify_policy.ml','lib/vm/wire/program_package.ml','lib/vm/wire/program_envelope.ml'];hashes={};inputs=cases()
 with tempfile.TemporaryDirectory(prefix='octra-admission-oracle-')as temp:
  f=pathlib.Path(temp);(f/'cases.json').write_text(json.dumps(inputs));checks=[]
  for i,path in enumerate(sources):
   source=subprocess.check_output(['git','-C',str(a.upstream),'show',f'HEAD:{path}']);assert source==(a.upstream/path).read_bytes();hashes[path]=hashlib.sha256(source).hexdigest();(f/f'source-{i}').write_bytes(source);checks.append(f'cmp {path} /fixture/source-{i}')
  (f/'native_package.ml').write_text('open Octra_vm\n'+(a.upstream/'lib/vm/wire/program_package.ml').read_text());shutil.copyfile(ROOT/'scripts/node-port/transaction-admission-oracle.ml',f/'main.ml');(f/'dune').write_text('(executable (name main) (libraries octra_core octra_node_runtime octra_vm yojson base64 unix))\n')
  command=' && '.join(checks+['mkdir vpn_admission_oracle','cp /fixture/main.ml /fixture/native_package.ml /fixture/dune vpn_admission_oracle/','opam exec -- dune exec ./vpn_admission_oracle/main.exe -- /fixture/cases.json'])
  output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={f},target=/fixture,readonly',a.builder_image,'bash','-lc',command],text=True)
 payload=json.loads(next(line.removeprefix('ORACLE_RESULT=')for line in output.splitlines()if line.startswith('ORACLE_RESULT=')));a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(dict(upstream_commit=pin,sources=hashes,**payload),indent=2)+'\n');print(f'Generated {len(inputs)} native cases: {a.out}')
if __name__=='__main__':main()
