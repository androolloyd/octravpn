#!/usr/bin/env python3
"""Native transaction resource and preverification lane budgets."""
import argparse,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
OPS='standard encrypt decrypt private deploy program_deploy call program_exec multi_exec upgrade deploy_circle circle_program_update circle_asset_put circle_asset_put_encrypted circle_sealed_slot_put circle_slot_policy_put circle_state_descriptor_put circle_balance_cell_put circle_register_cell_put circle_transport_policy_put circle_hfhe_policy_put circle_key_policy_put circle_key_grant circle_key_extend circle_key_revoke circle_key_erase circle_outbox_open circle_relay_claim circle_relay_cancel circle_ingress_commit circle_call validator_set_update validator_ready validator_bond validator_exit validator_withdraw validator_evidence stealth claim recrypt key_switch op01_burn compute_fund compute_return compute_settle'.split()
def fixtures():
 out=[];rng=random.Random(8188);base=dict(ou='1000',length=0,minimum='5000',message=None,budget=dict(txs=1,bytes=200,ou='2000000',proof=1),used=dict(txs=0,bytes=0,ou='0',proof=0))
 for op in OPS:
  for ou in [-1,0,999,1000,999999,1000000,2000000,5000000,10000000,10000001,20000000,20000001,(1<<62)-1,1<<62,1<<130]:out.append(dict(base,op=op,ou=str(ou)))
 for op in ['program_deploy','deploy_circle','call','circle_call','circle_asset_put','circle_balance_cell_put','multi_exec','stealth']:
  for length in [1,1023,1024,1025,4096,16385]:out.append(dict(base,op=op,length=length))
 for op in ['call','circle_call','deploy_circle','program_deploy']:
  for length in [2*1024*1024,4*1024*1024]:out.append(dict(base,op=op,length=length))
 for _ in range(120):
  used=dict(txs=rng.choice([0,1,100,-1,(1<<62)-1]),bytes=rng.choice([0,1,199,200,201,(1<<62)-1]),ou=str(rng.choice([0,1,999,2000000,10000000])),proof=rng.choice([0,1,16,32,64,(1<<62)-1]))
  budget=dict(txs=rng.choice([0,1,128,2048]),bytes=rng.choice([0,100,200,4194304]),ou=str(rng.choice([0,1,1000,10000000])),proof=rng.choice([0,1,32,64]))
  out.append(dict(base,op=rng.choice(OPS),ou=str(rng.choice([1000,10000,1000000])),used=used,budget=budget,minimum=str(rng.choice([1,5000,10000000000])),message=rng.choice([None,'[]','{"calls":[]}','{"calls":[1,2,3]}','bad'])))
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/resource-lanes-oracle.ml',fixtures(),'octra_core yojson')
 report['scope']='Native resource lanes, all operations, exact serialized byte cost, declared/execution OU, queue activation, budgets and int63 counter rollover'
 a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native resource cases: {a.out}")
if __name__=='__main__':main()
