#!/usr/bin/env python3
"""Native c49 intake/queue replay with explicit inactive I/O boundary adapters.

Original native admission, signatures, payload checks, fee/duty rules, queue and
ledger lookup declarations execute unchanged. Persistent-store misses are empty;
network/websocket notifications are inactive. Encrypted VM/HFHE payload branches
outside the historical inputs fail fast rather than returning simulated results.
"""
import argparse, hashlib, json, os, re, subprocess
from pathlib import Path
PIN='c49de45cf49ebbc2e5c0697eb956cbcada5845e7';ROOT=Path(__file__).resolve().parents[2]
def sha(data):return hashlib.sha256(data).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ['upstream','out','fixture','ocaml-bin']:p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True);out=a.out.resolve();hashes={};extracts={};generated={}
 paths=subprocess.check_output(['git','-C',str(a.upstream),'ls-tree','-r','--name-only',PIN],text=True).splitlines()
 def path(name):return next(p for p in paths if p.endswith('/'+name+'.ml'))
 def read(name):
  p=path(name);raw=subprocess.check_output(['git','-C',str(a.upstream),'show',f'{PIN}:{p}']);hashes[p]=sha(raw);return raw.decode()
 def part(name,start,end):
  text=read(name);i=text.index(start);j=text.index(end,i);value=text[i:j];extracts.setdefault(path(name),[]).append({'start_line':text[:i].count('\n')+1,'end_line':text[:j].count('\n'),'sha256':sha(value.encode())});return value
 def decl(name,kind,label):
  text=read(name);m=re.search(r'^'+kind+' '+re.escape(label)+r'\b',text,re.M);assert m,(name,label);end=re.search(r'^(?:let|type|module) ',text[m.end():],re.M);j=m.end()+end.start()if end else len(text);value=text[m.start():j];extracts.setdefault(path(name),[]).append({'start_line':text[:m.start()].count('\n')+1,'end_line':text[:j].count('\n'),'sha256':sha(value.encode())});return value
 def put(name,text):generated[name]=text;(out/(name+'.ml')).write_text(text)
 whole=['oce1','hash_domain','octra_ed25519','octra_log_format','octra_log','c_protocol','epoch_time','c_epoch_time_policy','c_quorum_policy','c_types','c_reward_source','c_codec','c_config','c_hash','c_qc','c_parent_commit','c_evidence','c_role','rule_graph','json_tree','transaction','tx_signature','tx_envelope','tx_outcome','tx_payload','resource_lanes','validator_entry','validator_participation','validator_policy','validator_evidence','validator_registry','validator_set_update','validator_ready_policy','set_fold','bft_control_check','drop_record','ledger_types','tx_sender_key','consensus_mode','env']
 for name in whole:put(name,read(name))
 put('c_catchup',decl('c_catchup','let','range_epochs'))
 cons=[n for n in whole if n.startswith('c_')or n in ['epoch_time']]+['c_catchup']
 put('octra_consensus','\n'.join('module '+n.capitalize()+'='+n.capitalize()for n in cons)+'\n')
 net='''module Oce1=Oce1
module Hash_domain=Hash_domain
module P2p_frame=struct type frame={msg_type:int;payload:string} let msg_tx_gossip=0 end
module P2p_swarm=struct type t=unit let peer_count _=failwith "fixture has no swarm" let broadcast _ _=failwith "fixture has no swarm" end
'''
 # Real gossip codec is used for payload construction even though transport is inactive.
 put('p2p_tx_gossip',read('p2p_tx_gossip'));net+='module P2p_tx_gossip=P2p_tx_gossip\n';put('octra_net',net)
 put('crypto',part('crypto','let z_to_yojson','module WalletKey'))
 put('compute_bill',''.join(decl('compute_bill','let',n)for n in ['max_wire','max_fuel','model_limit','encode_request','decode_request','fee']))
 put('tx_drop',part('tx_drop','type row =','type t ='))
 historical=(ROOT/'crates/octra-node-runtime/tests/fixtures/staging-intake.json').read_bytes();old=json.loads(historical)
 clock=old['instrumentation']['lib/core/tx_staging.ml']['prefix'];put('tx_staging',clock+read('tx_staging'))
 put('store_irmin','type t=unit\nlet get_account _ _ = Lwt.return_none\nlet open_store _ = Lwt.return_unit\nlet close _ = Lwt.return_unit\n')
 put('ledger',part('ledger','type account =','type epoch_journal =')+'''type t={cache:(string,account)Hashtbl.t;store:Store_irmin.t}
let create store={cache=Hashtbl.create 32;store}
let run_s=Lwt_main.run
'''+decl('ledger','let','empty_account')+decl('ledger','let','get_account_internal')+''.join(decl('ledger','let',n)for n in ['mem','find','find_opt']))
 core=['rule_graph','crypto','transaction','tx_signature','tx_envelope','tx_payload','json_tree','resource_lanes','validator_registry','tx_staging','store_irmin','ledger','tx_drop']
 put('octra_core','\n'.join('module '+n.capitalize()+'='+n.capitalize()for n in core)+'\n')
 txview='''module Address=Octra_core.Crypto.Address
module Transaction=Octra_core.Transaction
module Staging=Octra_core.Tx_staging
module Crypto=Octra_core.Crypto
module Program_package=struct let validate_base64 _=failwith "fixture reached VM encrypted payload validation" end
let encrypt_decrypt_payload_ok _=failwith "fixture reached HFHE encrypted payload validation"
let stealth_payload_ok _=failwith "fixture reached HFHE stealth payload validation"
let claim_payload_ok _=failwith "fixture reached HFHE claim payload validation"
let key_switch_payload_ok _=failwith "fixture reached HFHE key validation"
'''
 names=['requires_heavy_preverify','intake_fee_check','low_fee_heavy_hashes','semantic_check','staging_submit_check','duty_nonce_check']
 txview+=''.join(decl('tx_view','let',n)for n in names)+decl('tx_view','type','staging_submit_effects')
 names=['staging_submit_effects','address_route_check','self_route_check','staging_error','semantic_error_reason','has_html','call_params_message_ok','call_params_ok','encrypted_payload_ok']
 txview+=''.join(decl('tx_view','let',n)for n in names)+decl('tx_view','type','payload_limits')
 names=['payload_limits','circle_asset_body_too_large','payload_size_check','payload_check','bft_op_check','duty_retry','pre_route_check','submission_pubkey','signature_check','sender_check','submit_pre_signature_check','encrypted_data_missing_or_empty','post_signature_check','submit_signature_check']
 txview+=''.join(decl('tx_view','let',n)for n in names);put('tx_view',txview)
 put('preverify_cache','let remove _=()\nlet has_capacity ()=true\nlet pending_count ()=0\nlet pending_max ()=6\n')
 put('rest_read_rpc','module Transaction=Transaction\n'+decl('rest_read_rpc','let','stealth_floor'))
 put('text',decl('text','let','prefix_or_unknown')+decl('text','let','hash_short'))
 put('log','module Log=Octra_log\ninclude Log\n')
 facade=old['instrumentation']['node_runtime/node_rest_facade.ml']['prefix']+'''module Ledger=Octra_core.Ledger
module Transaction=Octra_core.Transaction
module Staging=Octra_core.Tx_staging
module WSServer=struct let notify_staging_update ~total_txs:_ ~total_ou:_ ~max_ou:_=() let notify_new_tx _=() end
'''+decl('node_rest_facade','type','runtime')
 names=['cli_has_flag','notify_staging_update','sweep_low_fee_stealth','expire_duty','prepare_tx','add_tx_to_staging','max_timestamp_drift','consensus_mode_flags','bft_mode','observer_rejects_submissions','bft_pending_nonce_window','validate_and_submit_tx']
 facade+=''.join(decl('node_rest_facade','let',n)for n in names);put('node_rest_facade',facade)
 put('octra_node_runtime','module Node_rest_facade=Node_rest_facade\nmodule Tx_view=Tx_view\n')
 wrapper=(ROOT/'scripts/node-port/staging-intake-oracle.ml').read_text().replace('let runtime:R.runtime={swarm_ref=','let runtime:R.runtime={signing=(fun()->C.Tx_signature.Historical);marks_mode=(fun()->C.Rule_graph.Prior);swarm_ref=')
 put('oracle',wrapper)
 env=os.environ.copy();env['PATH']=str(a.ocaml_bin)+os.pathsep+env['PATH']
 # Discover transitive source order. Only the explicitly exported native modules
 # and boundary adapters can satisfy dependencies; unresolved modules fail build.
 dep=subprocess.check_output([str(a.ocaml_bin/'ocamldep'),'-modules',*[n+'.ml'for n in generated]],cwd=out,env=env,text=True)
 bymod={n.capitalize():n for n in generated};deps={}
 for line in dep.splitlines():
  name,mods=line.split(':',1);deps[Path(name).stem]=[bymod[m]for m in mods.split()if m in bymod]
 order=[];seen=set();active=set()
 def visit(n):
  if n in seen:return
  if n in active:raise RuntimeError('dependency cycle '+n)
  active.add(n)
  for d in deps[n]:visit(d)
  active.remove(n);seen.add(n);order.append(n)
 visit('oracle')
 cmd=[str(a.ocaml_bin/'ocamlfind'),'ocamlopt','-thread','-package','digestif.c,zarith,yojson,base64,unix,mirage-crypto-ec,lwt.unix','-linkpkg',*[n+'.ml'for n in order],'-o','oracle']
 r=subprocess.run(cmd,cwd=out,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(out/'build.log').write_text(r.stdout)
 if r.returncode:raise SystemExit(f'native build failed: {out/"build.log"}')
 cases=[c['input']for c in old['cases']]
 r=subprocess.run([str(out/'oracle')],input=json.dumps(cases),env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120);(out/'run.log').write_text(r.stderr);(out/'stdout.log').write_text(r.stdout);r.check_returncode()
 result={'upstream_commit':PIN,'source_sha256':hashes,'extraction':extracts,'compiled_sha256':{n+'.ml':sha(t.encode())for n,t in generated.items()},'runner_sha256':sha(Path(__file__).read_bytes()),'oracle_sha256':sha((ROOT/'scripts/node-port/staging-intake-oracle.ml').read_bytes()),'historical_fixture_sha256':sha(historical),'historical_instrumentation':old['instrumentation'],'build_command':cmd,'scope':__doc__,'cases':json.loads(r.stdout.splitlines()[-1])}
 a.fixture.write_text(json.dumps(result,separators=(',',':'))+'\n');print(json.dumps({'cases':len(cases),'steps':sum(len(c['expected']['traces'])for c in result['cases']),'fixture':str(a.fixture)}))
if __name__=='__main__':main()
