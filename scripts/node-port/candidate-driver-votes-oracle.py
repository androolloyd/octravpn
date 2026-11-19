#!/usr/bin/env python3
"""Replay historical vote-journal inputs with exact c49 driver declaration slices.

The fixture record projects only fields read by the selected native functions;
network/bootstrap/create orchestration is outside this oracle's scope. Every
native function body, journal, signature, engine and value-log module is original.
"""
import argparse, hashlib, importlib.util, json, os, re, shutil, subprocess
from pathlib import Path
PIN='8f785a93a4e7392a0f3e65674f9de89854d33dbc'
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def sha(data): return hashlib.sha256(data).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ['upstream','out','fixture','ocaml-bin']: p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True);out=a.out.resolve()
 hashes={}; extraction={}
 def read(path):
  data=subprocess.check_output(['git','-C',str(a.upstream),'show',f'{PIN}:{path}']);hashes[path]=sha(data);return data.decode()
 spec=importlib.util.spec_from_file_location('engine',HERE/'consensus-engine-fixtures.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
 sources=base.SOURCES+['lib/consensus/c_measure.ml','logging/octra_log_format.ml','lib/consensus/c_vote_log.ml','lib/consensus/c_value_log.ml']
 for path in sources: (out/Path(path).name).write_text(read(path))
 driver=read('lib/consensus/c_driver.ml')
 def decl(name):
  m=re.search(r'^let '+re.escape(name)+r'\b',driver,re.M);assert m,name
  end=re.search(r'^(?:let|type|module) ',driver[m.end():],re.M)
  stop=m.end()+end.start() if end else len(driver)
  text=driver[m.start():stop];extraction[name]={'start_line':driver[:m.start()].count('\n')+1,'end_line':driver[:stop].count('\n'),'sha256':sha(text.encode())};return text
 names=['raw_to_hex','log_node','warn_node','error_node','vote_step_label','local_validator','vote_floor_bootstrap','vote_allowed','vote_log_bootstrap_pending','vote_key','hold_vote_fault','clear_vote_fault','proposal_binds_vote','keep_polc_votes','keep_polc','persist_precommit','hold_vote_log','vote_floor_wait','vote_log_reason','vote_state','resume_local_vote','restored_vote','restore_votes','require_vote_floor','prepare_vote_log','saved_vote']
 harness='''(* Projected fixture records; implementation declarations below are native. *)
type config = {chain_id:string; my_addr:string; role_can_vote:unit->bool; can_vote:unit->bool;
 before_precommit_broadcast:epoch_id:int64->round:int->proposal_id:string->proposed_state_root:string->txid_hi:int64->proposal_wire:string->vote_wire:string->bool Lwt.t;}
type vote_fault={epoch_id:int64;round:int;reason:string}
type t={policy:C_quorum_policy.t;config:config;engine:C_engine.t;mutable running:bool;
 vote_log:C_vote_log.t;mutable saved_value:(C_types.validator_set*C_types.propose) option;
 mutable vote_log_issue:string option;mutable vote_fault:vote_fault option;
 durable_votes:(string,C_types.vote) Hashtbl.t;pending_polc:(int64*int,int) Hashtbl.t;
 mutable proof_lock:(int64*int) option;mutable saved_polc:C_vote_log.polc_receipt option;
 finality_proof_needed:bool ref;}
let create_fixture ~config ~validator_set ~start_height ~vote_log =
 let policy=C_quorum_policy.for_chain config.chain_id in
 let finality_proof_needed=ref false in
 let can_vote ()=config.can_vote () && not !finality_proof_needed in
 let validator_set=C_types.validator_set_for_epoch ~policy ~chain_id:config.chain_id ~epoch_id:start_height validator_set in
 let engine=C_engine.create_for_policy policy ~chain_id:config.chain_id ~my_addr:config.my_addr ~validator_set ~start_height ~can_vote in
 {policy;config;engine;running=false;vote_log;saved_value=None;vote_log_issue=None;vote_fault=None;
 durable_votes=Hashtbl.create 32;pending_polc=Hashtbl.create 16;proof_lock=None;saved_polc=None;finality_proof_needed}
'''
 body=harness+'\n'.join(decl(name) for name in names);(out/'c_driver.ml').write_text(body)
 wrapper=(HERE/'driver-votes-oracle.ml').read_text()
 start=wrapper.index(' let swarm=');end=wrapper.index(' before_precommit_broadcast=',start)
 wrapper=wrapper[:start]+''' let config=D.{chain_id=chain;my_addr=local;role_can_vote=(fun()-> !role);can_vote=(fun()-> !ready);
'''+wrapper[end:]
 start=wrapper.index(' lookup_epoch_root=');end=wrapper.index(' `List(member"steps"',start)
 wrapper=wrapper[:start]+''' }in
 let driver=D.create_fixture ~config ~validator_set:validators ~start_height:(i j"height") ~vote_log:(C_vote_log.disk ~data_dir:dir)in
'''+wrapper[end:]
 # The shortened record still has a semicolon preceding its closing brace.
 wrapper=wrapper.replace('let run j=','let run j=\n let chain=if member\"chain\"j=`Null then chain else raw j\"chain\"in')
 (out/'oracle.ml').write_text(wrapper)
 modules=['C_types','C_quorum_policy','C_protocol','C_config','C_codec','Epoch_time','C_epoch_time_policy','C_reward_source','C_hash','C_qc','C_engine','C_vote_log','C_value_log','C_driver']
 (out/'octra_net.ml').write_text('module Oce1=Oce1\nmodule Hash_domain=Hash_domain\n')
 (out/'octra_consensus.ml').write_text('\n'.join('module '+m+'='+m for m in modules)+'\n')
 env=os.environ.copy();env['PATH']=str(a.ocaml_bin)+os.pathsep+env['PATH']
 order=['oce1','hash_domain','octra_net','octra_log_format','octra_log','octra_ed25519','c_protocol','epoch_time','c_epoch_time_policy','c_quorum_policy','c_measure','c_types','c_reward_source','c_codec','c_config','c_hash','c_qc','c_engine','c_vote_log','c_value_log','c_driver','octra_consensus','oracle']
 command=[shutil.which('ocamlfind',path=env['PATH']),'ocamlopt','-thread','-package','digestif.c,zarith,yojson,base64,unix,mirage-crypto-ec,lwt.unix','-linkpkg',*[m+'.ml' for m in order],'-o','oracle']
 r=subprocess.run(command,cwd=out,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(out/'build.log').write_text(r.stdout)
 if r.returncode: raise SystemExit(f'native build failed: {out / "build.log"}')
 historical=(ROOT/'crates/octra-node-runtime/tests/fixtures/driver-votes.json').read_bytes();cases=[c['input'] for c in json.loads(historical)['cases']]
 original_count=len(cases)
 for height in [1,2]:
  for epoch in [0,1,2,3]:
   for kind in [1,2]:
    vote=dict(chain=b'vote-guard-fixture'.hex(),epoch=str(epoch),round=0,type=kind,pid='bound',signer=1,corrupt=False,proposal='present')
    cases.append(dict(local=1,height=str(height),steps=[dict(op='floor',epoch=str(height-1)),dict(op='prepare',wires=[],restore_error=None),dict(op='save',vote=vote,persist=True)]))
 for height in [1737332,1737333,1739999,1740000]:
  chain=b'octra-devnet-9871-cluster'.hex()
  vote=dict(chain=chain,epoch=str(height),round=0,type=2,pid='bound',signer=1,corrupt=False,proposal='present')
  cases.append(dict(chain=chain,local=1,height=str(height),steps=[dict(op='floor',epoch=str(height-1)),dict(op='prepare',wires=[],restore_error=None),dict(op='save',vote=vote,persist=True)]))
 r=subprocess.run([str(out/'oracle')],input=json.dumps(cases),env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120);(out/'run.log').write_text(r.stderr);r.check_returncode()
 (out/'stdout.log').write_text(r.stdout)
 traces=json.loads(r.stdout.splitlines()[-1])
 report={'upstream_commit':PIN,'source_sha256':hashes,'extraction':extraction,'compiled_driver_sha256':sha(body.encode()),'fixture_record_sha256':sha(harness.encode()),'compiled_oracle_sha256':sha(wrapper.encode()),'oracle_sha256':sha((HERE/'driver-votes-oracle.ml').read_bytes()),'runner_sha256':sha(Path(__file__).read_bytes()),'historical_fixture_sha256':sha(historical),'historical_case_count':original_count,'compiler_version':subprocess.check_output([str(a.ocaml_bin/'ocamlopt'),'-version'],text=True).strip(),'build_command':command,'scope':__doc__,'cases':traces}
 a.fixture.write_text(json.dumps(report,separators=(',',':'))+'\n');print(json.dumps({'cases':len(traces),'transitions':sum(len(c['expected']) for c in traces),'fixture':str(a.fixture)}))
if __name__=='__main__':main()
