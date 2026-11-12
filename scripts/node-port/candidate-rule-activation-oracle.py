#!/usr/bin/env python3
"""Current native Rule_graph + Set_rule bound context, preserving historical inputs."""
import argparse, hashlib, importlib.util, json, os, subprocess
from pathlib import Path
PIN='c49de45cf49ebbc2e5c0697eb956cbcada5845e7'
ROOT=Path(__file__).resolve().parents[2]
def sha(data):return hashlib.sha256(data).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ['upstream','out','fixture','ocaml-bin']:p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True);out=a.out.resolve();hashes={};extracts={}
 def read(path):
  data=subprocess.check_output(['git','-C',str(a.upstream),'show',f'{PIN}:{path}']);hashes[path]=sha(data);return data.decode()
 def part(path,start,end):
  text=read(path);i=text.index(start);j=text.index(end,i);value=text[i:j]
  extracts.setdefault(path,[]).append({'start_line':text[:i].count('\n')+1,'end_line':text[:j].count('\n'),'sha256':sha(value.encode())});return value
 spec=importlib.util.spec_from_file_location('engine',ROOT/'scripts/node-port/consensus-engine-fixtures.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
 for path in base.SOURCES+['logging/octra_log_format.ml','lib/core/rule_graph.ml','node_runtime/set_rule.ml']:(out/Path(path).name).write_text(read(path))
 set_fold='lib/core/set_fold.ml';epoch='lib/core/epoch_exec.ml'
 (out/'set_fold.ml').write_text('module C_types = Octra_consensus.C_types\n'+part(set_fold,'type final =','type t =')+part(set_fold,'type cap_mode =','type final_step =')+part(set_fold,'let verify_commit ~chain_id commit =','let advance ?'))
 (out/'epoch_exec.ml').write_text(part(epoch,'type fold_ctx =','let ledger_ops'))
 modules=['C_types','C_quorum_policy','C_protocol','C_config','C_codec','Epoch_time','C_epoch_time_policy','C_reward_source','C_hash','C_qc','C_engine']
 (out/'octra_net.ml').write_text('module Oce1=Oce1\nmodule Hash_domain=Hash_domain\n')
 (out/'octra_consensus.ml').write_text('\n'.join('module '+m+'='+m for m in modules)+'\n')
 (out/'octra_core.ml').write_text('module Rule_graph=Rule_graph\nmodule Set_fold=Set_fold\nmodule Epoch_exec=Epoch_exec\n')
 (out/'octra_node_runtime.ml').write_text('module Set_rule=Set_rule\n')
 wrapper=(ROOT/'scripts/node-port/rule-activation-oracle.ml').read_text()
 wrapper=wrapper.replace('R.settle_activation_for_chain chain|]','R.settle_activation_for_chain chain;R.stake_activation_for_chain chain;R.program_records_activation_for_chain chain;R.duty_marks_activation_for_chain chain;R.proof_key_activation_for_chain chain;R.tx_network_activation_for_chain chain|]')
 wrapper=wrapper.replace('R.cipher_migration;R.settle|]','R.cipher_migration;R.settle;R.stake;R.program_records;R.duty_marks;R.proof_key;R.tx_network|]')
 wrapper=wrapper.replace('c.vm_bytes;c.wasm_float]','c.vm_bytes;c.wasm_float;c.proof_key;c.program_records;c.duty_marks]')
 (out/'oracle.ml').write_text(wrapper)
 order=['oce1','hash_domain','octra_net','octra_log_format','octra_log','octra_ed25519','c_protocol','epoch_time','c_epoch_time_policy','c_quorum_policy','c_types','c_reward_source','c_codec','c_config','c_hash','c_qc','c_engine','octra_consensus','rule_graph','set_fold','epoch_exec','octra_core','set_rule','octra_node_runtime','oracle']
 env=os.environ.copy();env['PATH']=str(a.ocaml_bin)+os.pathsep+env['PATH']
 cmd=[str(a.ocaml_bin/'ocamlfind'),'ocamlopt','-package','digestif.c,zarith,yojson,base64,unix,mirage-crypto-ec','-linkpkg',*[m+'.ml'for m in order],'-o','oracle']
 r=subprocess.run(cmd,cwd=out,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(out/'build.log').write_text(r.stdout)
 if r.returncode:raise SystemExit(f'native build failed: {out/"build.log"}')
 historical=(ROOT/'crates/octra-node-runtime/tests/fixtures/rule-activation.json').read_bytes();cases=[c['input']for c in json.loads(historical)['cases']]
 r=subprocess.run([str(out/'oracle')],input=json.dumps(cases),env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120);(out/'run.log').write_text(r.stderr);r.check_returncode()
 result={'upstream_commit':PIN,'source_sha256':hashes,'extraction':extracts,'oracle_sha256':sha((ROOT/'scripts/node-port/rule-activation-oracle.ml').read_bytes()),'runner_sha256':sha(Path(__file__).read_bytes()),'compiled_oracle_sha256':sha(wrapper.encode()),'compiled_sha256':{p.name:sha(p.read_bytes())for p in out.glob('*.ml')},'historical_fixture_sha256':sha(historical),'build_command':cmd,'scope':'Unchanged native Rule_graph/Set_rule resolve and exact native parent-commit validation; fold context type only extracted from Epoch_exec; no execution or network qualification','cases':json.loads(r.stdout.splitlines()[-1])}
 a.fixture.write_text(json.dumps(result,separators=(',',':'))+'\n');print(json.dumps({'cases':len(cases),'fixture':str(a.fixture)}))
if __name__=='__main__':main()
