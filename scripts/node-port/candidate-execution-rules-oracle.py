#!/usr/bin/env python3
"""Native c49 preview rule binding, stopping before state preview or execution.

The complete production selection prefix is extracted verbatim. Its continuation
serializes the captured modes instead of opening State_preview. Native Set_rule,
parent authentication and signatures remain unchanged. Historical inputs stay
byte-for-byte bound; this is not a complete c49 preview/state execution oracle.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

PIN = '8f785a93a4e7392a0f3e65674f9de89854d33dbc'
ROOT = Path(__file__).resolve().parents[2]
def sha(data): return hashlib.sha256(data).hexdigest()
def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['upstream','out','fixture','ocaml-bin']:
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True);out=a.out.resolve()
    dependency=ROOT/'scripts/node-port/candidate-rule-activation-oracle.py'
    depfixture=out/'rule-dependencies.json'
    subprocess.run(['python3',str(dependency),'--upstream',str(a.upstream),'--out',str(out),
        '--fixture',str(depfixture),'--ocaml-bin',str(a.ocaml_bin)],check=True)
    provenance=json.loads(depfixture.read_text())
    def read(path):
        raw=subprocess.check_output(['git','-C',str(a.upstream),'show',f'{PIN}:{path}'])
        provenance['source_sha256'][path]=sha(raw);return raw.decode()
    def part(path,start,end):
        text=read(path);lo=text.index(start);hi=text.index(end,lo);body=text[lo:hi]
        provenance['extraction'].setdefault(path,[]).append(dict(start_line=text[:lo].count('\n')+1,
            end_line=text[:hi].count('\n'),sha256=sha(body.encode())))
        return body
    env=part('lib/core/epoch_exec.ml','type env =','type tx_reject =')
    (out/'epoch_exec.ml').write_text(env+(out/'epoch_exec.ml').read_text())
    prefix=part('node_runtime/consensus_proposal_preview_shell.ml',
        '      match Octra_core.Rule_graph.circle rules ~epoch:epoch_id with',
        '                      Octra_core.State_preview.with_preview')
    # Preserve all production branches up to the boundary. Four nested begin/end
    # blocks close after this serialization-only continuation.
    continuation='''Lwt.return_ok (circle_mode, wasm_compute_mode, object_cost,
      owner_migration_mode, cipher_mode, private_payload_mode, fold_ctx)
    end end end end\n'''
    selected='let select ~rules ~epoch_id ~env ~parent_commit =\n'+prefix+continuation
    (out/'selection.ml').write_text(selected)
    # Reuse only the activation-input helper; this contains no selection logic.
    rule_wrapper=(out/'oracle.ml').read_text()
    helper=rule_wrapper[rule_wrapper.index('let activations chain='):rule_wrapper.index('let modes=')]
    wrapper=Path(__file__).with_suffix('.ml').read_bytes()
    (out/'oracle.ml').write_text('module R=Octra_core.Rule_graph\n'+helper+wrapper.decode())
    order=[Path(s).stem for s in provenance['build_command'] if s.endswith('.ml')]
    order=order[:-1]+['selection','oracle']
    packages='digestif.c,zarith,yojson,base64,unix,mirage-crypto-ec,lwt.unix'
    command=[str(a.ocaml_bin/'ocamlfind'),'ocamlopt','-thread','-package',packages,'-linkpkg',
        *[m+'.ml' for m in order],'-o','oracle']
    buildenv=os.environ.copy();buildenv['PATH']=str(a.ocaml_bin)+os.pathsep+buildenv['PATH']
    result=subprocess.run(command,cwd=out,env=buildenv,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/'execution-build.log').write_text(result.stdout)
    if result.returncode: raise SystemExit('native preview build failed; see execution-build.log')
    historical=(ROOT/'crates/octra-node-runtime/tests/fixtures/execution-rules.json').read_bytes()
    cases=[c['input'] for c in json.loads(historical)['cases']]
    result=subprocess.run([str(out/'oracle')],input=json.dumps(cases),env=buildenv,text=True,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
    (out/'execution-run.log').write_text(result.stderr);result.check_returncode()
    report=dict(upstream_commit=PIN,source_sha256=provenance['source_sha256'],extraction=provenance['extraction'],
        oracle_sha256=sha(wrapper),runner_sha256=sha(Path(__file__).read_bytes()),
        dependency_runner_sha256=sha(dependency.read_bytes()),
        compiled_sha256={p.name:sha(p.read_bytes()) for p in out.glob('*.ml')},
        historical_fixture_sha256=sha(historical),build_command=command,scope=__doc__,cases=json.loads(result.stdout.splitlines()[-1]))
    a.fixture.write_text(json.dumps(report,separators=(',',':'))+'\n')
    changed=[i for i,(old,new) in enumerate(zip(json.loads(historical)['cases'],report['cases'])) if old['expected']!=new['expected']]
    print(json.dumps(dict(cases=len(cases),changed=changed,fixture=str(a.fixture))))
if __name__=='__main__':main()
