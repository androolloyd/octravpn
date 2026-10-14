"""Actual upstream preview rule binding, stopped at the snapshot guard."""
import argparse,copy,hashlib,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
SOURCE=ROOT/'crates/octra-node-runtime/tests/fixtures/rule-activation.json'
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def fixtures():
    for case in json.loads(SOURCE.read_text())['cases']:
        v=case['input']
        if v['kind']!='graph':continue
        v={k:v[k] for k in ['chain','epoch','config','default','roots']}
        v.update(plans=case['expected']['plans'],parent=case['expected']['parent'])
        yield v
        if v['epoch']>=1688734 and v['default']=='good' and v['plans'][0] is not None:
            anchors=sorted({p[0] for p in v['plans'] if p is not None})
            for first in anchors:
                for second in anchors:
                    if first==second:continue
                    changed=copy.deepcopy(v);changed['roots']={str(first):'unreadable',str(second):'bad'}
                    yield changed
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/execution-rules-oracle.ml',list(fixtures()),'octra_core octra_node_runtime octra_vm yojson lwt.unix')
    report['input_fixture_sha256']=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    report['scope']='Actual Consensus_proposal_preview_shell.node_backend.run rule binding. An intentionally mismatched snapshot ends successful binding before execution. Native signed parent/anchor fixtures are inputs, not bootstrap authority.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native preview rule contexts')
if __name__=='__main__':main()
