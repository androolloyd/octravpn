"""Actual native BFT Circle processor, epoch commit and upstream counter WASM."""
import argparse,base64,hashlib,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
native=module('native',ROOT/'scripts/node-port/native-oracle.py')
circles=module('circles',ROOT/'scripts/node-port/circle-transaction-fixtures.py')
def compact(report, counter):
    for case in report['cases']:
        if case['input'].pop('wasm') != counter['wasm_b64']:raise ValueError('Guest differs between cases')
    report['wasm_b64']=counter['wasm_b64']
    return report
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    counter=json.loads((ROOT/'crates/octra-node-runtime/tests/fixtures/circle-view.json').read_text())
    for name,digest in counter['guest_source_sha256'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=digest:raise SystemExit('Guest source changed')
    if hashlib.sha256(base64.b64decode(counter['wasm_b64'])).hexdigest()!=counter['wasm_sha256']:raise SystemExit('WASM differs')
    cases=[case|{'wasm':counter['wasm_b64'],'circle_policy':policy,'wasm_compute':compute} for case in circles.fixtures() for policy in [False,True] for compute in [False,True]]
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/epoch-circle-oracle.ml',cases,'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix')
    report.update(guest_source_sha256=counter['guest_source_sha256'],wasm_sha256=counter['wasm_sha256'],scope='Actual unmodified Consensus_vm_transition.process_tx inside Epoch_exec.run_core, upstream public counter WASM, complete committed state roots, fees and VM receipts. Both Circle policy and compute-manifest modes, with explicit VM inspect/proof modes. No HFHE, external signature admission or peer consensus is claimed.')
    compact(report,counter)
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native BFT Circle epochs')
if __name__=='__main__':main()
