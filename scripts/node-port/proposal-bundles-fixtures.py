#!/usr/bin/env python3
"""Native proposal bundle validation using independently signed native inputs."""
import argparse, copy, importlib.util, json, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

def fixtures():
    out = []
    for case in json.loads((ROOT/'crates/octra-node-runtime/tests/fixtures/pending-recovery.json').read_text())['cases']:
        e = case['expected']
        record = json.loads(bytes.fromhex(e['record']))
        hx = lambda values: [v.encode().hex() for v in values]
        j = dict(proposal=e['proposal'], hashes=hx(record['tx_hashes']),
                 txs=hx(record['txs_json']), receipts=hx(record['receipts_json']),
                 expected_hashes=hx(record['tx_hashes']), rules=e['rules'])
        out.append(j)
        if case['input']['mutate'] != 'none':
            continue
        for mutation in ['response_hash', 'expected_hash', 'expected_length', 'tx_length',
                         'receipt_and_bad_tx', 'bad_tx', 'bad_receipt', 'raw_expected_hash']:
            m = copy.deepcopy(j)
            if mutation == 'response_hash': m['hashes'] = [b'ignored'.hex() for _ in m['hashes']]
            elif mutation == 'expected_hash': m['expected_hashes'] = [b'bad'.hex() for _ in m['expected_hashes']]
            elif mutation == 'expected_length': m['expected_hashes'].append(b'bad'.hex())
            elif mutation == 'tx_length': m['txs'].append(b'{}'.hex())
            elif mutation == 'receipt_and_bad_tx':
                m['txs'] = [b'bad'.hex() for _ in m['txs']]
                m['receipts'].append(b'{}'.hex())
            elif mutation == 'bad_tx': m['txs'] = [b'bad'.hex() for _ in m['txs']]
            elif mutation == 'bad_receipt': m['receipts'].append(b'{}'.hex())
            elif mutation == 'raw_expected_hash':
                m['expected_hashes'] = [bytes.fromhex(v).decode() for v in m['expected_hashes']]
            m['mutation'] = mutation
            out.append(m)
    return out

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--upstream',type=pathlib.Path,required=True)
    p.add_argument('--builder-image',required=True)
    p.add_argument('--out',type=pathlib.Path,required=True)
    a=p.parse_args()
    if a.out.exists(): raise SystemExit('require fresh report')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/proposal-bundles-oracle.ml',fixtures(),'octra_node_runtime octra_core octra_consensus yojson')
    report['scope']='Unmodified native proposal bundle validation. Proposal authentication and canonical execution are separate gates.'
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(report['cases']),'native proposal bundle cases')
if __name__=='__main__': main()
