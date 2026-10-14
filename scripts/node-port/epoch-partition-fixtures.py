"""Native candidate/finalized partition checks using recorded epoch artifacts."""
import argparse, base64, hashlib, importlib.util, json, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT/'crates/octra-node-runtime/tests/fixtures/epoch-execution.json'
spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

def fixtures():
    for case in json.loads(SOURCE.read_text())['cases']:
        expected = case['expected']
        result = expected['result']
        if 'error' in result:
            continue
        transactions = [json.loads(base64.b64decode(t)) for t in expected['transactions']]
        # Both network decoders reject negative money; the source fixture also
        # contains direct native-object probes that are outside this boundary.
        if any(int(t['amount']) < 0 or int(t['ou']) < 0 for t in transactions):
            continue
        for finalized in [False, True]:
            for mutation in ['none', 'drop_confirmed', 'reverse_confirmed', 'drop_rejected',
                             'duplicate_rejected', 'charged', 'reason', 'type', 'exception', 'error']:
                yield dict(transactions=expected['transactions'],
                           confirmed=[i for i, _ in result['confirmed']],
                           rejected=result['rejected'], finalized=finalized,
                           compute=case['input']['vm'], settle=False, envelope=False,
                           mutation=mutation)
        if result['rejected']:
            for compute in [False, True]:
                for envelope in [False, True]:
                    for op in ['standard', 'compute_fund', 'compute_return', 'compute_settle', 'circle_call']:
                        modified = [dict(t) for t in transactions]
                        # Shape/gate checks only: altered inputs are deliberately
                        # not re-signed and no signature verification is claimed.
                        rejected = [dict(r, charged=True) for r in result['rejected']]
                        for r in rejected:
                            modified[r['index']]['op_type'] = op
                        yield dict(transactions=[base64.b64encode(json.dumps(t,separators=(',',':')).encode()).decode() for t in modified],
                                   confirmed=[i for i, _ in result['confirmed']], rejected=rejected,
                                   finalized=True, compute=compute, settle=False, envelope=envelope,
                                   mutation='none')

def compact(report):
    for field, target, pool_name in [('transactions','input','transaction_pool'),
                                     ('rejections','expected','rejection_pool')]:
        pool, indices = [], {}
        for case in report['cases']:
            if field not in case[target]:
                continue
            refs = []
            for value in case[target][field]:
                if value not in indices:
                    indices[value] = len(pool)
                    pool.append(value)
                refs.append(indices[value])
            case[target][field] = refs
        report[pool_name] = pool
    return report

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--upstream',type=pathlib.Path,required=True)
    p.add_argument('--builder-image',required=True)
    p.add_argument('--out',type=pathlib.Path,required=True)
    a=p.parse_args()
    if a.out.exists(): raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/epoch-partition-oracle.ml',list(fixtures()),
                      'octra_core octra_node_runtime yojson base64')
    report['artifact_fixture_sha256']=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    report['scope']='Actual native Consensus_proposal.verify_preview_partition and Tx_outcome/Tx_envelope finalized selection. Supplied artifacts exercise ordering, normalized rejection bytes, charged gates and fault priority. No new transaction execution or signature admission is claimed.'
    compact(report)
    report['generator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(report['cases']),'native partition cases')
if __name__=='__main__': main()
