"""Native dependency isolation and ordered precheck, with supplied proof verdicts."""
import argparse, base64, hashlib, importlib.util, json, pathlib, random
ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/octra-node-runtime/tests/fixtures/epoch-partition.json'

def fixtures():
    source = json.loads(SOURCE.read_text())
    pool = [json.loads(base64.b64decode(t)) for t in source['transaction_pool']]
    senders = list(dict.fromkeys(t['from'] for t in pool))
    assert len(senders) >= 2
    def tx(op='standard', sender=0, nonce=1, ident=0, ou=1000):
        return dict(pool[0], op_type=op, **{'from':senders[sender], 'to':senders[sender]},
                    nonce=nonce, amount='1', ou=str(ou), message=str(ident))
    def row(txs, verdicts=None):
        for ordered in [False, True]:
            yield dict(ordered=ordered, transactions=[base64.b64encode(json.dumps(t,separators=(',',':')).encode()).decode() for t in txs],
                       verdicts=verdicts or ['ready']*len(txs))
    yield from row([])
    private = ['encrypt','decrypt','stealth','claim','key_switch']
    snapshots = ['circle_call','circle_balance_cell_put','circle_register_cell_put']
    for op in ['standard', *private, *snapshots]:
        for verdict in ['ready','invalid','unavailable']:
            for pos in range(3):
                values = [tx(sender=1,nonce=i+1,ident=i) for i in range(3)]
                values[pos] = tx(op,nonce=2,ident=8)
                verdicts = ['ready']*3;verdicts[pos]=verdict
                yield from row(values,verdicts)
    for first in private:
        for second in private:
            # Original order differs from nonce order; public successors must
            # be deferred at the second private cutoff too.
            yield from row([tx(second,nonce=3),tx(nonce=4),tx(first,nonce=1),tx(nonce=2),tx(sender=1)])
    for op in snapshots:
        for verdict in ['ready','invalid','unavailable']:
            yield from row([tx(op),tx('circle_call',nonce=2),tx(sender=1)], [verdict,'ready','ready'])
            value = tx(op)
            yield from row([value,value,tx(sender=1)], [verdict,verdict,'ready'])
    for op in ['standard','circle_call','program_deploy','encrypt']:
        yield from row([tx(op,nonce=i+1,ident=i,ou=30_000_000) for i in range(3)])
    for verdict in ['invalid','unavailable']:
        yield from row([tx(nonce=3),tx(nonce=1),tx(nonce=2),tx(sender=1)], ['ready',verdict,'ready','ready'])
    rng = random.Random(20261014)
    for _ in range(120):
        n=rng.randrange(1,8)
        yield from row([tx(rng.choice(['standard',*private,*snapshots]),rng.randrange(2),rng.randrange(1,6),i) for i in range(n)],
                       [rng.choice(['ready','ready','invalid','unavailable']) for _ in range(n)])

def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists(): raise SystemExit('Require fresh output')
    spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    # Export the existing helper through its interface for this oracle only.
    # No implementation is patched; the runner records both interface hashes.
    exports={'node_runtime/consensus_proposal.mli':
             'val precheck : ordered:bool -> run_many:(Octra_core.Transaction.t list -> Octra_core.Preverify_worker.batch Lwt.t) -> Octra_core.Transaction.t list -> Octra_core.Preverify_worker.batch Lwt.t\n'}
    report=native.run(a.upstream,'octra-vpn-latest-builder-20261012:latest',ROOT/'scripts/node-port/preverify-batch-oracle.ml',list(fixtures()),'octra_core octra_node_runtime yojson base64',prefixes=exports)
    report['generator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    report['transaction_fixture_sha256']=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    report['scope']='Actual native run_checked and ordered precheck selection, resource work, retryability and callback ordering with supplied proof verdicts; no proof verification claim.'
    # Intern repeated transaction payloads without changing bytes.
    pool=[];indices={}
    for case in report['cases']:
        refs=[]
        for raw in case['input']['transactions']:
            if raw not in indices: indices[raw]=len(pool);pool.append(raw)
            refs.append(indices[raw])
        case['input']['transactions']=refs
    report['transaction_pool']=pool
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(report['cases']),'native preverification selection cases')
if __name__=='__main__': main()
