#!/usr/bin/env python3
"""Validator bond, exit, withdraw and evidence on the devnet chain at the candidate.

Replays the historical validator-transaction sequences shifted to the devnet
chain across seatless activation (epoch 1,845,000), with and without the
finalizing voting set and a signed parent commit, plus cases for penalties,
blocking weight and evidence against the voting set. Unchanged
`Epoch_exec.process_standard_tx` through the sender loop and savepoints.
"""
import argparse, base64, copy, hashlib, importlib.util, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import candidate_native  # noqa: E402

spec = importlib.util.spec_from_file_location('vt', HERE / 'validator-transaction-fixtures.py')
vt = importlib.util.module_from_spec(spec); spec.loader.exec_module(vt)

DEVNET = base64.b64encode(b'octra-devnet-9871-cluster').decode()
OFFSET = 1_844_992
VOTING = [dict(id=i, weight='1000000') for i in (1, 2, 3, 4)]

def b64(v): return base64.b64encode(v.encode() if isinstance(v, str) else v).decode()

def shift(case, seatless_inputs):
    case = copy.deepcopy(case)
    case['chain'] = DEVNET
    for rnd in case['rounds']:
        rnd['epoch'] += OFFSET
        for tx in rnd['transactions']:
            if 'vote_epoch' in tx:
                tx['vote_epoch'] += OFFSET
        if seatless_inputs:
            rnd['voting'] = VOTING
            rnd['legacy_active'] = [1, 2, 3, 4]
            rnd['parent'] = dict(epoch=str(rnd['epoch'] - 1), round=1, members=4, signers=[1, 2, 3])
    return case

def cases():
    out = []
    for case in vt.fixtures():
        out.append(shift(case, True))
        out.append(shift(case, False))
    rich = [dict(id=i, balance='100000000', nonce=0) for i in range(1, 7)]
    tx, rnd = vt.tx, vt.round
    def seat(epoch, txs, **kw):
        v = rnd(epoch, txs, voting=VOTING, legacy_active=[1, 2, 3, 4],
                parent=dict(epoch=str(epoch - 1), round=1, members=4, signers=[1, 2, 3]))
        v.update(kw); return v
    bonded = [tx(sender=i) for i in (1, 2, 3, 4)]
    ready = [dict(id=i, bond='1000000') for i in (1, 2, 3, 4)]
    for amount in ['1000000', '1999999', '2000000', '2000001', '3000000', '20000000']:
        for sender in (5, 1):
            for epoch in (1_844_999, 1_845_010, 1_845_056):
                out.append(dict(chain=DEVNET, accounts=rich, rounds=[
                    seat(epoch, [tx(sender=sender, amount=amount)], registry=ready)]))
    for registry in ([dict(id=i, bond='1000000') for i in (1, 2, 3, 4, 5)],
                     [dict(id=1, bond='1000000'), dict(id=2, bond='1000000'), dict(id=3, bond='1000000'), dict(id=4, bond='1000000'), dict(id=5, bond='1900000')]):
        for exits in ([1], [5], [2]):
            out.append(dict(chain=DEVNET, accounts=rich, rounds=[
                seat(1_845_010, [tx('validator_exit', sender=s) for s in exits], registry=registry)]))
    for penalized in (1, 5):
        out.append(dict(chain=DEVNET, accounts=rich, rounds=[
            seat(1_845_010, [tx(sender=penalized)], penalize=penalized, registry=ready)]))
    for exits in ([1], [1, 2], [4]):
        out.append(dict(chain=DEVNET, accounts=rich, rounds=[
            rnd(1_844_993, bonded + [tx(sender=5, amount='3000000')]),
            seat(1_845_010, [tx('validator_exit', sender=s, nonce=2) for s in exits])]))
    for offender in (1, 5):
        out.append(dict(chain=DEVNET, accounts=rich, rounds=[
            rnd(1_844_993, bonded + [tx(sender=5)]),
            seat(1_845_010, [tx('validator_evidence', sender=2, nonce=2, to=offender, offender=offender, vote_epoch=1_845_008)],
                 meta=vt.supply('600000000'))]))
    out.append(dict(chain=DEVNET, accounts=rich, rounds=[
        rnd(1_844_993, bonded),
        seat(1_845_010, [tx('validator_evidence', sender=2, nonce=2, to=1, offender=1, vote_epoch=1_845_008)], meta=vt.supply('400000000')),
        seat(1_845_011, [tx(sender=1, nonce=3), tx('validator_exit', sender=3, nonce=2)])]))
    return out

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    inputs = cases()
    observed, provenance = candidate_native.run(HERE / 'candidate-validator-transaction-oracle.ml',
        'octra_core octra_node_runtime octra_consensus yojson lwt.unix mirage-crypto-ec', inputs)
    result = dict(provenance, scope=__doc__, generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  generator_dependency_sha256=hashlib.sha256((HERE / 'validator-transaction-fixtures.py').read_bytes()).hexdigest(),
                  cases=observed)
    args.fixture.write_text(json.dumps(result, separators=(',', ':')) + '\n')
    import collections
    counts = collections.Counter()
    for case in observed:
        for r in case['expected']:
            o = r['outcome']
            if 'error' in o: counts['error: ' + o['error'][:80]] += 1
            for e in o.get('events', []):
                out = e['outcome']
                counts[out if isinstance(out, str) else json.dumps(out)[:110]] += 1
    print(json.dumps(dict(cases=len(observed), bytes=args.fixture.stat().st_size)))
    for k, v in counts.most_common(30): print(v, k)

if __name__ == '__main__':
    main()
