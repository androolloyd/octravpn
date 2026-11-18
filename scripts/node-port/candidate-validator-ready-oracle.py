#!/usr/bin/env python3
"""Validator readiness on the devnet chain at the candidate (8f785a93).

The historical readiness sequences shifted across seatless activation
(epoch 1,845,000) on the devnet chain, as they were and with the finalizing
voting set and matching members, plus penalised senders and readiness that
would give one member a blocking share. Unchanged `Epoch_exec` through the
sender loop and savepoints; parents are weighted, as they are on devnet.
"""
import argparse, base64, copy, hashlib, importlib.util, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import candidate_native  # noqa: E402

def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
ready_fixtures = module('ready', 'validator-ready-fixtures.py')

DEVNET = 'octra-devnet-9871-cluster'
OLD = ready_fixtures.CHAIN
OFFSET = 1_844_992
VOTING = [dict(id=i, weight='1000000') for i in (1, 2, 3, 4)]
def b64(v): return base64.b64encode(v.encode() if isinstance(v, str) else v).decode()

def shift_tx(tx):
    if isinstance(tx.get('head'), int) and tx['head'] >= 0:
        tx['head'] += OFFSET
    if 'vote_epoch' in tx:
        tx['vote_epoch'] += OFFSET
    extra = tx.get('extra')
    if isinstance(extra, dict):
        if extra.get('chain_id') == OLD:
            extra['chain_id'] = DEVNET
        if str(extra.get('catchup_head_epoch', '')).lstrip('-').isdigit():
            extra['catchup_head_epoch'] = str(int(extra['catchup_head_epoch']) + OFFSET)

def shift(case, seatless):
    case = copy.deepcopy(case)
    case['chain'] = b64(DEVNET)
    for rnd in case['rounds']:
        rnd['epoch'] += OFFSET
        for tx in rnd['transactions']:
            shift_tx(tx)
        if isinstance(rnd.get('parent'), dict):
            rnd['parent']['chain'] = b64(DEVNET)
            rnd['parent']['epoch'] = str(int(rnd['parent']['epoch']) + OFFSET)
        if isinstance(rnd.get('roots'), dict):
            rnd['roots'] = {str(int(k) + OFFSET): v for k, v in rnd['roots'].items()}
        if seatless:
            rnd['voting'] = VOTING
            rnd['legacy_active'] = [1, 2, 3, 4]
    return case

def cases():
    out = []
    for case in ready_fixtures.fixtures():
        out.append(shift(case, False))
        out.append(shift(case, True))
    # Penalised readiness and readiness under seatless with heavier bonds.
    tx, rnd, case = ready_fixtures.tx, ready_fixtures.round, ready_fixtures.case
    def ready(**kw): return ready_fixtures.ready(**kw)
    for penalize in (1, 2):
        c = case([rnd(1, [tx()]), ready_fixtures.active(10, [ready(head=9, proposal='auto', extra=ready_fixtures.claim(9))],
                  active=[1], penalize=penalize)], readiness=True)
        out.append(shift(c, True))
    for bond in ('1000000', '2000000', '5000000'):
        bonds = [tx(sender=i, amount=bond if i == 1 else '1000000') for i in (1, 2, 3, 4)]
        c = case([rnd(1, bonds)] + [ready_fixtures.active(e, [ready(sender=s, nonce=nonce, head=e - 1, proposal='auto',
                  extra=ready_fixtures.claim(e - 1)) for s in (1, 2, 3, 4)], active=[1, 2, 3, 4])
                  for nonce, e in ((2, 10), (3, 11))], readiness=True)
        c['accounts'] = [dict(id=i, balance='100000000', nonce=0) for i in range(1, 5)]
        out.append(shift(c, True))
    return out

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    inputs = cases()
    observed, provenance = candidate_native.run(HERE / 'candidate-validator-ready-oracle.ml',
        'octra_core octra_node_runtime octra_consensus yojson lwt.unix mirage-crypto-ec', inputs)
    result = dict(provenance, scope=__doc__, generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  generator_dependency_sha256=hashlib.sha256((HERE / 'validator-ready-fixtures.py').read_bytes()).hexdigest(),
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
                if not (isinstance(out, dict) and 'mismatch' in out):
                    counts[out if isinstance(out, str) else json.dumps(out)[:120]] += 1
    print(json.dumps(dict(cases=len(observed), bytes=args.fixture.stat().st_size)))
    for k, v in counts.most_common(30): print(v, k)

if __name__ == '__main__':
    main()
