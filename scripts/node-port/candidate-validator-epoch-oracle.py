#!/usr/bin/env python3
"""Validator-set advance on the devnet chain under seatless voting (8f785a93).

Drives the unchanged `Epoch_exec.prepare_validator_penalties` and
`advance_validator_set` around activation epoch 1,845,000 with weighted
voting sets, slashes, recorded penalties, pending and eviction updates, and
records every meta key they may write plus the resulting tree root.
"""
import argparse, base64, hashlib, itertools, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import candidate_native  # noqa: E402

CHAIN = base64.b64encode(b'octra-devnet-9871-cluster').decode()
MILLION = 1_000_000

def b64(raw): return base64.b64encode(raw).decode()
def member(id, weight): return dict(id=id, weight=str(weight))
def slash(n, offender, applied, evidence=None, amount=MILLION):
    return dict(id=b64(hashlib.sha256(f'evidence-{n}'.encode()).digest()), offender=offender,
                evidence=str(evidence if evidence is not None else applied), applied=str(applied), amount=str(amount))
def rnd(epoch, voting, legacy=None, **kw):
    v = dict(epoch=epoch, voting=voting, legacy=legacy if legacy is not None else [m['id'] for m in voting])
    v.update(kw); return v

def cases():
    out = []
    bonds = {1: MILLION, 2: MILLION, 3: MILLION, 4: MILLION, 5: 2 * MILLION, 6: 9 * MILLION, 7: MILLION}
    def candidates(ids, ready='0', exited=()):
        return [dict(id=i, bond=str(bonds[i]), ready=ready, **({'exit': '1'} if i in exited else {})) for i in ids]
    sets = {
        'four': [member(i, MILLION) for i in (1, 2, 3, 4)],
        'five': [member(i, MILLION) for i in (1, 2, 3, 4, 5)],
        'heavy': [member(1, MILLION), member(2, MILLION), member(3, MILLION), member(6, 9 * MILLION)],
        'uneven': [member(1, MILLION), member(2, MILLION), member(3, MILLION), member(4, MILLION), member(5, 2 * MILLION)],
    }
    epochs = [[1_844_992], [1_844_999, 1_845_000], [1_845_055, 1_845_056, 1_845_057], [1_845_120]]
    flags = [dict(), dict(standard=True), dict(standard=True, plan=True)]
    # Snapshots and promotion without evidence.
    for name, voting in sets.items():
        for rounds in epochs:
            for flag in flags:
                for ids in [(1, 2, 3, 4), (1, 2, 3, 4, 5), (1, 2, 3, 4, 5, 6), (1, 2, 3, 6, 7)]:
                    out.append(dict(chain=CHAIN, candidates=candidates(ids),
                                    rounds=[rnd(e, voting, **flag) for e in rounds]))
    # A due pending set: kept, replaced by the active set, or refused.
    for name, voting in sets.items():
        for pending_members in [sets['four'], sets['five'], sets['heavy'], sets['uneven'],
                                [member(i, MILLION) for i in (1, 2, 3)]]:
            for source, activate in [(1_844_928, 1_844_992), (1_844_992, 1_845_056), (1_845_056, 1_845_120)]:
                for e in [1_844_992, 1_845_056, 1_845_120]:
                    out.append(dict(chain=CHAIN, candidates=candidates((1, 2, 3, 4, 5, 6)),
                                    rounds=[rnd(e, voting, pending=dict(source=str(source), activate=str(activate), members=pending_members))]))
    # Evidence: penalties, eviction or wait, cancelled pending sets.
    for name, voting in sets.items():
        voters = [m['id'] for m in voting]
        for offenders in [[voters[0]], [voters[-1]], voters[:2], [7]]:
            for applied in [1_844_990, 1_845_000, 1_845_056, 1_845_200]:
                records = [slash(k, o, applied) for k, o in enumerate(offenders)]
                for e in [[1_844_999, 1_845_000], [1_845_056, 1_845_057], [1_845_201]]:
                    for pending in [None, dict(source='1845056', activate='1845120', members=sets['five'])]:
                        rounds = [rnd(x, voting) for x in e]
                        if pending:
                            rounds[0]['pending'] = pending
                        out.append(dict(chain=CHAIN, candidates=candidates((1, 2, 3, 4, 5, 6, 7)), slashes=records, rounds=rounds))
    # A stored eviction comes due the next epoch.
    for name, voting in sets.items():
        voters = [m['id'] for m in voting]
        for offenders in [[voters[0]], voters[:2]]:
            records = [slash(k, o, 1_845_010) for k, o in enumerate(offenders)]
            out.append(dict(chain=CHAIN, candidates=candidates((1, 2, 3, 4, 5, 6, 7)), slashes=records,
                            rounds=[rnd(1_845_010, voting), rnd(1_845_011, voting)]))
            out.append(dict(chain=CHAIN, candidates=candidates((1, 2, 3, 4, 5, 6, 7)), slashes=records,
                            rounds=[rnd(1_845_011, voting, eviction=dict(source='1845010', source_set=voting, offenders=offenders))]))
    # Stored penalty bookkeeping, missing or mismatched voting sets.
    base = dict(chain=CHAIN, candidates=candidates((1, 2, 3, 4, 5)), slashes=[slash(0, 2, 1_845_000)])
    for value in [b'1845000', b'1844999', b'1845005', b'1845100', b'-1', b'x', b'']:
        out.append(dict(base, rounds=[rnd(1_845_005, sets['five'], meta=[dict(key='validator_penalty_epoch', value=b64(value))])]))
    out.append(dict(base, rounds=[rnd(1_845_005, sets['five'], meta=[dict(key='validator_penalty:' + 'x', value=b64(b'id'))])]))
    out.append(dict(base, rounds=[dict(epoch=1_845_005, legacy=[1, 2, 3, 4, 5])]))
    out.append(dict(base, rounds=[rnd(1_845_005, sets['five'], legacy=[1, 2, 3, 4])]))
    out.append(dict(base, rounds=[rnd(1_845_005, sets['heavy'])]))
    out.append(dict(chain=CHAIN, candidates=candidates((1, 2, 3, 4, 5)), rounds=[dict(epoch=1_845_056, legacy=[1, 2, 3, 4])]))
    # A non-devnet chain never enters seatless rules.
    out.append(dict(chain=b64(b'local-validator-epoch'), candidates=candidates((1, 2, 3, 4, 5)),
                    slashes=[slash(0, 2, 1_845_000)], rounds=[rnd(1_845_056, sets['five'])]))
    return out

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    inputs = cases()
    observed, provenance = candidate_native.run(HERE / 'candidate-validator-epoch-oracle.ml',
                                                'octra_core octra_consensus yojson mirage-crypto-ec', inputs)
    result = dict(provenance, scope=__doc__,
                  generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), cases=observed)
    args.fixture.write_text(json.dumps(result, separators=(',', ':')) + '\n')
    errors = sum(1 for case in observed for r in case['expected'].get('rounds', []) if r.get('error'))
    print(json.dumps(dict(cases=len(observed), rounds_with_errors=errors, bytes=args.fixture.stat().st_size)))

if __name__ == '__main__':
    main()
