#!/usr/bin/env python3
"""Node epoch footer at the candidate (8f785a93) under seatless voting.

Drives the unchanged `Consensus_epoch_apply_footer.run_node` and
`Epoch_exec.apply_epoch_footer_with_reward` on the devnet chain: rewards of
slashed or penalised validators are burned, supply metadata follows, and
each epoch records its execution profile after checking its parent's.
Also replays the historical footer cases on the devnet chain before and
after activation.
"""
import argparse, base64, copy, hashlib, importlib.util, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import candidate_native  # noqa: E402

spec = importlib.util.spec_from_file_location('footer_fixtures', HERE / 'footer-fixtures.py')
historical = importlib.util.module_from_spec(spec); spec.loader.exec_module(historical)

DEVNET = b'octra-devnet-9871-cluster'
def b64(v): return base64.b64encode(v if isinstance(v, bytes) else str(v).encode()).decode()
def evidence(n): return b64(hashlib.sha256(f'evidence-{n}'.encode()).digest())
def profile(epoch): return hashlib.sha256(f'profile-{epoch}'.encode()).hexdigest()
def marker(epoch): return b64(json.dumps(dict(epoch=epoch, profile=profile(epoch)), separators=(',', ':')))
def registry(slashes):
    return b64(json.dumps(dict(standard='bonded_stake', candidates=[], slashes=[
        dict(id=evidence(n), offender=o, evidence_epoch=str(a), applied_epoch=str(a), amount='1000000')
        for n, (o, a) in enumerate(slashes)]), separators=(',', ':')))

def cases():
    out = []
    # The historical footer cases on the devnet chain, before and after activation.
    for case in historical.fixtures():
        for epoch in [1_844_999, 1_845_000]:
            c = copy.deepcopy(case)
            c.update(chain=b64(DEVNET), epoch=epoch, profiles=[])
            if c.get('activation') is not None:
                c['activation'] = epoch - 10 + (c['activation'] - 10)
            out.append(c)
    # Seatless exclusion and burn.
    addresses = {name: f'oct{name * 44}' for name in 'ABCDE'}
    validators = [dict(address=b64(addresses[n]), key=b64('key-' + n), weight=str(w))
                  for n, w in [('A', 1), ('B', 2), ('C', 3), ('D', 1)]]
    base = dict(chain=b64(DEVNET), epoch=1_845_010, guard=False, activation=None, legacy=None,
                accounts=[dict(address=b64('sender'), balance='9000', nonce=1, key=None)],
                proposer=b64(addresses['A']), proposer_key=b64('pk'), validators=validators,
                fallback=[], fees='1000', profiles=[])
    supply = [[b64('emission_remaining'), b64('0')], [b64('total_supply'), b64('10000')]]
    for slashed in [[], ['B'], ['A'], ['B', 'C'], ['E'], ['A', 'B', 'C', 'D']]:
        for applied in [1_845_009, 1_845_010, 1_845_011]:
            for penalized in [[], ['C'], ['A'], ['E']]:
                for fees in ['0', '1', '1000', '7']:
                    for activation in [None, 1_845_000]:
                        meta = list(supply)
                        if slashed:
                            meta.append([b64('bft.validator_registry'), registry([(addresses[s], applied) for s in slashed])])
                        for p in penalized:
                            meta.append([b64('validator_penalty:' + addresses[p]), b64('id')])
                        out.append(dict(base, meta=meta, fees=fees, activation=activation))
    for epoch in [1_844_999, 1_845_000, 1_845_010]:
        meta = supply + [[b64('bft.validator_registry'), registry([(addresses['B'], 1_844_990)])],
                         [b64('validator_penalty:' + addresses['C']), b64('id')]]
        out.append(dict(base, epoch=epoch, meta=meta))
    out.append(dict(base, meta=supply + [[b64('bft.validator_registry'), b64('not json')]]))
    # Execution profile: the parent marker, its epochs, and the new marker.
    for previous in [None, 'good', 'stale', 'other', 'junk']:
        for last in [None, 'parent', 'wrong']:
            for epoch in [1_845_000, 1_845_001, 1_845_010]:
                meta = list(supply)
                if last == 'parent':
                    meta += [[b64('last_epoch'), b64(str(epoch - 1))], [b64('current_epoch'), b64(str(epoch))]]
                elif last == 'wrong':
                    meta += [[b64('last_epoch'), b64(str(epoch - 2))], [b64('current_epoch'), b64(str(epoch))]]
                if previous == 'good':
                    meta.append([b64('execution_profile'), marker(epoch - 1)])
                elif previous == 'stale':
                    meta.append([b64('execution_profile'), marker(epoch - 2)])
                elif previous == 'other':
                    meta.append([b64('execution_profile'), b64(json.dumps(dict(epoch=epoch - 1, profile='00' * 32), separators=(',', ':')))])
                elif previous == 'junk':
                    meta.append([b64('execution_profile'), b64('{"epoch":1}')])
                profiles = [[e, profile(e)] for e in (epoch - 1, epoch) if e >= 1_845_000]
                out.append(dict(base, epoch=epoch, meta=meta, profiles=profiles))
    return out

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    inputs = cases()
    observed, provenance = candidate_native.run(HERE / 'candidate-footer-oracle.ml',
                                                'octra_core octra_node_runtime yojson base64 lwt.unix irmin hex', inputs)
    result = dict(provenance, scope=__doc__,
                  generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  generator_dependency_sha256=hashlib.sha256((HERE / 'footer-fixtures.py').read_bytes()).hexdigest(),
                  cases=observed)
    args.fixture.write_text(json.dumps(result, separators=(',', ':')) + '\n')
    import collections
    outcomes = collections.Counter(next(iter(c['expected']['outcome'])) + (':' + c['expected']['outcome']['error'][:60] if 'error' in c['expected']['outcome'] else '') for c in observed)
    print(json.dumps(dict(cases=len(observed), bytes=args.fixture.stat().st_size)))
    for k, v in outcomes.most_common(25): print(v, k)

if __name__ == '__main__':
    main()
