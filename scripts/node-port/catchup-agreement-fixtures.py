"""Exercise the unmodified native range query's weighted/prefix selection."""
import argparse
import importlib.util
import json
import pathlib
import random

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native', ROOT / 'scripts/node-port/native-oracle.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def fixtures():
    corpus = json.loads((ROOT / 'crates/octra-node-protocol/tests/fixtures/consensus-wire.json').read_text())
    wire = next(c['expected']['wire'] for c in corpus['cases']
                if c['input']['kind'] == 'catchup_v2' and 'wire' in c['expected'])
    rng = random.Random(2026101322)
    cases = []
    for index in range(384):
        count = rng.choice([1, 3, 4, 7, 13, 40])
        epoch = rng.choice([1, 1306546, 1306547, 1500000])
        patterns = [[], [1], [1, 2], [1, 3], [1, 2, 4], [1, 2, 5], [6], [7, 8], list(range(1, 17))]
        responses = []
        for n in range(count):
            records = rng.choice(patterns) if index % 4 else rng.choice([[1, 2], [1, 3]])
            responses.append(dict(responder='v' + str(n + 1), records=records,
                                  status=rng.choice(['ok', 'ok', 'ok', 'not_found', 'internal_error']),
                                  next=str(epoch + len(records) + rng.choice([0, 0, 0, 1])) if rng.randrange(5) else None,
                                  valid=rng.randrange(8) != 0, incomplete=rng.randrange(20) == 0))
        rng.shuffle(responses)
        cases.append(dict(chain=rng.choice(['octra-devnet-9871-cluster', 'octra-mainnet']),
                          height='1', local=1, weights=[str(rng.choice([1, 2, 5, 100])) for _ in range(count)],
                          weighted=rng.choice([True, False]), wire=wire, responses=responses,
                          **{'from': str(epoch), 'max': rng.choice([-1, 0, 1, 2, 16, 100]),
                             'activation': rng.choice([None, str(epoch), str(epoch + 3), str(epoch + 16)])},
                          peers=rng.randrange(80), budget=rng.choice([0.0, 0.1, 1.0, 20.0]), wave_count=rng.randrange(5)))
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upstream', type=pathlib.Path, required=True)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh report')
    report = native.run(args.upstream, args.builder_image, ROOT / 'scripts/node-port/catchup-agreement-oracle.ml',
                        fixtures(), 'octra_consensus octra_net yojson lwt.unix mirage-crypto-ec')
    report['scope'] = 'Unmodified native query_catchup_range selection, rejection memoization, historical count/weight rules, activation cap, peer waves and cleanup. Responses are injected after authentication; transport and finality validity are separate gates.'
    assert all(c['expected']['clean'] for c in report['cases'])
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(report['cases']), 'native catchup agreement cases')


if __name__ == '__main__':
    main()
