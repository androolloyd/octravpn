#!/usr/bin/env python3
"""Compare native IPP folding, both verifier policies, and transcript outcomes."""
import argparse
import hashlib
import json
import pathlib
import platform
import random
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def scalar(value):
    return value.to_bytes(32, 'little').hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('use a fresh fixture path')
    pin = json.loads((ROOT / 'docs/rust-node/upstream.json').read_text())['commit']
    if subprocess.check_output(['git', '-C', str(args.upstream), 'rev-parse', 'HEAD'], text=True).strip() != pin:
        raise SystemExit('upstream pin mismatch')
    sources = subprocess.check_output(['git', '-C', str(args.upstream), 'ls-files', 'pvac'], text=True).splitlines()
    runtime = json.loads((ROOT / 'docs/rust-node/source-map.json').read_text())['files']
    hashes = {}
    for source in sources:
        data = subprocess.check_output(['git', '-C', str(args.upstream), 'show', f'HEAD:{source}'])
        if data != (args.upstream / source).read_bytes():
            raise SystemExit(f'modified oracle source: {source}')
        if source in runtime:
            hashes[source] = hashlib.sha256(data).hexdigest()
    rng = random.Random(20261014)
    order = (1 << 252) + 27742317777372353535851937790883648493
    cases = []
    for rule in [0, 1]:
        for n in [1, 2, 4, 8, 16, 32]:
            for pattern in range(4):
                if pattern == 0:
                    a, b = [0] * n, [0] * n
                elif pattern == 1:
                    a, b = list(range(1, n + 1)), list(range(n + 1, 2 * n + 1))
                elif pattern == 2:
                    a, b = [rng.randrange(order) for _ in range(n)], [rng.randrange(order) for _ in range(n)]
                else:
                    a, b = [(1 << 256) - 1] * n, [rng.getrandbits(256) for _ in range(n)]
                for variant in ([0, 1, 2] if pattern == 1 else [0]):
                    cases.append({'mode': 'prove', 'rule': rule, 'n': n, 'variant': variant,
                        'a': list(map(scalar, a)), 'b': list(map(scalar, b))})
        for n in [0, 1, 2, 3, 8, 16, 64]:
            for pattern in range(3):
                values = [rng.randrange(order) for _ in range(n)]
                if pattern == 1 and n:
                    values[n // 2] = 0
                if pattern == 2:
                    values = [rng.getrandbits(256) for _ in range(n)]
                cases.append({'mode': 'batch', 'rule': rule, 'n': n, 'a': list(map(scalar, values)), 'b': []})
                cases.append({'mode': 'inner', 'rule': rule, 'n': n, 'a': list(map(scalar, values)),
                    'b': [scalar(rng.getrandbits(256)) for _ in range(n)]})
        for n in range(9):
            for pattern in range(2):
                values = [rng.randrange(order) for _ in range(n)]
                if pattern == 1 and n:
                    values[0] = 0
                cases.append({'mode': 'verification_scalars', 'rule': rule, 'n': n, 'a': list(map(scalar, values)), 'b': []})
    architecture = platform.machine()
    flags = ['-march=armv8-a+crypto'] if architecture in ('arm64', 'aarch64') else ['-maes', '-msse2']
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-inner-product-') as temp:
        executable = pathlib.Path(temp) / 'oracle'
        subprocess.run(['clang++', '-std=c++17', '-O2', *flags, '-I', str(args.upstream / 'pvac/include'),
            str(ROOT / 'scripts/node-port/hfhe-inner-product-oracle.cpp'), '-o', str(executable)], check=True)
        lines = []
        for case in cases:
            line = f'{case["mode"]} {case["rule"]} {case["n"]} '
            if case['mode'] == 'prove':
                line += f'{case["variant"]} '
            line += ' '.join(case['a'] + case['b'])
            lines.append(line)
        output = subprocess.check_output([str(executable)], input='\n'.join(lines) + '\n', text=True)
        results = [json.loads(line) for line in output.splitlines()]
        if len(results) != len(cases):
            raise SystemExit('native oracle output count mismatch')
        for case, result in zip(cases, results):
            case['expected'] = result
    report = {'upstream_commit': pin, 'source_sha256': hashes, 'architecture': architecture,
        'scope': 'Native Prior/Wide inner-product proofs, verification and scalar helpers; no complete backend qualification',
        'cases': cases}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Generated {len(cases)} IPP cases, including {sum(c["mode"] == "prove" for c in cases)} proofs and both verifiers under 12 mutations')


if __name__ == '__main__':
    main()
