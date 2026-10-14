#!/usr/bin/env python3
"""Generate exact native linear arithmetic, graph compaction and budget vectors."""
import argparse
import hashlib
import json
import pathlib
import platform
import random
import runpy
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
WIRE = runpy.run_path(str(ROOT / 'scripts/node-port/hfhe-cipher-wire-fixtures.py'))
cipher, layer, edge = (WIRE[name] for name in ['cipher', 'layer', 'edge'])


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
    sources = subprocess.check_output(['git', '-C', str(args.upstream), 'ls-files', 'pvac', 'pvac_ffi/pvac_serialize.hpp'], text=True).splitlines()
    runtime = json.loads((ROOT / 'docs/rust-node/source-map.json').read_text())['files']
    hashes = {}
    for source in sources:
        data = subprocess.check_output(['git', '-C', str(args.upstream), 'show', f'HEAD:{source}'])
        if data != (args.upstream / source).read_bytes():
            raise SystemExit(f'modified oracle source: {source}')
        if source in runtime:
            hashes[source] = hashlib.sha256(data).hexdigest()
    rng = random.Random(20261013)
    modulus = (1 << 127) - 1
    cases = []
    def add(op, left, right=b'', budget=1200000, value=0, scalar=0, math=False, name=''):
        cases.append({'name': name or op, 'op': op, 'left': left.hex(), 'right': right.hex(),
            'budget': budget, 'field': value.to_bytes(16, 'little').hex(), 'scalar_bits': str(scalar), 'math': math})
    for slots in [1, 2, 8]:
        graph = [layer(3), layer(3), layer(3, rule=1), layer(3, rule=1, parents=(2, 0)), layer(3)]
        weights = [rng.randrange(modulus) for _ in range(slots)]
        # Duplicate-edge cancellation needs both field addition and sigma XOR.
        edges = [edge(3, 5, 1, weights), edge(0, 3, 0, [0]*slots, words=(0, 0)),
            edge(3, 5, 1, [(modulus - value) % modulus for value in weights]),
            edge(0, 2, 1, [2]*slots, words=(0, 1)), edge(3, 1, 0, [5]*slots),
            edge(3, 1, 1, [5]*slots)]
        for populated in [False, True]:
            left = cipher(3, slots, graph, [7] * slots if populated else [], edges)
            right = cipher(3, slots, graph, [11] * slots if populated else [], list(reversed(edges)))
            for op in ['add', 'sub', 'compact_edges', 'compact_layers', 'guard']:
                for budget in [0, 1, 6, 12, 1200000]:
                    add(op, left, right, budget, name=f'{op}-{slots}-{populated}-budget{budget}')
            add('neg', left)
            add('ubk', left)
            add('ubk', cipher(3, slots, [layer(3)], edges=[edge(weights=weights, words=(0xffffffffffffffff, 0xffffffffffffffff))]))
            for value in [0, 1, 2, (1 << 63), (1 << 64)-1, (1 << 126), modulus - 1]:
                for op in ['scale', 'div_const']:
                    add(op, left, value=value)
                for math in [False, True]:
                    add('add_const', left, value=value, math=math)
                    add('sub_const', left, value=value, math=math)
            for scalar in [0, 1, (1 << 63)-1, (1 << 63), (1 << 64)-1]:
                add('scale_i64', left, scalar=scalar)
                add('scale_u64', left, scalar=scalar)
            # A valid ciphertext with no live edges loses all layers on compact.
            add('compact_layers', cipher(3, slots, graph, [], []))
            add('add', left, cipher(3, slots, graph, [11]*slots if not populated else []))
            add('sub', left, cipher(3, slots + 1))
    for kind, bad_edge in [('index', edge(index=7)), ('sigma', edge(bits=64, words=(1,)))]:
        value = cipher(3, 1, [layer(3)], [], [bad_edge])
        for op in ['compact_edges', 'guard', 'add', 'sub']:
            for budget in [0, 1, 1200000]:
                add(op, value, cipher(), budget=budget, name=f'{op}-invalid-{kind}-budget{budget}')
    for op in ['compact_edges', 'compact_layers', 'guard', 'neg', 'scale', 'add', 'sub', 'ubk']:
        add(op, cipher(), cipher(), budget=0)
    architecture = platform.machine()
    flags = ['-march=armv8-a+crypto'] if architecture in ('arm64', 'aarch64') else ['-maes', '-msse2']
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-arithmetic-') as temp:
        executable = pathlib.Path(temp) / 'oracle'
        subprocess.run(['clang++', '-std=c++17', '-O2', *flags, '-I', str(args.upstream / 'pvac/include'),
            '-I', str(args.upstream / 'pvac_ffi'), str(ROOT / 'scripts/node-port/hfhe-arithmetic-oracle.cpp'), '-o', str(executable)], check=True)
        lines = []
        for case in cases:
            value = int.from_bytes(bytes.fromhex(case['field']), 'little')
            lines.append(f'{case["op"]} {case["budget"]} {int(case["math"])} {value & ((1 << 64)-1)} {value >> 64} {case["scalar_bits"]} {case["left"]} {case["right"] or "-"}')
        output = subprocess.check_output([str(executable)], input='\n'.join(lines) + '\n', text=True)
        results = [json.loads(line) for line in output.splitlines()]
        if len(results) != len(cases):
            raise SystemExit('native oracle output count mismatch')
        for case, result in zip(cases, results):
            case['expected'] = result
    report = {'upstream_commit': pin, 'source_sha256': hashes, 'architecture': architecture,
        'scope': 'Native linear arithmetic, graph compaction, UBK and commitment hash; no multiplication, proofs or backend qualification', 'cases': cases}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Generated {len(cases)} arithmetic vectors')


if __name__ == '__main__':
    main()
