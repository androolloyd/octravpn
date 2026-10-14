#!/usr/bin/env python3
"""Generate signed Pedersen commitment boundaries using the pinned C++ oracle.

Every seed, field and blinding value is deterministic public test material.
These vectors cover signed-field interpretation and reduction modulo the
Ristretto scalar order, independently of seeded key generation.
"""
import argparse
import hashlib
import json
import pathlib
import platform
import random
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCES = [
    'pvac/include/pvac/crypto/ristretto255.hpp',
    'pvac/include/pvac/core/field.hpp',
    'pvac/include/pvac/core/hash.hpp',
    'pvac/include/pvac/core/random.hpp',
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('use a fresh fixture path')
    pin = json.loads((ROOT / 'docs/rust-node/upstream.json').read_text())['commit']
    actual = subprocess.check_output(
        ['git', '-C', str(args.upstream), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != pin:
        raise SystemExit('upstream pin mismatch')
    runtime_sources = json.loads((ROOT / 'docs/rust-node/source-map.json').read_text())['files']
    hashes = {}
    for source in SOURCES:
        original = subprocess.check_output(
            ['git', '-C', str(args.upstream), 'show', f'HEAD:{source}'])
        digest = hashlib.sha256(original).hexdigest()
        if (args.upstream / source).read_bytes() != original:
            raise SystemExit(f'modified native source: {source}')
        if runtime_sources[source] != digest:
            raise SystemExit(f'adopted source map mismatch: {source}')
        hashes[source] = digest

    prime = (1 << 127) - 1
    order = (1 << 252) + 27742317777372353535851937790883648493
    fields = [0, 1, 2, (1 << 63) - 1, 1 << 63, (1 << 64) - 1,
              1 << 64, prime // 2, prime // 2 + 1, prime - 1]
    blinds = [0, 1, 2, order - 1, order, order + 1, 2 * order - 1,
              2 * order, 15 * order - 1, 15 * order,
              (1 << 255) - 1, 1 << 255, (1 << 256) - 1]
    values = [(value, blind) for value in fields for blind in blinds]
    rng = random.Random(809303)
    values.extend((rng.randrange(prime), rng.getrandbits(256)) for _ in range(2048))
    cases = [{'field': value.to_bytes(16, 'little').hex(),
              'blind': blind.to_bytes(32, 'little').hex()} for value, blind in values]
    oracle = ROOT / 'scripts/node-port/hfhe-commitment-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-commitment-') as temp:
        executable = pathlib.Path(temp) / 'oracle'
        subprocess.run(['clang++', '-std=c++17', '-O2', '-I', str(args.upstream / 'pvac/include'),
                        str(oracle), '-o', str(executable)], check=True)
        output = subprocess.check_output([str(executable)], text=True,
            input=''.join(f"{case['field']} {case['blind']}\n" for case in cases))
    expected = output.splitlines()
    if len(expected) != len(cases):
        raise SystemExit('native oracle output count mismatch')
    for case, commitment in zip(cases, expected):
        if len(bytes.fromhex(commitment)) != 32:
            raise SystemExit('native commitment length mismatch')
        case['expected'] = commitment
    report = {
        'upstream_commit': pin,
        'source_sha256': hashes,
        'oracle_sha256': hashlib.sha256(oracle.read_bytes()).hexdigest(),
        'architecture': platform.machine(),
        'scope': 'Signed field commitments and scalar reduction; not complete proof or backend parity',
        'boundary_cases': len(fields) * len(blinds),
        'random_cases': 2048,
        'cases': cases,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Generated {len(cases)} native signed commitment cases')


if __name__ == '__main__':
    main()
