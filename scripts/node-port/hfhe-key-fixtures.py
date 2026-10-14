#!/usr/bin/env python3
"""Generate seeded keys, matrix samples and compression from pinned native PVAC.

Seeds are deterministic public test material, never a wallet or launch secret.
Small key vectors include every byte; the full-size vector includes SHA-256
and lengths over every serialized byte, plus the complete secret-key fixture.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('use a fresh fixture path')
    pin = json.loads((ROOT / 'docs/rust-node/upstream.json').read_text())['commit']
    actual = subprocess.check_output(['git', '-C', str(args.upstream), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != pin:
        raise SystemExit('upstream pin mismatch')
    sources = subprocess.check_output(['git', '-C', str(args.upstream), 'ls-files', 'pvac', 'pvac_ffi/pvac_serialize.hpp'], text=True).splitlines()
    runtime_sources = json.loads((ROOT / 'docs/rust-node/source-map.json').read_text())['files']
    hashes = {}
    for source in sources:
        native = subprocess.check_output(['git', '-C', str(args.upstream), 'show', f'HEAD:{source}'])
        if (args.upstream / source).read_bytes() != native:
            raise SystemExit(f'modified oracle source: {source}')
        if source in runtime_sources:
            hashes[source] = hashlib.sha256(native).hexdigest()

    rng = random.Random(20261013)
    seeds = [bytes(32), bytes([255]) * 32, bytes(range(32))] + [rng.randbytes(32) for _ in range(17)]
    profiles = [
        [3, 1, 1, 0, 0, 0, 1, 1, 1],
        [7, 63, 9, 0, 9, 63, 63, 64, 8],
        [9, 65, 17, 65, 1, 0, 65, 129, 8],
        [21, 127, 31, 13, 17, 12, 127, 257, 8],
        [337, 192, 41, 31, 0, 7, 129, 4096, 8],
    ]
    key_cases = [{'seed': seed.hex(), 'params': profiles[i % len(profiles)], 'profile': 2} for i, seed in enumerate(seeds)]
    key_cases.append({'seed': bytes(range(32)).hex(), 'params': [337, 8192, 16384, 192, 128, 128, 4096, 16384, 8], 'profile': 2})
    base = profiles[3]
    for index, value in [(0, 2), (0, 4), (1, 0), (2, -1), (3, -1), (3, 128), (4, 32), (5, -1), (5, 128), (6, 0), (7, 0), (8, 0)]:
        params = base.copy()
        params[index] = value
        key_cases.append({'seed': bytes(32).hex(), 'params': params, 'profile': 2})
    key_cases.extend([dict(case, profile=1) for case in key_cases[:20]])
    matrix_cases = [
        [k, n, factor, str(tag)] for k, n in [(0, 0), (1, 1), (3, 7), (19, 19), (127, 192)]
        for factor in [0, 1, 2, 8] for tag in [0, (1 << 64) - 1]
    ] + [[-1, 1, 0, '0'], [1, -1, 0, '0'], [2, 1, 0, '0'], [2, 7, (1 << 64) - 1, '0']]
    architecture = platform.machine()
    flags = ['-march=armv8-a+crypto'] if architecture in ('arm64', 'aarch64') else ['-maes', '-msse2']
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-key-') as temp:
        executable = pathlib.Path(temp) / 'oracle'
        subprocess.run(['clang++', '-std=c++17', '-O2', *flags, '-I', str(args.upstream / 'pvac/include'),
            '-I', str(args.upstream / 'pvac_ffi'), str(ROOT / 'scripts/node-port/hfhe-key-oracle.cpp'), '-o', str(executable)], check=True)

        def run(lines):
            output = subprocess.check_output([str(executable)], input=''.join(line + '\n' for line in lines), text=True)
            result = [json.loads(line) for line in output.splitlines()]
            if len(result) != len(lines):
                raise SystemExit('native oracle output count mismatch')
            return result

        expected = run([('key_v6 ' if case['profile'] == 1 else 'key ') + case['seed'] + ' ' + ' '.join(map(str, case['params'])) for case in key_cases])
        for case, result in zip(key_cases, expected):
            case['expected'] = result
        matrix_results = run(['matrix ' + ' '.join(map(str, case)) for case in matrix_cases])
        data = [bytes(), bytes([0]), bytes([255]), bytes(range(256)), bytes(512), bytes([255]) * 512,
            b'PVAC\x05\x01' * 128] + [rng.randbytes(length) for length in [3, 7, 31, 64, 127, 1024, 4096]]
        compressed = run(['pack ' + (raw.hex() or '-') for raw in data])
        malformed = [bytes(), b'\xec', b'\x00' * 5, bytes.fromhex('ec02000001'), bytes.fromhex('ec00000001'),
            bytes.fromhex('ec00000100ff')]
        for raw, packed in zip(data, compressed):
            wire = bytes.fromhex(packed['bytes'])
            malformed.extend([wire, wire[:-1], wire[:5], wire + b'\x00\xff'])
            for size in [0, len(raw) + 1, max(0, len(raw) - 1)]:
                malformed.append(wire[:1] + size.to_bytes(4, 'big') + wire[5:])
        decompressed = run(['unpack ' + (wire.hex() or '-') for wire in malformed])
        pub_inputs, sec_inputs = [], []
        for key in key_cases[:5]:
            raw = bytes.fromhex(key['expected']['raw'])
            secret = bytes.fromhex(key['expected']['secret'])
            pub_inputs.extend([raw, bytes.fromhex(key['expected']['packed'])])
            sec_inputs.append(secret)
            for version in range(1, 6):
                legacy_pub = raw[:-33] if version < 3 else raw[:-1] if version < 5 else raw
                legacy_sec = secret[:38] + secret[134:] if version < 3 else secret[:86] + secret[134:] if version < 5 else secret
                pub_inputs.append(legacy_pub[:4] + bytes([version]) + legacy_pub[5:])
                sec_inputs.append(legacy_sec[:4] + bytes([version]) + legacy_sec[5:])
            for inputs, wire in [(pub_inputs, raw), (sec_inputs, secret)]:
                cuts = range(len(wire)) if key is key_cases[0] else [0, 3, 4, 5, 6, 38, 39, 85, 86, 98, 106, 114, len(wire)-1]
                inputs.extend(wire[:cut] for cut in cuts)
                inputs.extend([wire+b'\x00', b'BAD!'+wire[4:], wire[:4]+b'\x00'+wire[5:], wire[:5]+b'\xff'+wire[6:]])
                for _ in range(12):
                    changed = bytearray(wire)
                    position = rng.randrange(len(wire))
                    changed[position] ^= 1 << rng.randrange(8)
                    inputs.append(bytes(changed))
            # Find exact column, permutation and field offsets in the raw v5 key.
            offset = 106
            columns = int.from_bytes(raw[offset:offset+8], 'little'); offset += 8
            bitvec_start = offset
            for _ in range(columns):
                words = int.from_bytes(raw[offset+8:offset+16], 'little')
                offset += 16 + words*8
            perm_len = int.from_bytes(raw[offset:offset+8], 'little'); offset += 8
            perm_start = offset; offset += perm_len*4
            inv_len = int.from_bytes(raw[offset:offset+8], 'little'); offset += 8
            inv_start = offset; offset += inv_len*4
            omega_start = offset + 32
            for position, size, value in [(6,4,0), (10,4,0), (14,4,0), (106,8,(1<<64)-1),
                    (bitvec_start,8,(1<<20)+1), (bitvec_start+8,8,0), (perm_start,4,(1<<32)-1),
                    (inv_start,4,(1<<32)-1), (omega_start,16,(1<<127)-1), (len(raw)-1,1,3)]:
                pub_inputs.append(raw[:position]+value.to_bytes(size,'little')+raw[position+size:])
            pub_inputs.append(raw[:-33]+bytes([255])*32+raw[-1:])
            for position in [38, 86]:
                sec_inputs.append(secret[:position]+((1<<127)-1).to_bytes(16,'little')+secret[position+16:])
            sec_inputs.append(secret[:134]+((1<<64)-1).to_bytes(8,'little')+secret[142:])
        imported_pub = run(['import_pub ' + (wire.hex() or '-') for wire in pub_inputs])
        imported_sec = run(['import_sec ' + (wire.hex() or '-') for wire in sec_inputs])
    report = {'upstream_commit': pin, 'source_sha256': hashes, 'architecture': architecture,
        'scope': 'Seeded v5 keys, matrix sampling and compression; not full HFHE or backend qualification',
        'keys': key_cases,
        'matrix': [{'input': case, 'expected': result} for case, result in zip(matrix_cases, matrix_results)],
        'pack': [{'input': raw.hex(), 'expected': result} for raw, result in zip(data, compressed)],
        'unpack': [{'input': wire.hex(), 'expected': result} for wire, result in zip(malformed, decompressed)],
        'import_pub': [{'input': wire.hex(), 'expected': result} for wire, result in zip(pub_inputs, imported_pub)],
        'import_sec': [{'input': wire.hex(), 'expected': result} for wire, result in zip(sec_inputs, imported_sec)]}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Generated {len(key_cases)} key, {len(matrix_cases)} matrix, {len(data)} pack and {len(malformed)} unpack cases')
    print(f'Generated {len(pub_inputs)} public and {len(sec_inputs)} secret key import/refusal cases')


if __name__ == '__main__':
    main()
