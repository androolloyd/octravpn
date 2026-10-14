#!/usr/bin/env python3
"""Generate exact native cipher v1-v5 imports, policy boundaries and refusals."""
import argparse
import hashlib
import json
import pathlib
import platform
import random
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def u64(value):
    return struct.pack('<Q', value)


def layer(version, rule=0, parents=(0, 0), rpc=None, pc=None, commitment=None):
    output = bytes([rule])
    output += struct.pack('<QQQ', 7, 11, (1 << 64) - 1) if rule == 0 else struct.pack('<II', *parents)
    if version < 4:
        # R_com is opaque bytes, unlike the individually validated PC/R_PC points.
        output += commitment if commitment is not None else bytes([255]) * 32
    if version == 3:
        points = rpc or []
        output += u64(len(points)) + b''.join(points)
    if 2 <= version < 4:
        points = pc or []
        output += u64(len(points)) + b''.join(points)
    return output


def edge(layer_id=0, index=3, sign=0, weights=(1,), bits=65, words=(0xabcdef, 1)):
    return struct.pack('<IHB', layer_id, index, sign) + u64(len(weights)) + b''.join(
        value.to_bytes(16, 'little') for value in weights) + u64(bits) + u64(len(words)) + b''.join(u64(word) for word in words)


def cipher(version=3, slots=1, layers=(), c0=(), edges=()):
    return b'PVAC' + bytes([version, 0]) + u64(slots) + u64(len(layers)) + b''.join(layers) + u64(len(c0)) + b''.join(
        value.to_bytes(16, 'little') for value in c0) + u64(len(edges)) + b''.join(edges)


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
    hashes = {}
    runtime_sources = json.loads((ROOT / 'docs/rust-node/source-map.json').read_text())['files']
    sources = subprocess.check_output(['git', '-C', str(args.upstream), 'ls-files', 'pvac', 'pvac_ffi/pvac_serialize.hpp'], text=True).splitlines()
    for source in sources:
        native = subprocess.check_output(['git', '-C', str(args.upstream), 'show', f'HEAD:{source}'])
        if (args.upstream / source).read_bytes() != native:
            raise SystemExit(f'modified oracle source: {source}')
        if source in runtime_sources:
            hashes[source] = hashlib.sha256(native).hexdigest()

    cases = []
    def add(name, data, strict=True, cap=True, zeros=0):
        cases.append({'name': name, 'input': data.hex(), 'strict': strict, 'cap': cap, 'zero_fill': zeros})
    point = bytes.fromhex('e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76')
    for version in range(1, 6):
        for slots in (1, 2, 8):
            layers = [layer(version, pc=[point] * slots, rpc=[bytes(32)] * slots), layer(version, rule=1)]
            sample = cipher(version, slots, layers, list(range(slots)), [edge(weights=range(slots)), edge(layer_id=1, sign=1, weights=[(1 << 127) - 2] * slots)])
            add(f'v{version}-slots{slots}', sample)
            if slots == 1:
                for cut in range(len(sample)):
                    add(f'v{version}-truncated-{cut}', sample[:cut])
                add(f'v{version}-trailing', sample + b'\x00')
                add(f'v{version}-magic', b'BAD!' + sample[4:])
                add(f'v{version}-version', sample[:4] + b'\x00' + sample[5:])
                add(f'v{version}-tag', sample[:5] + b'\xff' + sample[6:])
        for strict, cap in [(True, True), (True, False), (False, True), (False, False)]:
            for slots in [0, 8, 9, 4096, 4097, 65536, 65537, (1 << 64) - 1]:
                add(f'v{version}-slots{slots}-policy{strict},{cap}', cipher(version, slots), strict, cap)
            # v4+ materializes one R_PC per slot, even in legacy mode.
            for slots in [0, 8, 9]:
                add(f'v{version}-base-slots{slots}-policy{strict},{cap}', cipher(version, slots, [layer(version)]), strict, cap)
            for slots, count in [(8, 512), (8, 513), (1, 4097)]:
                # Public-size refusal comes before layer decoding. Compact padding
                # satisfies count bounds without allocating accepted huge layers.
                if version >= 4 and (strict or cap):
                    data = b'PVAC' + bytes([version, 0]) + u64(slots) + u64(count)
                    add(f'v{version}-public-cells-{slots}x{count}-policy{strict},{cap}', data, strict, cap, count * 8)

    for version in range(1, 6):
        base = layer(version)
        add(f'v{version}-empty', cipher(version))
        add(f'v{version}-invalid-rule', cipher(version, layers=[layer(version, rule=2)]))
        add(f'v{version}-parent-self', cipher(version, layers=[base, layer(version, rule=1, parents=(0, 1))]))
        add(f'v{version}-parent-out', cipher(version, layers=[base, layer(version, rule=1, parents=(0xffffffff, 0))]))
        add(f'v{version}-c0-length', cipher(version, layers=[base], c0=[1, 2]))
        add(f'v{version}-noncanonical-c0', cipher(version, layers=[base], c0=[(1 << 127) - 1]))
        for kwargs in [dict(layer_id=1), dict(sign=2), dict(index=7), dict(index=65535), dict(bits=64), dict(bits=66), dict(weights=()), dict(weights=[1, 2]), dict(weights=[(1 << 127) - 1]),
                dict(bits=(1 << 20) + 1), dict(bits=65, words=(1,)), dict(bits=1, words=(0xffffffffffffffff,)), dict(bits=0, words=())]:
            add(f'v{version}-edge-{kwargs}', cipher(version, layers=[base], edges=[edge(**kwargs)]))
        if version < 4:
            for points in [dict(pc=[point, point]), dict(rpc=[point, point]), dict(pc=[bytes([255]) * 32]), dict(rpc=[bytes([255]) * 32])]:
                add(f'v{version}-points-{list(points)}-{len(next(iter(points.values())))}', cipher(version, layers=[layer(version, **points)]))
                add(f'v{version}-product-{list(points)}-{len(next(iter(points.values())))}', cipher(version, layers=[base, layer(version, rule=1, **points)]))

    # Check count maximum vs remaining-data precedence without committing 128MB fixtures.
    for count in [(1 << 24), (1 << 24) + 1]:
        prefix = b'PVAC\x04\x00' + u64(1) + u64(count)
        add(f'layer-count-{count}-insufficient', prefix)
        add(f'layer-count-{count}-maximum', prefix, zeros=count * 8)
    rng = random.Random(20261013)
    base = cipher(3, 2, [layer(3, rpc=[point] * 2, pc=[bytes(32)] * 2), layer(3, rule=1)], [7, 9], [edge(weights=[19, 21])])
    for index in range(160):
        mutated = bytearray(base)
        offset = rng.randrange(len(mutated))
        mutated[offset] ^= 1 << rng.randrange(8)
        add(f'mutation-{index}-{offset}', mutated)
    for index in range(128):
        point_bytes = rng.randbytes(32)
        for target in ['rpc', 'pc']:
            add(f'point-encoding-{target}-{index}', cipher(3, layers=[layer(3, **{target: [point_bytes]})]))
    architecture = platform.machine()
    flags = ['-march=armv8-a+crypto'] if architecture in ('arm64', 'aarch64') else ['-maes', '-msse2']
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-cipher-wire-') as temp:
        executable = pathlib.Path(temp) / 'oracle'
        subprocess.run(['clang++', '-std=c++17', '-O2', *flags, '-I', str(args.upstream / 'pvac/include'),
            '-I', str(args.upstream / 'pvac_ffi'), str(ROOT / 'scripts/node-port/hfhe-cipher-wire-oracle.cpp'), '-o', str(executable)], check=True)
        def run(inputs):
            lines = [f'import {int(case["strict"])} {int(case["cap"])} {case["zero_fill"]} {case["input"] or "-"}' for case in inputs]
            results = subprocess.check_output([str(executable)], input='\n'.join(lines) + '\n', text=True)
            parsed = [json.loads(line) for line in results.splitlines()]
            if len(parsed) != len(inputs):
                raise SystemExit('native oracle output count mismatch')
            for case, result in zip(inputs, parsed):
                case['expected'] = result
        run(cases)
        # Compression is a distinct operation: native cipher import rejects its header.
        compressed = [case['expected']['packed'] for case in cases[:10] if 'packed' in case['expected']]
        extra = []
        for index, packed in enumerate(compressed):
            extra.append({'name': f'compressed-input-{index}', 'input': packed, 'strict': True, 'cap': True, 'zero_fill': 0})
        run(extra)
        cases.extend(extra)
    report = {'upstream_commit': pin, 'source_sha256': hashes, 'architecture': architecture,
        'scope': 'Native v1-v5 cipher decoding, v3 outgoing bytes and commitment hash; no encryption, proofs or backend qualification',
        'cases': cases}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Generated {len(cases)} cipher wire vectors')


if __name__ == '__main__':
    main()
