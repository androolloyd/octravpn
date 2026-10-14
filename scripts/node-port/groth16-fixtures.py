#!/usr/bin/env python3
"""Compare native Groth16 wire verification and VM gates without source patches."""
import argparse
import base64
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def encoded(value):
    return base64.b64encode(value).decode()

def fixtures(upstream):
    converter = load('zk_convert', upstream / 'test/zk_convert.py')
    vectors = upstream / 'test/cases/zk/multiplier'
    key = converter.encode_vk(json.loads((vectors / 'verification_key.json').read_text()))
    proof = converter.encode_proof(json.loads((vectors / 'proof.json').read_text()))
    inputs = converter.encode_inputs(json.loads((vectors / 'public.json').read_text()))
    valid = [key, proof, inputs]
    cases = []
    def add(name, args=valid, **options):
        case = dict(name=name, args=[{'str': encoded(a)} for a in args],
                    view=True, limit=1_000_000, **options)
        cases.append(case)
        return case
    # Three native wire formats: bytes, base64 strings, and typed byte values.
    for kind, b64 in itertools.product(['str', 'bytes', 'addr'], [False, True]):
        for strict, byte_budget in itertools.product([False, True], repeat=2):
            c = add(f'valid {kind} base64={b64} strict={strict} budget={byte_budget}', strict=strict, bytes=byte_budget)
            c['args'] = [{kind: encoded(encoded(a).encode() if b64 else a)} for a in valid]
    for part, raw in enumerate(valid):
        for length in sorted(set([0, 1, 5, 6, 9, 10, len(raw)-1, len(raw)+1, 3000])):
            args = valid.copy(); args[part] = (raw + bytes(3001))[:length]
            add(f'length {part} {length}', args)
        for offset in range(0, len(raw), 31):
            args = valid.copy(); changed = bytearray(raw); changed[offset] ^= 1; args[part] = bytes(changed)
            add(f'mutation {part} {offset}', args)
    for part, offsets in [(0, range(10, len(key), 32)), (1, range(6, len(proof), 32)), (2, range(0, len(inputs), 32))]:
        modulus = converter.BN254_R if part == 2 else converter.BN254_P
        for offset in offsets:
            args = valid.copy(); changed = bytearray(args[part]); changed[offset:offset+32] = modulus.to_bytes(32, 'big'); args[part] = bytes(changed)
            add(f'noncanonical field {part} {offset}', args)
    for part, offset, size in [(0, 10, 64), (0, 74, 128), (0, 458, 64), (1, 6, 64), (1, 70, 128), (1, 198, 64)]:
        args = valid.copy(); args[part] = args[part][:offset] + bytes(size) + args[part][offset+size:]
        add(f'infinity {part} {offset}', args)
    for limit in [0, 49_999, 50_000, 50_001, 69_999, 70_000, 70_001, 70_002]:
        for byte_budget in [False, True]:
            c = add(f'effort {limit} {byte_budget}', bytes=byte_budget); c['limit'] = limit
    for proof_exec, fhe_work, math, view in itertools.product([False, True], repeat=4):
        c = add(f'activation {proof_exec} {fhe_work} {math} {view}', proof_exec=proof_exec, fhe_work=fhe_work, math=math)
        c['view'] = view
    for view, asynchronous in itertools.product([False, True], repeat=2):
        for unavailable in [False, True]:
            c = add(f'worker view={view} async={asynchronous} unavailable={unavailable}', proof_exec=True, fhe_work=True, math=True, unavailable=unavailable)
            c.update(view=view, **{'async': asynchronous})
    for part in range(3):
        c = add(f'integer operand {part}'); c['args'][part] = {'int': 0}
    # A public algebraic identity provides valid arbitrary-size keys without
    # trusted setup: e(-a,b)*e(a,b)*e(-a,b)*e(a,b)=1, with all inputs zero.
    # These are verifier vectors, never deployment keys.
    a, b = proof[6:70], proof[70:198]
    negative_a = a[:32] + ((-int.from_bytes(a[32:], 'big')) % converter.BN254_P).to_bytes(32, 'big')
    for count in [0, 1, 6, 31, 32, 33, 255]:
        identity_key = b'OG16V1' + count.to_bytes(4, 'big') + a + b * 3 + negative_a + a * count
        identity_proof = b'OG16P1' + a + b + a
        add(f'public input count {count}', [identity_key, identity_proof, bytes(count * 32)])
        if count <= 32:
            c = add(f'count {count} active worker', [identity_key, identity_proof, bytes(count * 32)], proof_exec=True, fhe_work=True, math=True)
            c['view'] = False
    return cases

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--upstream', required=True, type=Path)
    p.add_argument('--builder-image', required=True)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    native = load('native', ROOT / 'scripts/node-port/native-oracle.py')
    oracle = ROOT / 'scripts/node-port/groth16-oracle.ml'
    report = native.run(args.upstream, args.builder_image, oracle, fixtures(args.upstream), 'octra_vm octra_core yojson lwt.unix zk_ffi')
    report['generator_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['vector_sha256'] = {str(p.relative_to(args.upstream)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [args.upstream / 'test/zk_convert.py', *sorted((args.upstream / 'test/cases/zk/multiplier').glob('*.json'))]}
    report['scope'] = 'Native BN254 proof bytes, VM charging, activation, synchronous/stepped/async verification and worker outages. No full-node or funded VPN qualification.'
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(report['cases']), 'native Groth16 cases')

if __name__ == '__main__':
    main()
