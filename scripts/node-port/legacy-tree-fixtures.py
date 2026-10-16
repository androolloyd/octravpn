#!/usr/bin/env python3
"""Pinned native Node/Tree bytes, signatures, float hashes and finalize aliasing."""
import argparse
import base64
import importlib.util
import json
import pathlib
import random
import struct

ROOT = pathlib.Path(__file__).resolve().parents[2]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=pathlib.Path, required=True)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('require a fresh fixture path')
    spec = importlib.util.spec_from_file_location('native_oracle', pathlib.Path(__file__).with_name('native-oracle.py'))
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    rng = random.Random(20261015)
    timestamps = [0.0, -0.0, 1.0, 1e-7, 1e-6, 1e20, 1e21, -1e22,
                  1.2345678901234567, 5e-324, 1.7976931348623157e308]
    for _ in range(48):
        bits = rng.getrandbits(64)
        if (bits >> 52) & 2047 != 2047:
            timestamps.append(struct.unpack('>d', bits.to_bytes(8, 'big'))[0])
    inputs = []
    def encoded(n):
        return base64.b64encode(json.dumps(n, separators=(',', ':')).encode()).decode()
    def node(time, score=1.0):
        return dict(id='node\\\"\x00id', parent=None, children=['older'], state_hash='ab'*32,
                    txs=['tx\x00one', 'tx-two'], txs_with_hashes=[dict(hash='ef'*32, data='tx\x00one')],
                    validator='validator', metrics={k: score for k in ('ths','npt','svb','sp','cps')},
                    timestamp=time, signature='observed-signature')
    for time in timestamps:
        inputs.append(dict(operation='node', node_b64=encoded(node(time))))
    for epoch in [0, 1, 17, (1 << 62)-1]:
        for score in [1.0, 0.54, 0.55]:
            inputs.append(dict(operation='tree', epoch=str(epoch), node_b64=encoded(node(123.456789012345, score))))
    report = native.run(args.upstream, args.builder_image, pathlib.Path(__file__).with_name('legacy-tree-oracle.ml'), inputs, 'octra_core yojson base64')
    report['inputs'] = inputs
    report['scope'] = 'Native diagnostic Node/Tree bytes and signatures; no BFT commitment or public-network qualification'
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'cases':len(inputs), 'upstream_commit':report['upstream_commit'], 'out':str(args.out)}))

if __name__ == '__main__':
    main()
