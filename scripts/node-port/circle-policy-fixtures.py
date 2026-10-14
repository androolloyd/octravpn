#!/usr/bin/env python3
"""Native epoch tests where the Circle update policy changes the outcome."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import itertools
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=pathlib.Path, required=True)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    native = module('native', ROOT / 'scripts/node-port/native-oracle.py')
    circles = module('circles', ROOT / 'scripts/node-port/circle-transaction-fixtures.py')
    source = ROOT / 'scripts/node-port/circle-policy-guest.rs'
    with tempfile.TemporaryDirectory(prefix='octra-circle-policy-') as directory:
        target = pathlib.Path(directory) / 'policy.wasm'
        command = ['rustc', '--edition=2021', '--crate-type=cdylib',
                   '--target=wasm32-unknown-unknown', '-C', 'panic=abort',
                   '-C', 'opt-level=2', str(source), '-o', str(target)]
        subprocess.run(command, check=True)
        wasm = target.read_bytes()
    code = base64.b64encode(wasm).decode()
    seed = circles.fixtures()[0]
    seed['accounts'][0]['balance'] = '10000000'
    seed['transactions'][0].update(method=circles.b64('update'), amount='0', ou='100')
    inputs = []
    for proof, inspect, policy, compute in itertools.product([False, True], repeat=4):
        case = copy.deepcopy(seed)
        case.update(wasm=code, proof=proof, storage_proof=proof, inspect=inspect,
                    circle_policy=policy, wasm_compute=compute)
        inputs.append(case)
    report = native.run(args.upstream, args.builder_image,
                        ROOT / 'scripts/node-port/epoch-circle-oracle.ml', inputs,
                        'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix')
    for case in report['cases']:
        case['input'].pop('wasm')
        expected = case['expected']['result']
        refused = case['input']['circle_policy'] or case['input']['inspect']
        if ('error' in expected or bool(expected['confirmed']) == refused
                or len(expected['rejected']) != int(refused)):
            raise RuntimeError('Native policy-sensitive outcome differs')
        if refused and base64.b64decode(expected['rejected'][0]['reason']) != (
                b'wasm_v1 nonpersistent host imports are disabled for updates'):
            raise RuntimeError('Native policy rejection differs')
    report.update(wasm_b64=code, wasm_sha256=hashlib.sha256(wasm).hexdigest(),
                  guest_source_sha256={str(source.relative_to(ROOT)): hashlib.sha256(source.read_bytes()).hexdigest()},
                  rustc=subprocess.check_output(['rustc', '--version'], text=True).strip(),
                  scope='Unmodified native BFT Circle execution of a purpose-built guest with an unused session import; prior updates succeed, activated policy or inspection refuses the module. Complete fees, state roots and receipts across 16 mode combinations.')
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(report['cases']), 'native policy-sensitive Circle epochs')


if __name__ == '__main__':
    main()
