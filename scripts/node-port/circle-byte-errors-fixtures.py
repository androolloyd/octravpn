"""Byte-preserving Circle refusals and receipts through native epoch execution."""
import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('calls', ROOT / 'scripts/node-port/circle-octb-execution-fixtures.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)


def fixtures():
    out = []
    wire, Program = calls.wire, calls.Program
    stop, revert = wire.ins(0x17), wire.ins(0x18)

    def add(name, program, methods):
        deploy = calls.tx('deploy', calls.code.payload(runtime='octb', code_b64=calls.b64(program.image())), 1, to='$derive')
        transactions = [deploy] + [calls.tx('call', [], i + 2, method=method, amount=amount) for i, (method, amount) in enumerate(methods)]
        out.append(dict(name=name, transactions=transactions, entries=[],
                        accounts=[dict(address=calls.b64(calls.SENDER), nonce=0, balance='10000000')],
                        epoch=3, now=123.5, float=False, math=False, circle_policy=False, wasm_compute=False))

    def state(program):
        program.method('state', [wire.ins(0x1b, 1), wire.ins(0x1e, 0, 1), program.read('key', 2), program.event('state', 0, 2), stop])

    for tag, reason in itertools.product([2, 3], [b'', b'\xff\x00reason', b'\xc0\xaf\xed\xa0\x80', b'\"\\\r\n\t\x01\xfe']):
        p = Program()
        p.method('fail', [p.load(1, calls.TARGET), p.load(2, 100, 0), wire.ins(0x23, 0, 1, 2), p.store('key', 2),
                          p.event('Require'), p.load(3, reason, tag), p.event('Require', 3, 2),
                          p.load(3, b'later\xff'), p.event('Require', 3), revert])
        state(p)
        add('Require bytes ' + repr((tag, reason)), p, [('fail', 1000), ('state', 0), ('fail', 500), ('state', 0)])
    for key in [b'hfhe_policy:\xff', b'object_policy:\xff', b'transport_policy:\xff', b'\x00\xff', b'ordinary\xff', b'\xff']:
        p = Program()
        p.method('write', [p.load(1, key), p.load(2, b'value\xff'), wire.ins(0x11, 1, 2), p.event(b'write\xff', 1, 2), stop])
        p.method('read', [p.read(key, 0), p.event(b'read\xff', 0), stop])
        add('storage bytes ' + repr(key), p, [('write', 1000), ('read', 0), ('write', 500), ('read', 0)])
    for method in [b'\xffmethod', b'\x00\xff', b'\"\\\r\n\t\xfe']:
        p = Program()
        p.method(method, [p.load(0, b'return\xff'), p.event(b'event\x00\xff', 0), stop])
        add('method and event bytes ' + repr(method), p, [(method, 0), (b'missing\xff', 0), (method, 0)])
    for field in ['runtime', 'privacy_class', 'browser_mode', 'resource_mode']:
        p = Program().method('ok', [stop])
        add('deployment refusal bytes ' + field, p, [])
        valid = out[-1]['transactions'][0]
        invalid = copy.deepcopy(valid)
        payload = calls.code.payload(runtime='octb', code_b64=calls.b64(p.image())) | {field: '$BINARY'}
        invalid['params'] = calls.b64(json.dumps(payload, separators=(',', ':')).encode().replace(b'$BINARY', b'\xff\xfe'))
        out[-1]['transactions'] = [invalid, valid]
    cases = []
    for proof, inspect, storage in itertools.product([False, True], repeat=3):
        for original in out:
            cases.append(copy.deepcopy(original) | dict(proof=proof, inspect=inspect, storage_proof=storage))
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upstream', required=True, type=pathlib.Path)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    counter = json.loads((ROOT / 'crates/octra-node-runtime/tests/fixtures/circle-view.json').read_text())
    # Warnings can echo arbitrary method bytes to stdout. Keep the oracle JSON
    # transport UTF-8 by using the native logging API, without modifying source.
    oracle_source = b'let () = Octra_log._set_level Octra_log.FATAL\n' + (ROOT / 'scripts/node-port/circle-code-oracle.ml').read_bytes()
    with tempfile.TemporaryDirectory(prefix='octra-circle-bytes-') as directory:
        oracle = pathlib.Path(directory) / 'main.ml'
        oracle.write_bytes(oracle_source)
        report = calls.native.run(args.upstream, args.builder_image, oracle,
                                  dict(wasm_b64=counter['wasm_b64'], cases=fixtures()),
                                  'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix str')
    report.update(wasm_b64=counter['wasm_b64'], wasm_sha256=counter['wasm_sha256'], guest_source_sha256=counter['guest_source_sha256'],
                  generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                  generator_dependencies={name: hashlib.sha256((ROOT / 'scripts/node-port' / name).read_bytes()).hexdigest() for name in ['circle-code-fixtures.py', 'octb-execution-fixtures.py', 'circle-octb-execution-fixtures.py']},
                  scope='Unmodified native Circle and epoch execution with arbitrary byte strings: Require and commit refusals, binary method/event names, rollback of value and storage, retained fees/nonces, exact roots/accounts/receipts. Independent proof-execution, VM-bytes and storage-proof modes. No full-node qualification.')
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(report['cases']), 'native Circle byte-string epochs')


if __name__ == '__main__':
    main()
