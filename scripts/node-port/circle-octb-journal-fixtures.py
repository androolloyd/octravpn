"""OCTB/WASM nested Circle calls against production native epoch execution."""
import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('execution', ROOT / 'scripts/node-port/circle-octb-execution-fixtures.py')
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
b64, ins, stop = e.b64, e.wire.ins, e.wire.ins(0x17)


def seed(address, raw, enabled=True, wasm=False):
    digest = hashlib.sha256(raw).hexdigest()
    fields = {'runtime': 'wasm_v1' if wasm else 'octb', 'version': '1', 'owner': e.SENDER,
              'code_hash': digest, 'stable_root': '0' * 64, 'assets_root': '0' * 64,
              'privacy/class': 'public', 'browser/mode': 'gateway_allowed', 'resources/mode': 'public_resources',
              'limits/max_stable_bytes': '33554432', 'limits/max_assets_bytes': '33554432',
              'limits/max_inline_value': '65536', 'limits/max_wasm_bytes': '33554432', 'program/code_b64': b64(raw)}
    if enabled:
        fields['call_code'] = digest
    return [dict(path=list(map(b64, ['circles', address, *key.split('/')])), value=b64(value)) for key, value in fields.items()]


def fixtures(wasm):
    out = []
    parent, child = e.Program(), e.Program()
    for method, times, revert in [('chain', 1, False), ('twice', 2, False), ('after_fail', 1, True), ('many', 4, False)]:
        body = [e.mem(1, 1001), e.mem(2, 1002)] + [e.mem(10 + n, 1003 + n) for n in range(4)]
        body += [parent.load(3, 'before'), parent.store('parent', 3), parent.event('Before', 3)]
        for _ in range(times):
            body += [ins(0x21, 0, 1, 2, 10, 4)]
        body += [parent.read('parent', 3), parent.store('return', 0), parent.event('After', 0, 3), ins(0x18) if revert else stop]
        parent.method(method, body)
    parent.method('mutate', [parent.load(0, 'reentered'), parent.store('parent', 0), parent.event('Inner', 0), stop])
    parent.method('recurse', [e.mem(10, 1001), parent.load(11, 0, 0), ins(0x07, 12, 10, 11), e.wire.jump(0x15, 999, 12),
                             parent.load(11, 1, 0), ins(0x01, 10, 10, 11), ins(0x1b, 1), parent.load(2, 'recurse'),
                             ins(0x21, 0, 1, 2, 10, 1), e.wire.jump(0x16, 999), parent.event('Depth', 10), stop])
    child.method('echo', [e.mem(n, 1001 + n) for n in range(4)] + [child.event('Echo', 0, 1, 2, 3), child.store('child', 0), stop])
    child.method('context', [ins(tag, n) for n, tag in enumerate([0x19, 0x1a, 0x1b, 0x1c, 0x7b, 0x1d, 0x1f, 0x20, 0x7a])] + [child.event('Context', *range(9)), stop])
    child.method('bytes', [child.load(0, b'\x00binary\xff', 3), child.event('Bytes', 0), stop])
    child.method('address', [ins(0x1b, 0), stop])
    child.method('large', [child.load(0, 2**190, 0), stop])
    child.method('fail', [child.load(0, 'discard'), child.store('child', 0), child.event('Require', 0), ins(0x18)])
    child.method('money', [child.load(1, 'oct' + '7' * 44), child.load(2, 3, 0), ins(0x23, 0, 1, 2), child.event('Money', 0), stop])
    child.method('reserved', [child.load(0, 'invalid'), child.store('hfhe_policy:unknown', 0), stop])
    child.method('events', [child.event('Loop') for _ in range(64)] + [stop])
    child.method('empty', [stop])
    parent_raw, child_raw = parent.image(), child.image()

    def add(name, method, params, *, parent_wasm=False, child_wasm=False, entries=None, **fields):
        out.append(dict(name=name, transactions=[e.tx('call', params, 1, method=method, amount=20, to=e.CIRCLE, ou=5_000_000)],
                        entries=entries if entries is not None else seed(e.CIRCLE, wasm if parent_wasm else parent_raw, wasm=parent_wasm) + seed(e.TARGET, wasm if child_wasm else child_raw, wasm=child_wasm),
                        accounts=[dict(address=b64(address), nonce=0, balance=str(balance)) for address, balance in [(e.SENDER, 100_000_000), (e.CIRCLE, 100), (e.TARGET, 40)]],
                        epoch=3, now=123.5, proof=True, inspect=False, fhe_work=False, storage_proof=True, float=False, math=False, circle_policy=False, wasm_compute=False, **fields))

    for outer in ['chain', 'twice', 'after_fail']:
        for inner, params in [('echo', [True, 'raw', 2**140]), ('context', []), ('bytes', []), ('address', []), ('large', []), ('fail', []), ('reserved', []), ('money', []), ('missing', [])]:
            add('OCTB ' + outer + ' ' + inner, outer, [e.TARGET, inner, *params])
        add('OCTB reentry ' + outer, outer, [e.CIRCLE, 'mutate'])
    for depth in [0, 1, 2, 7, 8, 9]:
        add('recursive depth ' + str(depth), 'recurse', [depth])
    for count in [60, 61, 62, 63, 64]:
        add('OCTB to WASM shared budget ' + str(count), 'many', [e.TARGET, 'events', count], child_wasm=True)
    add('OCTB shared budget', 'many', [e.TARGET, 'events'])
    add('child call code disabled', 'chain', [e.TARGET, 'echo'], entries=seed(e.CIRCLE, parent_raw) + seed(e.TARGET, child_raw, False))
    add('parent call code disabled', 'chain', [e.TARGET, 'echo'], entries=seed(e.CIRCLE, parent_raw, False) + seed(e.TARGET, child_raw))
    for target in ['missing', 'oct' + '8' * 44]:
        add('missing child ' + target, 'chain', [target, 'echo'])
    for inner, params in [('return', [True]), ('return', [2**130]), ('empty', []), ('money', ['oct' + '7' * 44, '3']), ('fail', ['oct' + '7' * 44, '3'])]:
        add('OCTB to WASM ' + inner + repr(params), 'chain', [e.TARGET, inner, *params], child_wasm=True)
    for inner, params in [('echo', [True, 'hello', 77]), ('bytes', []), ('address', []), ('large', []), ('context', []), ('money', []), ('fail', [])]:
        add('WASM to OCTB ' + inner, 'chain', [e.TARGET, inner, *params], parent_wasm=True)
    for inner in ['chain', 'after_fail']:
        add('failure then success ' + inner, inner, [e.TARGET, 'fail' if inner == 'chain' else 'money'])
        out[-1]['transactions'].append(e.tx('call', [e.TARGET, 'money'], 2, method='chain', to=e.CIRCLE, ou=5_000_000))
    cases = []
    for inspect, storage, fhe in itertools.product([False, True], repeat=3):
        for original in out:
            cases.append(copy.deepcopy(original) | dict(inspect=inspect, storage_proof=storage, fhe_work=fhe))
    # Both callers enforce the native prior-mode cross-call restriction.
    cases += [copy.deepcopy(v) | dict(proof=False) for v in cases[:3]]
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upstream', required=True, type=pathlib.Path)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    guest_path = ROOT / 'crates/octra-node-runtime/tests/fixtures/circle-journal.json'
    guest = json.loads(guest_path.read_text())
    wasm = e.base64.b64decode(guest['wasm_b64'])
    report = e.native.run(args.upstream, args.builder_image, ROOT / 'scripts/node-port/circle-octb-journal-oracle.ml',
                          dict(wasm_b64=guest['wasm_b64'], cases=fixtures(wasm)),
                          'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix str')
    report.update(wasm_b64=guest['wasm_b64'], wasm_sha256=guest['wasm_sha256'], guest_source_sha256=guest['guest_source_sha256'],
                  guest_fixture_sha256=hashlib.sha256(guest_path.read_bytes()).hexdigest(),
                  generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                  generator_dependencies={name: hashlib.sha256((ROOT / 'scripts/node-port' / name).read_bytes()).hexdigest() for name in ['circle-octb-execution-fixtures.py', 'circle-code-fixtures.py', 'octb-execution-fixtures.py']},
                  scope='Unmodified native Circle and epoch execution: OCTB/WASM cross-calls, reentry, value/storage rollback, depth/fuel limits, shared receipt budgets, ordered events and complete epoch roots/accounts/fees/nonce journals. No OCPG certificates, private/compute execution or full-node qualification.')
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(report['cases']), 'native mixed-runtime Circle epochs')


if __name__ == '__main__':
    main()
