"""Native OCTB browser queries, metadata and snapshot-bound legacy subviews."""
import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/node-port' / name)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
calls = module('circle-octb-execution-fixtures.py')
state = module('circle-state-fixtures.py')
b64 = calls.b64
CIRCLE = state.CIRCLE
CHILD = ('oct' + '2' * 44).encode()
CALLER = b'oct00000000000000000000000000000000000000000000'

def fixtures():
    P, w = calls.Program, calls.wire
    stop = w.ins(0x17)
    out = []
    def add(name, program, method, params=None, *, storage=None, entries=None, **fields):
        code = program.image() if isinstance(program, P) else program
        es = state.state() | {(b'meta', b'last_epoch'): b'0',
            (b'circles', CIRCLE, b'runtime'): b'octb',
            (b'circles', CIRCLE, b'owner'): CALLER,
            (b'circles', CIRCLE, b'code_hash'): hashlib.sha256(code).hexdigest().encode(),
            (b'circles', CIRCLE, b'call_code'): hashlib.sha256(code).hexdigest().encode(),
            (b'circles', CIRCLE, b'program', b'code_b64'): b64(code).encode()}
        for key, value in (storage or {}).items():
            es[(b'circles', CIRCLE, b'stable', b'by_hash', state.assets.digest(b'octra:stable_key:v1', key.encode()).encode())] = state.entry(key, value)
        es.update(entries or {})
        out.append(dict(name=name, circle=b64(CIRCLE), caller=b64(CALLER), epoch=1,
            method=b64(method), params=b64(json.dumps(params or [], separators=(',', ':'))),
            entries=state.encoded(es), limit=20_000_000, **fields))
    p = P()
    p.method('echo', [calls.mem(i, 999 + i) for i in range(8)] + [p.event('args', *range(8)), w.ins(0x0c, 0, 2), stop])
    for params in [[], ['hello'], [True, False, None], [2**150, -7], [[], {}, 1.5]]:
        add('parameter ' + repr(params), p, 'echo', params)
    p = P()
    p.method('context', [w.ins(tag, reg) for reg, tag in enumerate([0x19, 0x1a, 0x1b, 0x1c, 0x7b, 0x1d, 0x1f, 0x20, 0x7a])]
        + [w.ins(0x1e, 9, 0), w.ins(0x1e, 10, 2), p.event('context', *range(11)), stop])
    account = dict(balance='12345678901234567890', nonce=7, public_key=None, encrypted_balance=None, decrypt_allowance='0')
    add('authenticated context balances', p, 'context', entries={(b'accounts', CALLER, b'data'): json.dumps(account).encode()})
    p = P()
    p.method('read', [p.read('key', 0), p.event('read', 0), stop])
    p.method('write', [p.load(0, 19, 0), p.store('key', 0), stop])
    p.method('delete', [w.constant(0x0f, p.constant('key')), stop])
    p.method('transfer', [p.load(1, CHILD), p.load(2, 0, 0), w.ins(0x23, 0, 1, 2), stop])
    p.method('spawn', [p.load(1, b'OCTB' + b'\0' * 8), w.ins(0x22, 0, 1), stop])
    for method in ['read', 'write', 'delete', 'transfer', 'spawn', 'missing']:
        add('view guard ' + method, p, method, storage={'key': 'original'})
    for tag, raw in [(0, '999999999999999999999999999999999999999'), (1, b'\1'), (2, b'hello\0'), (3, b'\xffbytes')]:
        p = P().method('return', [])
        p.methods[0] = ('return', [p.load(0, raw, tag), p.event('value', 0), stop])
        add('return ' + str(tag), p, 'return')
    child = P()
    child.method('echo', [calls.mem(0, 1001), child.event('child', 0), stop])
    child.method('state', [child.read('key', 0), stop])
    child.method('write', [child.load(0, 1, 0), child.store('key', 0), stop])
    child.method('balance', [w.ins(0x19, 1), w.ins(0x1e, 0, 1), stop])
    child_state = {(b'contracts', CHILD, b'bytecode'): b64(child.image()).encode(),
        (b'contracts', CHILD, b'storage', b'key'): b'legacy storage'}
    for method, value in [('echo', ('str', 'hello')), ('echo', ('bool', True)), ('echo', ('bytes', b'\xffdata')), ('state', ('str', 'ignored')), ('write', ('str', 'ignored')), ('missing', ('str', 'ignored')), ('balance', ('str', 'ignored'))]:
        p = P()
        kind, value = value
        tag = {'str': 2, 'bytes': 3, 'bool': 1}[kind]
        if kind == 'bool': value = b'\1'
        body = [p.load(1, CHILD), p.load(2, method), p.load(3, value, tag),
            w.ins(0x21, 0, 1, 2, 3, 1 if method == 'echo' else 0), p.event('parent', 0), stop]
        p.method('call', body)
        add('legacy child ' + repr((method, kind)), p, 'call', entries=child_state)
        if method == 'echo':
            add('disabled call marker ' + kind, p, 'call', entries=child_state | {(b'circles', CIRCLE, b'call_code'): b'disabled'})
    p = P()
    p.method('call', [p.load(1, CHILD), p.load(2, 'echo'), w.ins(0x21, 0, 1, 2, 3, 0), stop])
    add('legacy child arity refusal', p, 'call', entries=child_state)
    add('missing legacy target', p, 'call')
    add('corrupt legacy target', p, 'call', entries={(b'contracts', CHILD, b'bytecode'): b'!'})
    # A Circle with the same address must not satisfy a legacy RPC subview.
    add('Circle does not substitute for legacy target', p, 'call', entries={
        (b'circles', CHILD, b'program', b'code_b64'): b64(child.image()).encode(),
        (b'circles', CHILD, b'runtime'): b'octb'})
    for depth in [7, 8, 9]:
        targets = [('oct' + str(i) * 44).encode() for i in range(1, depth + 1)]
        es = {}
        for i, target in enumerate(targets):
            c = P()
            body = ([c.load(1, targets[i+1]), c.load(2, 'go'), w.ins(0x21, 0, 1, 2, 3, 0)]
                if i+1 < depth else [c.load(0, 17, 0)])
            c.method('go', body + [w.ins(0x19, 1), w.ins(0x1a, 2), c.event('context', 0, 1, 2), stop])
            es[(b'contracts', target, b'bytecode')] = b64(c.image()).encode()
        p = P()
        p.method('call', [p.load(1, targets[0]), p.load(2, 'go'), w.ins(0x21, 0, 1, 2, 3, 0), stop])
        add('nested depth ' + str(depth), p, 'call', entries=es)
    # Each subcall fits the allocation budget on its own. Their combined gross
    # allocations must use the same budget even after the first child returns.
    c = P()
    c.method('burn', [c.load(0, 'x'), c.load(2, '')] + [w.ins(0x28, 0, 0, 0)] * 16
        + [w.ins(0x28, 0, 0, 2)] * 1023 + [c.load(0, 1, 0), stop])
    for count in [1, 2]:
        p = P()
        p.method('call', [p.load(1, CHILD), p.load(2, 'burn')]
            + [w.ins(0x21, 0, 1, 2, 3, 0)] * count + [stop])
        add('shared allocation budget ' + str(count), p, 'call',
            entries={(b'contracts', CHILD, b'bytecode'): b64(c.image()).encode()})
    p = P()
    p.method('get_counter', [p.read('counter', 0), stop])
    p.method('inc', [p.read('counter', 0), p.load(1, 1, 0), w.ins(0x00, 0, 0, 1), p.store('counter', 0), p.event('increment', 0), stop])
    p.method('caller_echo', [w.ins(0x19, 0), stop])
    add('browser counter', p, 'get_counter', storage={'counter': '4'})
    p = P()
    p.method('loop', [w.jump(0x16, 999), w.jump(0x14, 999)])
    for limit in [0, 10, 100, 1000]:
        add('fuel ' + str(limit), p, 'loop')
        out[-1]['limit'] = limit
    # Mutating declarations are descriptive; execution always enforces a view.
    for code in [w.wire([stop], []), b'OCTB', w.wire([w.ins(0x19, 255)], [])]:
        add('code admission ' + repr(code), code, 'anything')
    result = []
    for proof, point, integer_work, fhe_work in itertools.product([False, True], repeat=4):
        result += [copy.deepcopy(case) | dict(proof=proof, point=point, integer_work=integer_work, fhe_work=fhe_work) for case in out]
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upstream', required=True, type=pathlib.Path)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.out.exists(): raise SystemExit('Require fresh output')
    report = calls.native.run(args.upstream, args.builder_image, ROOT / 'scripts/node-port/circle-octb-view-oracle.ml', fixtures(),
        'octra_core octra_circle_runtime octra_vm lwt.unix yojson base64 irmin')
    report.update(generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        generator_dependencies={name: hashlib.sha256((ROOT / 'scripts/node-port' / name).read_bytes()).hexdigest() for name in
            ['circle-octb-execution-fixtures.py', 'circle-code-fixtures.py', 'octb-execution-fixtures.py', 'circle-state-fixtures.py', 'circle-assets-fixtures.py']},
        scope='Unmodified native OCTB Circle views under the actual RPC context: results, effort, events, method declarations, balance and legacy-contract subviews, view guards, shared budgets and immutable roots. No private/OCPG execution or full-node qualification.')
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(report['cases']), 'native OCTB Circle views')

if __name__ == '__main__': main()
