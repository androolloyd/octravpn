"""Legacy OCTB calls through unchanged native Circle and epoch execution."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import itertools
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/node-port' / name)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


native = module('native-oracle.py')
code = module('circle-code-fixtures.py')
wire = module('octb-execution-fixtures.py')
b64 = code.b64
SENDER = 'oct' + '2' * 44
TARGET = 'oct' + '5' * 44
CIRCLE = 'oct' + '3' * 44


class Program:
    def __init__(self):
        self.constants = []
        self.methods = []

    def constant(self, value, tag=2):
        raw = value if isinstance(value, bytes) else str(value).encode()
        entry = (tag, raw)
        if entry not in self.constants:
            self.constants.append(entry)
        return self.constants.index(entry)

    def load(self, reg, value, tag=2):
        return wire.constant(0x0b, self.constant(value, tag), reg)

    def event(self, name, *regs):
        return wire.emit(self.constant(name), regs)

    def store(self, key, reg):
        return wire.constant(0x0e, self.constant(key), reg)

    def read(self, key, reg):
        return wire.constant(0x0d, self.constant(key), reg)

    def method(self, name, body):
        self.methods.append((name, body))
        return self

    def image(self):
        instructions = [wire.ins(0x17), wire.jump(0x16, 100), mem(60, 1000)]
        for index, (name, _) in enumerate(self.methods):
            instructions += [self.load(61, name), wire.ins(0x07, 62, 60, 61), wire.jump(0x15, 200 + index, 62)]
        instructions += [wire.ins(0x18)]
        for index, (_, body) in enumerate(self.methods):
            instructions += [wire.jump(0x16, 200 + index), *body]
        return wire.wire(instructions, self.constants)


def mem(reg, index):
    return bytes([0x12, reg]) + struct.pack('<H', index)


def tx(op, params, nonce, *, amount=0, method=None, to='$previous', ou=100):
    return dict(op=op, params=b64(json.dumps(params, separators=(',', ':'))), nonce=nonce,
                amount=str(amount), method=None if method is None else b64(method),
                to=b64(to), ou=str(ou), **{'from': b64(SENDER)})


def fixtures():
    out = []
    stop = wire.ins(0x17)
    revert = wire.ins(0x18)

    def add(name, program, calls, *, payload=None, entries=None, **fields):
        raw = program.image() if isinstance(program, Program) else program
        deploy = tx('deploy', code.payload(runtime='octb', code_b64=b64(raw), **(payload or {})), 1, to='$derive')
        transactions = [deploy] + [tx('call', params, i + 2, method=method, **extra) for i, (method, params, extra) in enumerate(calls)]
        out.append(dict(name=name, transactions=transactions, entries=entries or [],
                        accounts=[dict(address=b64(SENDER), nonce=0, balance='10000000')],
                        epoch=3, now=123.5, float=False, math=False, circle_policy=False, wasm_compute=False, **fields))

    p = Program()
    p.method('echo', [mem(i, 999 + i) for i in range(9)] + [p.event('params', *range(9)), stop])
    for params in [[], [1], [True, False, None], ['0x2a', 2**140, -(2**130), ''], [[], {}, 1.5, '\u0000\n"\\']]:
        add('parameter conversion ' + repr(params), p, [('echo', params, {}), ('missing', [], {}), ('echo', params, {})])
    add('non-list parameters', p, [('echo', {}, {})])
    p = Program()
    p.method('context', [wire.ins(tag, reg) for reg, tag in enumerate([0x19, 0x1a, 0x1b, 0x1c, 0x7b, 0x1d, 0x1f, 0x20, 0x7a])]
             + [wire.ins(0x1e, 9, 2), wire.ins(0x1e, 10, 0), p.event('context', *range(11)), stop])
    add('authenticated context and staged balances', p, [('context', [], {'amount': 1234}), ('context', [], {'amount': 321})])
    add('epoch zero context', p, [('context', [], {})], epoch_override=0, time_override=-0.0001)
    p = Program()
    p.method('write', [mem(1, 1001), p.store('key', 1), p.read('key', 0), p.event('write', 0, 1), stop])
    p.method('read', [p.read('key', 0), p.event('read', 0), stop])
    p.method('erase', [wire.constant(0x0f, p.constant('key')), p.read('key', 0), p.event('erased', 0), stop])
    add('write read erase across calls', p, [('write', [42], {}), ('read', [], {}), ('write', [True], {}), ('read', [], {}), ('erase', [], {}), ('read', [], {})])
    for size in [65535, 65536, 65537]:
        add('inline limit ' + str(size), p, [('write', ['x' * size], {}), ('read', [], {})])
    limits = code.payload()['limits'] | dict(max_stable_bytes='1')
    add('stable byte limit commit refusal', p, [('write', ['ab'], {}), ('read', [], {})], payload=dict(limits=limits))
    p = Program()
    p.method('write', [mem(1, 1001), mem(2, 1002), wire.ins(0x11, 1, 2), p.event('write', 1, 2), stop])
    for key in ['object_policy:unknown', 'hfhe_policy:unknown', 'transport_policy:unknown', '\u0000private', '', 'ordinary']:
        add('reserved storage ' + repr(key), p, [('write', [key, 'new'], {}), ('write', ['ordinary', 'after'], {})])
    p = Program()
    body = [mem(1, 1001), mem(2, 1002), wire.ins(0x23, 0, 1, 2), p.event('transfer', 0), stop]
    p.method('send', body)
    for amount in [-1, 0, 1, 1000, 1001, 2**80]:
        add('transfer ' + str(amount), p, [('send', [TARGET, amount], {'amount': 1000}), ('send', [TARGET, 1], {})])
    add('invalid transfer target', p, [('send', ['invalid', 0], {'amount': 1000}), ('send', ['invalid', 1], {})])
    p = Program()
    p.method('fail', [p.load(1, TARGET), p.load(2, 100, 0), wire.ins(0x23, 0, 1, 2), p.store('key', 2),
                      p.event('Require'), p.load(3, 'first reason'), p.event('Require', 3, 2), p.load(3, 'later reason'), p.event('Require', 3), revert])
    p.method('state', [wire.ins(0x1b, 1), wire.ins(0x1e, 0, 1), p.read('key', 2), p.event('state', 0, 2), stop])
    add('transfer value writes and Require rollback', p, [('fail', [], {'amount': 1000}), ('state', [], {}), ('fail', [], {'amount': 500}), ('state', [], {})])
    p = Program()
    p.method('fail', [p.load(0, 1, 0), p.store('key', 0), p.load(1, 0, 0), wire.ins(0x03, 0, 0, 1), stop])
    add('division refusal after write', p, [('fail', [], {}), ('missing', [], {})])
    for count in [255, 256, 257]:
        p = Program()
        p.method('events', [p.event('empty') for _ in range(count)] + [stop])
        add('event cap ' + str(count), p, [('events', [], {})])
    p = Program()
    p.method('loop', [wire.jump(0x16, 999), wire.jump(0x14, 999)])
    add('fuel exhaustion charged rollback', p, [('loop', [], {'amount': 1000})])
    p = Program().method('old', [stop])
    new = Program().method('new', [stop])
    add('update and dispatcher lifecycle', p, [('old', [], {})])
    out[-1]['transactions'] += [tx('update', dict(code_b64=b64(new.image())), 3), tx('call', [], 4, method='old'), tx('call', [], 5, method='new')]
    # Read-only admission failures on a pre-existing Circle, including priority
    # over method lookup. Hash/base64 corruption does not pass deployment.
    seed = next(v for v in code.fixtures() if v['name'] == 'update wasm')['entries']
    for name, raw, stored, digest in [
        ('no dispatcher', wire.wire([stop], []), None, None),
        ('short bytecode', b'OCTB', None, None),
        ('invalid register', wire.wire([wire.ins(0x19, 255)], []), None, None),
        ('hash mismatch', p.image(), None, '0' * 64),
        ('invalid base64', p.image(), '!', None),
    ]:
        entries = copy.deepcopy(seed)
        changes = dict(runtime='octb', code_hash=digest or hashlib.sha256(raw).hexdigest(), code_b64=stored or b64(raw))
        for entry in entries:
            leaf = base64.b64decode(entry['path'][-1]).decode()
            if leaf in changes:
                entry['value'] = b64(changes[leaf])
        add('seeded ' + name, p, [], entries=entries)
        out[-1]['transactions'] = [tx('call', [], 1, to=CIRCLE, method='old')]
    cases = []
    for proof, inspect, storage in itertools.product([False, True], repeat=3):
        for original in out:
            case = copy.deepcopy(original)
            case.update(proof=proof, inspect=inspect, storage_proof=storage)
            case['epoch'] = case.pop('epoch_override', case['epoch'])
            case['now'] = case.pop('time_override', case['now'])
            cases.append(case)
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
    report = native.run(args.upstream, args.builder_image, ROOT / 'scripts/node-port/circle-code-oracle.ml',
                        dict(wasm_b64=counter['wasm_b64'], cases=fixtures()),
                        'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix str')
    report.update(wasm_b64=counter['wasm_b64'], wasm_sha256=counter['wasm_sha256'], guest_source_sha256=counter['guest_source_sha256'],
                  generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                  generator_dependencies={name: hashlib.sha256((ROOT / 'scripts/node-port' / name).read_bytes()).hexdigest() for name in ['circle-code-fixtures.py', 'octb-execution-fixtures.py']},
                  scope='Unmodified native Circle and epoch execution: legacy OCTB calls, deployment/update, context, storage, events, fees, value transfers and rollback. Complete roots/accounts/nonce journals/receipts across independent proof-execution, VM-bytes and storage-proof modes. No OCPG certificates, private/compute execution or full-node qualification.')
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(report['cases']), 'native OCTB Circle epochs')


if __name__ == '__main__':
    main()
