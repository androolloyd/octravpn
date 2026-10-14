"""OCTB child-Circle creation and commit refusal through native epochs."""
import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('calls', ROOT / 'scripts/node-port/circle-octb-execution-fixtures.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)


def fixtures(counter):
    out = []
    wire, Program, tx = calls.wire, calls.Program, calls.tx
    stop, revert = wire.ins(0x17), wire.ins(0x18)
    child = Program().method('child', [stop])
    payload = calls.code.payload(runtime='octb', code_b64=calls.b64(child.image()))

    def add(name, p, methods):
        deploy = tx('deploy', calls.code.payload(runtime='octb', code_b64=calls.b64(p.image())), 1, to='$derive')
        out.append(dict(name=name, transactions=[deploy] + [tx('call', [], i + 2, method=method, amount=1000) for i, method in enumerate(methods)],
                        entries=[], accounts=[dict(address=calls.b64(calls.SENDER), nonce=0, balance='10000000')],
                        epoch=3, now=123.5, float=False, math=False, circle_policy=False, wasm_compute=False))

    def program(raw, owner='caller', *, encoded=True, count=1, fail=False, rollback=False, owner_tag=2):
        p = Program()
        body = [p.load(1, calls.b64(raw) if encoded else raw), p.load(2, owner, owner_tag)]
        if rollback:
            body += [wire.ins(0x24)]
        for i in range(count):
            body += [wire.ins(0x53, 0, 1, 2, 1), p.event('child', 0), p.store('child', 0)]
            if rollback and i == 0:
                body += [wire.ins(0x25)]
        if fail:
            body += [p.load(3, b'after spawn'), p.event('Require', 3), revert]
        else:
            body += [stop]
        p.method('spawn', body)
        p.method('state', [p.read('child', 0), p.event('state', 0), stop])
        return p

    def raw(p):
        return json.dumps(p, separators=(',', ':')).encode()

    for owner in ['caller', 'parent', 'bad']:
        for count in [0, 1, 2, 4, 5]:
            add('count owner ' + repr((count, owner)), program(raw(payload), owner, count=count), ['spawn', 'state', 'spawn', 'state'])
    for fail, rollback in [(True, False), (False, True), (True, True)]:
        add('journal ' + repr((fail, rollback)), program(raw(payload), count=2, fail=fail, rollback=rollback), ['spawn', 'state'])
    for encoded in [False, True]:
        add('payload transport ' + str(encoded), program(raw(payload), encoded=encoded), ['spawn', 'state'])
    for child_payload in [
        payload | dict(code_b64=None),
        payload | dict(code_b64='!'),
        payload | dict(code_b64=calls.b64(b'bad code')),
        payload | dict(limits=payload['limits'] | dict(max_wasm_bytes='0')),
        payload | dict(resource_mode='sealed_read'),
        payload | dict(runtime='unknown'),
        payload | dict(runtime='wasm_v1', code_b64=calls.b64(b'bad wasm')),
        payload | dict(runtime='wasm_v1', code_b64=None),
        payload | dict(limits={}),
    ]:
        add('child admission ' + repr(child_payload), program(raw(child_payload)), ['spawn', 'state'])
    for broken in [b'OCTB' + b'\0' * 12, b'not a json payload', b'{"broken":true}']:
        add('malformed payload ' + repr(broken), program(broken), ['spawn', 'state'])
    add('bytes owner rejected', program(raw(payload), 'caller', owner_tag=3), ['spawn', 'state'])
    p = Program()
    p.method('spawn', [p.load(1, calls.b64(raw(payload))), wire.ins(0x22, 0, 1), stop])
    add('plain SPAWN missing owner', p, ['spawn'])
    # Exercise deferred WASM admission with the already-qualified upstream guest.
    add('WASM child', program(raw(calls.code.payload(code_b64=counter['wasm_b64'])), 'parent'), ['spawn', 'state'])
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
    report = calls.native.run(args.upstream, args.builder_image, ROOT / 'scripts/node-port/circle-code-oracle.ml',
                              dict(wasm_b64=counter['wasm_b64'], cases=fixtures(counter)),
                              'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix str')
    report.update(wasm_b64=counter['wasm_b64'], wasm_sha256=counter['wasm_sha256'], guest_source_sha256=counter['guest_source_sha256'],
                  generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                  generator_dependencies={name: hashlib.sha256((ROOT / 'scripts/node-port' / name).read_bytes()).hexdigest() for name in ['circle-code-fixtures.py', 'octb-execution-fixtures.py', 'circle-octb-execution-fixtures.py']},
                  scope='Unmodified native OCTB Circle spawning through full epoch execution: caller/parent ownership, count cap, raw/base64 input, deferred child runtime admission, inner/outer rollback, fees and state roots across independent proof/inspection/storage modes. No full-node qualification.')
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(report['cases']), 'native OCTB Circle spawn epochs')


if __name__ == '__main__':
    main()
