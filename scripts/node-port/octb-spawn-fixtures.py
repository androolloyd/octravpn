"""Native synchronous and suspended OCTB deployment opcode qualification."""
import argparse
import hashlib
import importlib.util
import itertools
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('wire', ROOT / 'scripts/node-port/octb-execution-fixtures.py')
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


def fixtures():
    out = []
    def add(name, source, *, params=(), code=None, **fields):
        code = code or [wire.ins(0x53, 0, 1, 2, len(params)), wire.ins(0x17)]
        out.append(dict(name=name, raw=wire.b64(wire.wire(code, [])),
                        regs=[(1, source)] + [(i + 2, p) for i, p in enumerate(params)], **fields))
    raw = b'OCTB' + b'\0' * 8
    params = [wire.text('caller'), wire.integer(17), wire.text(b'\xff', 'bytes')]
    for active, strict, asynchronous, success in itertools.product([False, True], repeat=4):
        rules = dict(bytes=active, strict=strict, **{'async': asynchronous}, spawn_ok=success)
        for source in [raw, wire.b64(raw).encode(), b'OCPG' + b'\0' * 12, b'bad json! and \xff', b'YWJjZA==', b'!', b'']:
            for tag in ['str', 'bytes']:
                add('input ' + repr((tag, source)), wire.text(source, tag), params=params, **rules)
        for value in [wire.integer(12345678901234567890), {'bool': True}]:
            add('non-text source', value, params=params, **rules)
        for depth in [7, 8, 9]:
            add('depth ' + str(depth), wire.text(raw), params=params, depth=depth, **rules)
        add('view refusal', wire.text(raw), params=params, view=True, **rules)
        for nonce in [b'0', b'-1', b'0x3fffffffffffffff', b'4611686018427387903', b'0xffffffffffffffff', b'bad', b'1_0']:
            add('nonce ' + repr(nonce), wire.text(raw), params=params,
                storage=[(wire.b64(b'\0spawn_nonce'), wire.b64(nonce))], **rules)
        for n in [0, 1, 4]:
            add('spawn repeated ' + str(n), wire.text(raw), code=[wire.ins(0x22, 0, 1)] * n + [wire.ins(0x17)], **rules)
        add('inner storage rollback', wire.text(raw), code=[wire.ins(0x24), wire.ins(0x22, 0, 1), wire.ins(0x25), wire.ins(0x22, 0, 1), wire.ins(0x17)], **rules)
        for effort in [0, 1, 999999]:
            for limit in [4999, 5000, 9999, 10000, 10001, 10002, 10010, 10100, 1000000]:
                add('budget ' + repr((effort, limit)), wire.text(wire.b64(raw).encode()), params=params,
                    spawn_effort=effort, limit=limit, **rules)
        for base, count in [(64, 0), (64, 1), (63, 2), (255, 0)]:
            add('register span ' + repr((base, count)), wire.text(raw), code=[wire.ins(0x53, 0, 1, base, count)], **rules)
    for active, fhe in itertools.product([False, True], repeat=2):
        add('shared scope ' + repr((active, fhe)), wire.text(raw), params=params, bytes=active, fhe_work=fhe, spawn_ok=True)
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upstream', required=True, type=pathlib.Path)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    report = wire.native.run(args.upstream, args.builder_image, ROOT / 'scripts/node-port/octb-spawn-oracle.ml', fixtures(), 'octra_vm yojson lwt.unix')
    report.update(generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                  generator_dependency_sha256=hashlib.sha256((ROOT / 'scripts/node-port/octb-execution-fixtures.py').read_bytes()).hexdigest(),
                  scope='Unmodified native OCTB SPAWN/SPAWN2 with controlled deployment host: synchronous and suspended execution, exact local state, budgets, host arguments, storage nonce/rollback and failure order. Circle deployment is separately qualified.')
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(report['cases']), 'native OCTB spawn comparisons')


if __name__ == '__main__':
    main()
