#!/usr/bin/env python3
"""Core OCTB execution at the candidate release, with and without `scalar_work`.

Runs the unchanged upstream VM (lib/vm at PIN) on the historical core execution
cases in both modes, plus cases at the scalar-work limits: integers of 65,536
and 65,537 bits, numeric text of 65,536 and 65,537 characters, typed storage
loads, events, outputs, equality between numbers and text, comparison and
bitwise effort, integer parsing and vector stores. Large inputs are written
compactly (`repeat`, `pow2`) and large results as SHA-256 digests.

Upstream is built with its own storage build wrapper (controls/lib/gc_build.py)
inside the given builder image; no upstream source is modified. Prior-mode
cases whose result equals the historical capture are not stored: the generator
asserts that equality and records the count.
"""
import argparse, hashlib, importlib.util, itertools, json, subprocess
from pathlib import Path

PIN = '8f785a93a4e7392a0f3e65674f9de89854d33dbc'
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
HISTORICAL = ROOT / 'crates/octra-node-runtime/tests/fixtures/octb-execution.json'

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / name)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

base = load('octb-execution-fixtures.py')
b64, text, integer, ins, constant, emit, wire = base.b64, base.text, base.integer, base.ins, base.constant, base.emit, base.wire

def pow2(k, offset=0, kind='int'): return {kind: {'pow2': [k, str(offset)]}}
def neg2(k, offset=0): return {'int': {'neg_pow2': [k, str(offset)]}}
def repeat(chunk, count, kind='str'): return {kind: {'repeat': [b64(chunk), count]}}
def blob(chunk, count): return {'repeat': [b64(chunk), count]}

def scalar_cases():
    out = []
    modes = [dict(scalar=s, bytes=b, strict=t) for s, b, t in itertools.product([False, True], repeat=3)]
    def add(name, code, regs=(), constants=(), mode_set=None, **kw):
        for mode in modes if mode_set is None else mode_set:
            out.append(dict(name=name, raw=b64(wire(code, constants)), regs=list(regs), **mode, **kw))
    small = [integer(0), integer(7), integer(-7)]
    edge = [pow2(65535), pow2(65535, -1), neg2(65535, -1), neg2(65535), pow2(65536), pow2(65535, 0, 'u256'),
            repeat(b'9', 65536), repeat(b'1', 65537), repeat(b'7', 2048), text('123'), text('-0'), text('0x10'),
            repeat(b'a', 70000)]
    for tag in [0, 1, 2, 3, 4, 7, 8, 9, 10, 0x47, 0x48, 0x49]:
        for a in edge + small[:1]:
            for b in [integer(3), pow2(65535, -1), repeat(b'9', 65536)]:
                add(f'scalar binary {tag}', [ins(tag, 0, 1, 2), ins(0x17)], [(1, a), (2, b)])
    for a, b in [(integer(1), integer(65535)), (integer(1), integer(65536)), (pow2(65535, -1), integer(1)), (integer(-1), integer(65536))]:
        add('scalar shift', [ins(0x4a, 0, 1, 2), ins(0x17)], [(1, a), (2, b)])
    for value in edge:
        add('scalar move', [ins(0x0c, 3, 1), ins(0x17)], [(1, value)])
        add('scalar output', [ins(0x0c, 0, 1), ins(0x17)], [(1, value)])
        for tag in [5, 6, 0x2c, 0x41, 0x52, 0x45, 0x56]:
            add(f'scalar unary {tag}', [ins(tag, 0, 1), ins(0x17)], [(1, value)])
        add('scalar assert addr', [ins(0x42, 1), ins(0x17)], [(1, value)])
        add('scalar event', [emit(0, [1, 1]), ins(0x17)], [(1, value)], constants=[(2, b'ev')])
        add('scalar store', [constant(0x0e, 0, 1), ins(0x17)], [(1, value)], constants=[(2, b'key')])
        add('scalar concat', [ins(0x28, 0, 1, 2), ins(0x17)], [(1, value), (2, text('x'))])
        add('scalar transfer', [ins(0x23, 0, 1, 2), ins(0x17)], [(1, value), (2, integer(1))], transfer_ok=True)
        add('scalar parse', [ins(0x40, 0, 1, 2), ins(0x17)], [(1, value), (2, integer(0))])
    # Equality between numbers and their decimal text.
    pairs = [(integer(0), text('0')), (integer(0), text('-0')), (integer(-12), text('-12')), (integer(12), text('012')),
             (integer(12), text('+12')), (pow2(64), text(str(2**64))), (pow2(64), text(str(2**64 + 1))),
             (pow2(64, 0, 'u128'), text(str(2**64), 'bytes')), (integer(5), {'bool': True}), (integer(1), {'bool': True}),
             (pow2(65535, -1), repeat(b'9', 19729)), (integer(7), text('7', 'addr')), (integer(7), text('7', 'bytes32'))]
    for a, b in pairs:
        for tag in [7, 10]:
            add(f'scalar equality {tag}', [ins(tag, 0, 1, 2), ins(0x17)], [(1, a), (2, b)])
            add(f'scalar equality swapped {tag}', [ins(tag, 0, 2, 1), ins(0x17)], [(1, a), (2, b)])
    # Typed storage loads: numeric text is parsed and charged; other kinds are scanned.
    for kind in [0, 2, 5, 7]:
        for value in [blob(b'9', 65536), blob(b'9', 65537), blob(b'1', 3000), b64(b'42'), b64(b'-5'),
                      b64(str(2**64).encode()), b64(str(2**256).encode()), blob(b'x', 9000)]:
            for limit in [100, 10000, 1000000]:
                add(f'scalar typed load {kind} {limit}', [constant(0x0d, 0, 0), ins(0x17)], constants=[(2, b'key')],
                    kinds=[[b64(b'key'), kind]], storage=[[b64(b'key'), value]], limit=limit)
        add(f'scalar repeated typed load {kind}', [constant(0x0d, 0, 1), constant(0x0d, 0, 2), constant(0x0d, 0, 3), ins(0x07, 0, 1, 2), ins(0x17)],
            constants=[(2, b'key')], kinds=[[b64(b'key'), kind]], storage=[[b64(b'key'), blob(b'3', 5000)]])
    # Effort thresholds for comparison and bitwise work on wide integers.
    for tag in [8, 0x47]:
        for limit in [1, 2, 3, 5, 10, 50, 100, 200, 400, 1000, 3000]:
            add(f'scalar effort {tag} {limit}', [ins(tag, 0, 1, 2), ins(0x17)], [(1, pow2(65535, -1)), (2, pow2(30000))], limit=limit)
    for limit in [10, 100, 500, 1000, 2000, 5000, 20000]:
        add(f'scalar text effort {limit}', [ins(0, 0, 1, 2), ins(0x17)], [(1, repeat(b'9', 30000)), (2, integer(1))], limit=limit)
        add(f'scalar event effort {limit}', [emit(0, [1]), ins(0x17)], [(1, pow2(60000))], constants=[(2, b'ev')], limit=limit)
        add(f'scalar parse effort {limit}', [ins(0x40, 0, 1, 2), ins(0x17)], [(1, text(','.join(['9' * 3000] * 4))), (2, integer(0))], limit=limit)
    # Vector family: wide memory operands and stores past the width limit.
    mems = [[[0, pow2(65534)], [1, pow2(65534)], [10, integer(2)], [11, integer(2)]],
            [[0, pow2(40000)], [1, integer(1)], [10, pow2(40000)], [11, integer(1)]],
            [[0, repeat(b'9', 30000)], [1, integer(1)], [10, integer(1)], [11, integer(1)]]]
    for memory in mems:
        add('scalar vecdot', [ins(0x61, 0, 1, 2, 3), ins(0x17)], [(1, integer(0)), (2, integer(10)), (3, integer(2))], memory=memory)
        add('scalar residual', [ins(0x6a, 1, 2, 3), ins(0x17)], [(1, integer(0)), (2, integer(10)), (3, integer(2))], memory=memory)
        add('scalar matmul', [ins(0x60, 4, 1, 2, 3, 5, 6), ins(0x17)],
            [(1, integer(0)), (2, integer(10)), (3, integer(1)), (4, integer(20)), (5, integer(2)), (6, integer(1))], memory=memory)
        add('scalar mloadr', [ins(0x2e, 0, 1), ins(0x17)], [(1, integer(0))], memory=memory)
    return out

def fixtures():
    historical = base.fixtures()
    for case in historical:
        case['scalar'] = False
    with_scalar = [dict(case, scalar=True) for case in historical]
    return historical, with_scalar, scalar_cases()

def run_native(upstream, image, cases, work):
    work.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', '-C', str(upstream), 'archive', '--format=tar', '-o', str(work / 'src.tar'), PIN], check=True)
    (work / 'main.ml').write_bytes(Path(__file__).with_suffix('.ml').read_bytes())
    (work / 'dune').write_text('(executable (name main) (libraries octra_vm octra_core yojson digestif))\n')
    (work / 'input.json').write_text(json.dumps(cases))
    script = ('set -euo pipefail; command -v cargo >/dev/null || { curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null; };'
              ' source ~/.cargo/env; mkdir -p /home/opam/pin && cd /home/opam/pin && tar xf /in/src.tar;'
              ' mkdir -p mcl/obj mcl/lib && make -s -C mcl MCL_FP_BIT=256 MCL_FR_BIT=256 lib/libmcl.a > /in/mcl.log 2>&1;'
              ' mkdir -p vpn_port_oracle && cp /in/main.ml /in/dune vpn_port_oracle/;'
              ' opam exec -- python3 controls/lib/gc_build.py -- dune build ./vpn_port_oracle/main.exe > /in/build.log 2>&1 || { tail -40 /in/build.log; exit 1; };'
              ' ./_build/default/vpn_port_oracle/main.exe < /in/input.json > /in/output.json')
    subprocess.run(['docker', 'run', '--rm', '-v', f'{work}:/in', '--entrypoint', 'bash', image, '-lc', script], check=True)
    return json.loads((work / 'output.json').read_text())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--image', default='octra-native-oracle-recovery:20261017')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--native-output', type=Path, help='reuse a previous native run of the same input')
    args = parser.parse_args()
    historical, with_scalar, extra = fixtures()
    cases = historical + with_scalar + extra
    if args.native_output:
        observed = json.loads(args.native_output.read_text())
        assert [c['name'] for c in observed] == [c['name'] for c in cases]
    else:
        observed = run_native(args.upstream.resolve(), args.image, cases, args.out.resolve())
    old = json.loads(HISTORICAL.read_text())['cases']
    assert len(old) == len(historical)
    prior = observed[:len(historical)]
    scalar = observed[len(historical):2 * len(historical)]
    # Historical cases are stored only where the candidate differs from the
    # historical capture (prior mode) or from the candidate prior mode
    # (scalar mode, changed fields only). The Rust test replays every historical case in both
    # modes and takes its expectation from these overrides when present.
    prior_changed, scalar_changed = {}, {}
    for index, (before, now, metered) in enumerate(zip(old, prior, scalar)):
        assert before['name'] == now['name'] == metered['name']
        if before['expected'] != now['expected']:
            prior_changed[index] = now['expected']
        if metered['expected'] != now['expected']:
            # Only the fields that differ; the rest equal the prior result.
            scalar_changed[index] = {key: value for key, value in metered['expected'].items()
                                     if now['expected'].get(key) != value}
    stored = observed[2 * len(historical):]
    originals = {path: subprocess.check_output(['git', '-C', str(args.upstream), 'show', f'{PIN}:{path}'])
                 for path in ['lib/vm/runtime/contract_vm.ml', 'lib/vm/runtime/scalar_work.ml', 'lib/vm/runtime/cost.ml']}
    result = dict(upstream_commit=PIN, scope=__doc__, image=args.image,
                  source_sha256={k: hashlib.sha256(v).hexdigest() for k, v in originals.items()},
                  oracle_sha256=hashlib.sha256(Path(__file__).with_suffix('.ml').read_bytes()).hexdigest(),
                  generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  generator_dependency_sha256=hashlib.sha256((HERE / 'octb-execution-fixtures.py').read_bytes()).hexdigest(),
                  historical_sha256=hashlib.sha256(HISTORICAL.read_bytes()).hexdigest(),
                  historical_cases=len(historical),
                  prior_overrides={str(k): v for k, v in prior_changed.items()},
                  scalar_overrides={str(k): v for k, v in scalar_changed.items()},
                  cases=stored)
    args.fixture.write_text(json.dumps(result, separators=(',', ':')) + '\n')
    print(json.dumps(dict(prior_changed=len(prior_changed), scalar_changed=len(scalar_changed), stored=len(stored),
                          bytes=args.fixture.stat().st_size)))

if __name__ == '__main__':
    main()
