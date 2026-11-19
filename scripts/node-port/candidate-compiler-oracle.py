#!/usr/bin/env python3
"""Offline c49 compiler/publication oracle; preserves adopted historical fixtures.

Compiler, source verifier, encoder and publication policy functions are unchanged.
The native runtime module is sliced to its pure ISA/value/verifier definitions;
crypto metadata and store record definitions are sliced from their original files.
No execution, FHE host, filesystem store or public RPC is exercised.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

PIN = '8f785a93a4e7392a0f3e65674f9de89854d33dbc'
ROOT = Path(__file__).resolve().parents[2]


def fixtures():
    basic = 'contract Record { state { n: int } constructor() { self.n = 0 } view fn read(): int { return self.n } }'
    scope = '''contract Scope { enum Choice { First } public fn run(): int {
let kept = 1
match Choice.First { Choice.First => { let kept = 2 } }
let padding = 0
let separate = 7
kept = 9
return separate
} }'''
    sources = [basic, scope,
        'contract Cycle { const a: int = b const b: int = a fn f(): int { return 1 } }',
        'contract Alias { const base = 7 const other = base fn run(): int { return other } }',
        'contract Limit {' + ''.join(f' fn f{i}(): int {{ return 1 }}' for i in range(257)) + '}',
        'contract Budget { fn run(): int { let n = 0\n' + 'n = n + 1\n' * 17000 + 'return n } }',
    ]
    rows = []
    for number, source in enumerate(sources):
        for compiler in ['source', 'forms', 'protocol']:
            for metered in [False, True]:
                rows.append(dict(kind='compile', label=f'case{number}/{compiler}/{metered}',
                                 source=source, compiler=compiler, loops=False, metered=metered))
    for compiler, loops in [('source', False), ('source', True), ('forms', False), ('forms', True),
                            ('protocol', False), ('historical', False), ('package', False),
                            ('package_historical', False), ('package_source', False),
                            ('package_preview', False), ('package', True),
                            ('package_source', True), ('package_preview', True)]:
        for metered in [False, True]:
            rows.append(dict(kind='publish', label=f'publish/{compiler}/{loops}/{metered}',
                source=scope, compiler=compiler, loops=loops, metered=metered))
            rows.append(dict(kind='publish', label=f'program/{compiler}/{loops}/{metered}',
                source=basic.replace('contract Record', 'program Record'), compiler=compiler, loops=loops, metered=metered))
    for source in sources[:5]:
        rows.append(dict(kind='scope', source=source))
    for path in ['program/main-v5.aml', 'program/private-admin-factory.aml']:
        for compiler in ['source', 'forms']:
            for loops in [False, True]:
                rows.append(dict(kind='compile', label=f'{path}/{compiler}/{loops}', path=path,
                    source=(ROOT/path).read_text(), compiler=compiler, loops=loops, metered=True))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--ocaml-bin', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['PATH'] = str(args.ocaml_bin) + os.pathsep + env['PATH']
    find = str(args.ocaml_bin / 'ocamlfind')
    paths = subprocess.check_output(['git', '-C', str(args.upstream), 'ls-tree', '-r', '--name-only', PIN], text=True).splitlines()
    originals, generated, extracts = {}, {}, {}
    def read(path):
        if path not in originals:
            originals[path] = subprocess.check_output(['git', '-C', str(args.upstream), 'show', f'{PIN}:{path}'])
        return originals[path].decode()
    def part(path, start=None, end=None):
        text = read(path)
        lo = text.index(start) if start is not None else 0
        hi = text.index(end, lo) if end is not None else len(text)
        return text[lo:hi]
    def sliced(name, path, spans):
        text = '\n'.join(part(path, *span) for span in spans)
        generated[name] = text
        extracts[name] = dict(source=path, spans=spans, compiled_sha256=hashlib.sha256(text.encode()).hexdigest())
    for path in paths:
        if path.startswith('lib/vm/') and path.endswith('.ml'):
            generated[Path(path).name] = read(path)
    sliced('contract_vm.ml', 'lib/vm/runtime/contract_vm.ml', [
        (None, 'type mem ='), ('type storage_kind =', 'type byte_result ='),
        ('let call_depth_max =', 'let create_state '),
        ('let to_z =', 'let storage_value_matches '), ('let valid_reg_span ', 'let add_dyn_effort '), ('module Verifier =', None)])
    sliced('pvac_ffi.ml', 'pvac_ffi/pvac_ffi.ml', [(None, 'external isolate_worker')])
    sliced('fhe_image.ml', 'lib/core/fhe_image.ml', [(None, 'let key_size ')])
    sliced('rule_graph.ml', 'lib/core/rule_graph.ml', [(None, 'type root_read =')])
    sliced('store_chaindata.ml', 'lib/core/store_chaindata.ml', [
        ('type program_record =', 'type program_record_save_error ='),
        ('let program_record_json ', 'let program_record_of_json ')])
    sliced('circles.ml', 'lib/core/circles.ml', [('let is_hex_char =', 'let normalize_slot_ref ')])
    sliced('program_record.ml', 'lib/vm/runtime/program_record.ml', [(None, 'let read ?snapshot ')])
    generated['json_tree.ml'] = read('lib/core/json_tree.ml')
    generated['octra_ed25519.ml'] = read('crypto_guard/octra_ed25519.ml')
    generated['octra_core.ml'] = '\n'.join(f'module {name} = {name}' for name in ['Fhe_image', 'Json_tree', 'Rule_graph', 'Store_chaindata']) + '\n'
    stamp = re.search(r"expected = '([a-f0-9]{64})'", read('lib/vm/dune')).group(1)
    stamp_hash = hashlib.sha256()
    for path in sorted(path for path in paths
        if any(path.startswith('lib/vm/' + group + '/') for group in ['compiler', 'aml', 'policy', 'wire', 'runtime'])
        and Path(path).suffix in ['.ml', '.mli', '.c', '.h']):
        read(path)
        header = ('// SPDX-License-Identifier: BSD-3-Clause\n// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>\n\n'
            if Path(path).suffix in ['.c', '.h'] else '(* SPDX-License-Identifier: BSD-3-Clause *)\n(* Copyright (c) 2023-2026 Octra Labs <dev@octra.org> *)\n\n').encode()
        body = originals[path].removeprefix(header).rstrip(b'\n')
        stamp_hash.update((hashlib.sha256(body).hexdigest() + '  ' + path.removeprefix('lib/vm/') + '\n').encode())
    assert stamp_hash.hexdigest() == stamp, 'committed compiler source stamp differs'
    generated['source_stamp.ml'] = f'let id = "{stamp}"\n'
    oracle = Path(__file__).with_suffix('.ml').read_bytes()
    generated['oracle.ml'] = oracle.decode()
    for name, body in generated.items():
        (out / name).write_text(body)
    names = list(generated)
    deps_text = subprocess.check_output([str(args.ocaml_bin/'ocamldep'), '-modules', *names], cwd=out, env=env, text=True)
    deps = dict(line.split(':', 1) for line in deps_text.splitlines())
    modules = {Path(name).stem.capitalize(): name for name in names}
    order, active, done = [], set(), set()
    def visit(name):
        if name in done:
            return
        if name in active:
            raise RuntimeError(f'module cycle: {name}')
        active.add(name)
        for module in deps[name].split():
            if module in modules:
                visit(modules[module])
        active.remove(name)
        done.add(name)
        order.append(name)
    visit('oracle.ml')
    packages = 'zarith,yojson,base64,digestif.c,mirage-crypto-ec,threads,lwt.unix'
    c_path = 'lib/vm/compiler/type_index_stubs.c'
    (out/'type_index_stubs.c').write_text(read(c_path))
    commands = [[find, 'ocamlopt', '-c', 'type_index_stubs.c']]
    commands.extend([find, 'ocamlopt', '-thread', '-package', packages, '-w', '-a', '-c', name] for name in order)
    commands.append([find, 'ocamlopt', '-thread', '-package', packages, '-linkpkg', *[str(Path(name).with_suffix('.cmx')) for name in order], 'type_index_stubs.o', '-o', 'oracle'])
    with (out/'build.log').open('w') as log:
        for command in commands:
            result = subprocess.run(command, cwd=out, env=env, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                raise SystemExit(f'native build failed: {command}; see {out / "build.log"}')
    cases = fixtures()
    (out/'input.json').write_text(json.dumps(cases))
    native = subprocess.run([str(out/'oracle')], input=json.dumps(cases), text=True, capture_output=True, env=env, timeout=180)
    (out/'stderr.log').write_text(native.stderr)
    if native.returncode:
        raise SystemExit(f'native oracle failed ({native.returncode}); see stderr.log')
    result = dict(upstream_commit=PIN, scope=__doc__,
        source_sha256={k:hashlib.sha256(v).hexdigest() for k,v in sorted(originals.items())},
        compiled_modules=order,
        extraction=extracts,
        oracle_sha256=hashlib.sha256(oracle).hexdigest(),
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        source_stamp=stamp,
        generated_sha256={name:hashlib.sha256(generated[name].encode()).hexdigest() for name in order},
        compiler_version=subprocess.check_output([str(args.ocaml_bin/'ocamlopt'), '-version'], text=True).strip(),
        cases=json.loads(native.stdout))
    args.fixture.parent.mkdir(parents=True, exist_ok=True)
    args.fixture.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(cases=len(result['cases']), modules=len(order), fixture=str(args.fixture))))

if __name__ == '__main__':
    main()
