#!/usr/bin/env python3
"""Validator eviction updates from the unchanged native Validator_set_update.

Builds on the module set the transaction-intake oracle assembles (the whole
update, entry, policy, registry, codec and address modules, unmodified) and
adds only a serializing wrapper. Covers construction, the canonical
encoding, and what the stored-update parser accepts; not epoch execution.
"""
import argparse, hashlib, json, os, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['upstream', 'out', 'fixture', 'ocaml-bin']:
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    out = a.out.resolve()
    dependency = HERE / 'candidate-staging-intake-oracle.py'
    subprocess.run(['python3', str(dependency), '--upstream', str(a.upstream), '--out', str(out),
                    '--fixture', str(out / 'intake.json'), '--ocaml-bin', str(a.ocaml_bin)],
                   check=True, stdout=subprocess.DEVNULL)
    base = json.loads((out / 'intake.json').read_text())
    wrapper = Path(__file__).with_suffix('.ml').read_bytes()
    (out / 'eviction.ml').write_bytes(wrapper)
    env = os.environ.copy()
    env['PATH'] = str(a.ocaml_bin) + os.pathsep + env['PATH']
    names = sorted(path.name for path in out.glob('*.ml') if path.name != 'oracle.ml')
    dep = subprocess.check_output([str(a.ocaml_bin / 'ocamldep'), '-modules', *names], cwd=out, env=env, text=True)
    bymod = {Path(n).stem.capitalize(): Path(n).stem for n in names}
    deps = {}
    for line in dep.splitlines():
        name, mods = line.split(':', 1)
        deps[Path(name).stem] = [bymod[m] for m in mods.split() if m in bymod]
    order, seen = [], set()

    def visit(n):
        if n in seen:
            return
        seen.add(n)
        for d in deps[n]:
            visit(d)
        order.append(n)
    visit('eviction')
    command = [str(a.ocaml_bin / 'ocamlfind'), 'ocamlopt', '-thread', '-package',
               'digestif.c,zarith,yojson,base64,unix,mirage-crypto-ec,lwt.unix', '-linkpkg',
               *[n + '.ml' for n in order], '-o', 'eviction']
    build = subprocess.run(command, cwd=out, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / 'eviction-build.log').write_text(build.stdout)
    if build.returncode:
        raise SystemExit(f"native build failed: {out / 'eviction-build.log'}")
    observed = json.loads(subprocess.check_output([str(out / 'eviction')], env=env))
    compiled = {n + '.ml': base['compiled_sha256'][n + '.ml'] for n in order if n + '.ml' in base['compiled_sha256']}
    report = {'upstream_commit': base['upstream_commit'], 'source_sha256': base['source_sha256'],
              'compiled_sha256': compiled, 'oracle_sha256': sha(wrapper),
              'runner_sha256': sha(Path(__file__).read_bytes()),
              'dependency_runner_sha256': sha(dependency.read_bytes()),
              'build_command': command, 'scope': __doc__, **observed}
    a.fixture.write_text(json.dumps(report, separators=(',', ':')) + '\n')
    print(json.dumps({'cases': len(report['cases']),
                      'parsed': sum(len(c['expected'].get('parsed', [])) for c in report['cases']),
                      'fixture': str(a.fixture)}))


if __name__ == '__main__':
    main()
