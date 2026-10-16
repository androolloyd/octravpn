#!/usr/bin/env python3
"""Compile the real VPN and factory with the exact adopted, offline native AML compiler."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ['program/main-v5.aml', 'program/private-admin-factory.aml']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    inputs = [dict(path=path, source=(ROOT/path).read_text(), syntax=syntax, loops=loops)
              for path in SOURCES for syntax in ['forms', 'source'] for loops in [False, True]]
    spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    report = native.run(args.upstream, args.builder_image, ROOT/'scripts/node-port/vpn-compiler-oracle.ml',
                        inputs, 'octra_vm octra_core yojson lwt.unix')
    report['generator_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['vpn_source_sha256'] = {path: hashlib.sha256((ROOT/path).read_bytes()).hexdigest() for path in SOURCES}
    report['scope'] = ('Actual VPN/factory AML compiled by unmodified adopted Aml_source and Oct_compile; '
                       'exact OCTB, ABI, verification report, certificate, storage/type-flow facts and RPC bytes '
                       'across Forms/Source syntax and loop gates. No stateful deployment qualification.')
    args.out.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS native VPN/factory compiler', len(report['cases']), 'cases')


if __name__ == '__main__':
    main()
