#!/usr/bin/env python3
"""Run unchanged production VPN methods with isolated AML security fragments."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    source = (ROOT/'program/main-v5.aml').read_text()
    fragment_paths = sorted((ROOT/'program/tests/v5').glob('*.t.aml'))
    methods = []
    for path in fragment_paths:
        fragments = path.read_text()
        refusals = dict(re.findall(r'^// expect-revert (test_\w+) "([^"]*)"$', fragments, re.M))
        names = re.findall(r'^fn (test_\w+)\(', fragments, re.M)
        assert len(names) <= 6, 'Native fixed labels require bounded fragments'
        assert set(refusals).issubset(names)
        combined = source.rstrip().removesuffix('}') + '\n' + fragments + '\n}\n'
        methods.extend(dict(method=name, refusal=refusals.get(name), source=combined,
                            fragment=str(path.relative_to(ROOT))) for name in names)
    assert len(methods) >= 30
    spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    report = native.run(args.upstream, args.builder_image, ROOT/'scripts/node-port/vpn-settlement-oracle.ml',
                        dict(methods=methods), 'octra_vm octra_core yojson lwt.unix')
    for case in report['cases']:
        expected, refusal = case['expected'], case['input']['refusal']
        if refusal is None:
            assert expected['ok'] and expected['result'] is True, case['input']
        else:
            assert not expected['ok'], case['input']
            reasons = [base64.b64decode(event[1][0]).decode()
                       for event in expected['events'] if base64.b64decode(event[0]) == b'Require']
            assert refusal in reasons, (case['input'], reasons)
    report['generator_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['aml_sha256'] = hashlib.sha256(source.encode()).hexdigest()
    report['fragments_sha256'] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in fragment_paths}
    report['scope'] = ('Production main-v5 method bodies with appended isolated AML security methods; '
                       'native compiler/VM exact state, effort, events and successful-transfer transcript. '
                       'Covers amount binding, zero traffic, amount equivocation, migration, policy anchor '
                       'and cooperative timeout. No funded ledger, consensus or public deployment claim.')
    args.out.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS native VPN security methods', len(methods), 'cases')


if __name__ == '__main__':
    main()
