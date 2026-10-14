#!/usr/bin/env python3
"""Qualify the real VPN admin AML with public proof material from a development run."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--upstream', required=True, type=Path)
    p.add_argument('--builder-image', required=True)
    p.add_argument('--public-fixture', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    a = p.parse_args()
    if a.out.exists():
        raise SystemExit('Require fresh output')
    material = json.loads(a.public_fixture.read_text())
    auth = material['authorization']
    address, domain = material['program'], material['domain']
    source = (ROOT/'program/main-v5.aml').read_text()
    constructor = dict(method='constructor', program=address,
        params=[1, 1, 100_000_000, 100, 1000, auth['commitment'], material['verification_key_b64'], domain, 0])
    authorized = dict(method=auth['method'], params=auth['params'], program=address)
    wrong_action = copy.deepcopy(authorized); wrong_action['params'][0] ^= 1
    wrong_program = copy.deepcopy(authorized); wrong_program['program'] = 'oct'+'2'*44
    malformed = copy.deepcopy(authorized); malformed['params'][-1] = 'A'*352
    calls = [constructor, wrong_action, wrong_program, malformed, authorized, authorized,
             dict(method='get_admin_nonce', params=[], program=address)]
    spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    report = native.run(a.upstream, a.builder_image, ROOT/'scripts/node-port/vpn-admin-oracle.ml',
                        dict(source=source, calls=calls), 'octra_vm octra_core yojson lwt.unix')
    assert [c['expected']['ok'] for c in report['cases']['cases']] == [True, False, False, False, True, False, True]
    report['generator_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['aml_sha256'] = hashlib.sha256(source.encode()).hexdigest()
    report['public_fixture_sha256'] = hashlib.sha256(a.public_fixture.read_bytes()).hexdigest()
    report['scope'] = 'Current VPN AML constructor and private-admin authorization/replay through real VM execution. Development public proof only. No Circle deployment, account funding, consensus or tunnel qualification.'
    a.out.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS native compiled VPN administration',len(calls),'calls')

if __name__ == '__main__':
    main()
