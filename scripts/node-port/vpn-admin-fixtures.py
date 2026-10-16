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
    success_flags = [True, False, False, False, True, False, True]
    if 'authorizations' in material:
        auths = material['authorizations']
        def authorization(number):
            row = auths[str(number)]
            return dict(method=row['method'], params=row['params'], program=address)
        # All proof packages are public development fixtures. Replay the original
        # nonce order against the CURRENT native compiler and VM, including the
        # cancelled handoff and later rotation to a third private credential.
        sequence = [(4, False), (5, True), (6, True), (8, False),
                    (9, False), (10, False), (11, False), (12, True),
                    (7, False), (13, True), (14, False), (15, True),
                    (15, False), (16, False), (17, True), (18, True)]
        calls = calls[:6]
        success_flags = success_flags[:6]
        for number, succeeds in sequence:
            calls.append(authorization(number)); success_flags.append(succeeds)
        calls.append(dict(method='get_admin_handoff_kind', params=[], program=address))
        success_flags.append(True)
        # A valid proof at the current nonce must still roll back when the
        # signed governance request attempts to enable protocol commission.
        for number, succeeds in [(19, True), (20, False), (21, True), (22, False), (23, False)]:
            calls.append(authorization(number)); success_flags.append(succeeds)
        for retired in [auths['1']['commitment'], auths['15']['commitment']]:
            reuse = copy.deepcopy(authorization(22)); reuse['params'][0] = retired
            calls.append(reuse); success_flags.append(False)
        for method in ['get_admin_nonce', 'get_admin_commitment', 'get_pending_admin_commitment']:
            calls.append(dict(method=method, params=[], program=address)); success_flags.append(True)
    spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    report = native.run(a.upstream, a.builder_image, ROOT/'scripts/node-port/vpn-admin-oracle.ml',
                        dict(source=source, calls=calls), 'octra_vm octra_core yojson lwt.unix')
    assert [c['expected']['ok'] for c in report['cases']['cases']] == success_flags
    report['generator_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['aml_sha256'] = hashlib.sha256(source.encode()).hexdigest()
    report['public_fixture_sha256'] = hashlib.sha256(a.public_fixture.read_bytes()).hexdigest()
    report['scope'] = ('Current VPN AML constructor, private-admin authorization, cancellation/reproposal, handoff, '
                       'rotation, retired credential and replay refusal through real VM execution. Development '
                       'public proofs only. No Circle deployment, account funding, consensus or tunnel qualification.')
    a.out.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS native compiled VPN administration',len(calls),'calls')

if __name__ == '__main__':
    main()
