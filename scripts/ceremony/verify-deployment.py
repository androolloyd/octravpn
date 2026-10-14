#!/usr/bin/env python3
"""Verify actual code and expected v5 private administration (or legacy owner)."""
import argparse
import json
import sys
import urllib.request

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('program_addr')
p.add_argument('--rpc-url', required=True)
p.add_argument('--expected-code-hash', required=True)
p.add_argument('--expected-owner', help='Legacy v1-v4 verification only')
p.add_argument('--expected-admin-commitment')
p.add_argument('--expected-admin-domain')
p.add_argument('--expected-admin-verification-key-hash', help='SHA256 of canonical base64 verification-key text')
p.add_argument('--expected-factory')
p.add_argument('--expected-factory-code-hash')
p.add_argument('--expected-max-locked-value', type=int, help='Mandatory v5 immutable fund ceiling; zero is unbounded')
a = p.parse_args()

def rpc(method, params):
    req = urllib.request.Request(a.rpc_url, data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(), headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=20) as response:
        data = json.load(response)
    if data.get('id') != 1 or 'error' in data or 'result' not in data:
        raise ValueError(f'{method}: {data}')
    return data['result']

try:
    if len(a.expected_code_hash) != 64 or any(c not in '0123456789abcdef' for c in a.expected_code_hash):
        raise ValueError('expected code hash must be canonical lowercase SHA256')
    info = rpc('vm_contract', [a.program_addr])
    if info.get('code_hash') != a.expected_code_hash:
        raise ValueError('live code hash differs from the reviewed target artifact')
    private_fields = (a.expected_admin_commitment, a.expected_admin_domain,
                      a.expected_admin_verification_key_hash, a.expected_factory,
                      a.expected_factory_code_hash)
    if any(private_fields):
        if not all(private_fields):
            raise ValueError('all private administration and factory verification fields are required')
        if a.expected_max_locked_value is None or not 0 <= a.expected_max_locked_value < 2**64:
            raise ValueError('explicit v5 fund ceiling is required')
        if a.expected_owner:
            raise ValueError('choose private administration or legacy owner verification')
        fields = {'get_admin_commitment': a.expected_admin_commitment,
                  'get_admin_domain': a.expected_admin_domain,
                  'get_admin_verification_key_hash': a.expected_admin_verification_key_hash}
        for method, expected in fields.items():
            if not expected or len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
                raise ValueError(f'{method}: explicit canonical SHA256 expected value required')
            observed = rpc('contract_call', [a.program_addr, method, []])
            if not isinstance(observed, dict) or observed.get('result') != expected:
                raise ValueError(f'{method}: live administration state differs from reviewed value')
        if not a.expected_factory or info.get('owner') != a.expected_factory:
            raise ValueError('native metadata owner must be the reviewed factory address')
        if len(a.expected_factory) != 47 or not a.expected_factory.startswith('oct'):
            raise ValueError('invalid expected factory address')
        if len(a.expected_factory_code_hash) != 64 or any(c not in '0123456789abcdef' for c in a.expected_factory_code_hash):
            raise ValueError('factory code hash must be canonical lowercase SHA256')
        factory = rpc('vm_contract', [a.expected_factory])
        if not a.expected_factory_code_hash or factory.get('code_hash') != a.expected_factory_code_hash:
            raise ValueError('factory code differs from reviewed deployment route')
        cap = rpc('contract_call', [a.program_addr, 'get_max_locked_value', []])
        if not isinstance(cap, dict) or isinstance(cap.get('result'), bool) or str(cap.get('result')) != str(a.expected_max_locked_value):
            raise ValueError('live immutable fund ceiling differs from reviewed canary')
        pending = rpc('contract_call', [a.program_addr, 'get_pending_admin_commitment', []])
        if not isinstance(pending, dict) or pending.get('result') != '':
            raise ValueError('admin handoff is pending')
        print('Deployment code, private administration and factory authority: PASS')
    else:
        if not a.expected_owner or not a.expected_owner.startswith('oct'):
            raise ValueError('explicit private administration fields or legacy owner address required')
        owner = rpc('contract_call', [a.program_addr, 'get_owner', []])
        if not isinstance(owner, dict) or owner.get('result') != a.expected_owner:
            raise ValueError('current contract owner differs from the expected owner')
        print('Deployment code hash and current owner: PASS')
    print('This read-only check does not certify economics, governance or launch readiness.')
except (OSError, ValueError, KeyError) as error:
    print(f'Deployment verification FAIL: {error}', file=sys.stderr)
    sys.exit(1)
