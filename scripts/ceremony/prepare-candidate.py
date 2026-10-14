#!/usr/bin/env python3
"""Compile an unsigned candidate. Integrity verification is not launch approval."""
import argparse
import base64
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
REQUIRED = (
    'target_network_and_genesis', 'target_execution_profile', 'owner_authorization_scheme',
    'reviewed_economic_parameters', 'native_money_path_tests', 'vpn_daemon_interop',
    'independent_security_review', 'deployment_and_recovery_rehearsal',
)
PRIVATE_REQUIRED = REQUIRED + ('private_admin_circuit_and_multiparty_setup',)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def encoded(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()

def command(args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True).stdout

def snapshot(repo):
    repo = repo.resolve()
    names = command(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], repo).split(b'\0')
    records = []
    for raw in sorted(set(names)):
        if not raw:
            continue
        name = raw.decode()
        path = repo / name
        if path.is_symlink():
            data = str(path.readlink()).encode()
        elif path.is_file():
            data = path.read_bytes()
        else:
            continue
        records.append([name, sha(data)])
    return {'head': command(['git', 'rev-parse', 'HEAD'], repo).decode().strip(),
            'tree_sha256': sha(encoded(records)),
            'dirty': bool(command(['git', 'status', '--porcelain'], repo))}

def compile_candidate(args):
    output = args.out.resolve()
    if output.exists():
        raise ValueError('output already exists; use a fresh candidate directory')
    config = tomllib.loads(args.params.read_text())
    # No guessed RPC, owner, nonce, network or synthetic signature envelope.
    target = config.get('target', {})
    economic = config['constructor']
    values = [economic[k] for k in ('min_session_deposit', 'min_tailnet_deposit', 'min_circle_stake',
                                   'session_grace_epochs', 'unbond_grace_epochs')]
    if any(type(v) is not int or v <= 0 or v >= 2**64 for v in values):
        raise ValueError('constructor values must be positive u64 integers')
    if values[2] < 100_000_000 or values[4] < 1000:
        raise ValueError('stake/unbond grace violate contract floors')
    compiler = args.amlc.resolve(strict=True)
    version = args.program_version
    source = ROOT / f'program/main-v{version}.aml'
    text = source.read_text()
    if not re.search(r'const PROTOCOL_FEE_DEFAULT_BPS: uint = 0\b', text) or not re.search(r'require\(new_protocol_fee_bps == 0,', text) or 'total_paid * self.protocol_fee_bps' in text:
        raise ValueError('VPN protocol commission must be disabled')
    private = config.get('private_admin', {})
    admin_values = [private.get(k) or None for k in ('commitment', 'verification_key_b64', 'domain')]
    if version == 5:
        if any(admin_values) and not all(admin_values):
            raise ValueError('private administration needs commitment, verification key and deployment domain together')
        if all(admin_values):
            for text in (admin_values[0], admin_values[2]):
                if len(text) != 64 or any(c not in '0123456789abcdef' for c in text):
                    raise ValueError('admin commitment/domain must be canonical SHA256 hex')
            vk = base64.b64decode(admin_values[1], validate=True)
            if len(vk) != 906 or vk[:10] != b'OG16V1\0\0\0\x06':
                raise ValueError('private admin verification key must be the reviewed six-input OG16V1 key')
            if base64.b64encode(vk).decode() != admin_values[1]:
                raise ValueError('verification key base64 must be canonical')
        cap = economic.get('max_locked_value', 0)
        if type(cap) is not int or not 0 <= cap < 2**64 or (cap and cap <= values[2]):
            raise ValueError('fund cap must be zero or exceed stake within u64')
        values += admin_values + [cap]
    # v4 is self-contained; an import would require a complete source bundle.
    if any(line.lstrip().startswith('import ') for line in source.read_text().splitlines()):
        raise ValueError('source bundle must include imported files')
    output.mkdir(parents=True)
    bundled = output / f'main-v{version}.aml'
    bundled.write_bytes(source.read_bytes())
    report = command([str(compiler), 'compile', str(bundled), '--out', str(output / f'main-v{version}.octb')]).decode()
    code = (output / f'main-v{version}.octb').read_bytes()
    if not report.startswith('status = pass ') or not code.startswith(b'OCTB'):
        raise ValueError('real compiler did not produce valid OCTB')
    abi_raw = command([str(compiler), 'abi', str(bundled)])
    abi = json.loads(abi_raw)
    if not isinstance(abi, dict) or not isinstance(abi.get('functions'), list) or not abi['functions']:
        raise ValueError('compiler ABI missing methods')
    (output / f'main-v{version}.abi.json').write_text(json.dumps(abi, indent=2) + '\n')
    (output / 'compiler-report.txt').write_text(report)
    target_fields = ('rpc_url', 'chain_id', 'genesis_root') if version == 5 else ('rpc_url', 'chain_id', 'genesis_root', 'owner')
    intent = {'kind': 'unsigned_deployment_intent', 'contract': f'OctraVPN v{version}',
              'target': {k: target.get(k) or None for k in target_fields},
              'constructor_args': values, 'nonce': None, 'signed': False,
              'economics': {'vpn_protocol_fee_bps': 0},
              'policy': 'governed onboarding; opaque permissionless slashing disabled',
              'warning': 'Intent is not a transaction. Recompile under the selected target epoch/profile before signing.'}
    if version == 5:
        intent['deployment_route'] = 'factory deploy_vpn; never deploy VPN directly from a wallet'
        intent['private_admin'] = {'commitment': admin_values[0], 'domain': admin_values[2],
                                 'verification_key_b64_sha256': sha(admin_values[1].encode()) if admin_values[1] else None,
                                 'credential_witness_included': False,
                                 'setup_certified': False}
        factory = output/'private-admin-factory.aml'
        factory.write_bytes((ROOT/'program/private-admin-factory.aml').read_bytes())
        factory_report = command([str(compiler), 'compile', str(factory), '--out', str(output/'private-admin-factory.octb')]).decode()
        if not factory_report.startswith('status = pass ') or not (output/'private-admin-factory.octb').read_bytes().startswith(b'OCTB'):
            raise ValueError('factory compilation failed')
        (output/'private-admin-factory.abi.json').write_bytes(command([str(compiler), 'abi', str(factory)]))
        (output/'factory-compiler-report.txt').write_text(factory_report)
    (output / 'intent.json').write_text(json.dumps(intent, indent=2) + '\n')
    payload = {'schema': 2, 'program_version': version, 'compiler': {'version': command([str(compiler), 'version']).decode().strip(),
               'binary_sha256': sha(compiler.read_bytes()),
               'patches': {path.name: sha(path.read_bytes()) for path in args.compiler_patch},
               'upstream_commit': '3a183bc8892b1795f2e1059848f1f331ce1a3a51'},
               'files': {p.name: sha(p.read_bytes()) for p in sorted(output.iterdir()) if p.is_file()},
               'repositories': {name: snapshot(ROOT if name == 'octra' else ROOT.parent / name)
                                for name in ('octra', 'octra-foundry', 'headscale-rs')}}
    candidate_id = sha(encoded(payload))
    manifest = {'candidate_id': candidate_id, 'payload': payload,
                'launch_ready': False, 'unmet_prerequisites': list(PRIVATE_REQUIRED if version == 5 else REQUIRED),
                'scope': 'Compiled unsigned candidate; standalone VM checks do not certify a target chain profile.'}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Unsigned candidate: {output}\nCandidate ID: {candidate_id}\nLaunch status: NOT_READY')

def verify(args):
    output = args.out.resolve()
    manifest = json.loads((output / 'manifest.json').read_text())
    payload = manifest['payload']
    if sha(encoded(payload)) != manifest['candidate_id']:
        raise ValueError('candidate manifest digest mismatch')
    for name, expected in payload['files'].items():
        path = pathlib.Path(name)
        if path.name != name or path.is_absolute():
            raise ValueError('invalid artifact path')
        if sha((output / name).read_bytes()) != expected:
            raise ValueError(f'artifact changed: {name}')
    # Readiness fields are declarations, never trusted as approval evidence.
    prerequisites = PRIVATE_REQUIRED if payload.get('program_version') == 5 else REQUIRED
    if manifest.get('launch_ready') is not False or manifest.get('unmet_prerequisites') != list(prerequisites):
        raise ValueError('readiness declaration changed; this tool cannot certify a launch')
    print('Candidate integrity: PASS\nLaunch status: NOT_READY')
    if args.require_ready:
        print('Missing verified prerequisites: ' + ', '.join(prerequisites), file=sys.stderr)
        return 1
    return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prepare = sub.add_parser('prepare')
    prepare.add_argument('--amlc', type=pathlib.Path, required=True)
    prepare.add_argument('--params', type=pathlib.Path, default=ROOT/'ceremony/mainnet-candidate.toml.example')
    prepare.add_argument('--program-version', type=int, choices=(4, 5), default=5)
    prepare.add_argument('--compiler-patch', type=pathlib.Path, action='append', default=[])
    prepare.add_argument('--out', type=pathlib.Path, required=True)
    check = sub.add_parser('verify')
    check.add_argument('--out', type=pathlib.Path, required=True)
    check.add_argument('--require-ready', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            compile_candidate(args)
            return 0
        return verify(args)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f'Candidate failed: {error}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
