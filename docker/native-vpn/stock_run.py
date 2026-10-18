#!/usr/bin/env python3
"""Isolated real stock Tailscale prepaid gate, against freshly frozen binaries.

Build the existing native-vpn image first. Both Program and Circle applications
must run as separate fresh invocations. No public chain, host networking, host
VPN state, trusted grant endpoint or plaintext DERP interpretation is used.
"""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import time
import uuid

from json_snapshot import read_object

SUITE = pathlib.Path(__file__).resolve().parent
TAILSCALE = 'tailscale/tailscale@sha256:87c55d6be56ad85b3d8bceca5f87f73de288c609131460dd1be1874c250cc41d'
OPERATOR_IP = '100.64.0.1'
PUBLIC = '93.184.216.34'


def command(args, timeout=120, data=None):
    result = subprocess.run([str(x) for x in args], input=data, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: {result.stderr[-1500:]}')
    return result.stdout.strip()


def until(check, label, timeout=120):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value: return value
        except (RuntimeError, ValueError, OSError, AssertionError, subprocess.TimeoutExpired) as error:
            last = str(error)
        time.sleep(.25)
    raise RuntimeError(f'{label} timed out: {last}')


def atomic(path, value):
    temporary = path.with_suffix('.tmp'); temporary.write_text(json.dumps(value) + '\n'); temporary.replace(path)


def cleanup_owned(output, containers, volume, network):
    """Remove only this invocation's named resources and independently audit absence.

    A failed Docker query is an unknown cleanup result, never proof of absence.
    Container logs are captured by the caller before this helper removes them.
    """
    resources = {'containers': list(containers), 'volumes': [volume] if volume else [],
                 'networks': [network]}
    atomic(output / 'owned-resources.json', resources)
    attempts = []
    for kind, names in [('container', list(reversed(containers))), ('volume', resources['volumes']),
                        ('network', resources['networks'])]:
        for name in names:
            argv = ['docker', kind, 'rm', *(['-f'] if kind == 'container' else []), name]
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
                attempts.append({'argv': argv, 'exit_code': result.returncode, 'stderr': result.stderr[-2000:]})
            except (OSError, subprocess.TimeoutExpired) as error:
                attempts.append({'argv': argv, 'error': str(error)})
    remaining = {}; inventories = {}; errors = []
    for kind, names in resources.items():
        singular = {'containers': 'container', 'networks': 'network', 'volumes': 'volume'}[kind]
        argv = ['docker', singular, 'ls', *(['-a'] if singular == 'container' else []),
                '--format', '{{.Names}}' if singular == 'container' else '{{.Name}}']
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            if result.returncode:
                errors.append({'argv': argv, 'exit_code': result.returncode, 'stderr': result.stderr[-2000:]})
                continue
            present = set(result.stdout.splitlines()); inventories[kind] = sorted(present.intersection(names))
            remaining[kind] = inventories[kind]
        except (OSError, subprocess.TimeoutExpired) as error:
            errors.append({'argv': argv, 'error': str(error)})
    record = {'verified': not errors and not any(remaining.values()), 'owned': resources,
              'remaining_owned': remaining, 'inventory_errors': errors, 'removal_attempts': attempts}
    atomic(output / 'cleanup.json', record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-image', required=True)
    parser.add_argument('--context', type=pathlib.Path, required=True,
                        help='frozen Docker context containing octra, octra-foundry and headscale-rs')
    parser.add_argument('--headscale-commit', required=True)
    parser.add_argument('--application', choices=['program', 'circle'], required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    assert len(args.headscale_commit) == 40 and all(c in '0123456789abcdef' for c in args.headscale_commit)
    os.umask(0o077); args.out.mkdir(mode=0o700); output = args.out.resolve()
    evidence = output / 'evidence'; evidence.mkdir(mode=0o700)
    private = output / 'private'; private.mkdir(mode=0o700)
    peer_config = private / 'peer'; peer_config.mkdir()
    operator_config = private / 'operator'; operator_config.mkdir()
    commands = private / 'commands'; commands.mkdir()
    identifier = 'octra-stock-' + uuid.uuid4().hex[:12]
    image = identifier + ':local'; network = identifier; containers = []; credentials = []
    volume = None; requests = 0
    report = {'qualified': False, 'application': args.application, 'steps': [], 'public_network_qualified': False,
              'scope': 'real kernel stock Tailscale1.104.1, native TLS DERP, Circle HTTPS, canonical prepaid exit and4ExEx',
              'headscale_commit': args.headscale_commit}

    def save(): atomic(output / 'qualification.json', report)
    def step(name, **value): report['steps'].append({'name': name, **value}); save(); print(name, flush=True)
    def execute(name, *argv, timeout=90): return command(['docker', 'exec', name, *argv], timeout)
    def ts(*argv, timeout=60): return execute(identifier + '-peer', 'tailscale', '--socket=/tmp/tailscaled.sock', *argv, timeout=timeout)
    def peer(action, *argv, timeout=40): return json.loads(execute(identifier + '-peer', 'python3', '/usr/local/bin/stock_peer.py', action, *argv, timeout=timeout))
    def control(action, **values):
        nonlocal requests
        requests += 1
        path = commands / f'{requests}.json'
        atomic(path, {'action': action, **values})
        result = until(lambda: json.loads(path.with_suffix('.result.json').read_text()), 'operator ' + action, 240)
        if 'error' in result: raise RuntimeError(result['error'])
        return result['ok']
    def state(): return control('state')
    def stock_path(direct):
        current = json.loads(ts('status', '--json'))
        peers = [value for value in current.get('Peer', {}).values() if OPERATOR_IP in value.get('TailscaleIPs', [])]
        assert len(peers) == 1 and peers[0].get('Online') is True
        row = peers[0]
        if direct: assert row.get('CurAddr'), row
        else: assert not row.get('CurAddr') and row.get('Relay'), row
        return {name: row.get(name) for name in ('CurAddr', 'Relay', 'RxBytes', 'TxBytes', 'PublicKey', 'ExitNode')}
    def blocked(action='blocked', *argv):
        before = state(); result = peer(action, *argv); after = state()
        assert after['hop']['sent_packets'] == before['hop']['sent_packets'], 'denied traffic reached external target kernel'
        if before['meter'] is not None:
            assert after['meter']['purchased'] == before['meter']['purchased']
        return result

    try:
        source = json.loads(command(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat',
                                     args.node_image, '/usr/local/share/native-source.json']))
        assert source['files'] and source['binaries']
        # Bind actual binary-image inputs to the caller's frozen context, not
        # merely a mutable image tag or a current Git HEAD label.
        for row in source['files']:
            relative = pathlib.PurePosixPath(row['path'])
            assert not relative.is_absolute() and '..' not in relative.parts
            path = args.context / relative
            assert path.is_file() and not path.is_symlink(), path
            assert path.stat().st_size == row['bytes'] and hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256'], path
        lock = (args.context / 'octra/Cargo.lock').read_text()
        assert args.headscale_commit in lock, 'captured Headscale pin differs from root lock'
        report['native_source'] = source
        report['suite_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in SUITE.glob('stock*') if path.is_file()}
        command(['docker', 'build', '-f', SUITE / 'stock_Dockerfile', '--build-arg', 'NODE_IMAGE=' + args.node_image,
                 '--build-arg', 'TAILSCALE_IMAGE=' + TAILSCALE, '-t', image, SUITE], timeout=300)
        report['image'] = json.loads(command(['docker', 'image', 'inspect', image]))[0]['Id']
        report['tailscale_image'] = TAILSCALE
        command(['docker', 'network', 'create', '--internal', '--subnet', '172.30.238.0/24', network])
        ca = private / 'ca'; ca.mkdir()
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Stock isolated gate CA',
                 '-keyout', ca / 'key.pem', '-out', ca / 'cert.pem'])
        for name, hostname in [('control', 'control.mesh.test'), ('portal', 'portal.mesh.test'), ('circles', 'circles.mesh.test')]:
            request = private / (name + '.csr'); extensions = private / (name + '.ext')
            command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + hostname,
                     '-keyout', operator_config / (name + '.key'), '-out', request])
            extensions.write_text('subjectAltName=DNS:' + hostname + '\nextendedKeyUsage=serverAuth\n')
            command(['openssl', 'x509', '-req', '-in', request, '-CA', ca / 'cert.pem', '-CAkey', ca / 'key.pem',
                     '-CAcreateserial', '-days', '1', '-extfile', extensions, '-out', operator_config / (name + '.crt')])
        shutil.copyfile(ca / 'cert.pem', peer_config / 'ca.pem')
        token = secrets.token_hex(32); credentials.append(token); (operator_config / 'admin.token').write_text(token)
        mesh = {'state_dir': '/tmp/native-vpn/mesh', 'tailnet_id': identifier, 'http_addr': '127.0.0.1:51821',
                'https_addr': '172.30.238.2:443', 'hostname': 'control.mesh.test', 'control_url': 'https://control.mesh.test',
                'admin_token_file': '/config/admin.token', 'tls': {'certificate': '/config/control.crt', 'key': '/config/control.key'},
                'serve_derp': True, 'dns': {'base_domain': 'stock.mesh.test', 'magic_dns': True, 'override_local_dns': False},
                'stock_exit': {'operator_ipv4': OPERATOR_IP, 'portal_port': 443, 'circle_gateway': True,
                               'endpoints': ['172.30.238.2:19874']}}
        (operator_config / 'mesh.json').write_text(json.dumps(mesh))
        volume = command(['docker', 'volume', 'create'])
        target = identifier + '-target'; containers.append(target)
        command(['docker', 'run', '-d', '--name', target, '--network', 'none', '--cap-drop=ALL', '--cap-add=NET_ADMIN',
            '--device=/dev/net/tun', '--read-only', '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m',
            '-v', f'{evidence}:/evidence', '-v', f'{volume}:/hop', image, 'python3', '-u', '/usr/local/bin/packet_target.py'])
        until(lambda: execute(target, 'test', '-S', '/hop/target.sock') is not None, 'target kernel')
        node = identifier + '-operator'; containers.append(node)
        command(['docker', 'run', '-d', '--name', node, '--network', network, '--ip', '172.30.238.2',
            '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW', '--device=/dev/net/tun',
            '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv4.conf.all.rp_filter=0',
            '--sysctl', 'net.ipv4.conf.default.rp_filter=0', '--sysctl', 'net.ipv4.conf.all.route_localnet=1',
            '--sysctl', 'net.ipv4.conf.default.route_localnet=1', '--read-only', '--security-opt=no-new-privileges',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=1g', '-v', f'{evidence}:/evidence', '-v', f'{volume}:/hop',
            '-v', f'{operator_config}:/config:ro', '-v', f'{commands}:/commands', image, 'python3', '-u', '/usr/local/bin/stock_operator.py', '--application', args.application])
        ready = until(lambda: json.loads((evidence / 'stock-ready.json').read_text()), 'real canonical stock fixture', 900)
        until(lambda: (commands).is_dir(), 'fixture command channel')
        minted = control('preauth'); credentials.append(minted['key']); (peer_config / 'auth.key').write_text(minted['key'])
        name = identifier + '-peer'; containers.append(name)
        command(['docker', 'run', '-d', '--name', name, '--network', network, '--ip', '172.30.238.3',
                 '--add-host', 'control.mesh.test:172.30.238.2', '--dns', '100.100.100.100',
                 '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW', '--device=/dev/net/tun',
                 '--read-only', '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
                 '-v', f'{peer_config}:/config:ro', '-e', 'SSL_CERT_FILE=/config/ca.pem', image,
                 'tailscaled', '--state=/tmp/tailscale.state', '--socket=/tmp/tailscaled.sock'])
        until(lambda: json.loads(ts('status', '--json')), 'stock daemon')
        version = ts('version').splitlines()[0]; assert version == '1.104.1', version
        up = ['up', '--login-server=https://control.mesh.test', '--hostname=stock-payer', '--auth-key=file:/config/auth.key',
              '--accept-dns=true', '--accept-routes=true', '--exit-node=' + OPERATOR_IP, '--exit-node-allow-lan-access=false', '--timeout=30s']
        ts(*up)
        identity = until(lambda: peer('identity'), 'authenticated stock node identity')
        until(lambda: peer('dns')['address'] == OPERATOR_IP, 'portal MagicDNS')
        until(lambda: peer('dns_paid')['address'] == '198.18.0.0', 'paid Circle MagicDNS')
        peer('route')
        asset_path = '/circles/' + ready['circle'] + '/not-free.txt'
        portal = until(lambda: peer('portal'), 'unpaid trusted portal TLS')
        assert portal['status'] == 200 and 'Octranet canonical onboarding portal' in portal['body']
        assert portal['headers'].get('x-octra-chain') and portal['headers'].get('x-octra-epoch')
        assert peer('portal', '--path', '/portal.css')['body_sha256'] == ready['portal_assets']['/portal.css']
        for path in ['/not-free.txt', '/rpc', '/app', '/circles/' + ready['circle'] + '/not-free.txt']:
            assert peer('portal', '--path', path)['status'] != 200, path
        try: peer('paid_circle', '--path', asset_path)
        except RuntimeError: pass
        else: raise AssertionError('unfunded general Circle HTTPS completed')
        blocked()
        initial = control('blocked_purchase', **identity)
        blocked()
        assert state()['earnings'] == initial['earnings'] == 0
        assert peer('portal')['status'] == 200
        step('stock kernel join, MagicDNS and fixed canonical portal work before purchases; arbitrary traffic denied', identity=identity, version=version)
        funded = control('release_purchase'); assert funded['purchased'] == [65536, 65536, 4096]
        peer('tcp_icmp'); peer('udp', '--count', '4', '--marker', 'direct:')
        paid = peer('paid_circle', '--path', asset_path)
        assert paid['status'] == 200 and paid['body_sha256'] == ready['portal_assets']['/not-free.txt']
        assert paid['headers'].get('x-octra-chain') and paid['headers'].get('x-octra-epoch')
        direct = until(lambda: stock_path(True), 'actual stock direct path')
        step('actual stock direct prepaid TCP UDP ICMP and arbitrary canonical Circle HTTPS', path=direct)
        execute(name, 'iptables', '-I', 'OUTPUT', '-o', 'eth0', '-p', 'udp', '-j', 'DROP')
        until(lambda: stock_path(False), 'forced native TLS DERP path', 90)
        peer('tcp_icmp'); peer('udp', '--count', '4', '--marker', 'derp:')
        assert peer('portal')['status'] == 200 and peer('paid_circle', '--path', asset_path)['status'] == 200
        relay = stock_path(False)
        assert relay['RxBytes'] > direct['RxBytes'] and relay['TxBytes'] > direct['TxBytes']
        step('same paid traffic and Circle TLS traverse authenticated native DERP with direct UDP blocked', path=relay)
        before = state(); after = control('restart')
        peer('tcp_icmp'); assert peer('portal')['status'] == 200
        assert after['journal']['authorized_bytes'] == before['journal']['authorized_bytes']
        step('stock daemon survives actual operator and controller SIGKILL with retained canonical purchases')
        # Deliberate registration rotation is independent of chain revocation.
        rotation = control('pause_rotation')
        ts('logout')
        minted = control('preauth'); credentials.append(minted['key']); (peer_config / 'auth.key').write_text(minted['key'])
        ts(*up)
        rotated = peer('identity')
        assert rotated['node_key'] != identity['node_key'], 'stock logout did not actually rotate the public node key'
        blocked('blocked_icmp')
        assert peer('portal')['status'] == 200
        next_plan = control('rotated_plan', **rotated)
        assert next_plan['purchased'] == [65536, 65536, 4096]
        peer('tcp_icmp')
        step('real stock logout reenrollment invalidates old paid registration until a fresh signed canonical plan', old_identity=identity, new_identity=rotated)
        # Exhaust one purchased class with real packets. Other classes provide
        # the required live-path positive control and no automatic top-up occurs.
        for index in range(128):
            before = state(); record = before['meter']
            used = sum(record[field][1] for field in ('committed', 'uncertain', 'pending'))
            probe_length = len(f'exhaust-{index}:'.encode()) + 4 + len(b'stock-native-udp') * 60 + 28
            if record['purchased'][1] - used < probe_length: break
            try: peer('udp', '--count', '1', '--marker', f'exhaust-{index}:')
            except RuntimeError: pass
        else: raise AssertionError('premium allowance did not exhaust')
        exhausted = state(); blocked('blocked', '--marker', 'denied-after-exhaustion:'); peer('tcp_icmp'); assert peer('portal')['status'] == 200
        assert state()['purchased'] == exhausted['purchased'] == [65536, 65536, 4096]
        step('premium exhaustion denies new traffic without topup while other classes and free portal remain live')
        withdrawn = control('withdraw'); peer('blocked_icmp')
        final = state()
        assert final['hop']['sent_packets'] == withdrawn['hop']['sent_packets'], 'revoked packets escaped at operator'
        assert peer('portal')['status'] == 200
        result = control('finish')
        observed = read_object(evidence / 'target.json')
        assert not observed['errors'] and not observed['hop']['errors']
        assert observed['udp_payload_bytes'] > 0 and observed['tcp_payload_bytes'] > 0
        assert observed['observed_sources'] and all(observed['observed_sources'].values())
        assert all(set(sources) == {'192.0.2.1'} for sources in observed['observed_sources'].values())
        report['network'] = {'target': observed, 'final_state': final, 'direct': direct, 'derp': relay}
        step('instant channel withdrawal independently revokes live stock packets; replay refused; four canonical ExEx sinks agree', claims=result['claims'], paid=result['paid'])
        control('stop')
        until(lambda: json.loads((evidence / 'journal.json').read_text())['qualified'], 'operator fixture successful')
        report['qualified'] = True; save()
    finally:
        for name in containers:
            result = subprocess.run(['docker', 'logs', name], capture_output=True, text=True)
            log = result.stdout + result.stderr
            for credential in credentials: log = log.replace(credential, '[redacted fixture credential]')
            (output / (name + '.log')).write_text(log)
        report['cleanup'] = cleanup_owned(output, containers, volume, network)
        if not report['cleanup']['verified']: report['qualified'] = False
        save()
        if not report['cleanup']['verified']: raise RuntimeError('owned Docker resource cleanup could not be verified')


if __name__ == '__main__': main()
