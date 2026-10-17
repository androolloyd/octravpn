#!/usr/bin/env python3
"""Stock Tailscale kernel TUNs, DNS, native DERP and canonical Circle HTTPS.
All containers use a fresh internal network. No host VPN or public chain writes.
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

SUITE = pathlib.Path(__file__).resolve().parent


def command(args, data=None, timeout=90):
    result = subprocess.run([str(arg) for arg in args], input=data, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        # Commands contain file paths, never bearer/preauth values.
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr[-1500:]}')
    return result.stdout.strip()


def until(check, label, timeout=60):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as caught:
            error = str(caught)
        time.sleep(.3)
    raise RuntimeError(f'{label} timed out: {error}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-image', default='octranet-qualification:20261017')
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700)
    output = args.out.resolve()
    private = output / 'private'
    private.mkdir(mode=0o700)
    os.umask(0o077)
    identifier = 'octranet-check-' + uuid.uuid4().hex[:12]
    image = identifier + ':local'
    network = identifier
    containers = []
    credentials = []
    journal = {'qualified': False, 'steps': [], 'scope': 'Isolated stock Tailscale/native mesh, DNS and canonical Circle HTTPS; paid sessions are a separate gate.'}

    def save():
        (output / 'qualification.json').write_text(json.dumps(journal, indent=2) + '\n')

    def step(name, **evidence):
        journal['steps'].append({'name': name, **evidence})
        save()
        print(name, flush=True)

    def execute(name, *argv, data=None, timeout=90):
        return command(['docker', 'exec', '-i', name, *argv], data, timeout)

    def control(payload, mode='admin'):
        return json.loads(execute(identifier + '-control', 'python3', '/suite/control.py', mode,
                                  data=json.dumps(payload)))

    def policy(raw):
        return control({'method': 'PUT', 'path': '/api/v1/policy', 'body': raw})

    def ts(name, *argv, timeout=90):
        return execute(name, 'tailscale', '--socket=/tmp/tailscaled.sock', *argv, timeout=timeout)

    def status(name):
        return json.loads(ts(name, 'status', '--json'))

    def peer_read(name):
        value = json.loads(execute(name, 'python3', '/suite/peer.py', 'get', timeout=15))
        assert value['status'] == 200 and value['chain'] and value['epoch']
        assert 'committed state of your local Rust node' in value['body']
        return value

    try:
        command(['docker', 'build', '-f', SUITE / 'Dockerfile', '--build-arg',
                 'NODE_IMAGE=' + args.node_image, '-t', image, SUITE], timeout=180)
        journal['image'] = json.loads(command(['docker', 'image', 'inspect', image]))[0]['Id']
        journal['native_source'] = json.loads(command(['docker', 'run', '--rm', '--network', 'none',
            '--entrypoint', 'cat', args.node_image, '/usr/local/share/native-source.json']))
        journal['suite_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in SUITE.iterdir() if p.is_file()}
        command(['docker', 'network', 'create', '--internal', network])
        ca = private / 'ca'
        ca.mkdir()
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-subj', '/CN=Octranet isolated qualification CA', '-keyout', ca / 'key.pem', '-out', ca / 'cert.pem'])
        for name, host in [('control', 'control.mesh.test'), ('peer-b', 'octra.to')]:
            directory = private / name
            directory.mkdir()
            command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + host,
                     '-keyout', directory / 'tls.key', '-out', directory / 'request.pem'])
            (directory / 'extensions').write_text('subjectAltName=DNS:' + host + '\nextendedKeyUsage=serverAuth\n')
            command(['openssl', 'x509', '-req', '-in', directory / 'request.pem', '-CA', ca / 'cert.pem',
                     '-CAkey', ca / 'key.pem', '-CAcreateserial', '-days', '1', '-extfile', directory / 'extensions',
                     '-out', directory / 'cert.pem'])
        for name in ['peer-a', 'peer-c']:
            (private / name).mkdir()
        for name in ['peer-a', 'peer-b', 'peer-c']:
            shutil.copyfile(ca / 'cert.pem', private / name / 'ca.pem')
        token = secrets.token_hex(32)
        credentials.append(token)
        (private / 'control/admin.token').write_text(token)
        (private / 'control/records.json').write_text('[]')
        mesh = {'state_dir': '/state/mesh', 'tailnet_id': identifier, 'http_addr': '127.0.0.1:51821',
                'https_addr': '0.0.0.0:443', 'hostname': 'control.mesh.test',
                'control_url': 'https://control.mesh.test', 'admin_token_file': '/config/admin.token',
                'tls': {'certificate': '/config/cert.pem', 'key': '/config/tls.key'}, 'serve_derp': True,
                'dns': {'base_domain': 'mesh.octra.test', 'override_local_dns': False,
                        'extra_records_path': '/config/records.json'}}
        (private / 'control/mesh.json').write_text(json.dumps(mesh))
        (private / 'state').mkdir()
        node = identifier + '-control'
        containers.append(node)
        command(['docker', 'run', '-d', '--name', node, '--network', network, '--network-alias', 'control.mesh.test',
                 '--cap-drop=ALL', '--security-opt=no-new-privileges', '-v', f'{SUITE}:/suite:ro',
                 '-v', f'{private}/control:/config:ro', '-v', f'{private}/state:/state',
                 '-e', 'RUST_LOG=warn', image, 'python3', '/suite/control.py'])
        until(lambda: int(control({'method': 'node_status'}, 'rpc')['epoch']) >= 2, 'native validators', 120)
        noise = control({'path': '/key?v=113'})
        info = control({'path': '/api/v1/machines'})
        assert info == []
        address = json.loads(command(['docker', 'inspect', node]))[0]['NetworkSettings']['Networks'][network]['IPAddress']
        step('four native validators and embedded HTTPS mesh started', control_ip=address)

        def start_peer(name, replay=None):
            directory = private / name
            if replay is None:
                minted = control({'method': 'POST', 'path': '/admin/preauth',
                                  'body': json.dumps({'user': 'tester', 'ttl_secs': 900})})
                key = minted['key']
            else:
                key = replay
            credentials.append(key)
            (directory / 'auth.key').write_text(key)
            container = identifier + '-' + name
            containers.append(container)
            command(['docker', 'run', '-d', '--name', container, '--network', network,
                     '--add-host', 'control.mesh.test:' + address, '--dns', '100.100.100.100',
                     '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW', '--device=/dev/net/tun',
                     '--security-opt=no-new-privileges', '-e', 'SSL_CERT_FILE=/config/ca.pem',
                     '-v', f'{directory}:/config:ro', '-v', f'{SUITE}:/suite:ro', image,
                     'tailscaled', '--state=/tmp/tailscale.state', '--socket=/tmp/tailscaled.sock'])
            until(lambda: status(container), 'tailscaled socket')
            try:
                ts(container, 'up', '--login-server=https://control.mesh.test', '--hostname=' + name,
                   '--auth-key=file:/config/auth.key', '--accept-dns=true', '--timeout=20s', timeout=25)
            except (RuntimeError, subprocess.TimeoutExpired):
                if replay is None:
                    raise
            return container, key

        a, key_a = start_peer('peer-a')
        b, _ = start_peer('peer-b')
        a_status, b_status = status(a), status(b)
        assert a_status['BackendState'] == b_status['BackendState'] == 'Running'
        ip = b_status['TailscaleIPs'][0]
        step('two stock Tailscale clients enrolled with real kernel TUNs',
             version=ts(a, 'version').splitlines()[0], peer_a=a_status['TailscaleIPs'], peer_b=b_status['TailscaleIPs'])
        until(lambda: ts(a, 'ping', '--c=1', '--tsmp', '--timeout=3s', ip), 'encrypted TSMP')
        until(lambda: ts(a, 'ping', '--c=1', '--icmp', '--timeout=3s', ip), 'encrypted ICMP')
        records = [{'name': 'octra.to', 'type': 'A', 'value': ip}]
        (private / 'control/records.json').write_text(json.dumps(records))
        fqdn = b_status['Self']['DNSName'].rstrip('.')
        for name in [fqdn, 'octra.to']:
            until(lambda: json.loads(execute(a, 'python3', '/suite/peer.py', 'dns', name))['address'] == ip,
                  'normal application DNS for ' + name)
        step('MagicDNS peer names and octra.to resolve through the tunnel', expected_ip=ip, peer_name=fqdn)
        command(['docker', 'exec', '-d', b, 'python3', '/suite/peer.py', 'serve'])
        response = until(lambda: peer_read(a), 'Circle website HTTPS')
        step('ordinary HTTPS application fetched canonical Circle website over Tailscale',
             chain=response['chain'], epoch=response['epoch'], body_sha256=hashlib.sha256(response['body'].encode()).hexdigest())
        for peer in [a, b]:
            execute(peer, 'iptables', '-I', 'OUTPUT', '-o', 'eth0', '-p', 'udp', '-j', 'DROP')
        relay = until(lambda: ts(a, 'ping', '--c=1', '--until-direct=false', '--timeout=3s', ip),
                      'native DERP relay', 45)
        assert 'via DERP(' in relay, relay
        peer_read(a)
        step('native Rust DERP carried encrypted traffic with direct UDP blocked', ping=relay)
        for peer in [a, b]:
            execute(peer, 'iptables', '-D', 'OUTPUT', '-o', 'eth0', '-p', 'udp', '-j', 'DROP')
        denied = '{"acls":[]}'
        policy(denied)
        def blocked():
            try:
                peer_read(a)
                return False
            except RuntimeError:
                return True
        until(blocked, 'deny-all packet filter')
        command(['docker', 'restart', '--time=20', node], timeout=50)
        until(lambda: control({'path': '/key?v=113'}) == noise, 'retained Noise identity', 120)
        assert control({'path': '/api/v1/policy'})['raw'] == denied
        assert len(control({'path': '/api/v1/machines'})) == 2
        assert blocked()
        step('mesh identity enrollment and deny-all policy survive native node restart')
        policy('{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}')
        until(lambda: peer_read(a), 'post-restart Circle HTTPS', 90)
        c, _ = start_peer('peer-c', replay=key_a)
        assert status(c)['BackendState'] != 'Running'
        assert len(control({'path': '/api/v1/machines'})) == 2
        step('single-use enrollment replay rejected by an actual third stock client')
        journal['qualified'] = True
        journal['public_network_qualified'] = False
        journal['paid_exit_qualified'] = False
        save()
    finally:
        for name in containers:
            result = subprocess.run(['docker', 'logs', name], capture_output=True, text=True)
            log = result.stdout + result.stderr
            for value in credentials:
                log = log.replace(value, '[redacted credential]')
            (output / (name + '.log')).write_text(log)
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
        subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
        save()


if __name__ == '__main__':
    main()
