#!/usr/bin/env python3
"""Real WG/forwarding lab, only in a disposable network-none Linux container."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

PROCESSES = []
NAMES = ['paid-node', 'paid-relay', 'paid-web', 'paid-client']


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def ns(name, *args, **kwargs):
    return run('ip', 'netns', 'exec', name, *args, **kwargs)


def start(name, code):
    p = subprocess.Popen(['ip', 'netns', 'exec', name, 'python3', '-u', '-c', code],
                         stdout=subprocess.PIPE, text=True)
    PROCESSES.append(p)
    assert p.stdout.readline().strip() == 'ready'


def client(name, address, port):
    return ns(name, 'python3', '-c', "import socket; s=socket.create_connection((%r,%r),2); print(s.recv(100).decode())" % (address, port))


def main():
    assert {x['ifname'] for x in json.loads(run('ip', '-j', 'link'))} == {'lo'}
    run('ip', 'link', 'add', 'lab0', 'type', 'bridge')
    run('ip', 'link', 'set', 'lab0', 'up')
    for i, name in enumerate(NAMES):
        run('ip', 'netns', 'add', name)
        ns(name, 'ip', 'link', 'set', 'lo', 'up')
        if name == 'paid-client':
            continue
        run('ip', 'link', 'add', 'port' + str(i), 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name)
        run('ip', 'link', 'set', 'port' + str(i), 'master', 'lab0')
        run('ip', 'link', 'set', 'port' + str(i), 'up')
        ns(name, 'ip', 'address', 'add', f'192.0.2.{i+1}/24', 'dev', 'eth0')
        ns(name, 'ip', 'link', 'set', 'eth0', 'up')
    ns('paid-node', 'ip', 'route', 'add', 'default', 'via', '192.0.2.2')
    run('ip', 'link', 'add', 'octrapay0', 'netns', 'paid-node', 'type', 'veth',
        'peer', 'name', 'pay0', 'netns', 'paid-client')
    for name, dev, addr in [('paid-node', 'octrapay0', '198.18.0.1/15'), ('paid-client', 'pay0', '198.18.0.2/15')]:
        ns(name, 'ip', 'address', 'add', addr, 'dev', dev)
        ns(name, 'ip', 'link', 'set', dev, 'up')
    ns('paid-client', 'ip', 'route', 'add', 'default', 'via', '198.18.0.1')
    for name in ['paid-node', 'paid-relay']:
        ns(name, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
        ns(name, 'sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=0')
        ns(name, 'sysctl', '-qw', 'net.ipv4.conf.default.rp_filter=0')
    ns('paid-web', 'ip', 'address', 'add', '203.0.113.1/32', 'dev', 'lo')
    ns('paid-relay', 'ip', 'route', 'add', '203.0.113.1/32', 'via', '192.0.2.3')
    ns('paid-relay', 'ip', 'link', 'add', 'octra-wg', 'type', 'wireguard')
    with tempfile.TemporaryDirectory() as temporary:
        keys = {}
        for name in ['paid-node', 'paid-relay']:
            p = Path(temporary) / name
            p.write_text(run('wg', 'genkey') + '\n'); p.chmod(0o600)
            keys[name] = (str(p), run('wg', 'pubkey', input=p.read_text()))
        ns('paid-relay', 'wg', 'set', 'octra-wg', 'listen-port', '51821',
           'private-key', keys['paid-relay'][0], 'peer', keys['paid-node'][1], 'allowed-ips', '10.203.1.2/32')
        ns('paid-relay', 'ip', 'address', 'add', '10.203.1.1/30', 'dev', 'octra-wg')
        ns('paid-relay', 'ip', 'link', 'set', 'octra-wg', 'up')
        ns('paid-relay', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.203.1.2/32', '-o', 'eth0', '-j', 'MASQUERADE')
        cfg = Path(temporary) / 'underlay.json'
        cfg.write_text(json.dumps({'namespace': ns('paid-node', 'readlink', '/proc/self/ns/net'),
            'outer_ipv4': '192.0.2.1', 'relay_ipv4': '192.0.2.2', 'relay_public_key': keys['paid-relay'][1],
            'private_key_file': keys['paid-node'][0]}))
        ns('paid-node', 'python3', '/app/paid_underlay.py', '--config', str(cfg))
        # Echo the source address; it must be the relay, never the Mac/node.
        start('paid-web', "import socket\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('203.0.113.1',8080));s.listen();print('ready',flush=True)\nwhile True:\n c,a=s.accept();c.sendall(a[0].encode());c.close()")
        time.sleep(1)
        assert client('paid-client', '203.0.113.1', 8080) == '192.0.2.2'
        # Public UDP ingress and reply traverse the same authenticated WG peer.
        ns('paid-relay', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-d', '192.0.2.2', '-p', 'udp', '--dport', '20804', '-j', 'DNAT', '--to-destination', '10.203.1.2:20804')
        start('paid-node', "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',20804));print('ready',flush=True)\nwhile True:\n b,a=s.recvfrom(2048);s.sendto(b,a)")
        assert ns('paid-web', 'python3', '-c', "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'paid-ingress',('192.0.2.2',20804));print(s.recv(100).decode())") == 'paid-ingress'
        # Delete WG and deliberately restore an otherwise working physical
        # path. The paid interface must still be blocked by its kernel guard.
        ns('paid-node', 'ip', 'link', 'delete', 'octra-wg')
        ns('paid-node', 'ip', 'route', 'replace', 'default', 'via', '192.0.2.2', 'dev', 'eth0')
        ns('paid-node', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '198.18.0.0/15', '-o', 'eth0', '-j', 'MASQUERADE')
        assert client('paid-node', '203.0.113.1', 8080) == '192.0.2.1'
        blocked = subprocess.run(['ip', 'netns', 'exec', 'paid-client', 'python3', '-c',
            "import socket;socket.create_connection(('203.0.113.1',8080),2)"], capture_output=True)
        assert blocked.returncode != 0 and b'TimeoutError' in blocked.stderr
        rules = ns('paid-node', 'iptables', '-nvL', 'OCTRA_PAID_WG')
        assert any('DROP' in line and int(line.split()[0]) > 0 for line in rules.splitlines() if 'DROP' in line)
        print(json.dumps({'passed': True, 'relay_egress_verified': True, 'udp_ingress_verified': True,
                         'physical_path_control_passed': True, 'paid_fallback_dropped': True}))


if __name__ == '__main__':
    try:
        main()
    finally:
        for p in PROCESSES:
            p.terminate(); p.wait(timeout=5)
        for name in reversed(NAMES):
            subprocess.run(['ip', 'netns', 'delete', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
