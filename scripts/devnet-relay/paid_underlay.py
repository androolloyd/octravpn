#!/usr/bin/env python3
"""Install a WireGuard underlay inside an owned Octra container namespace.

Run through `docker exec`/a namespace-sharing helper, never on the Mac or relay.
Paid forwarding keeps a kill switch even if the underlay disappears. This tool
does not change the node, its admission policy, or the relay's public firewall.
"""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess

WG = 'octra-wg'
PAID = 'octrapay0'
CHAIN = 'OCTRA_PAID_WG'
PREFIX = '198.18.0.0/15'


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def up(config):
    if set(config) != {'namespace', 'outer_ipv4', 'relay_ipv4', 'relay_public_key', 'private_key_file'}:
        raise ValueError('Unexpected underlay configuration')
    if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') != config['namespace']:
        raise ValueError('Owned container namespace differs')
    relay = str(ipaddress.IPv4Address(config['relay_ipv4']))
    outer = str(ipaddress.IPv4Address(config['outer_ipv4']))
    if ipaddress.ip_address(relay).is_multicast or ipaddress.ip_address(relay).is_unspecified:
        raise ValueError('Invalid relay address')
    if len(base64.b64decode(config['relay_public_key'], validate=True)) != 32:
        raise ValueError('Invalid relay public key')
    key = Path(config['private_key_file'])
    details = key.lstat()
    if (not key.is_absolute() or not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0 or details.st_mode & 0o077 or details.st_nlink != 1):
        raise ValueError('Underlay key must be a root-only regular file with one link')
    links = {x['ifname'] for x in json.loads(run('ip', '-j', 'link'))}
    if not {'lo', 'eth0'} <= links or not links <= {'lo', 'eth0', PAID}:
        raise ValueError('Unexpected container interfaces; refusing reuse')
    assigned = json.loads(run('ip', '-j', '-4', 'address', 'show', 'dev', 'eth0'))
    if outer not in {a['local'] for x in assigned for a in x['addr_info']}:
        raise ValueError('Container outer address differs')
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default'))
    if len(routes) != 1 or routes[0].get('dev') != 'eth0' or 'gateway' not in routes[0]:
        raise ValueError('Expected one original Docker default route')
    if run('sysctl', '-n', 'net.ipv4.ip_forward') != '1':
        raise ValueError('Owned node namespace must already enable forwarding')
    if any(run('sysctl', '-n', 'net.ipv4.conf.' + name + '.rp_filter') != '0'
           for name in ['all', 'default']):
        raise ValueError('Owned node namespace requires reverse-path filtering disabled')
    gateway = str(ipaddress.IPv4Address(routes[0]['gateway']))
    if subprocess.run(['iptables', '-S', CHAIN], capture_output=True).returncode == 0:
        raise ValueError('Paid underlay guard already exists; refusing recreation')
    # Install the permanent forwarding guard before creating any transport.
    # Failure leaves paid traffic closed; do not remove the guard on rollback.
    run('iptables', '-N', CHAIN)
    run('iptables', '-A', CHAIN, '-i', PAID, '-s', PREFIX, '-o', WG, '-j', 'ACCEPT')
    run('iptables', '-A', CHAIN, '-o', PAID, '-d', PREFIX, '-i', WG,
        '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
    run('iptables', '-A', CHAIN, '-j', 'DROP')
    run('iptables', '-I', 'FORWARD', '1', '-i', PAID, '-j', CHAIN)
    run('iptables', '-I', 'FORWARD', '1', '-o', PAID, '-j', CHAIN)
    for direction in ['-i', '-o']:
        run('ip6tables', '-I', 'FORWARD', '1', direction, PAID, '-j', 'DROP')
    run('ip', 'link', 'add', WG, 'type', 'wireguard')
    run('wg', 'set', WG, 'private-key', str(key), 'peer', config['relay_public_key'],
        'allowed-ips', '0.0.0.0/0', 'endpoint', relay + ':51821', 'persistent-keepalive', '25')
    run('ip', 'address', 'add', '10.203.1.2/30', 'dev', WG)
    run('ip', 'link', 'set', WG, 'mtu', '1380', 'up')
    # Keep encrypted outer packets on Docker while inner public egress uses WG.
    run('ip', 'route', 'add', relay + '/32', 'via', gateway, 'dev', 'eth0')
    run('iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', PREFIX, '-o', WG,
        '-m', 'comment', '--comment', 'octra-paid-underlay-v1', '-j', 'MASQUERADE')
    run('ip', 'route', 'replace', 'default', 'dev', WG)
    return {'namespace': config['namespace'], 'wireguard_public_key': run('wg', 'show', WG, 'public-key'),
            'relay_ipv4': relay, 'original_gateway': gateway, 'paid_interface': PAID,
            'paid_prefix': PREFIX, 'kill_switch': CHAIN, 'consensus_changes': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(up(json.loads(args.config.read_text()))))
