#!/usr/bin/env python3
"""Start the owned paid node only after its underlay has been verified."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import time


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def ready(path, public_key):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 1024):
            raise ValueError('Invalid underlay readiness file')
        value = json.loads(stream.read(1025))
    if value != {'namespace': os.readlink('/proc/self/ns/net'),
                 'public_key': public_key, 'relay_ipv4': '143.110.222.241',
                 'verified_tls': True}:
        raise ValueError('Underlay readiness differs from this deployment')
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default'))
    if len(routes) != 1 or routes[0].get('dev') != 'octra-wg':
        raise ValueError('Paid default route is unavailable')
    for rule in [
        ['-i', 'octrapay0', '-s', '198.18.0.0/15', '-o', 'octra-wg', '-j', 'ACCEPT'],
        ['-o', 'octrapay0', '-d', '198.18.0.0/15', '-i', 'octra-wg',
         '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
        ['-j', 'DROP'],
    ]:
        run('iptables', '-C', 'OCTRA_PAID_WG', *rule)
    for direction in ['-i', '-o']:
        run('iptables', '-C', 'FORWARD', direction, 'octrapay0', '-j', 'OCTRA_PAID_WG')
        run('ip6tables', '-C', 'FORWARD', direction, 'octrapay0', '-j', 'DROP')
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-key', required=True)
    args = parser.parse_args()
    deadline = time.monotonic() + 180
    while not ready(Path('/run/octra-paid-ready.json'), args.public_key):
        if time.monotonic() >= deadline:
            raise TimeoutError('Paid underlay was not verified before startup')
        time.sleep(0.1)
    os.execv('/usr/local/bin/octra-node', [
        'octra-node', 'run-network', '--config', '/config/network.json'])
