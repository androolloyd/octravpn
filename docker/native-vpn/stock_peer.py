#!/usr/bin/env python3
"""Normal application sockets inside a stock kernel Tailscale namespace."""
import argparse
import hashlib
import ipaddress
import json
import socket
import ssl
import struct
import subprocess
import urllib.error
import urllib.request

PUBLIC = '93.184.216.34'
PORTAL = 'portal.mesh.test'


def ts(*args):
    result = subprocess.run(['tailscale', '--socket=/tmp/tailscaled.sock', *args], capture_output=True, text=True, timeout=25)
    if result.returncode:
        raise RuntimeError(result.stderr[-1200:])
    return result.stdout


def status():
    value = json.loads(ts('status', '--json'))
    assert value['BackendState'] == 'Running'
    return value


def source():
    addresses = status()['TailscaleIPs']
    return next(address for address in addresses if ipaddress.ip_address(address).version == 4)


def portal(path='/index.html', hostname=PORTAL):
    context = ssl.create_default_context(cafile='/config/ca.pem')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    try:
        response = opener.open('https://' + hostname + path, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(65_537)
        assert len(body) <= 65_536
        return {'status': response.code, 'headers': dict(response.headers),
                'body_sha256': hashlib.sha256(body).hexdigest(), 'body': body.decode(errors='replace')}


def udp(count, marker, *, expect=True):
    completed = 0
    payload_bytes = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.bind((source(), 0)); connection.settimeout(2)
        for index in range(count):
            payload = marker.encode() + struct.pack('!I', index) + b'stock-native-udp' * 60
            connection.sendto(payload, (PUBLIC, 20001))
            try:
                data, peer = connection.recvfrom(2048)
            except socket.timeout:
                if expect: raise
                continue
            assert data == payload and peer == (PUBLIC, 20001)
            if not expect: raise AssertionError('unfunded/revoked stock traffic delivered')
            completed += 1; payload_bytes += len(data)
    return {'completed': completed, 'payload_bytes': payload_bytes}


def tcp_icmp():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.bind((source(), 0)); connection.settimeout(10); connection.connect((PUBLIC, 20003))
        payload = b'stock-canonical-tcp' * 32
        connection.sendall(payload); body = b''
        while len(body) < len(payload):
            part = connection.recv(len(payload) - len(body)); assert part; body += part
        assert body == payload
    icmp(True)
    return {'tcp_payload_bytes': len(payload), 'icmp': True}


def icmp(expect):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as connection:
        connection.bind((source(), 0)); connection.settimeout(3)
        payload = b'stock-revocation-positive-control'
        message = bytearray(struct.pack('!BBHHH', 8, 0, 0, 7, 1) + payload)
        padded = message + (b'\0' if len(message) % 2 else b'')
        checksum = sum(struct.unpack('!' + str(len(padded) // 2) + 'H', padded))
        while checksum >> 16: checksum = (checksum & 65535) + (checksum >> 16)
        struct.pack_into('!H', message, 2, (~checksum) & 65535)
        connection.sendto(message, (PUBLIC, 0))
        try: data, peer = connection.recvfrom(2048)
        except socket.timeout:
            assert not expect, 'stock prepaid ICMP did not deliver'; return {'blocked': True}
        assert expect, 'revoked stock ICMP delivered'
        assert peer[0] == PUBLIC and data[0] == 0 and data[8:] == payload
        return {'delivered': True}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('action'); parser.add_argument('--count', type=int, default=1)
    parser.add_argument('--marker', default='stock:'); parser.add_argument('--path', default='/index.html')
    args = parser.parse_args()
    if args.action == 'identity':
        value = status(); result = {'node_key': value['Self']['PublicKey'], 'ipv4': source()}
    elif args.action == 'dns':
        result = {'address': socket.gethostbyname(PORTAL)}
    elif args.action == 'dns_paid': result = {'address': socket.gethostbyname('circles.mesh.test')}
    elif args.action == 'portal': result = portal(args.path)
    elif args.action == 'paid_circle': result = portal(args.path, 'circles.mesh.test')
    elif args.action == 'udp': result = udp(args.count, args.marker)
    elif args.action == 'blocked': result = udp(2, args.marker, expect=False)
    elif args.action == 'tcp_icmp': result = tcp_icmp()
    elif args.action == 'icmp': result = icmp(True)
    elif args.action == 'blocked_icmp': result = icmp(False)
    elif args.action == 'route':
        result = json.loads(subprocess.check_output(['ip', '-j', 'route', 'get', PUBLIC], text=True))[0]
        assert result['dev'] == 'tailscale0', 'application route bypassed stock kernel TUN'
    else: raise ValueError('unknown fixed peer action')
    print(json.dumps(result))


if __name__ == '__main__': main()
