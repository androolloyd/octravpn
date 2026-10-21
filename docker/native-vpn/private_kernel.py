#!/usr/bin/env python3
"""Isolated kernel provisioning for the shielded canonical Rust test.

The second container owns the remote TCP/UDP/IP stack. Only a bounded Unix
packet link joins the kernels; Docker networking remains disabled.
"""
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import threading

from packet_target import Hop, PUBLIC, SNAT

EVIDENCE = Path('/evidence')
LINK = 'vpn-egress'


def ip(*args):
    return subprocess.run(['ip', *args], capture_output=True, text=True,
                          check=True, timeout=10).stdout


def command(*args):
    return subprocess.run(args, capture_output=True, text=True,
                          check=True, timeout=10).stdout


def write(name, value):
    path = EVIDENCE / name
    temporary = path.with_suffix('.part')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    os.replace(temporary, path)


def scope():
    marker = json.loads((EVIDENCE / 'kernel-scope.json').read_text())
    if marker.get('fixture_only') is not True or marker.get('network_none') is not True:
        raise ValueError('explicit isolated kernel fixture marker required')
    if json.loads(ip('-j', 'route', 'show', 'default')):
        raise ValueError('kernel fixture must have no external default route')


def name(value):
    if not value or len(value) > 15 or not value.replace('-', '').isalnum():
        raise ValueError('invalid isolated interface')
    return value


def serve(server):
    scope()
    server = name(server)
    stop = threading.Event()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(sig, lambda *_: stop.set())
    threading.Thread(target=lambda: (sys.stdin.buffer.read(), stop.set()), daemon=True).start()
    hop = Hop('/hop', role='node', name=LINK)
    try:
        ip('link', 'set', 'lo', 'up')
        ip('rule', 'del', 'priority', '0')
        ip('rule', 'add', 'priority', '2000', 'lookup', 'local')
        ip('route', 'add', PUBLIC + '/32', 'via', '192.0.2.2', 'dev', LINK)
        command('iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '198.18.0.0/15',
                '-d', PUBLIC + '/32', '-o', LINK, '-j', 'SNAT', '--to-source', SNAT)
        ip('rule', 'add', 'priority', '5', 'iif', LINK, 'to', '198.18.0.0/15', 'lookup', '402')
        ip('rule', 'add', 'priority', '10', 'iif', 'lo', 'to', PUBLIC + '/32', 'lookup', '401')
        ip('route', 'replace', '198.18.0.0/15', 'dev', server, 'table', '402')
        while not stop.is_set():
            write('private-link.json', {'ready': True, 'hop': hop.metrics()})
            if hop.stop.wait(.1):
                raise RuntimeError('packet hop stopped unexpectedly')
    finally:
        hop.close()
        metrics = hop.metrics()
        write('private-link.json', {'ready': False, 'hop': metrics})
    if metrics['errors'] or metrics['rejected_packets']:
        raise RuntimeError('private packet hop rejected traffic')


def client(interface, server, address):
    import ipaddress
    scope()
    interface, server = name(interface), name(server)
    address = str(ipaddress.IPv4Address(address))
    if ipaddress.IPv4Address(address) not in ipaddress.ip_network('198.18.0.0/15'):
        raise ValueError('client is outside isolated paid subnet')
    ip('route', 'replace', '198.18.0.0/15', 'dev', server, 'table', '402')
    ip('route', 'replace', PUBLIC + '/32', 'dev', interface, 'src', address, 'table', '401')
    # A client and its operator share this container's kernel. Avoid creating a
    # second conntrack entry at the virtual client edge; exit NAT stays real.
    for chain, flag, source, destination in [
        ('OUTPUT', '-o', address, PUBLIC), ('PREROUTING', '-i', PUBLIC, address),
    ]:
        rule = ['iptables', '-t', 'raw', '-C', chain, flag, interface, '-s', source + '/32',
                '-d', destination + '/32', '-j', 'NOTRACK']
        checked = subprocess.run(rule, capture_output=True, timeout=10)
        if checked.returncode:
            rule[3] = '-A'
            command(*rule)
    route = json.loads(ip('-j', 'route', 'get', PUBLIC, 'from', address, 'iif', 'lo'))[0]
    if route.get('dev') != interface:
        raise ValueError('application route bypasses the private client TUN')
    return {'client_route': interface, 'address': address, 'mtu': 1280}


def traffic(address, phase):
    scope()
    if phase not in ['1', '2']:
        raise ValueError('invalid private traffic phase')
    total_udp = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind((address, 0))
        udp.settimeout(8)
        for index, length in enumerate([48, 1047, 1240, 1047, 48, 1240]):
            marker = f'private:{phase}:{index}:'.encode()
            payload = marker + b'x' * (length - len(marker))
            udp.sendto(payload, (PUBLIC, 20001))
            reply, peer = udp.recvfrom(2048)
            if reply != payload or peer != (PUBLIC, 20001):
                raise ValueError('private UDP response differs')
            total_udp += len(payload)
    total_tcp = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        tcp.bind((address, 0))
        tcp.settimeout(8)
        tcp.connect((PUBLIC, 20003))
        for index in range(4):
            payload = f'private-tcp:{phase}:{index}:'.encode() + b'y' * 1200
            tcp.sendall(payload)
            received = b''
            while len(received) < len(payload):
                part = tcp.recv(len(payload) - len(received))
                if not part:
                    raise ValueError('private TCP closed early')
                received += part
            if received != payload:
                raise ValueError('private TCP response differs')
            total_tcp += len(payload)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as ping:
        ping.bind((address, 0))
        ping.settimeout(8)
        payload = b'private-kernel-icmp:' + phase.encode()
        packet = bytearray(struct.pack('!BBHHH', 8, 0, 0, 7, 1) + payload)
        padded = packet + (b'\0' if len(packet) % 2 else b'')
        checksum = sum(struct.unpack('!' + str(len(padded) // 2) + 'H', padded))
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        struct.pack_into('!H', packet, 2, (~checksum) & 65535)
        ping.sendto(packet, (PUBLIC, 0))
        reply, peer = ping.recvfrom(2048)
        if reply[0] != 0 or reply[8:] != payload or peer[0] != PUBLIC:
            raise ValueError('private ICMP response differs')
    return {'udp_echoed_bytes': total_udp, 'udp_datagrams': 6,
            'tcp_echoed_bytes': total_tcp, 'icmp_echoes': 1, 'retries': 0}


if __name__ == '__main__':
    mode, *args = sys.argv[1:]
    if mode == 'serve' and len(args) == 1:
        serve(*args)
    elif mode == 'client' and len(args) == 3:
        print(json.dumps(client(*args)))
    elif mode == 'traffic' and len(args) == 2:
        print(json.dumps(traffic(*args)))
    else:
        raise SystemExit('invalid isolated kernel helper mode')
