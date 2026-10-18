"""An isolated second kernel for the native VPN qualification fixture.

Only IPv4 packets for the fixture's fixed public target cross the private Unix
datagram link. TCP, ICMP, routing and NAT remain the endpoint kernels' work.
"""

import fcntl
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import threading


PUBLIC = '93.184.216.34'
SNAT = '192.0.2.1'
REMOTE = '192.0.2.2'
MTU = 1280


def _ip(*args):
    subprocess.run(['ip', *args], check=True, capture_output=True, text=True)


class Hop:
    """A bounded raw IPv4 link between two disposable network namespaces."""

    def __init__(self, directory, *, public=PUBLIC, role='node', name='vpn-egress'):
        if role not in ('node', 'target'):
            raise ValueError('unknown packet-hop role')
        if not name or len(name.encode()) > 15 or not name.replace('-', '').isalnum():
            raise ValueError('invalid fixture TUN name')
        self.public = str(ipaddress.IPv4Address(public))
        self.role = role
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError('packet-hop directory must be an owned real directory')
        # Docker creates a fresh, dedicated volume with mode0755. Both fixture
        # endpoints are root in their isolated containers; no host path is used.
        self.directory.chmod(0o700)
        self.path = self.directory / (role + '.sock')
        self.peer = self.directory / ('target.sock' if role == 'node' else 'node.sock')
        if os.path.lexists(self.path):
            raise ValueError('packet-hop endpoint already exists')
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts = {'sent_packets': 0, 'sent_bytes': 0,
                       'received_packets': 0, 'received_bytes': 0,
                       'rejected_packets': 0, 'rejected_headers': [], 'errors': []}
        self.fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            fcntl.ioctl(self.fd, 0x400454ca, struct.pack('16sH', name.encode(), 0x1001))
            # This fixture transports IPv4 only; do not emit unrelated IPv6
            # router solicitations into its deliberately strict packet link.
            _ip('link', 'set', 'dev', name, 'addrgenmode', 'none')
            _ip('link', 'set', name, 'mtu', str(MTU))
            address = SNAT if role == 'node' else REMOTE
            _ip('address', 'add', address + '/24', 'dev', name)
            _ip('link', 'set', name, 'up')
            if role == 'target':
                _ip('link', 'set', 'lo', 'up')
                _ip('address', 'add', self.public + '/32', 'dev', 'lo')
            self.sock.bind(str(self.path))
            self.identity = self.path.stat()
            self.sock.setblocking(False)
            self.thread = threading.Thread(target=self._run, name='packet-hop', daemon=True)
            self.thread.start()
        except BaseException:
            self.sock.close()
            os.close(self.fd)
            if hasattr(self, 'identity'):
                self.path.unlink(missing_ok=True)
            raise

    def _error(self, message):
        with self.lock:
            if len(self.counts['errors']) < 32:
                self.counts['errors'].append(message)

    def _valid(self, data, *, outgoing):
        if len(data) < 20 or len(data) > MTU or data[0] >> 4 != 4:
            return False
        header = (data[0] & 15) * 4
        if header < 20 or header > len(data) or struct.unpack_from('!H', data, 2)[0] != len(data):
            return False
        if struct.unpack_from('!H', data, 6)[0] & 0x3fff or data[9] not in (1, 6, 17):
            return False
        src, dst = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
        node_outgoing = (self.role == 'node') == outgoing
        expected = (SNAT, self.public) if node_outgoing else (self.public, SNAT)
        return (src, dst) == expected

    def _run(self):
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.fd, self.sock], [], [], .1)
                for source in ready:
                    outgoing = source == self.fd
                    if outgoing:
                        data = os.read(self.fd, MTU + 1)
                        valid_peer = True
                    else:
                        data, sender = self.sock.recvfrom(MTU + 1)
                        valid_peer = sender == str(self.peer)
                    if not valid_peer or not self._valid(data, outgoing=outgoing):
                        with self.lock:
                            self.counts['rejected_packets'] += 1
                            if len(self.counts['rejected_headers']) < 8:
                                self.counts['rejected_headers'].append({
                                    'outgoing': outgoing, 'valid_peer': valid_peer,
                                    'length': len(data), 'header': data[:20].hex()})
                        continue
                    if outgoing:
                        self.sock.sendto(data, str(self.peer))
                        direction = 'sent'
                    else:
                        if os.write(self.fd, data) != len(data):
                            raise OSError('short packet-hop TUN write')
                        direction = 'received'
                    with self.lock:
                        self.counts[direction + '_packets'] += 1
                        self.counts[direction + '_bytes'] += len(data)
        except OSError as error:
            if not self.stop.is_set():
                self._error(repr(error))
                self.stop.set()
        except BaseException as error:
            self._error(repr(error))
            self.stop.set()

    def metrics(self):
        with self.lock:
            return {**self.counts, 'errors': list(self.counts['errors']),
                    'rejected_headers': list(self.counts['rejected_headers']),
                    'role': self.role, 'mtu': MTU}

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()
        os.close(self.fd)
        try:
            current = self.path.lstat()
            if (current.st_dev, current.st_ino) == (self.identity.st_dev, self.identity.st_ino):
                self.path.unlink()
        except FileNotFoundError:
            pass


def main(hop_factory=Hop):
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda _sig, _frame: stop.set())
    hop = hop_factory(Path('/hop'), role='target', name='vpn-remote')
    lock = threading.Lock()
    stats = {'observed_sources': {'udp': [], 'tcp': []},
             'udp_payload_bytes': 0, 'tcp_payload_bytes': 0, 'errors': []}

    def error(message):
        with lock:
            if len(stats['errors']) < 32:
                stats['errors'].append(message)

    def account(protocol, peer, count):
        with lock:
            sources = stats['observed_sources'][protocol]
            if peer[0] not in sources:
                if len(sources) < 8:
                    sources.append(peer[0])
                else:
                    raise ValueError('too many fixture source addresses')
            if peer[0] != SNAT:
                raise ValueError('fixture target received a non-NAT source')
            stats[protocol + '_payload_bytes'] += count

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp.bind((PUBLIC, 20001))
    udp.settimeout(.25)
    tcp.bind((PUBLIC, 20003))
    tcp.listen(2)
    tcp.settimeout(.25)

    def udp_echo():
        try:
            while not stop.is_set():
                try:
                    data, peer = udp.recvfrom(2048)
                except socket.timeout:
                    continue
                account('udp', peer, len(data))
                udp.sendto(data, peer)
        except BaseException as exc:
            if not stop.is_set():
                error(repr(exc))
                stop.set()

    def tcp_echo():
        try:
            while not stop.is_set():
                try:
                    connection, peer = tcp.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(.25)
                    while not stop.is_set():
                        try:
                            data = connection.recv(2048)
                        except socket.timeout:
                            continue
                        if not data:
                            break
                        account('tcp', peer, len(data))
                        connection.sendall(data)
        except BaseException as exc:
            if not stop.is_set():
                error(repr(exc))
                stop.set()

    evidence = Path('/evidence/target.json')
    evidence.parent.mkdir(parents=True, exist_ok=True)

    def publish():
        with lock:
            value = json.loads(json.dumps(stats))
        value['hop'] = hop.metrics()
        temporary = evidence.with_name('target.json.part')
        with temporary.open('w') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
        os.replace(temporary, evidence)
        return value

    workers = [threading.Thread(target=udp_echo, daemon=True),
               threading.Thread(target=tcp_echo, daemon=True)]
    for worker in workers:
        worker.start()
    try:
        while not stop.wait(.5):
            publish()
            if hop.stop.is_set():
                error('packet hop stopped unexpectedly')
                stop.set()
    finally:
        stop.set()
        for worker in workers:
            worker.join(timeout=2)
        udp.close()
        tcp.close()
        hop.close()
        final = publish()
        print(json.dumps(final), flush=True)
    return int(bool(final['errors'] or final['hop']['errors'] or final['hop']['rejected_packets']))


if __name__ == '__main__':
    raise SystemExit(main())
