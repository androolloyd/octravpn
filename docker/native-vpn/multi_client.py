#!/usr/bin/env python3
"""Actual multi-payments CLI, kernel probes and explicit owned-route recovery."""
import json
import errno
import hashlib
import os
import pathlib
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

import payments_qualify as p
import qualify as g
from stock_operator import atomic

A_IP = '93.184.216.11'; B_IP = '93.184.216.21'
NAMES = ['route-entry', 'route-exit']


def diagnostic_snapshot(role, process=None):
    """Failure-only reads of this isolated fixture; never start a client."""
    assert role in ['A', 'B', 'C']
    value = {'role': role, 'wall_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(),
             'process_alive': None if process is None else process.poll() is None, 'observations': {}}
    observations = value['observations']

    def capture(name, read):
        row = {'began_wall_ns': time.time_ns(), 'began_monotonic_ns': time.monotonic_ns()}
        try: row['ok'] = read()
        except Exception as error: row.update({'error': type(error).__name__, 'message': str(error)[:1000]})
        row.update({'completed_wall_ns': time.time_ns(), 'completed_monotonic_ns': time.monotonic_ns()})
        observations[name] = row

    def document(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 262144:
                raise ValueError('diagnostic document must be a bounded regular file')
            raw = stream.read(262145)
        if len(raw) > 262144: raise ValueError('diagnostic document exceeds byte bound')
        return json.loads(raw)

    def selected(path, fields, envelope=None):
        body = document(path)
        if envelope is not None: body = body[envelope]
        return {name: body[name] for name in fields if name in body}

    def command(argv):
        completed = subprocess.run(argv, capture_output=True, timeout=1)
        return {'exit_code': completed.returncode, 'stdout': completed.stdout[:65536].decode('utf-8', 'replace'),
                'stderr': completed.stderr[:2000].decode('utf-8', 'replace'),
                'truncated': len(completed.stdout) > 65536 or len(completed.stderr) > 2000}

    for family in ['-4', '-6']:
        for kind, args in [('routes', ['route', 'show', 'table', 'all']), ('rules', ['rule', 'show'])]:
            capture(f'{family}_{kind}', lambda family=family, args=args: command(['ip', family, '-j', *args]))
    capture('addresses', lambda: command(['ip', '-j', 'address', 'show']))
    capture('target', lambda: document('/evidence/target.json'))
    if role == 'C':
        root = pathlib.Path('/state/client')
        for index, path in enumerate(sorted(root.glob('hop-*-*/state.json'))[:16]):
            capture(f'journal_{index}', lambda path=path: {
                'name': path.parent.name, **selected(path, ['local_bytes', 'authorized_bytes', 'connection_sequence',
                    'usage_sequence', 'handoff_sequence', 'pending', 'uncertain_bytes'], 'payload')})
    else:
        index = 0 if role == 'A' else 1
        root = pathlib.Path(f'/state/native-vpn/chain/node-{index}')
        capture('canonical_head', lambda: selected(root / 'HEAD.json',
            ['generation', 'epoch_id', 'state_root', 'ledger_state_root', 'txid_hi', 'ts', 'commit_id']))
        for number, path in enumerate(sorted((root / 'octranet-payments/transport').glob('*/meter.json'))[:16]):
            capture(f'meter_{number}', lambda path=path: selected(path,
                ['committed', 'pending', 'uncertain', 'purchased', 'budget_ou', 'transport'], 'record'))

        def status():
            # Fixed loopback GET, no proxy, credentials, writes or retries.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            url = f'http://127.0.0.1:{19871 + index * 10}/operator/status'
            try: response = opener.open(url, timeout=1)
            except urllib.error.HTTPError as error: response = error
            with response:
                raw = response.read(65537)
                if len(raw) > 65536: raise ValueError('diagnostic status exceeds byte bound')
                try: body = json.loads(raw)
                except ValueError: body = None
                fields = ['serving', 'epoch', 'state_root', 'suspension_reason', 'chain_id',
                          'peers', 'pending', 'vpn_settlement', 'vpn_program']
                return {'http_status': response.status, 'body_sha256': hashlib.sha256(raw).hexdigest(),
                        'body': {name: body[name] for name in fields if name in body} if isinstance(body, dict) else None,
                        'text': raw[:4096].decode('utf-8', 'replace') if body is None else None}

        capture('operator_status', status)
        capture('nat_counters', lambda: command(['iptables', '-t', 'nat', '-L', '-v', '-n', '-x']))
        capture('forward_counters', lambda: command(['iptables', '-L', 'FORWARD', '-v', '-n', '-x']))
    return value


def ip(*args): return g.command(['ip', *args])
def rows(family, *args): return json.loads(ip(family, '-j', *args))
def table(family): return [row for row in rows(family, 'route', 'show', 'table', 'all') if str(row.get('table')) == '186']


class Client:
    def __init__(self):
        g.ROOT = pathlib.Path('/state/client'); g.ROOT.mkdir()
        self.process = None; self.stream = None; self.round = 0; self.launches = 0
        ready = json.loads((g.EVIDENCE / 'multi-ready.json').read_text())
        self.private_control = ready.get('private_control', False)
        self.udp_calls = 0; self.udp_events = 0; self.udp_log_errors = []; self.last_udp_event = None
        mapping = [{'listen': ['127.0.0.1', port], 'target': [A_IP, 10000 + port]} for port in [19879, 19889]]
        # Underlay listeners are20879/20889, not the native loopback ports.
        for row, port in zip(mapping, [20879, 20889], strict=True): row['target'][1] = port
        path = g.ROOT / 'links.json'; path.write_text(json.dumps(mapping))
        self.link_log = (g.EVIDENCE / 'multi-client-links.log').open('x')
        self.link = None
        if not self.private_control:
            self.link = subprocess.Popen(['python3', '-u', '/usr/local/bin/multi_link.py', str(path)], stdout=self.link_log, stderr=self.link_log)
            g.until(lambda: '"ready": true' in (g.EVIDENCE / 'multi-client-links.log').read_text(), 20, 'local control management links')
        ip('route', 'replace', 'default', 'via', '172.31.237.2', 'dev', 'eth0')
        ip('route', 'replace', A_IP + '/32', 'via', '172.31.237.2', 'dev', 'eth0')
        if self.private_control:
            g.command(['iptables', '-N', 'OCTRA_PRIVATE_BOOTSTRAP'])
            g.command(['iptables', '-A', 'OUTPUT', '-j', 'OCTRA_PRIVATE_BOOTSTRAP'])
            g.command(['iptables', '-A', 'OCTRA_PRIVATE_BOOTSTRAP', '-o', 'eth0', '-d', B_IP, '-j', 'REJECT'])
            for protocol in ['udp', 'tcp']:
                g.command(['iptables', '-A', 'OCTRA_PRIVATE_BOOTSTRAP', '-p', protocol, '--dport', '53', '-j', 'REJECT'])
            try:
                with socket.create_connection((B_IP, 20889), timeout=1):
                    raise AssertionError('direct downstream control unexpectedly connected')
            except OSError:
                pass
            assert self.privacy_counters()[0]['packets'] > 0
            atomic(g.EVIDENCE / 'private-control-direct-negative.json', self.privacy_counters())
            g.command(['iptables', '-Z', 'OCTRA_PRIVATE_BOOTSTRAP'])
        self.configure(ready['plans'])
        atomic(g.EVIDENCE / 'multi-client-ready.json', {'ready': True})

    def configure(self, plans):
        route = {'journal': str(g.ROOT / f'route-{self.round}'), 'hops': [
            {'plan': plan, 'journal': str(g.ROOT / f'hop-{self.round}-{index}'),
             'receipt_key': f'/config/receipt-{"A" if index == 0 else "B"}.hex', 'interface_name': NAMES[index]}
            for index, plan in enumerate(plans)]}
        if self.private_control:
            route.update(bootstrap_privacy='pinned_ips', payment_privacy='public')
            for hop, address, wg_port, control_port in zip(route['hops'], [A_IP, B_IP], [19874, 19884], [20879, 20889], strict=True):
                hop.update(wireguard_pin=f'{address}:{wg_port}', control_pin=f'{address}:{control_port}')
        self.path = g.ROOT / 'route.json'; self.path.write_text(json.dumps(route)); self.route = route
        atomic(g.EVIDENCE / f'accepted-multi-route-{self.round}.json', route)

    def launch(self, resume=False, negative=False, wrong_host=False):
        assert self.process is None or self.process.poll() is not None
        self.launches += 1
        self.log_path = g.EVIDENCE / f'multi-client-{self.launches}.log'; self.stream = self.log_path.open('x')
        path = self.path
        if negative:
            suffix = '-tls-negative' if wrong_host else '-negative'
            route = json.loads(path.read_text()); route['journal'] += suffix
            for hop in route['hops']: hop['journal'] += suffix
            if wrong_host: route['hops'][0]['plan']['control_url'] = 'https://wrong.octra.invalid:20879/'
            path = g.ROOT / 'negative-route.json'; path.write_text(json.dumps(route))
        args = ['octravpn', 'multi-payments', '--route', str(path)]
        if resume: args.append('--resume')
        self.process = subprocess.Popen(args, stdout=self.stream, stderr=self.stream)

    def privacy_counters(self):
        text = g.command(['iptables', '-L', 'OCTRA_PRIVATE_BOOTSTRAP', '-v', '-n', '-x'])
        return [{'packets': int(row.split()[0]), 'bytes': int(row.split()[1]), 'rule': row}
                for row in text.splitlines() if row.split() and row.split()[0].isdigit()]

    def ready(self):
        assert self.process.poll() is None, self.log_path.read_text()[-2000:]
        return self.log_path.read_text().count('Octranet paid route hop ') == 2

    def interface(self, index):
        row = rows('-4', 'address', 'show', 'dev', NAMES[index])[0]
        address = [x['local'] for x in row['addr_info'] if x['family'] == 'inet']; assert len(address) == 1
        return address[0]

    def snapshot(self):
        result = {'process_alive': self.process is not None and self.process.poll() is None,
                  'links': json.loads(ip('-j', 'link', 'show')), 'routes': {}, 'rules': {}, 'journals': []}
        for family in ['-4', '-6']:
            result['routes'][family] = table(family)
            result['rules'][family] = rows(family, 'rule', 'show')
        for hop in self.route['hops']:
            path = pathlib.Path(hop['journal']) / 'state.json'
            result['journals'].append(json.loads(path.read_text())['payload'] if path.exists() else None)
        return result

    def record_udp(self, event, call, index, body, **details):
        row = {'event': event, 'call': call, 'index': index, 'payload_bytes': len(body),
               'payload_sha256': hashlib.sha256(body).hexdigest(),
               'wall_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(), **details}
        self.last_udp_event = row
        try:
            if self.udp_events >= 4096: raise ValueError('UDP diagnostic event count bound')
            path = g.EVIDENCE / 'multi-udp-events.jsonl'
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            try:
                info = os.fstat(descriptor)
                raw = (json.dumps(row, sort_keys=True) + '\n').encode()
                if not stat.S_ISREG(info.st_mode) or info.st_size + len(raw) > 4 * 1024 * 1024:
                    raise ValueError('UDP diagnostic file type/byte bound')
                if os.write(descriptor, raw) != len(raw): raise OSError('short UDP diagnostic write')
                self.udp_events += 1
            finally: os.close(descriptor)
        except Exception as error:
            if len(self.udp_log_errors) < 8: self.udp_log_errors.append(type(error).__name__)

    def udp(self, count, length=900, expect=True):
        assert 0 < count <= 64 and 32 <= length <= 1400
        self.udp_calls += 1; call = self.udp_calls
        received = 0; attempts = 0; acknowledged = set()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.bind((self.interface(1), 0)); connection.settimeout(2)
            # Permit the kernel to hand fragments to the actual TUN for the
            # oversized negative, so EMSGSIZE alone cannot impersonate a drop.
            connection.setsockopt(socket.IPPROTO_IP, 10, 0)
            for index in range(count):
                body = struct.pack('!QQ', call, index) + b'nested-paid:' + bytes(length - 28)
                assert len(body) == length
                delivered = False
                # UDP may lose a reply during publication or re-handshake.
                # Retries stay finite, paid and visible in the packet journal.
                for attempt in range(3 if expect else 1):
                    attempts += 1
                    try:
                        assert connection.sendto(body, (g.PUBLIC, 20001)) == length
                    except OSError as error:
                        if expect or error.errno not in [errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN,
                                                        errno.EACCES, errno.EPERM]:
                            raise
                        self.record_udp('kernel_rejected', call, index, body, errno=error.errno)
                        break
                    self.record_udp('sent', call, index, body, expected_reply=expect, attempt=attempt)
                    deadline = time.monotonic() + 2
                    try:
                        while True:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0: raise socket.timeout()
                            connection.settimeout(remaining)
                            data, peer = connection.recvfrom(2048)
                            assert expect, 'exhausted/oversized/revoked nested packet delivered'
                            assert peer == (g.PUBLIC, 20001)
                            if data in acknowledged:
                                self.record_udp('duplicate', call, index, data, peer=list(peer))
                                continue
                            assert data == body
                            self.record_udp('received', call, index, data, peer=list(peer), expected_reply=True)
                            acknowledged.add(body); received += len(data); delivered = True
                            break
                    except socket.timeout:
                        self.record_udp('timeout', call, index, body, expected_reply=expect, attempt=attempt)
                    if delivered: break
                if expect and not delivered:
                    raise socket.timeout('bounded paid UDP probe did not receive its echo')
        return {'received_payload_bytes': received, 'payload_length': length, 'sent_attempts': attempts}

    def cleanup(self):
        # Explicit fixture-only recovery, after the writer and all TUNs are gone.
        # Every row is checked and individually removed; never flush proto/table.
        assert self.process is None or self.process.poll() is not None
        assert not any(row['ifname'] in NAMES for row in json.loads(ip('-j', 'link', 'show')))
        saved = self.snapshot(); atomic(g.EVIDENCE / f'owned-route-recovery-{self.launches}.json', saved)
        for family in ['-4', '-6']:
            routes = saved['routes'][family]
            management = []; blockers = []
            for row in routes:
                assert set(row) <= {'type', 'dst', 'gateway', 'dev', 'protocol', 'scope', 'metric', 'flags', 'table', 'pref'}
                assert str(row.get('table')) == '186'
                assert str(row.get('protocol')) in {'186', 'bgp'}
                assert row.get('metric') in [45678, 45679]
                prefix = row.get('dst'); kind = row.get('type', 'unicast')
                assert 'pref' not in row or (family == '-6' and kind == 'blackhole' and
                    prefix in ['::/1', '8000::/1'] and row['pref'] == 'medium')
                if kind == 'unicast':
                    assert family == '-4' and prefix in [A_IP, A_IP + '/32'] and row.get('dev') == 'eth0' and row.get('gateway') == '172.31.237.2' and row['metric'] == 45678
                    assert row.get('flags', []) == ['onlink']
                    management.append(row)
                else:
                    assert 'gateway' not in row
                    assert row.get('dev') is None if family == '-4' else row.get('dev') == 'lo'
                    assert row.get('flags', []) == []
                    assert row['metric'] == 45679 and ((family == '-4' and ((kind == 'throw' and prefix == '100.64.0.0/10') or
                        (kind == 'blackhole' and prefix in ['0.0.0.0/1', '128.0.0.0/1', B_IP, B_IP + '/32']))) or
                        (family == '-6' and kind == 'blackhole' and prefix in ['::/1', '8000::/1']))
                    blockers.append(row)
            for row in management + blockers:
                argv = [family, 'route', 'del']
                if row.get('type', 'unicast') != 'unicast': argv.append(row['type'])
                argv.append(row['dst'])
                if row.get('gateway'): argv += ['via', row['gateway']]
                if row.get('flags') == ['onlink']: argv.append('onlink')
                if row.get('dev'): argv += ['dev', row['dev']]
                argv += ['proto', '186', 'metric', str(row['metric']), 'table', '186']; ip(*argv)
            selected = [row for row in saved['rules'][family] if str(row.get('table')) == '186']
            assert len(selected) <= 1 and all(row['priority'] == 1 for row in selected)
            if selected: ip(family, 'rule', 'del', 'priority', '1', 'lookup', '186')
        return saved

    def command(self, request):
        action = request['action']
        if action == 'foreign_rule':
            ip('-4', 'rule', 'add', 'priority', '1', 'lookup', 'main')
            self.launch(negative=True); self.process.wait(timeout=30); self.stream.close()
            assert self.process.returncode != 0 and 'higher-precedence foreign policy rule' in self.log_path.read_text()
            assert not table('-4') and not table('-6')
            ip('-4', 'rule', 'del', 'priority', '1', 'lookup', 'main'); self.process = None
            return {'refused_before_payment': True}
        if action == 'tls_negative':
            assert self.private_control
            self.launch(negative=True, wrong_host=True)
            self.process.wait(timeout=30); self.stream.close()
            text = self.log_path.read_text().lower()
            assert self.process.returncode != 0 and 'certificate' in text and 'name' in text, text[-2000:]
            self.cleanup(); self.process = None
            return {'wrong_hostname_refused': True}
        if action == 'launch': self.launch(request.get('resume', False)); return {'started': True}
        if action == 'ready':
            g.until(self.ready, 180, 'all-hop canonical purchases and handshakes')
            result = self.snapshot(); assert {row['ifname']: row['mtu'] for row in result['links'] if row['ifname'] in NAMES} == dict(zip(NAMES, [1280, 1075], strict=True))
            assert rows('-4', 'route', 'get', g.PUBLIC)[0]['dev'] == NAMES[1]
            assert rows('-4', 'route', 'get', B_IP)[0]['dev'] == NAMES[0]
            if self.private_control:
                counters = self.privacy_counters()
                assert len(counters) == 3 and all(row['packets'] == 0 for row in counters)
                result['privacy_counters'] = counters
            return result
        if action == 'state': return self.snapshot()
        if action == 'privacy':
            assert self.private_control
            counters = self.privacy_counters()
            assert len(counters) == 3 and all(row['packets'] == 0 for row in counters)
            return {'forbidden_physical_and_dns': counters}
        if action == 'traffic': return {'udp': self.udp(3), 'tcp_payload_bytes': p.tcp_and_icmp(self.interface(1))}
        if action == 'near_mtu': return self.udp(2, 1047)
        if action == 'oversize':
            result = self.udp(1, 1048, expect=False); self.udp(1, 500); return result
        if action == 'blocked': return self.udp(2, 900, expect=False)
        if action == 'exhaust_probe': return self.udp(1, 900)
        if action == 'icmp': return {'tcp_payload_bytes': p.tcp_and_icmp(self.interface(1))}
        if action == 'crash':
            self.process.kill(); self.process.wait(timeout=15); self.stream.close(); return self.cleanup()
        if action == 'carrier_loss':
            # Deliberately tempt the lower-priority physical path. The specific
            # table186 /32 blocker must dominate it after the carrier disappears.
            ip('-4', 'route', 'replace', B_IP + '/32', 'via', '172.31.237.2', 'dev', 'eth0')
            ip('link', 'del', 'dev', NAMES[0]); self.process.wait(timeout=30); self.stream.close()
            assert self.process.returncode != 0
            found = table('-4')
            assert any(row.get('type') == 'blackhole' and row.get('dst') in [B_IP, B_IP + '/32'] for row in found)
            probe = subprocess.run(['ip', '-4', '-j', 'route', 'get', B_IP], capture_output=True, text=True)
            assert probe.returncode != 0 or not any(row.get('dev') == 'eth0' for row in json.loads(probe.stdout))
            if self.private_control:
                try:
                    with socket.create_connection((B_IP, 20889), timeout=1):
                        raise AssertionError('downstream TLS escaped a missing carrier')
                except OSError:
                    pass
                assert all(row['packets'] == 0 for row in self.privacy_counters())
            self.cleanup(); ip('-4', 'route', 'del', B_IP + '/32', 'via', '172.31.237.2', 'dev', 'eth0')
            return {'physical_fallback_blocked': True}
        if action == 'clean_stop':
            self.process.send_signal(signal.SIGINT); self.process.wait(timeout=30); self.stream.close()
            assert self.process.returncode == 0; self.process = None
            assert not table('-4') and not table('-6')
            return {'clean': True}
        if action == 'reset': self.round += 1; self.configure(request['plans']); return {'new_consent': True}
        if action == 'wait_failure':
            self.process.wait(timeout=30); self.stream.close(); assert self.process.returncode != 0
            return self.cleanup()
        if action == 'stop': return {'stopped': True}
        raise ValueError('unknown fixed multi client action')

    def close(self):
        if self.process is not None and self.process.poll() is None: self.process.kill(); self.process.wait(timeout=15); self.stream.close()
        if self.link is not None:
            self.link.terminate(); self.link.wait(timeout=15)
        self.link_log.close()


def main():
    client = Client(); directory = pathlib.Path('/commands/C'); index = 1
    try:
        while True:
            path = directory / f'{index}.json'; g.until(path.exists, 300, 'multi client command')
            request = json.loads(path.read_text())
            try: atomic(directory / f'{index}.result.json', {'ok': client.command(request)})
            except Exception:
                original = traceback.format_exc()
                try:
                    action = request.get('action') if isinstance(request, dict) else None
                    if action != 'exhaust_probe':
                        observed = diagnostic_snapshot('C', client.process)
                        observed.update({'action': action, 'last_udp_event': client.last_udp_event,
                                         'udp_log_errors': client.udp_log_errors})
                        atomic(g.EVIDENCE / f'multi-client-failure-{index}.json', observed)
                except Exception: pass
                atomic(directory / f'{index}.result.json', {'error': original})
            index += 1
            if request['action'] == 'stop': break
    finally: client.close()


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--diagnostic-snapshot':
        print(json.dumps(diagnostic_snapshot(sys.argv[2]), sort_keys=True))
    else: main()
