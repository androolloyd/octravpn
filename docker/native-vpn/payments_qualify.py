#!/usr/bin/env python3
"""Real kernel/client/native-claim qualification for the payment-plan candidate.

Run only via the disposable, network-disabled two-container gate. Every app
deployment and payment is an ordinary signed transaction on four fresh native
validators. Canonical time is never overridden for rate notice or unstaking.
"""

import base64
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import struct
import subprocess
import time
import traceback

from json_snapshot import read_object
import urllib.error
import urllib.request

import qualify as g
from packet_target import Hop
from payment_control import ControlProxy

CLIENT = 'pay-client'
SERVER = 'pay-node'
LINK = 'vpn-egress'
SNAT = '192.0.2.1'
BUDGET = 500_000
FUND = 1_000_000
STAKE = 100_000_000
PREPAID_BYTES = [65_536, 65_536, 4_096]
CLIENT_LOG = None
CLIENT_LAUNCHES = 0
PAID_MTU = 1280
UDP_ATTEMPTS = 3
UDP_TIMEOUT = 3
UDP_PORT = 20001


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def factory_artifact(source, artifact):
    """Validate an explicit local Legacy build for the existing child API."""
    executable = base64.b64decode(artifact['bytecode'], validate=True)
    certificate = artifact['certificate']
    assert artifact['target_admission'] == 'legacy-binary' and artifact['typed_admission'] is False
    assert 'program_envelope' not in artifact and 'deploy_payload' not in artifact
    assert certificate['schema'] == 'aml_bytecode_certificate_v1'
    assert certificate['source_hash'] == hashlib.sha256(source.read_bytes()).hexdigest()
    code = executable
    assert code.startswith(b'OCTB')
    assert certificate['bytecode_hash'] == hashlib.sha256(code).hexdigest()
    return base64.b64encode(code).decode(), hashlib.sha256(code).hexdigest()


def register_operator_receipt_key(operator_key, program, domain, operator, label):
    generation = int(g.view(program, 'get_operator_generation', [operator]))
    assert generation > 0
    public = g.command(['octra', 'cast', 'wallet', 'pubkey', '--key', operator_key])
    message = f'Octranet operator key v1|{domain}|{program}|{operator}|{generation}'
    signature = g.command(['octra', 'cast', 'wallet', 'sign', '--key', operator_key, message])
    g.send(label, operator_key, program, 'register_operator_receipt_key', [public, signature])
    return generation


def ip(*args):
    return g.command(['ip', *args])


def target():
    return read_object(g.EVIDENCE / 'target.json')


def journal():
    # Checksums/semantics are verified by the actual client on each open. This
    # fixture only reads its public counters and signed receipts as evidence.
    return json.loads((g.ROOT / 'client-journal/state.json').read_text())['payload']


def launch_client(plan, receipt_key, *, resume, wait_interface=True):
    global CLIENT_LOG, CLIENT_LAUNCHES
    CLIENT_LAUNCHES += 1
    CLIENT_LOG = g.EVIDENCE / f'client-{CLIENT_LAUNCHES}.log'
    stream = CLIENT_LOG.open('x')
    args = ['octravpn', 'payments', '--plan', str(plan), '--receipt-key', str(receipt_key),
            '--journal', str(g.ROOT / 'client-journal'), '--tun-name', CLIENT]
    if resume:
        args.append('--resume')
    process = subprocess.Popen(args, cwd=g.ROOT, stdout=stream, stderr=subprocess.STDOUT,
                               env={**os.environ, 'RUST_LOG': 'info'})
    g.PROCESSES['payer'] = process
    g.FILES['payer'] = stream
    return client_ready() if wait_interface else None


def client_ready():
    def ready():
        assert g.PROCESSES['payer'].poll() is None, 'prepaid client exited before opening TUN'
        return 'Octranet interface ' in CLIENT_LOG.read_text()
    g.until(ready, 120, 'real prepaid client TUN after canonical purchase')
    addresses = json.loads(ip('-j', 'address', 'show', 'dev', CLIENT))[0]['addr_info']
    assigned = [item['local'] for item in addresses if item['family'] == 'inet']
    assert len(assigned) == 1
    assigned = assigned[0]
    assert ipaddress.ip_address(assigned) in ipaddress.ip_network('198.18.0.0/15')
    assert assigned != '198.18.0.1'
    ip('route', 'replace', g.PUBLIC + '/32', 'dev', CLIENT, 'src', assigned, 'table', '401')
    return assigned


def stop_client(*, crash=False):
    process = g.PROCESSES.pop('payer')
    process.send_signal(signal.SIGKILL if crash else signal.SIGINT)
    process.wait(timeout=20)
    g.FILES.pop('payer').close()
    if not crash:
        assert process.returncode == 0, 'payment client did not stop cleanly'


def public_status(path):
    """Bounded GETs of fixed public loopback diagnostics, without credentials."""
    assert path in ('/operator/status', '/status')
    row = {}
    try:
        try:
            response = urllib.request.urlopen(f'http://127.0.0.1:{g.BASE + 1}{path}', timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            row['http'] = response.code
            raw = response.read(16_385)
        if len(raw) > 16_384:
            row['error'] = 'public status exceeds diagnostic byte bound'
            return row
        try:
            row['body'] = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            row['body'] = raw.decode(errors='replace')
            row['error'] = 'public status is not JSON'
    except (OSError, ValueError) as error:
        row['error'] = type(error).__name__
        row['detail'] = str(error)[:512]
    return row


def operator_ready(minimum_epoch):
    # Binding a TUN/listener precedes the supervisor's peer-root attestation,
    # canonical catch-up and publication. Never substitute OS readiness for it.
    assert type(minimum_epoch) is int and minimum_epoch >= 0
    report = {'minimum_epoch': minimum_epoch, 'attempts': 0, 'ready': False}
    g.JOURNAL.setdefault('operator_readiness', []).append(report)
    started = time.monotonic()

    def ready():
        report['attempts'] += 1
        report['last'] = {path: public_status(path) for path in ('/operator/status', '/status')}
        operator = report['last']['/operator/status']
        public = report['last']['/status']
        body = operator.get('body')
        return (operator.get('http') == 200 and 'error' not in operator
                and isinstance(body, dict) and body.get('serving') is True
                and type(body.get('epoch')) is int and body['epoch'] >= minimum_epoch
                and public.get('http') == 200 and 'error' not in public)

    try:
        g.until(ready, 120, 'operator canonical Serving after restart')
        report['ready'] = True
    finally:
        report['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
    g.save()


def route_server(minimum_epoch):
    g.until(lambda: SERVER in ip('-j', 'link', 'show'), 90, 'real paid operator TUN')
    ip('route', 'replace', '198.18.0.0/15', 'dev', SERVER, 'table', '402')
    operator_ready(minimum_epoch)


def udp(assigned, count, marker):
    assert 0 < count <= 64
    total = 0
    completed = set()
    started = time.monotonic()
    report = {'phase': marker.decode('ascii'), 'unique_echoes': 0, 'attempts': [],
              'timeouts': 0, 'stale_duplicates': 0, 'sent_payload_bytes': 0,
              'max_attempts_per_id': UDP_ATTEMPTS, 'attempt_timeout_s': UDP_TIMEOUT}
    g.JOURNAL.setdefault('udp_probes', []).append(report)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.bind((assigned, 0))
            for index in range(count):
                payload = marker + struct.pack('!I', index) + b'payment-plan-udp' * 60
                for attempt in range(1, UDP_ATTEMPTS + 1):
                    stopped = [name for name, process in g.PROCESSES.items() if process.poll() is not None]
                    if stopped:
                        raise RuntimeError(f'UDP probe processes stopped: {stopped}')
                    row = {'id': index, 'attempt': attempt,
                           'sent_ms': round((time.monotonic() - started) * 1000, 3),
                           'outcome': 'pending'}
                    report['attempts'].append(row)
                    g.save()
                    assert connection.sendto(payload, (g.PUBLIC, UDP_PORT)) == len(payload)
                    report['sent_payload_bytes'] += len(payload)
                    deadline = time.monotonic() + UDP_TIMEOUT
                    while time.monotonic() < deadline:
                        connection.settimeout(max(.001, deadline - time.monotonic()))
                        try:
                            received, peer = connection.recvfrom(2048)
                        except socket.timeout:
                            break
                        assert peer == (g.PUBLIC, UDP_PORT), 'unexpected UDP echo endpoint'
                        if received in completed:
                            report['stale_duplicates'] += 1
                            continue
                        assert received == payload, 'unexpected UDP echo fixture ID or body'
                        row['outcome'] = 'echoed'
                        row['echo_ms'] = round((time.monotonic() - started) * 1000, 3)
                        break
                    if row['outcome'] == 'echoed':
                        completed.add(payload)
                        report['unique_echoes'] += 1
                        total += len(payload)
                        g.save()
                        break
                    row['outcome'] = 'timeout'
                    report['timeouts'] += 1
                    g.save()
                else:
                    raise TimeoutError(f'UDP fixture {report["phase"]}{index} exhausted {UDP_ATTEMPTS} attempts')
    except BaseException as error:
        report['failure'] = type(error).__name__
        raise
    finally:
        report['echoed_payload_bytes'] = total
        report['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
        try:
            report['target_payload_bytes'] = target().get('udp_payload_bytes')
            g.save()
        except (OSError, ValueError):
            if 'failure' not in report:
                raise
    return total


def tcp_and_icmp(assigned):
    total = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.bind((assigned, 0))
        connection.settimeout(12)
        connection.connect((g.PUBLIC, 20003))
        for index in range(4):
            payload = struct.pack('!I', index) + b'payment-plan-tcp' * 40
            connection.sendall(payload)
            received = b''
            while len(received) < len(payload):
                part = connection.recv(len(payload) - len(received))
                assert part, 'real target TCP closed early'
                received += part
            assert received == payload
            total += len(payload)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as ping:
        ping.bind((assigned, 0))
        ping.settimeout(8)
        payload = b'payment-plan-kernel-icmp'
        message = bytearray(struct.pack('!BBHHH', 8, 0, 0, 7, 1) + payload)
        padded = message + (b'\0' if len(message) % 2 else b'')
        checksum = sum(struct.unpack('!' + str(len(padded) // 2) + 'H', padded))
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        struct.pack_into('!H', message, 2, (~checksum) & 65535)
        ping.sendto(message, (g.PUBLIC, 0))
        reply, peer = ping.recvfrom(2048)
        assert reply[0] == 0 and reply[8:] == payload and peer[0] == g.PUBLIC
    return total


def settled(program, operator, tariff, minimum):
    state = journal()
    assert state['authorized_bytes'] == PREPAID_BYTES
    assert all(count <= bought for count, bought in zip(client_exposure(state), PREPAID_BYTES, strict=True))
    purchased = [int(g.view(program, 'get_prepaid_bytes', [0, index]))
                 for index in range(len(tariff['classes']))]
    if any(bought < max(required, accepted) for bought, required, accepted in
           zip(purchased, minimum, PREPAID_BYTES, strict=True)):
        return None
    paid = [0] * len(tariff['classes'])
    for _name, _event, _transaction, events in archive_claims(program, operator):
        for event in events:
            values = list(map(int, event['values']))
            paid[values[1]] += values[4]
    expected = [(row['rate_ou_per_mib'] * bought + 1_048_575) // 1_048_576
                for row, bought in zip(tariff['classes'], PREPAID_BYTES, strict=True)]
    if paid != expected:
        return None
    actual = int(g.view(program, 'get_earnings', [operator]))
    return (state, actual) if sum(paid) == actual and actual > 0 else None


def settled_prepaid(program, operator, tariff, minimum):
    result = settled(program, operator, tariff, minimum)
    if result is None:
        return None
    record = meter()
    if any(purchased < accepted for purchased, accepted in zip(record['purchased'], PREPAID_BYTES, strict=True)):
        return None
    assert all(held <= purchased for held, purchased in zip(exposure(record), record['purchased'], strict=True))
    return result


def snapshot(label):
    output = g.EVIDENCE / label
    output.mkdir()
    shutil.copyfile(g.ROOT / 'client-journal/state.json', output / 'client.json')
    root = g.ROOT / 'chain/node-0/octranet-payments'
    count = 0
    for source in root.rglob('*.json'):
        relative = source.relative_to(root)
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        count += 1
    assert count >= 2, 'public transport and claim journal evidence missing'


def failure_snapshot(control=None, hop=None):
    """Whitelist public journals before proxy/process teardown can change them."""
    if not g.EVIDENCE.exists():
        return
    output = g.EVIDENCE / 'failure'
    output.mkdir(exist_ok=True)
    root = g.ROOT / 'chain/node-0/octranet-payments'
    sources = [(g.ROOT / 'client-journal/state.json', pathlib.Path('client.json')),
               (root / 'claims/claims.json', pathlib.Path('claims/claims.json'))]
    sources.extend((path, path.relative_to(root))
                   for path in sorted((root / 'transport').glob('*/meter.json'))[:8])
    report = {'processes': {str(name): {'pid': process.pid, 'exit': process.poll()}
                            for name, process in g.PROCESSES.items()},
              'copied': [], 'errors': [],
              'public_status': {path: public_status(path)
                                for path in ('/operator/status', '/status')},
              'operator_readiness': g.JOURNAL.get('operator_readiness', [])}
    for source, relative in sources:
        if not source.exists():
            continue
        try:
            assert source.stat().st_size <= 64 * 1024 * 1024, 'public journal exceeds diagnostic bound'
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            report['copied'].append(str(relative))
        except (OSError, AssertionError) as error:
            report['errors'].append({'file': str(relative), 'error': type(error).__name__})
    if control is not None:
        report['proxy'] = control.metrics()
    if hop is not None:
        report['hop'] = hop.metrics()
    (output / 'diagnostics.json').write_text(json.dumps(report, indent=2) + '\n')


def meter():
    files = list((g.ROOT / 'chain/node-0/octranet-payments/transport').glob('*/meter.json'))
    assert len(files) == 1, 'exactly one durable plan meter required'
    record = json.loads(files[0].read_text())['record']
    accepted = json.loads((g.ROOT / 'accepted-plan.json').read_text())
    assert record['binding'] == accepted['binding'] and record['budget_ou'] == BUDGET
    assert 'credit' not in record, 'postpaid credit must not be configurable'
    return record


def exposure(record):
    return [sum(values) for values in zip(record['committed'], record['uncertain'],
                                         record['pending'], strict=True)]


def client_exposure(record):
    totals = list(record['local_bytes'])
    for index, held in enumerate(record.get('uncertain_bytes', [])):
        totals[index] += held
    if record.get('pending'):
        pending = record['pending']
        totals[pending['traffic_class']] += pending['bytes']
    return totals


def crash_operator():
    retained_epoch = g.epoch()
    process = g.PROCESSES.pop(0)
    process.kill()
    process.wait(timeout=15)
    g.FILES.pop(0).close()
    assert process.returncode == -signal.SIGKILL
    return retained_epoch


def blocked_probe(assigned):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.bind((assigned, 0))
        connection.settimeout(2)
        for index in range(3):
            connection.sendto(b'allowance-exhausted-probe' + bytes([index]) + b'x' * 900,
                              (g.PUBLIC, 20001))
            try:
                reply = connection.recvfrom(2048)
            except socket.timeout:
                continue
            raise AssertionError(f'exhausted allowance but tunnel returned {len(reply[0])} bytes')


def prepaid_start(program, operator, tariff, plan_path, faucet, control):
    # Hold the real payer authorization before it reaches native settlement.
    # A funded escrow and a signed control connection must yield zero traffic.
    launch_client(plan_path, faucet, resume=False, wait_interface=False)
    g.until(lambda: control.metrics()['usage_received'] >= 1, 30, 'initial prepaid purchase held')
    before = journal()
    before_meter = meter()
    assert before['authorized_bytes'] == PREPAID_BYTES
    assert before['local_bytes'] == [0] * len(PREPAID_BYTES)
    assert exposure(before_meter) == [0] * len(PREPAID_BYTES)
    assert before_meter['purchased'] == [0] * len(PREPAID_BYTES)
    assert int(g.view(program, 'get_earnings', [operator])) == 0
    assert control.metrics()['usage_forwarded'] == 0
    assert not any(item['ifname'] == CLIENT for item in json.loads(ip('-j', 'link', 'show')))
    snapshot('unpaid-before-restart')
    stop_client(crash=True)
    retained_epoch = crash_operator()
    peer_epoch = g.epoch(1)
    g.until(lambda: g.epoch(1) >= peer_epoch + 2, 90, 'native quorum progresses during unpaid restart')
    g.start(0)
    g.until(lambda: g.epoch() >= g.epoch(1), 120, 'unpaid operator restart catches up')
    route_server(retained_epoch)
    requests = control.metrics()['usage_received']
    launch_client(plan_path, faucet, resume=True, wait_interface=False)
    g.until(lambda: control.metrics()['usage_received'] > requests, 30, 'same durable purchase retried')
    after = journal()
    assert after['receipts'] == before['receipts'], 'restart replaced the exact purchase authorization'
    assert after['connection_sequence'] > before['connection_sequence']
    assert after['local_bytes'] == [0] * len(PREPAID_BYTES)
    assert meter()['purchased'] == [0] * len(PREPAID_BYTES)
    assert int(g.view(program, 'get_earnings', [operator])) == 0
    assert not any(item['ifname'] == CLIENT for item in json.loads(ip('-j', 'link', 'show')))
    snapshot('unpaid-after-restart')
    control.release()
    assigned = client_ready()
    state, earnings = g.until(lambda: settled_prepaid(program, operator, tariff, PREPAID_BYTES),
                               120, 'all purchased bytes canonically paid before traffic')
    assert state['local_bytes'] == [0] * len(PREPAID_BYTES)
    assert exposure(meter()) == [0] * len(PREPAID_BYTES)
    g.step('canonical prepaid purchase precedes first traffic across crash recovery',
           prepaid_bytes=PREPAID_BYTES, earnings_ou=earnings,
           previous_sequence=before['connection_sequence'], resumed_sequence=after['connection_sequence'],
           proxy=control.metrics(), crash_scope='idle before purchase; no syscall/power-loss claim')
    return assigned, state


def exhaust_prepaid(assigned, program, operator, tariff):
    prior = int(g.view(program, 'get_earnings', [operator]))
    successful = 0
    initial_client = client_exposure(journal())
    initial_server = exposure(meter())
    initial_receipts = journal()['receipts']
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.bind((assigned, 0)); connection.settimeout(3)
        for index in range(128):
            payload = b'prepaid-exhaust:' + struct.pack('!I', index) + b'x' * 900
            connection.sendto(payload, (g.PUBLIC, UDP_PORT))
            try:
                reply, _peer = connection.recvfrom(2048)
            except socket.timeout:
                pass
            else:
                assert reply == payload
                successful += 1
            client_left = PREPAID_BYTES[1] - client_exposure(journal())[1]
            server_left = meter()['purchased'][1] - exposure(meter())[1]
            assert min(client_left, server_left) >= 0
            if min(client_left, server_left) < len(payload) + 28:
                break
        else:
            raise AssertionError('finite prepaid allowance failed to stop traffic')
    blocked_probe(assigned)
    time.sleep(1)
    target_before = target()['udp_payload_bytes']
    blocked_probe(assigned)
    time.sleep(1)
    assert target()['udp_payload_bytes'] == target_before
    record = meter()
    assert all(held <= purchased for held, purchased in zip(exposure(record), record['purchased'], strict=True))
    assert record['purchased'] == PREPAID_BYTES
    assert min(PREPAID_BYTES[1] - client_exposure(journal())[1],
               record['purchased'][1] - exposure(record)[1]) < len(payload) + 28
    assert all(new >= old for new, old in zip(client_exposure(journal()), initial_client, strict=True))
    assert all(new >= old for new, old in zip(exposure(record), initial_server, strict=True))
    assert journal()['receipts'] == initial_receipts
    assert int(g.view(program, 'get_earnings', [operator])) == prior
    assert journal()['authorized_bytes'] == PREPAID_BYTES, 'consumption silently bought more bytes'
    assert settled_prepaid(program, operator, tariff, PREPAID_BYTES)
    g.step('finite prepaid UDP capacity exhausts without another payment or unpaid forwarding',
           successful_echoes=successful, operator_exposure=exposure(record), purchased=record['purchased'],
           earnings_ou=prior, target_payload_bytes=target_before)


def blocked_icmp_probe(assigned):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as ping:
        ping.bind((assigned, 0)); ping.settimeout(2)
        for index in range(3):
            raw = bytearray(struct.pack('!BBHHH', 8, 0, 0, 31, index) + b'revoked-prepaid-plan')
            padded = raw + (b'\0' if len(raw) % 2 else b'')
            checksum = sum(struct.unpack('!' + str(len(padded) // 2) + 'H', padded))
            while checksum >> 16:
                checksum = (checksum & 65535) + (checksum >> 16)
            struct.pack_into('!H', raw, 2, (~checksum) & 65535)
            ping.sendto(raw, (g.PUBLIC, 0))
            try:
                ping.recvfrom(2048)
            except socket.timeout:
                continue
            raise AssertionError('revoked prepaid plan still forwarded ICMP')


def archive_claims(program, operator):
    claims = []
    for path in sorted((g.ROOT / 'chain/node-0/exex').glob('*.json')):
        event = json.loads(path.read_text())
        for transaction in event.get('events', []):
            receipt = transaction.get('receipt')
            # The archive's successful receipt is retained with its containing
            # native transaction. Inspect actual successful UsageCharged events.
            envelope = json.loads(base64.b64decode(transaction['transaction'], validate=True))
            if envelope.get('to_') != program:
                continue
            if not isinstance(receipt, str):
                continue
            receipt = json.loads(base64.b64decode(receipt, validate=True))
            if receipt.get('method') != 'claim' or receipt.get('success') is not True:
                continue
            assert receipt.get('error') is None
            assert receipt['program'] == program and receipt['contract'] == program
            assert envelope['from'] == operator and envelope['encrypted_data'] == 'claim'
            identity = base64.b64decode(transaction['identity'], validate=True)
            assert hashlib.sha256(identity).hexdigest() == transaction['hash']
            assert json.loads(identity) == envelope and transaction['proof'] == 'exact'
            charged = [item for item in receipt.get('events', [])
                       if item.get('event') == 'UsageCharged']
            assert all(item['program'] == program and item['contract'] == program for item in charged)
            if charged:
                claims.append((path.name, event, transaction, charged))
    return claims


def exercise(program, operator, tariff, plan_path, faucet, hop, control):
    ip('address', 'del', g.PUBLIC + '/32', 'dev', 'lo')
    ip('rule', 'del', 'priority', '0')
    ip('rule', 'add', 'priority', '2000', 'lookup', 'local')
    ip('route', 'add', g.PUBLIC + '/32', 'via', '192.0.2.2', 'dev', LINK)
    g.command(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '198.18.0.0/15',
               '-d', g.PUBLIC + '/32', '-o', LINK, '-j', 'SNAT', '--to-source', SNAT])
    ip('rule', 'add', 'priority', '5', 'iif', LINK, 'to', '198.18.0.0/15', 'lookup', '402')
    ip('rule', 'add', 'priority', '10', 'iif', 'lo', 'to', g.PUBLIC + '/32', 'lookup', '401')
    assigned, baseline = prepaid_start(program, operator, tariff, plan_path, faucet, control)
    g.command(['iptables', '-t', 'raw', '-A', 'OUTPUT', '-o', CLIENT, '-s', assigned + '/32',
               '-d', g.PUBLIC + '/32', '-j', 'NOTRACK'])
    g.command(['iptables', '-t', 'raw', '-A', 'PREROUTING', '-i', CLIENT, '-s', g.PUBLIC + '/32',
               '-d', assigned + '/32', '-j', 'NOTRACK'])
    route = json.loads(ip('-j', 'route', 'get', g.PUBLIC, 'from', assigned, 'iif', 'lo'))[0]
    assert route['dev'] == CLIENT, 'application stack bypassed actual client TUN'
    udp_bytes = udp(assigned, 8, b'before-restart:')
    tcp_bytes = tcp_and_icmp(assigned)
    minimum = PREPAID_BYTES
    before, earnings = g.until(lambda: settled_prepaid(program, operator, tariff, minimum), 120,
                               'actual canonical payment claim')
    assert all(count > 0 for count in before['local_bytes']), 'all three classes must carry packets'
    assert all(count > 0 for count in before['authorized_bytes']), 'client must authorize all classes'
    assert before['local_bytes'][1] >= 2 * udp_bytes
    g.step('real paid kernel traffic and native canonical claim', assigned=assigned,
           udp_payload_bytes=udp_bytes, tcp_payload_bytes=tcp_bytes, icmp_echo=True,
           confirmed_bytes=before['local_bytes'], authorized_bytes=before['authorized_bytes'],
           uncertain_bytes=before.get('uncertain_bytes', []), operator_earnings_ou=earnings)
    snapshot('settled-before-restart')

    # Abrupt client death and a separate operator restart retain both independent
    # journals. --resume reuses this plan and key without a new fund/open call.
    stop_client(crash=True)
    retained_epoch = g.epoch()
    g.stop(0)
    peer_epoch = g.epoch(1)
    g.until(lambda: g.epoch(1) >= peer_epoch + 2, 90, 'remaining native quorum progresses')
    g.start(0)
    g.until(lambda: g.epoch() >= g.epoch(1), 120, 'operator canonical restart catches up')
    route_server(retained_epoch)
    assert launch_client(plan_path, faucet, resume=True) == assigned
    after = journal()
    assert after['connection_sequence'] > before['connection_sequence']
    assert all(new >= old for new, old in zip(after['local_bytes'], before['local_bytes'], strict=True))
    assert int(g.view(program, 'get_plan_budget', [0])) == BUDGET
    g.until(lambda: int(g.view(program, 'get_funds', [g.view(program, 'get_plan_payer', [0])]))
            + int(g.view(program, 'get_earnings', [operator])) == FUND,
            30, 'payer balance and operator earnings remain conserved')
    baseline, _earnings = g.until(lambda: settled_prepaid(program, operator, tariff, before['authorized_bytes']),
                                 120, 'resumed meter retains purchased capacity')
    new_udp = udp(assigned, 8, b'after-restart:')
    new_tcp = tcp_and_icmp(assigned)
    udp_bytes += new_udp
    tcp_bytes += new_tcp
    # Traffic consumes the original purchase; it never creates a new authorization.
    minimum = PREPAID_BYTES
    current, earnings = g.until(lambda: settled_prepaid(program, operator, tariff, minimum), 120,
                                'retained canonical purchases after client and operator restart')
    g.step('same plan survives crash and native operator restart',
           assigned=assigned, before_sequence=before['connection_sequence'],
           resumed_sequence=current['connection_sequence'], original_budget_ou=BUDGET,
           confirmed_bytes=current['local_bytes'], authorized_bytes=current['authorized_bytes'],
           uncertain_bytes=current.get('uncertain_bytes', []), operator_earnings_ou=earnings)
    snapshot('settled-after-restart')

    exhaust_prepaid(assigned, program, operator, tariff)
    # A live still-funded class rules out a dead tunnel masquerading as exhaustion.
    tcp_bytes += tcp_and_icmp(assigned)
    g.step('other prepaid classes still deliver after premium exhaustion', icmp_echo=True)

    # Delay the next HTTP status without altering its signed bytes. The actual
    # client still owns its established WG peer/TUN, so a local client stop
    # cannot masquerade as native server data-plane revocation.
    control.hold_status()
    g.until(lambda: control.metrics()['status_waiting'] >= 1, 10, 'client status poll held')
    payer = g.view(program, 'get_plan_payer', [0])
    generation = int(g.view(program, 'get_generation', [payer]))
    channel_before = int(g.view(program, 'get_channel_balance', [payer]))
    locked_before = int(g.view(program, 'get_locked_value'))
    g.send('partial channel withdrawal revokes old generation immediately', faucet, program,
           'withdraw_channel', [1])
    assert int(g.view(program, 'get_generation', [payer])) == generation + 1
    assert int(g.view(program, 'get_active', [payer])) == 1
    assert int(g.view(program, 'get_reserved', [payer])) == 0
    assert int(g.view(program, 'get_channel_balance', [payer])) == channel_before - 1
    assert int(g.view(program, 'get_locked_value')) == locked_before - 1
    assert int(g.view(program, 'get_user_exit_ms')) == 0
    assert g.view(program, 'can_forward', [0]) is False
    before_probe = journal()['local_bytes'][2]
    target_before = hop.metrics()['sent_packets']
    blocked_icmp_probe(assigned)
    time.sleep(1)
    assert g.PROCESSES['payer'].poll() is None, 'client stop hid server packet revocation'
    assert journal()['local_bytes'][2] > before_probe, 'no real WG handoff attempted after exit'
    assert hop.metrics()['sent_packets'] == target_before, 'partial withdrawal still forwarded old-generation packets'
    g.step('canonical partial withdrawal blocks old generation from live WireGuard client',
           attempted_local_bytes=journal()['local_bytes'][2] - before_probe,
           target_packets_after_exit=target_before)
    payer_process = g.PROCESSES.pop('payer')
    stream = g.FILES.pop('payer')
    control.release_status()
    payer_process.wait(timeout=15)
    stream.close()
    assert payer_process.returncode != 0, 'client continued with a non-admissible plan'
    # A new client cannot re-admit that paid plan by replaying the durable key.
    result = subprocess.run(['octravpn', 'payments', '--plan', str(plan_path), '--receipt-key', str(faucet),
                             '--journal', str(g.ROOT / 'client-journal'), '--tun-name', CLIENT, '--resume'],
                            cwd=g.ROOT, capture_output=True, text=True, timeout=20)
    (g.EVIDENCE / 'exiting-client.log').write_text(result.stdout + result.stderr)
    assert result.returncode != 0, 'old-generation replay admitted another tunnel'

    # Available balance is withdrawable immediately without requesting exit;
    # completed byte purchases and operator proceeds are final.
    remaining = int(g.view(program, 'get_channel_balance', [payer]))
    g.send('withdraw all available channel OCT immediately', faucet, program, 'withdraw_remaining', [])
    assert int(g.view(program, 'get_channel_balance', [payer])) == 0
    assert int(g.view(program, 'get_funds', [payer])) == 0
    assert int(g.view(program, 'get_reserved', [payer])) == 0
    assert int(g.view(program, 'get_active', [payer])) == 0
    assert int(g.view(program, 'get_locked_value')) == locked_before - 1 - remaining
    assert int(g.view(program, 'get_rate_notice_ms')) == 86_400_000
    # Drain the shared operator wallet's already-authorized claim queue before
    # the fixture submits another transaction from that wallet.
    claim_journal = g.ROOT / 'chain/node-0/octranet-payments/claims/claims.json'
    g.until(lambda: not json.loads(claim_journal.read_text())['journal']['slots'],
            90, 'native claim queue drained before operator transaction')

    def stable_claims():
        records = archive_claims(program, operator)
        increments = sum(int(item['values'][4]) for _name, _event, _tx, charged in records for item in charged)
        earned = int(g.view(program, 'get_earnings', [operator]))
        return (records, earned) if records and increments == earned else None
    claims, final_earnings = g.until(stable_claims, 30, 'complete canonical claims in ExEx')
    increments = [0] * len(tariff['classes'])
    for name, event, transaction, charged in claims:
        assert transaction['proof'] == 'exact'
        for index in range(1, 4):
            peer = g.ROOT / f'chain/node-{index}/exex' / name
            g.until(peer.exists, 60, 'matching peer claim ExEx')
            assert json.loads(peer.read_text()) == event
        for item in charged:
            values = list(map(int, item['values']))
            assert values[0] == 0
            increments[values[1]] += values[4]
        (g.EVIDENCE / ('claims-' + name)).write_text(json.dumps(event, indent=2))
    assert sum(increments) == final_earnings and increments[0] > 0 and increments[1] > 0
    assert increments[2] == 0, 'operator zero-rate class incurred a protocol commission'
    assert channel_before + final_earnings == FUND
    assert 1 + remaining + final_earnings == FUND
    assert int(g.view(program, 'get_earnings', [operator])) == final_earnings
    assert int(g.view(program, 'get_locked_value')) == STAKE + final_earnings
    g.step('identical canonical paid claims on four ExEx sinks with instant available withdrawal',
           claims=len(claims), per_class_increments_ou=increments, total_earnings_ou=final_earnings,
           payer_withdrawn_ou=1 + remaining)

    # Register the operator as a buyer, then allocate its earned OCT directly
    # into a new prepaid plan, without depositing another token.
    operator_key = g.ROOT / 'operator.hex'
    own_generation = int(g.view(program, 'get_generation', [operator])) + 1
    operator_public = g.JOURNAL['genesis']['validators'][0].split(':', 1)[1]
    domain = json.loads(plan_path.read_text())['binding']['deployment']['domain']
    registration = f'Octranet register v1|{domain}|{program}|{operator}|{own_generation}'
    proof = g.command(['octra', 'cast', 'wallet', 'sign', '--key', operator_key, registration])
    g.send('operator registers its own prepaid channel', operator_key, program,
           'register', [operator_public, proof])
    own_budget = max(1, final_earnings // 2)
    assert int(g.view(program, 'get_funds', [operator])) == 0
    assert int(g.view(program, 'get_earnings', [operator])) == final_earnings
    own_open = g.send('exit earnings fund operator own traffic without another deposit', operator_key,
                      program, 'open_plan', [0, own_budget])
    own_plan = int(next(event['values'][0] for event in own_open['events']
                        if event['event'] == 'PlanOpened'))
    assert int(g.view(program, 'get_funds', [operator])) == own_budget
    assert int(g.view(program, 'get_earnings', [operator])) == final_earnings - own_budget
    assert int(g.view(program, 'get_reserved', [operator])) == own_budget
    assert int(g.view(program, 'get_channel_balance', [operator])) == final_earnings
    assert int(g.view(program, 'get_locked_value')) == STAKE + final_earnings
    manifest = json.loads(plan_path.read_text())['binding']['manifest_hash']
    purchase = f'Octranet prepaid v1|{domain}|{program}|{operator}|{own_generation}|{own_plan}|0|{manifest}|0|1|32'
    signature = g.command(['octra', 'cast', 'wallet', 'sign', '--key', operator_key, purchase])
    g.send('earned OCT purchases operator own prepaid bytes', operator_key, program,
           'claim', [own_plan, 0, 1, 32, signature])
    assert int(g.view(program, 'get_prepaid_bytes', [own_plan, 0])) == 32
    assert int(g.view(program, 'get_plan_remaining', [own_plan])) == own_budget - 1
    assert int(g.view(program, 'get_channel_balance', [operator])) == final_earnings
    own_claims = g.until(lambda: [row for row in archive_claims(program, operator)
                                 if any(int(event['values'][0]) == own_plan for event in row[3])],
                         30, 'canonical operator own-byte purchase in ExEx')
    for name, event, _transaction, _charged in own_claims:
        for index in range(1, 4):
            peer = g.ROOT / f'chain/node-{index}/exex' / name
            g.until(peer.exists, 60, 'matching own-byte purchase peer ExEx')
            assert json.loads(peer.read_text()) == event
    g.send('request canonical operator unstake', operator_key, program, 'request_operator_unstake', [])
    unlock = int(g.view(program, 'get_operator_unlock_ms', [operator]))
    assert int(g.view(program, 'get_operator_unstake_ms')) == 604_800_000
    assert unlock > 0 and int(g.view(program, 'get_operator_stake', [operator])) == STAKE
    g.send('operator unstake retry keeps original deadline', operator_key, program,
           'request_operator_unstake', [])
    assert int(g.view(program, 'get_operator_unlock_ms', [operator])) == unlock
    g.send('stopped operator releases its unused prepaid allocation immediately', operator_key,
           program, 'release_stopped_plan', [own_plan])
    assert int(g.view(program, 'get_plan_remaining', [own_plan])) == 0
    g.send('operator channel balance withdraws while stake remains locked', operator_key,
           program, 'withdraw_remaining', [])
    assert int(g.view(program, 'get_channel_balance', [operator])) == 0
    assert int(g.view(program, 'get_locked_value')) == STAKE
    g.send('early operator stake withdrawal refused', operator_key, program,
           'withdraw_operator_stake', [], expected=False)
    g.step('available channel OCT withdraws instantly while operator stake remains seven days',
           operator_reused_earnings_ou=own_budget, own_prepaid_bytes=32,
           operator_unlock_ms=unlock, locked_stake_ou=STAKE)

    observed = g.until(lambda: target() if target().get('udp_payload_bytes', 0) >= udp_bytes
                       and target().get('tcp_payload_bytes', 0) >= tcp_bytes else None,
                       10, 'separate kernel received actual application traffic')
    assert not observed['errors'] and not observed['hop']['errors']
    assert all(set(sources) == {SNAT} for sources in observed['observed_sources'].values())
    assert not hop.metrics()['errors'] and hop.metrics()['rejected_packets'] == 0
    network = {'target_kernel': observed, 'hop': hop.metrics(), 'application_route': route,
               'nat_rules': g.command(['iptables', '-t', 'nat', '-L', '-v', '-n', '-x']),
               'raw_rules': g.command(['iptables', '-t', 'raw', '-L', '-v', '-n', '-x']),
               'rules': json.loads(ip('-j', 'rule', 'show'))}
    (g.EVIDENCE / 'payment-network.json').write_text(json.dumps(network, indent=2))
    assert 'SNAT' in network['nat_rules'] and SNAT in network['nat_rules']
    g.JOURNAL['limitations'] = ['No public-network or Mainnet qualification',
        '24-hour replacement-rate notice and seven-day unstake use separate canonical-clock boundary tests',
        'Explicit client --resume after process death; seamless reconnect is not asserted',
        'No stock Tailscale paid-exit, DNS/TLS or portal onboarding qualification',
        'Prepaid consent does not prove delivery; no trustless Web non-delivery slashing or prepaid refund remedy']


def prepare(validate_environment=g.native_guard, *, custody_cap=200_000_000):
    """Deploy the actual four-validator payment app and immutable Circle offer.

    Leave validators running; callers configure their real transport before the
    first operator restart. No grant or canonical receipt is fabricated here.
    """
    g.JOURNAL.update(scope='isolated four-validator prepaid payment-plan application; real client, '
                     'two endpoint kernels and canonical claims; no public-chain or Mainnet claim')
    validate_environment()
    g.ROOT.mkdir(mode=0o700)
    g.EVIDENCE.chmod(0o700)
    shutil.copyfile('/usr/local/share/native-source.json', g.EVIDENCE / 'source.json')
    g.save()
    g.command(['octra-node', 'init-devnet', '--directory', g.ROOT / 'chain',
               '--base-port', g.BASE, '--activated-applications'])
    configs = [json.loads((g.ROOT / f'chain/node-{i}/config.json').read_text())
               for i in range(4)]
    faucet = g.secret_hex(g.ROOT / 'chain/faucet.key', 'payer.hex')
    operator_key = g.secret_hex(g.ROOT / 'chain/node-0/validator.key', 'operator.hex')
    payer = g.command(['octra', 'cast', 'wallet', 'addr', '--key', faucet])
    operator = g.command(['octra', 'cast', 'wallet', 'addr', '--key', operator_key])
    chain = configs[0]['genesis']['chain']
    chain_id = chain['chain_id'].encode()
    domain = hashlib.sha256(b'Octranet payments network v1\0' + len(chain_id).to_bytes(8, 'big')
                            + chain_id + bytes(chain['genesis_root'])).hexdigest()
    g.JOURNAL['genesis'] = configs[0]['genesis']
    for i in range(4):
        configs[i]['gateway'] = {'listen': f'127.0.0.1:{g.BASE+i*10+5}',
                                 'origin': 'https://circles.example.ts.net'}
        (g.ROOT / f'chain/node-{i}/config.json').write_text(json.dumps(configs[i]))
        g.start(i)
    for i in range(4):
        g.until(lambda i=i: g.epoch(i) >= 2, 120, 'native validator finalized')
    g.record('fund native payment operator', g.cli('cast', 'transfer', operator, 300_000_000,
             '--key', faucet, '--rpc-url', g.RPC, '--ou', 1000), vm=False)
    artifacts = {}
    for name in ['octranet-payments.aml', 'octranet-payments-factory.aml']:
        source = pathlib.Path('/usr/local/share/aml') / name
        artifact = json.loads(g.command(['octra-node', 'compile-legacy', '--source', source,
                                         '--loops', '--point-ops']))
        (g.EVIDENCE / (name + '.compile.json')).write_text(json.dumps(artifact, indent=2))
        payload, code_hash = factory_artifact(source, artifact)
        artifacts[name] = {'build': artifact, 'factory_payload': payload, 'code_hash': code_hash}
    deployed = g.record('deploy native payment factory', g.cli('forge', 'create',
                        '/usr/local/share/aml/octranet-payments-factory.aml', '--key', faucet,
                        '--rpc-url', g.RPC, '--ou', g.FEE, '--no-wait'))
    factory = deployed['contract']
    spawned = g.send('deploy native payment application', faucet, factory, 'deploy_payments',
                     [artifacts['octranet-payments.aml']['factory_payload'], domain, custody_cap, STAKE])
    program = [event['values'][0] for event in spawned['events']
               if event['event'] == 'PaymentsDeployed'][0]
    assert g.rpc('vm_contract', [program])['owner'] == factory
    assert g.rpc('vm_contract', [program])['code_hash'] == artifacts['octranet-payments.aml']['code_hash']
    stored_code = g.rpc('octra_contractBytecode', [program])
    assert stored_code['bytecode'] == artifacts['octranet-payments.aml']['factory_payload']
    g.step('factory stores exact verified legacy OCTB child', program=program, factory=factory,
           code_hash=artifacts['octranet-payments.aml']['code_hash'],
           admission_scope='legacy binary execution; local source-build certificate only')
    g.send('bond actual operator stake', operator_key, program, 'bond_operator', [], STAKE)
    operator_generation = register_operator_receipt_key(
        operator_key, program, domain, operator, 'pin bonded operator service receipt key')
    receipt_public = configs[0]['genesis']['funded_public']
    message = f'Octranet register v1|{domain}|{program}|{payer}|1'
    signature = g.command(['octra', 'cast', 'wallet', 'sign', '--key', faucet, message])
    g.send('register payer receipt key', faucet, program, 'register', [receipt_public, signature])
    g.send('fund actual payer balance', faucet, program, 'fund', [payer], FUND)
    tariff = {'version': 1, 'operator': operator,
              'classes': [{'name': 'default', 'rate_ou_per_mib': 1000},
                          {'name': 'premium', 'rate_ou_per_mib': 10000},
                          {'name': 'operator-free', 'rate_ou_per_mib': 0}],
              'selectors': [{'prefix': {'network': g.PUBLIC, 'prefix_len': 32},
                             'protocol': 'udp', 'port': 20001, 'traffic_class': 1},
                            {'prefix': {'network': g.PUBLIC, 'prefix_len': 32},
                             'protocol': 'icmp', 'port': None, 'traffic_class': 2}]}
    tariff_bytes = canonical(tariff)
    manifest = hashlib.sha256(tariff_bytes).hexdigest()
    tariff_file = g.ROOT / 'tariff.json'
    tariff_file.write_bytes(tariff_bytes)
    payload = {'runtime': 'octb', 'privacy_class': 'public', 'browser_mode': 'gateway_allowed',
               'resource_mode': 'public_resources', 'code_b64': None, 'policy_hash': None,
               'members_root': None, 'export_policy': None,
               'limits': {'max_stable_bytes': '33554432', 'max_assets_bytes': '33554432',
                          'max_inline_value': '65536', 'max_wasm_bytes': '33554432'}}
    payload_path = g.ROOT / 'circle.json'
    payload_path.write_text(json.dumps(payload))
    deployed = g.cli('cast', 'circle', 'deploy', '--key', operator_key, '--rpc-url', g.RPC,
                     '--payload', payload_path, '--ou', g.FEE)
    circle = deployed['circle_id']
    g.record('deploy real public offer Circle', deployed, vm=False)
    g.record('publish hash-pinned Circle tariff', g.cli('cast', 'circle', 'put', '--circle', circle,
             '--path', f'/offers/{manifest}/tariff.json', '--file', tariff_file,
             '--content-type', 'application/json', '--key', operator_key,
             '--rpc-url', g.RPC, '--ou', g.FEE), vm=False)
    body, headers = g.until(lambda: g.get(f'http://127.0.0.1:19875/circles/{circle}/offers/{manifest}/tariff.json',
                                        'circles.example.ts.net'), 30, 'canonical Circle gateway tariff')
    assert body == tariff_bytes and headers['x-octra-chain'] == chain['chain_id']
    g.step('Circle gateway serves exact canonical tariff', tariff_sha256=manifest, circle=circle)
    g.send('create immutable operator offer', operator_key, program, 'create_offer', [manifest])
    for row in tariff['classes']:
        g.send('append exact class rate', operator_key, program, 'append_class', [0, row['rate_ou_per_mib']])
    g.send('seal exact operator offer', operator_key, program, 'seal_offer', [0])
    g.send('open funded plan', faucet, program, 'open_plan', [0, BUDGET])
    binding = {'deployment': {'domain': domain, 'program': program}, 'payer': payer,
               'generation': 1, 'plan': 0, 'offer': 0, 'manifest_hash': manifest}
    accepted = {'binding': binding, 'tariff': tariff, 'operator_generation': operator_generation,
                'original_budget_ou': BUDGET,
                'control_url': 'http://127.0.0.1:19879', 'wireguard_endpoint': '127.0.0.1:19874',
                'prepaid_bytes': PREPAID_BYTES}
    plan_path = g.ROOT / 'accepted-plan.json'
    plan_path.write_text(json.dumps(accepted))
    (g.EVIDENCE / 'accepted-plan.json').write_text(json.dumps(accepted, indent=2))
    application = {'program': program, 'code_hash': artifacts['octranet-payments.aml']['code_hash'],
                   'factory': factory, 'factory_code_hash': artifacts['octranet-payments-factory.aml']['code_hash'],
                   'domain': domain, 'operator_circle': circle, 'offer': 0}
    return {'configs': configs, 'faucet': faucet, 'operator': operator,
            'operator_key': operator_key, 'program': program, 'tariff': tariff,
            'plan_path': plan_path, 'application': application, 'circle': circle}


def main():
    fixture = prepare()
    configs, faucet, operator, program, tariff, plan_path, application = (
        fixture[name] for name in ['configs', 'faucet', 'operator', 'program',
                                   'tariff', 'plan_path', 'application'])
    retained_epoch = g.epoch()
    g.stop(0)
    configs[0]['payments'] = {'application': application, 'ip_tunnel': {'name': SERVER},
                              'max_claim_fees_ou': 100_000}
    (g.ROOT / 'chain/node-0/config.json').write_text(json.dumps(configs[0]))
    g.start(0)
    route_server(retained_epoch)
    hop = Hop(pathlib.Path('/hop'), role='node', name=LINK)
    try:
        with ControlProxy() as control:
            try:
                exercise(program, operator, tariff, plan_path, faucet, hop, control)
            except BaseException:
                try:
                    failure_snapshot(control, hop)
                except Exception as error:
                    g.JOURNAL['failure_snapshot_error'] = type(error).__name__
                raise
    finally:
        hop.close()
    for index in list(g.PROCESSES):
        g.stop(index)
    g.JOURNAL['qualified'] = True
    g.save()
    print('NATIVE_PAYMENT_PLAN_GATE_PASS', flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        failure = traceback.format_exc()
        if g.EVIDENCE.exists():
            if not (g.EVIDENCE / 'failure/diagnostics.json').exists():
                try:
                    failure_snapshot()
                except Exception as error:
                    g.JOURNAL['failure_snapshot_error'] = type(error).__name__
            g.JOURNAL['failure'] = failure
            try:
                g.save()
            except OSError:
                pass  # Diagnostic persistence cannot conceal the original failure.
        traceback.print_exc()
        raise SystemExit(1)
    finally:
        for child in g.PROCESSES.values():
            if child.poll() is None:
                child.terminate()
        for child in g.PROCESSES.values():
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
