#!/usr/bin/env python3
"""Real kernel/client/native-claim qualification for the payment-plan candidate.

Run only via the disposable, network-disabled two-container gate. Every app
deployment and payment is an ordinary signed transaction on four fresh native
validators. Canonical time is never overridden to fast-forward a withdrawal.
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
CREDIT_BYTES = 32_768


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


def ip(*args):
    return g.command(['ip', *args])


def target():
    path = g.EVIDENCE / 'target.json'
    return json.loads(path.read_text()) if path.exists() else {}


def journal():
    # Checksums/semantics are verified by the actual client on each open. This
    # fixture only reads its public counters and signed receipts as evidence.
    return json.loads((g.ROOT / 'client-journal/state.json').read_text())['payload']


def launch_client(plan, receipt_key, *, resume):
    log = g.EVIDENCE / ('client-resumed.log' if resume else 'client.log')
    stream = log.open('w')
    args = ['octravpn', 'payments', '--plan', str(plan), '--receipt-key', str(receipt_key),
            '--journal', str(g.ROOT / 'client-journal'), '--tun-name', CLIENT]
    if resume:
        args.append('--resume')
    process = subprocess.Popen(args, cwd=g.ROOT, stdout=stream, stderr=subprocess.STDOUT,
                               env={**os.environ, 'RUST_LOG': 'info'})
    g.PROCESSES['payer'] = process
    g.FILES['payer'] = stream
    g.until(lambda: 'Octranet interface ' in log.read_text(), 90, 'real paid client TUN')
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


def route_server():
    g.until(lambda: SERVER in ip('-j', 'link', 'show'), 90, 'real paid operator TUN')
    ip('route', 'replace', '198.18.0.0/15', 'dev', SERVER, 'table', '402')


def udp(assigned, count, marker):
    total = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.bind((assigned, 0))
        connection.settimeout(8)
        for index in range(count):
            payload = marker + struct.pack('!I', index) + b'payment-plan-udp' * 60
            connection.sendto(payload, (g.PUBLIC, 20001))
            received, peer = connection.recvfrom(2048)
            assert peer == (g.PUBLIC, 20001) and received == payload
            total += len(payload)
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
    assert all(state['local_bytes'][i] >= value
               for i, value in enumerate(state['authorized_bytes']))
    if any(authorized < floor for authorized, floor in
           zip(state['authorized_bytes'], minimum, strict=True)):
        return None
    paid = [0] * len(tariff['classes'])
    for _name, _event, _transaction, events in archive_claims(program, operator):
        for event in events:
            values = list(map(int, event['values']))
            paid[values[1]] += values[4]
    for row, authorized, canonical_paid in zip(tariff['classes'], state['authorized_bytes'], paid, strict=True):
        if canonical_paid < (row['rate_ou_per_mib'] * authorized + 1_048_575) // 1_048_576:
            return None
    actual = int(g.view(program, 'get_earnings', [operator]))
    return (state, actual) if sum(paid) == actual and actual > 0 else None


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


def meter():
    files = list((g.ROOT / 'chain/node-0/octranet-payments/transport').glob('*/meter.json'))
    assert len(files) == 1, 'exactly one durable plan meter required'
    record = json.loads(files[0].read_text())['record']
    accepted = json.loads((g.ROOT / 'accepted-plan.json').read_text())
    assert record['binding'] == accepted['binding'] and record['budget_ou'] == BUDGET
    assert record['credit'] == {'max_unacknowledged_bytes': CREDIT_BYTES,
                                'max_unacknowledged_ou': 100_000}
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
    process = g.PROCESSES.pop(0)
    process.kill()
    process.wait(timeout=15)
    g.FILES.pop(0).close()
    assert process.returncode == -signal.SIGKILL


def blocked_probe(assigned):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.bind((assigned, 0))
        connection.settimeout(2)
        for index in range(3):
            connection.sendto(b'credit-exhausted-probe' + bytes([index]) + b'x' * 900,
                              (g.PUBLIC, 20001))
            try:
                reply = connection.recvfrom(2048)
            except socket.timeout:
                continue
            raise AssertionError(f'credit exhausted but tunnel returned {len(reply[0])} bytes')


def bounded_credit(program, operator, tariff, assigned, plan_path, faucet, control):
    successful = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.bind((assigned, 0))
        connection.settimeout(3)
        for index in range(64):
            payload = b'credit-fixture' + struct.pack('!I', index) + b'x' * 900
            connection.sendto(payload, (g.PUBLIC, 20001))
            try:
                reply, _peer = connection.recvfrom(2048)
            except socket.timeout:
                break
            assert reply == payload
            successful += 1
        else:
            raise AssertionError('unacknowledged byte ceiling did not stop traffic')
    assert successful >= 8, 'traffic failed before exercising a substantial credit window'
    assert int(g.view(program, 'get_earnings', [operator])) == 0
    assert control.metrics()['usage_forwarded'] == 0
    blocked_probe(assigned)
    time.sleep(1)
    target_before = target()['udp_payload_bytes']
    before = journal()
    meter_before = meter()
    held_before = exposure(meter_before)
    assert CREDIT_BYTES - 1280 <= sum(held_before) <= CREDIT_BYTES
    assert sum(meter_before['redeemed']) == 0
    snapshot('credit-before-restart')
    stop_client(crash=True)
    crash_operator()
    peer_epoch = g.epoch(1)
    g.until(lambda: g.epoch(1) >= peer_epoch + 2, 90, 'native quorum continues during credit recovery')
    g.start(0)
    route_server()
    g.until(lambda: g.epoch() >= g.epoch(1), 120, 'credit-recovering operator catches up')
    assert launch_client(plan_path, faucet, resume=True) == assigned
    blocked_probe(assigned)
    time.sleep(1)
    assert target()['udp_payload_bytes'] == target_before, 'restart reset unpaid packet exposure'
    assert int(g.view(program, 'get_earnings', [operator])) == 0
    after = journal()
    meter_after = meter()
    held_after = exposure(meter_after)
    assert after['connection_sequence'] > before['connection_sequence']
    assert all(new >= old for new, old in zip(after['local_bytes'], before['local_bytes'], strict=True))
    assert all(new >= old for new, old in zip(held_after, held_before, strict=True))
    assert all(new >= old for new, old in zip(client_exposure(after), client_exposure(before), strict=True))
    assert meter_after['connect']['request']['sequence'] > meter_before['connect']['request']['sequence']
    assert sum(held_after) <= CREDIT_BYTES and sum(meter_after['redeemed']) == 0
    snapshot('credit-after-restart')
    control.release()
    g.until(lambda: settled(program, operator, tariff, [0, 2 * successful * 918, 0]),
            120, 'held signed receipts canonically restore credit')
    g.step('bounded unpaid credit survives client crash and operator restart',
           byte_ceiling=CREDIT_BYTES, successful_echoes=successful,
           previous_sequence=before['connection_sequence'], resumed_sequence=after['connection_sequence'],
           target_bytes_while_blocked=target_before, meter_exposure_before=held_before,
           meter_exposure_after=held_after, proxy=control.metrics(),
           crash_scope='SIGKILL both processes while idle at exhausted credit; not send/fsync fault injection')


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
    assigned = launch_client(plan_path, faucet, resume=False)
    g.command(['iptables', '-t', 'raw', '-A', 'OUTPUT', '-o', CLIENT, '-s', assigned + '/32',
               '-d', g.PUBLIC + '/32', '-j', 'NOTRACK'])
    g.command(['iptables', '-t', 'raw', '-A', 'PREROUTING', '-i', CLIENT, '-s', g.PUBLIC + '/32',
               '-d', assigned + '/32', '-j', 'NOTRACK'])
    route = json.loads(ip('-j', 'route', 'get', g.PUBLIC, 'from', assigned, 'iif', 'lo'))[0]
    assert route['dev'] == CLIENT, 'application stack bypassed actual client TUN'
    bounded_credit(program, operator, tariff, assigned, plan_path, faucet, control)
    udp_bytes = udp(assigned, 8, b'before-restart:')
    tcp_bytes = tcp_and_icmp(assigned)
    before, earnings = g.until(lambda: settled(program, operator, tariff,
                               [2 * tcp_bytes, 2 * udp_bytes, 1]), 120,
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
    g.stop(0)
    peer_epoch = g.epoch(1)
    g.until(lambda: g.epoch(1) >= peer_epoch + 2, 90, 'remaining native quorum progresses')
    g.start(0)
    route_server()
    g.until(lambda: g.epoch() >= g.epoch(1), 120, 'operator canonical restart catches up')
    assert launch_client(plan_path, faucet, resume=True) == assigned
    after = journal()
    assert after['connection_sequence'] > before['connection_sequence']
    assert all(new >= old for new, old in zip(after['local_bytes'], before['local_bytes'], strict=True))
    assert int(g.view(program, 'get_plan_budget', [0])) == BUDGET
    g.until(lambda: int(g.view(program, 'get_funds', [g.view(program, 'get_plan_payer', [0])]))
            + int(g.view(program, 'get_earnings', [operator])) == FUND,
            30, 'payer balance and operator earnings remain conserved')
    new_udp = udp(assigned, 8, b'after-restart:')
    new_tcp = tcp_and_icmp(assigned)
    udp_bytes += new_udp
    tcp_bytes += new_tcp
    # Exhausted-window probes reached the local WG socket but not the operator.
    # They stay in local exposure, not receipt liability. Add the new delivered
    # load to the last authenticated counters, never those rejected probes.
    minimum = [old + delivered for old, delivered in
               zip(before['authorized_bytes'], [2 * new_tcp, 2 * new_udp, 1], strict=True)]
    current, earnings = g.until(lambda: settled(program, operator, tariff, minimum), 120,
                                'canonical claims after client and operator restart')
    g.step('same plan survives crash and native operator restart',
           assigned=assigned, before_sequence=before['connection_sequence'],
           resumed_sequence=current['connection_sequence'], original_budget_ou=BUDGET,
           confirmed_bytes=current['local_bytes'], authorized_bytes=current['authorized_bytes'],
           uncertain_bytes=current.get('uncertain_bytes', []), operator_earnings_ou=earnings)
    snapshot('settled-after-restart')

    # Delay the next HTTP status without altering its signed bytes. The actual
    # client still owns its established WG peer/TUN, so a local client stop
    # cannot masquerade as native server data-plane revocation.
    control.hold_status()
    g.until(lambda: control.metrics()['status_waiting'] >= 1, 10, 'client status poll held')
    g.send('canonical payer exit revokes forwarding', faucet, program, 'request_exit', [])
    deadline = int(g.view(program, 'get_exit_deadline_ms', [g.view(program, 'get_plan_payer', [0])]))
    assert deadline > 0 and int(g.view(program, 'get_user_exit_ms')) == 86_400_000
    assert g.view(program, 'can_forward', [0]) is False
    before_probe = journal()['local_bytes'][1]
    target_before = target()['udp_payload_bytes']
    blocked_probe(assigned)
    time.sleep(1)
    assert g.PROCESSES['payer'].poll() is None, 'client stop hid server packet revocation'
    assert journal()['local_bytes'][1] > before_probe, 'no real WG handoff attempted after exit'
    assert target()['udp_payload_bytes'] == target_before, 'native exit still forwarded packets'
    g.step('canonical native exit blocks packets from live established WireGuard client',
           attempted_local_bytes=journal()['local_bytes'][1] - before_probe,
           target_bytes_after_exit=target_before)
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
    assert result.returncode != 0, 'exit replay admitted another tunnel'

    # Normal chain time remains in force. Neither the user nor operator can
    # withdraw early; this gate does not fake 24 hours or a week of consensus.
    g.send('early payer refund refused', faucet, program, 'withdraw_remaining', [], expected=False)
    # The CLI and native claim worker use the same operator wallet. Drain its
    # already-authorized claims before the fixture submits another operator
    # transaction, so it cannot manufacture an external nonce race.
    claim_journal = g.ROOT / 'chain/node-0/octranet-payments/claims/claims.json'
    g.until(lambda: not json.loads(claim_journal.read_text())['journal']['slots'],
            90, 'native claim queue drained before operator transaction')
    g.send('request canonical operator unstake', g.ROOT / 'operator.hex', program,
           'request_operator_unstake', [])
    unlock = int(g.view(program, 'get_operator_unlock_ms', [operator]))
    assert int(g.view(program, 'get_operator_unstake_ms')) == 604_800_000
    assert unlock > deadline and int(g.view(program, 'get_operator_stake', [operator])) == STAKE
    g.send('operator unstake retry keeps original deadline', g.ROOT / 'operator.hex', program,
           'request_operator_unstake', [])
    assert int(g.view(program, 'get_operator_unlock_ms', [operator])) == unlock
    g.send('early operator stake withdrawal refused', g.ROOT / 'operator.hex', program,
           'withdraw_operator_stake', [], expected=False)
    g.step('canonical exit and seven-day unstake stop admission without early withdrawal',
           payer_deadline_ms=deadline, operator_unlock_ms=unlock)

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
    payer = g.view(program, 'get_plan_payer', [0])
    assert int(g.view(program, 'get_funds', [payer])) == FUND - final_earnings
    assert int(g.view(program, 'get_reserved', [payer])) == BUDGET - final_earnings
    assert int(g.view(program, 'get_plan_remaining', [0])) == BUDGET - final_earnings
    assert int(g.view(program, 'get_locked_value')) == STAKE + FUND
    g.step('identical canonical paid claims on four ExEx sinks',
           claims=len(claims), per_class_increments_ou=increments, total_earnings_ou=final_earnings)

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
        '24-hour and seven-day maturity use separate canonical-clock boundary tests',
        'Explicit client --resume after process death; seamless reconnect is not asserted',
        'No stock Tailscale paid-exit, DNS/TLS or portal onboarding qualification']


def main():
    g.JOURNAL.update(scope='isolated four-validator payment-plan application; real client, '
                     'two endpoint kernels and canonical claims; no public-chain or Mainnet claim')
    g.native_guard()
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
                     [artifacts['octranet-payments.aml']['factory_payload'], domain, 200_000_000, STAKE])
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
    accepted = {'binding': binding, 'tariff': tariff, 'original_budget_ou': BUDGET,
                'control_url': 'http://127.0.0.1:19879', 'wireguard_endpoint': '127.0.0.1:19874'}
    plan_path = g.ROOT / 'accepted-plan.json'
    plan_path.write_text(json.dumps(accepted))
    (g.EVIDENCE / 'accepted-plan.json').write_text(json.dumps(accepted, indent=2))
    application = {'program': program, 'code_hash': artifacts['octranet-payments.aml']['code_hash'],
                   'factory': factory, 'factory_code_hash': artifacts['octranet-payments-factory.aml']['code_hash'],
                   'domain': domain, 'operator_circle': circle, 'offer': 0}
    g.stop(0)
    configs[0]['payments'] = {'application': application, 'ip_tunnel': {'name': SERVER},
                              'credit': {'max_unacknowledged_bytes': CREDIT_BYTES,
                                         'max_unacknowledged_ou': 100_000},
                              'max_claim_fees_ou': 100_000}
    (g.ROOT / 'chain/node-0/config.json').write_text(json.dumps(configs[0]))
    g.start(0)
    route_server()
    hop = Hop(pathlib.Path('/hop'), role='node', name=LINK)
    try:
        with ControlProxy() as control:
            exercise(program, operator, tariff, plan_path, faucet, hop, control)
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
        if g.EVIDENCE.exists():
            g.JOURNAL['failure'] = traceback.format_exc()
            g.save()
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
