#!/usr/bin/env python3
"""Real two-operator native fixture. Namespace links never terminate consensus."""
import argparse
import base64
import hashlib
import json
import pathlib
import shutil
import time
import traceback

import payments_qualify as p
import qualify as g
from packet_target import Hop
from payment_control import ControlProxy
from stock_operator import atomic, internal_guard

A_IP = '93.184.216.11'
B_IP = '93.184.216.21'
ENTRY = 'hop-entry'
EXIT = 'hop-exit'


def ready(index, interface, minimum):
    g.until(lambda: interface in p.ip('-j', 'link', 'show'), 120, 'actual operator TUN')
    p.ip('route', 'replace', '198.18.0.0/15', 'dev', interface, 'table', '402')
    def serving():
        body, _ = g.get(f'http://127.0.0.1:{g.BASE+index*10+1}/operator/status')
        value = json.loads(body)
        return value.get('serving') is True and value.get('epoch', -1) >= minimum
    g.until(serving, 180, 'canonical operator Serving')


def links(role):
    import subprocess
    mapping = []
    if role == 'A':
        mapping.append({'listen': ['127.0.0.1', 19880], 'target': ['172.31.237.4', 20880]})
        for port in [19870, 19890, 19900]:
            mapping.append({'listen': ['172.31.237.2', port + 1000], 'target': ['127.0.0.1', port]})
        mapping.extend([{'listen': [A_IP, 20879], 'target': ['127.0.0.1', 19879]},
                        {'listen': [A_IP, 20889], 'target': ['172.31.237.4', 20889]}])
    else:
        mapping.append({'listen': ['172.31.237.4', 20880], 'target': ['127.0.0.1', 19880]})
        for port in [19870, 19890, 19900]:
            mapping.append({'listen': ['127.0.0.1', port], 'target': ['172.31.237.2', port + 1000]})
        mapping.append({'listen': ['172.31.237.4', 20889], 'target': ['127.0.0.1', 19889]})
    path = g.ROOT / ('links-' + role + '.json'); path.write_text(json.dumps(mapping))
    stream = (g.EVIDENCE / ('links-' + role + '.log')).open('x')
    process = subprocess.Popen(['python3', '-u', '/usr/local/bin/multi_link.py', str(path)], stdout=stream, stderr=stream)
    g.until(lambda: '"ready": true' in (g.EVIDENCE / ('links-' + role + '.log')).read_text(), 20, 'opaque native fixture links')
    return process, stream, mapping


class A:
    def __init__(self, exhaust):
        self.fixture = p.prepare(internal_guard, custody_cap=400_000_000)
        self.program = self.fixture['program']; self.faucet = self.fixture['faucet']
        self.operator_a = self.fixture['operator']; self.circle = self.fixture['circle']
        self.operator_b_key = g.secret_hex(g.ROOT / 'chain/node-1/validator.key', 'operator-B.hex')
        self.operator_b = g.command(['octra', 'cast', 'wallet', 'addr', '--key', self.operator_b_key])
        self.payer_b_key = g.ROOT / 'payer-B.hex'
        generated = g.cli('cast', 'wallet', 'new', '--out', self.payer_b_key)
        self.payer_b = generated['address']
        for label, address, amount in [('B operator', self.operator_b, 300_000_000), ('B payer', self.payer_b, 30_000_000)]:
            g.record('fund actual ' + label, g.cli('cast', 'transfer', address, amount, '--key', self.faucet,
                     '--rpc-url', g.RPC, '--ou', 1000), vm=False)
        g.send('bond separate B operator stake', self.operator_b_key, self.program, 'bond_operator', [], p.STAKE)
        domain = self.fixture['application']['domain']
        message = f'Octranet register v1|{domain}|{self.program}|{self.payer_b}|1'
        signature = g.command(['octra', 'cast', 'wallet', 'sign', '--key', self.payer_b_key, message])
        public = g.command(['octra', 'cast', 'wallet', 'pubkey', '--key', self.payer_b_key])
        g.send('register independent B payer receipt key', self.payer_b_key, self.program, 'register', [public, signature])
        g.send('fund independent B payer channel', self.payer_b_key, self.program, 'fund', [self.payer_b], p.FUND)
        self.a_tariff = {'version': 1, 'operator': self.operator_a,
            'classes': [{'name': 'default', 'rate_ou_per_mib': 1000}, {'name': 'encrypted-carrier', 'rate_ou_per_mib': 2000}],
            'selectors': [{'prefix': {'network': B_IP, 'prefix_len': 32}, 'protocol': 'udp', 'port': 19884, 'traffic_class': 1}]}
        self.a_caps = [0, 131_072 if exhaust == 0 else 1_048_576]
        self.b_tariff = {**self.fixture['tariff'], 'operator': self.operator_b}
        self.b_caps = [131_072, 1_048_576 if exhaust == 0 else 65_536, 4096]
        self.plans = [self.offer(self.a_tariff, self.fixture['operator_key'], self.faucet, self.operator_a, self.a_caps, 19879, A_IP, 19874),
                      self.offer(self.b_tariff, self.operator_b_key, self.payer_b_key, self.operator_b, self.b_caps, 19889, B_IP, 19884)]
        assert self.plans[0]['binding']['payer'] != self.plans[1]['binding']['payer']
        self.withdrawn = [0, 0]
        configs = self.fixture['configs']
        for index, (plan, interface) in enumerate(zip(self.plans, [ENTRY, EXIT], strict=True)):
            configs[index]['payments'] = {'application': {**self.fixture['application'], 'offer': plan['binding']['offer']},
                'ip_tunnel': {'name': interface}, 'max_claim_fees_ou': 100_000}
        minimum = g.epoch()
        g.stop(1); g.stop(0)
        self.stopped_b_hashes = self.continuity(1)
        for index in [0, 1]: (g.ROOT / f'chain/node-{index}/config.json').write_text(json.dumps(configs[index]))
        p.ip('address', 'add', A_IP + '/32', 'dev', 'lo')
        p.ip('route', 'replace', B_IP + '/32', 'via', '172.31.237.4', 'dev', 'eth0')
        g.command(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', 'eth0', '-d', A_IP + '/32', '-p', 'udp',
                   '--dport', '19874', '-j', 'DNAT', '--to-destination', '127.0.0.1:19874'])
        g.command(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '198.18.0.0/15', '-d', B_IP + '/32',
                   '-p', 'udp', '--dport', '19884', '-o', 'eth0', '-j', 'SNAT', '--to-source', '172.31.237.2'])
        g.command(['iptables', '-A', 'FORWARD', '-i', ENTRY, '-d', B_IP + '/32', '-p', 'udp', '--dport', '19884', '-j', 'ACCEPT'])
        g.command(['iptables', '-A', 'FORWARD', '-i', ENTRY, '-j', 'DROP'])
        self.control = ControlProxy()
        self.link, self.link_stream, mapping = links('A')
        g.start(0); ready(0, ENTRY, minimum)
        commands = pathlib.Path('/commands')
        shutil.copyfile(self.faucet, commands / 'receipt-A.hex'); shutil.copyfile(self.payer_b_key, commands / 'receipt-B.hex')
        for name in ['receipt-A.hex', 'receipt-B.hex']: (commands / name).chmod(0o600)
        atomic(g.EVIDENCE / 'multi-ready.json', {'program': self.program, 'plans': self.plans, 'minimum_epoch': minimum,
            'stopped_B_continuity': self.stopped_b_hashes, 'opaque_links_A': mapping,
            'management_exceptions': {'application_controls': ['127.0.0.1:19879', '127.0.0.1:19889'],
                'fixture_underlay': [A_IP + ':20879', A_IP + ':20889'], 'entry_udp': A_IP + ':19874',
                'scope': 'explicit IP-level physical exceptions, not per-socket firewall isolation'}})

    def continuity(self, index):
        root = g.ROOT / f'chain/node-{index}'
        result = {}
        for item in sorted(root.rglob('*')):
            if item.is_file() and item.name != 'config.json':
                result[str(item.relative_to(root))] = hashlib.sha256(item.read_bytes()).hexdigest()
        assert result and any(name.startswith('exex/') for name in result)
        return result

    def offer(self, tariff, operator_key, payer_key, operator, caps, control, endpoint, port):
        data = p.canonical(tariff); digest = hashlib.sha256(data).hexdigest(); source = g.ROOT / (digest + '.json'); source.write_bytes(data)
        g.record('publish separate immutable hop tariff', g.cli('cast', 'circle', 'put', '--circle', self.circle,
                 '--path', f'/offers/{digest}/tariff.json', '--file', source, '--content-type', 'application/json',
                 '--key', self.fixture['operator_key'], '--rpc-url', g.RPC, '--ou', g.FEE), vm=False)
        created = g.send('create independently priced hop offer', operator_key, self.program, 'create_offer', [digest])
        offer = int(next(row['values'][0] for row in created['events'] if row['event'] == 'OfferCreated'))
        for row in tariff['classes']: g.send('append hop tariff', operator_key, self.program, 'append_class', [offer, row['rate_ou_per_mib']])
        g.send('seal immutable hop tariff', operator_key, self.program, 'seal_offer', [offer])
        opened = g.send('open independent prepaid hop plan', payer_key, self.program, 'open_plan', [offer, p.BUDGET])
        plan = int(next(row['values'][0] for row in opened['events'] if row['event'] == 'PlanOpened'))
        payer = g.command(['octra', 'cast', 'wallet', 'addr', '--key', payer_key])
        generation = int(g.view(self.program, 'get_generation', [payer]))
        return {'binding': {'deployment': {'domain': self.fixture['application']['domain'], 'program': self.program},
                    'payer': payer, 'generation': generation, 'plan': plan, 'offer': offer, 'manifest_hash': digest},
                'tariff': tariff, 'original_budget_ou': p.BUDGET, 'prepaid_bytes': caps,
                'control_url': f'http://127.0.0.1:{control}', 'wireguard_endpoint': f'{endpoint}:{port}'}

    def state(self):
        records = []
        for index, plan in enumerate(self.plans):
            paths = (g.ROOT / f'chain/node-{index}/octranet-payments/transport').glob('*/meter.json')
            found = [json.loads(path.read_text())['record'] for path in paths]
            found = [row for row in found if row['binding'] == plan['binding']]
            assert len(found) <= 1
            record = found[0] if found else None
            if record is not None:
                assert record['tariff_hash'] == hashlib.sha256(p.canonical(plan['tariff'])).hexdigest()
                assert all(a <= b for a, b in zip(p.exposure(record), record['purchased'], strict=True))
            records.append({'meter': record,
                'purchased': [int(g.view(self.program, 'get_prepaid_bytes', [plan['binding']['plan'], i])) for i in range(len(plan['tariff']['classes']))],
                'earnings': int(g.view(self.program, 'get_earnings', [plan['tariff']['operator']]))})
        return {'hops': records, 'epoch': g.epoch(), 'target': p.target(),
                'entry_nat': g.command(['iptables', '-t', 'nat', '-L', '-v', '-n', '-x']),
                'entry_forward': g.command(['iptables', '-L', 'FORWARD', '-v', '-n', '-x'])}

    def command(self, request):
        action = request['action']
        if action == 'state': return self.state()
        if action == 'release': self.control.release(); return {'released': True}
        if action == 'hold': self.control.hold(); return {'held': True}
        if action == 'hold_status':
            self.control.hold_status(); g.until(lambda: self.control.metrics()['status_waiting'] >= 1, 20, 'entry status held'); return {'held': True}
        if action == 'release_status': self.control.release_status(); return {'released': True}
        if action == 'restart':
            before = g.epoch(); p.crash_operator(); g.start(0); ready(0, ENTRY, before); return self.state()
        if action == 'revoke':
            index = request['hop']; plan = self.plans[index]
            key = self.faucet if index == 0 else self.payer_b_key
            g.send('instant selected-hop payer withdrawal', key, self.program, 'withdraw_channel', [1]); self.withdrawn[index] += 1
            assert g.view(self.program, 'can_forward', [plan['binding']['plan']]) is False
            return self.state()
        if action == 'reset':
            for index, key in enumerate([self.faucet, self.payer_b_key]):
                plan = self.plans[index]
                g.send('explicitly reset hop generation before new consent', key, self.program, 'withdraw_channel', [1]); self.withdrawn[index] += 1
                opened = g.send('explicit new plan, never automatic topup', key, self.program, 'open_plan', [plan['binding']['offer'], p.BUDGET])
                plan['binding']['plan'] = int(next(row['values'][0] for row in opened['events'] if row['event'] == 'PlanOpened'))
                plan['binding']['generation'] = int(g.view(self.program, 'get_generation', [plan['binding']['payer']]))
            return {'plans': self.plans}
        if action == 'claims':
            charges = [0, 0]; count = 0
            operators = [self.operator_a, self.operator_b]
            for path in sorted((g.ROOT / 'chain/node-0/exex').glob('*.json')):
                event = json.loads(path.read_text())
                for tx in event.get('events', []):
                    envelope = json.loads(base64.b64decode(tx['transaction'], validate=True))
                    if envelope.get('to_') != self.program or envelope.get('encrypted_data') != 'claim': continue
                    receipt = json.loads(base64.b64decode(tx['receipt'], validate=True))
                    assert receipt['success'] is True and receipt['contract'] == self.program and receipt['error'] is None
                    assert tx['proof'] == 'exact' and hashlib.sha256(base64.b64decode(tx['identity'], validate=True)).hexdigest() == tx['hash']
                    index = operators.index(envelope['from']); count += 1
                    for row in receipt['events']:
                        if row['event'] == 'UsageCharged': charges[index] += int(row['values'][4])
                    for peer in range(1, 4):
                        saved = g.ROOT / f'chain/node-{peer}/exex' / path.name
                        g.until(saved.exists, 60, 'all4 actual hop claim ExEx'); assert json.loads(saved.read_text()) == event
            assert count > 0
            for index, operator in enumerate(operators):
                assert charges[index] == int(g.view(self.program, 'get_earnings', [operator])) > 0
            for index, plan in enumerate(self.plans):
                assert int(g.view(self.program, 'get_funds', [plan['binding']['payer']])) + charges[index] + self.withdrawn[index] == p.FUND
            assert int(g.view(self.program, 'get_locked_value')) == 2 * p.STAKE + 2 * p.FUND - sum(self.withdrawn)
            return {'claims': count, 'per_operator_earnings': charges, 'payer_withdrawals': self.withdrawn}
        if action == 'stop': g.JOURNAL['qualified'] = True; g.save(); return {'stopped': True}
        raise ValueError('unknown fixed multi fixture action')

    def close(self):
        self.control.close(); self.link.terminate(); self.link.wait(timeout=15); self.link_stream.close()


class B:
    def __init__(self):
        value = json.loads((g.EVIDENCE / 'multi-ready.json').read_text())
        # Recheck the exact stopped physical state before the relocated writer
        # starts. Canonical/reward/signing history is not recreated or reset.
        actual = A.continuity(self, 1)
        assert actual == value['stopped_B_continuity']
        self.link, self.link_stream, mapping = links('B')
        p.ip('address', 'add', B_IP + '/32', 'dev', 'lo')
        g.command(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', 'eth0', '-d', B_IP + '/32', '-p', 'udp',
                   '--dport', '19884', '-j', 'DNAT', '--to-destination', '127.0.0.1:19884'])
        self.control = ControlProxy(port=19889, upstream_port=19883)
        g.start(1); ready(1, EXIT, value['minimum_epoch'])
        self.hop = Hop(pathlib.Path('/hop'), role='node', name=p.LINK)
        p.ip('route', 'replace', g.PUBLIC + '/32', 'via', '192.0.2.2', 'dev', p.LINK)
        g.command(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '198.18.0.0/15', '-d', g.PUBLIC + '/32',
                   '-o', p.LINK, '-j', 'SNAT', '--to-source', p.SNAT])
        p.ip('rule', 'add', 'priority', '5', 'iif', p.LINK, 'to', '198.18.0.0/15', 'lookup', '402')
        atomic(g.EVIDENCE / 'multi-B-ready.json', {'retained_state_verified': True, 'opaque_links_B': mapping})

    def command(self, request):
        action = request['action']
        if action == 'release': self.control.release(); return {'released': True}
        if action == 'hold_status':
            self.control.hold_status(); g.until(lambda: self.control.metrics()['status_waiting'] >= 1, 20, 'exit status held'); return {'held': True}
        if action == 'release_status': self.control.release_status(); return {'released': True}
        if action == 'restart':
            before = g.epoch(1); process = g.PROCESSES.pop(1); process.kill(); process.wait(timeout=15); g.FILES.pop(1).close()
            g.start(1); ready(1, EXIT, before); return {'epoch': g.epoch(1), 'hop': self.hop.metrics()}
        if action == 'state': return {'hop': self.hop.metrics(), 'nat': g.command(['iptables', '-t', 'nat', '-L', '-v', '-n', '-x'])}
        if action == 'stop': return {'stopped': True}
        raise ValueError('unknown fixed B fixture action')

    def close(self):
        self.control.close(); self.hop.close(); self.link.terminate(); self.link.wait(timeout=15); self.link_stream.close()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--role', choices=['A', 'B'], required=True)
    parser.add_argument('--exhaust-hop', type=int, choices=[0, 1], default=1); args = parser.parse_args()
    g.ROOT = pathlib.Path('/state/native-vpn')
    fixture = None
    try:
        fixture = A(args.exhaust_hop) if args.role == 'A' else B()
        directory = pathlib.Path('/commands') / args.role; index = 1
        while True:
            path = directory / f'{index}.json'; g.until(path.exists, 300, 'multi fixture command')
            request = json.loads(path.read_text())
            try: atomic(directory / f'{index}.result.json', {'ok': fixture.command(request)})
            except BaseException: atomic(directory / f'{index}.result.json', {'error': traceback.format_exc()}); raise
            index += 1
            if request['action'] == 'stop': break
    finally:
        if fixture: fixture.close()
        for index in list(g.PROCESSES): g.stop(index)


if __name__ == '__main__': main()
