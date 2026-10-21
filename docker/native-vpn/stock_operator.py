#!/usr/bin/env python3
"""Actual four-validator canonical paid stock-exit fixture; no fabricated grants."""
import argparse
import base64
import hashlib
import json
import pathlib
import signal
import time
import traceback

import payments_qualify as p
import qualify as g
from packet_target import Hop
from payment_control import ControlProxy

PORTAL_HOST = 'portal.mesh.test'
OPERATOR_IP = '100.64.0.1'


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def internal_guard():
    assert pathlib.Path('/.dockerenv').exists()
    links = json.loads(p.ip('-j', 'link', 'show'))
    assert {row['ifname'] for row in links} <= {'lo', 'eth0'}, 'unexpected fixture interface'
    assert not json.loads(p.ip('-j', 'route', 'show', 'default')), 'external default route forbidden'
    p.ip('link', 'set', 'lo', 'up')


class Fixture:
    def __init__(self, application):
        self.application = application
        self.context = p.prepare(internal_guard)
        self.program = self.context['program']
        if application == 'circle':
            self.circle_application()
        self.plan = self.context['plan_path']
        self.withdrawn = 0
        self.operator = self.context['operator']
        self.faucet = self.context['faucet']
        circle = self.context['circle']
        self.assets = {'/index.html': b'<!doctype html><html><head><link rel="stylesheet" href="portal.css"></head><body>Octranet canonical onboarding portal</body></html>',
                       '/portal.css': b'body{color:#123456}',
                       '/not-free.txt': b'this canonical asset is outside the unpaid capability'}
        for path, data in self.assets.items():
            source = g.ROOT / path[1:]
            source.write_bytes(data)
            g.record('publish stock portal asset ' + path, g.cli('cast', 'circle', 'put', '--circle', circle,
                     '--path', path, '--file', source, '--content-type', 'text/html' if path.endswith('html') else
                     'text/css' if path.endswith('css') else 'text/plain', '--key', self.context['operator_key'],
                     '--rpc-url', g.RPC, '--ou', g.FEE), vm=False)
        config = self.context['configs'][0]
        config['payments'] = {'application': self.context['application'], 'ip_tunnel': {'name': p.SERVER},
                              'max_claim_fees_ou': 100_000}
        config['mesh'] = json.loads(pathlib.Path('/config/mesh.json').read_text())
        config['stock_portal'] = {'listen': '198.18.0.1:443', 'origin': 'https://' + PORTAL_HOST,
            'portal': {'circle': circle, 'paths': ['/index.html', '/portal.css']},
            'tls': {'certificate': '/config/portal.crt', 'private_key': '/config/portal.key'}}
        config['stock_circle_gateway'] = {'origin': 'https://circles.mesh.test', 'sites': {},
            'tls': {'certificate': '/config/circles.crt', 'private_key': '/config/circles.key'}}
        before = g.epoch()
        g.stop(0)
        (g.ROOT / 'chain/node-0/config.json').write_text(json.dumps(config))
        g.start(0)
        p.route_server(before)
        g.command(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', 'eth0', '-d', '172.30.238.2/32',
                   '-p', 'udp', '--dport', '19874', '-j', 'DNAT', '--to-destination', '127.0.0.1:19874'])
        self.hop = Hop(pathlib.Path('/hop'), role='node', name=p.LINK)
        p.ip('route', 'replace', g.PUBLIC + '/32', 'via', '192.0.2.2', 'dev', p.LINK)
        g.command(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '198.18.0.0/15',
                   '-d', g.PUBLIC + '/32', '-o', p.LINK, '-j', 'SNAT', '--to-source', p.SNAT])
        p.ip('rule', 'add', 'priority', '5', 'iif', p.LINK, 'to', '198.18.0.0/15', 'lookup', '402')
        self.control = ControlProxy()
        self.peer = None
        self.controller = None
        self.baseline = None
        g.JOURNAL['scope'] = ('isolated actual stock Tailscale, Circle portal TLS/MagicDNS and four-validator '
                              + application + ' prepaid exit; no public deployment or mainnet claim')
        g.JOURNAL['application'] = application
        g.JOURNAL['limitations'] = ['No Web delivery proof or non-delivery slashing',
            'No public-network qualification', '24h rate notice and7day unstake are separate canonical-clock tests',
            'Explicit controller resume and stock daemon retained registration, not seamless crash recovery',
            'IPv4 exit only; IPv6 is captured and refused']
        self.initial_earnings = int(self.view('get_earnings', [self.operator]))
        atomic(g.EVIDENCE / 'stock-ready.json', {'program': self.program, 'application': application,
            'operator_ip': OPERATOR_IP, 'portal_host': PORTAL_HOST, 'paid_circle_host': 'circles.mesh.test', 'circle': circle,
            'portal_assets': {name: hashlib.sha256(data).hexdigest() for name, data in self.assets.items()},
            'source_sha256': json.loads((g.EVIDENCE / 'source.json').read_text())['source_sha256']})

    def send(self, label, key, method, params, value=0, expected=True, target=None):
        address = target or self.program
        if self.application == 'program':
            return g.send(label, key, address, method, params, value, expected)
        return g.record(label, g.cli('cast', 'circle', 'send', address, method,
            *[json.dumps(x, separators=(',', ':')) for x in params], '--key', key,
            '--rpc-url', g.RPC, '--ou', g.FEE, '--value', value), expected)

    def view(self, method, params=None):
        if self.application == 'program':
            return g.view(self.program, method, params)
        result = g.readonly_view('circle_view', self.program, method, params)
        assert isinstance(result, dict) and 'result' in result
        return result['result']

    def circle_application(self, custody_cap=200_000_000):
        old = json.loads(self.context['plan_path'].read_text())
        chain = g.JOURNAL['genesis']['chain']
        chain_id = chain['chain_id'].encode()
        domain = hashlib.sha256(b'Octranet Circle payments network v1\0' + len(chain_id).to_bytes(8, 'big')
                                + chain_id + bytes(chain['genesis_root'])).hexdigest()
        build = json.loads(g.command(['octra-node', 'compile-circle-payments', '--domain', domain,
                                      '--custody-cap', custody_cap, '--minimum-stake', p.STAKE]))
        assert build['application'] == 'circle' and build['initialization'] == 'separate-finalized-circle-call'
        assert build['terms'] == {'domain': domain, 'custody_cap': custody_cap, 'minimum_stake': p.STAKE}
        atomic(g.EVIDENCE / 'circle-payments-build.json', build)
        code = base64.b64decode(build['bytecode'], validate=True)
        factory_code = base64.b64decode(build['factory_bytecode'], validate=True)
        assert code.startswith(b'OCTB') and factory_code.startswith(b'OCTB')
        assert build['certificate']['source_hash'] == hashlib.sha256(build['source'].encode()).hexdigest()
        assert build['certificate']['bytecode_hash'] == hashlib.sha256(code).hexdigest()
        payload = json.loads((g.ROOT / 'circle.json').read_text())
        payload['code_b64'] = build['factory_bytecode']
        path = g.ROOT / 'circle-payment-factory.json'
        path.write_text(json.dumps(payload))
        created = g.cli('cast', 'circle', 'deploy', '--payload', path, '--key', self.context['faucet'],
                        '--rpc-url', g.RPC, '--ou', g.FEE)
        g.record('deploy native Circle payment factory', created, vm=False)
        factory = created['circle_id']
        payload['code_b64'] = build['bytecode']
        spawned = self.send('spawn code-pinned Circle payment app', self.context['faucet'], 'deploy_payments',
                            [base64.b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode()], target=factory)
        self.program = next(event['values'][0] for event in spawned['events'] if event['event'] == 'PaymentsCircleDeployed')
        self.send('initialize real spawned Circle payment app', self.context['faucet'], 'initialize', [])
        self.send('bond Circle operator stake', self.context['operator_key'], 'bond_operator', [], p.STAKE)
        operator = self.context['operator']
        operator_generation = int(self.view('get_operator_generation', [operator]))
        assert operator_generation > 0
        operator_public = g.command(['octra', 'cast', 'wallet', 'pubkey',
                                     '--key', self.context['operator_key']])
        operator_message = f'Octranet operator key v1|{domain}|{self.program}|{operator}|{operator_generation}'
        operator_signature = g.command(['octra', 'cast', 'wallet', 'sign',
                                        '--key', self.context['operator_key'], operator_message])
        self.send('pin Circle operator service receipt key', self.context['operator_key'],
                  'register_operator_receipt_key', [operator_public, operator_signature])
        payer = old['binding']['payer']
        message = f'Octranet register v1|{domain}|{self.program}|{payer}|1'
        signature = g.command(['octra', 'cast', 'wallet', 'sign', '--key', self.context['faucet'], message])
        self.send('register Circle receipt key', self.context['faucet'], 'register',
                  [g.JOURNAL['genesis']['funded_public'], signature])
        self.send('fund actual Circle payer', self.context['faucet'], 'fund', [payer], p.FUND)
        self.send('create actual Circle operator offer', self.context['operator_key'], 'create_offer', [old['binding']['manifest_hash']])
        for row in self.context['tariff']['classes']:
            self.send('append Circle tariff', self.context['operator_key'], 'append_class', [0, row['rate_ou_per_mib']])
        self.send('seal Circle tariff', self.context['operator_key'], 'seal_offer', [0])
        self.send('open actual funded Circle plan', self.context['faucet'], 'open_plan', [0, p.BUDGET])
        old['binding']['deployment'] = {'domain': domain, 'program': self.program}
        old['operator_generation'] = operator_generation
        self.context['plan_path'].write_text(json.dumps(old))
        atomic(g.EVIDENCE / 'accepted-plan.json', old)
        self.context['application'] = {**self.context['application'], 'application': 'circle',
            'domain': domain, 'program': self.program, 'factory': factory,
            'code_hash': hashlib.sha256(code).hexdigest(), 'factory_code_hash': hashlib.sha256(factory_code).hexdigest()}

    def launch(self, resume):
        import subprocess
        assert self.peer is not None and self.controller is None
        number = len(list(g.EVIDENCE.glob('stock-controller-*.log'))) + 1
        log = g.EVIDENCE / f'stock-controller-{number}.log'
        stream = log.open('x')
        args = ['octravpn', 'stock-payments', '--plan', str(self.plan), '--journal', str(g.ROOT / 'client-journal'),
                '--receipt-key', str(self.faucet), '--node-key', self.peer['node_key']]
        if resume:
            args.append('--resume')
        before = {row['ifname'] for row in json.loads(p.ip('-j', 'link', 'show'))}
        self.controller = subprocess.Popen(args, cwd=g.ROOT, stdout=stream, stderr=subprocess.STDOUT)
        self.controller_stream = stream
        self.controller_log = log
        self.before_interfaces = before

    def ready(self):
        assert self.controller.poll() is None, self.controller_log.read_text()[-2000:]
        if 'Prepaid stock Tailscale allowances are canonical' not in self.controller_log.read_text():
            return False
        assert {row['ifname'] for row in json.loads(p.ip('-j', 'link', 'show'))} == self.before_interfaces
        return True

    def state(self):
        meters = list((g.ROOT / 'chain/node-0/octranet-payments/transport').glob('*/meter.json'))
        binding = json.loads(self.plan.read_text())['binding']
        records = [json.loads(path.read_text())['record'] for path in meters]
        matches = [row for row in records if row['binding'] == binding]
        assert len(matches) <= 1
        record = matches[0] if matches else None
        if record is not None:
            assert record['binding'] == json.loads(self.plan.read_text())['binding']
            assert record['budget_ou'] == p.BUDGET and 'credit' not in record
            assert 'Stock' in record['transport'] or 'stock' in record['transport'], record['transport']
            assert all(used <= bought for used, bought in zip(p.exposure(record), record['purchased'], strict=True))
        return {'meter': record, 'journal': p.journal() if (g.ROOT / 'client-journal/state.json').exists() else None,
                'earnings': int(self.view('get_earnings', [self.operator])),
                'purchased': [int(self.view('get_prepaid_bytes', [json.loads(self.plan.read_text())['binding']['plan'], i])) for i in range(3)],
                'hop': self.hop.metrics(), 'target': p.target(), 'epoch': g.epoch(),
                'fixture_nat': g.command(['iptables', '-t', 'nat', '-L', '-v', '-n', '-x'])}

    def claims(self):
        rows = []
        for path in sorted((g.ROOT / 'chain/node-0/exex').glob('*.json')):
            event = json.loads(path.read_text())
            for tx in event.get('events', []):
                envelope = json.loads(base64.b64decode(tx['transaction'], validate=True))
                if envelope.get('to_') != self.program or envelope.get('encrypted_data') != 'claim':
                    continue
                receipt = json.loads(base64.b64decode(tx['receipt'], validate=True))
                assert receipt['success'] is True and receipt['error'] is None and receipt['contract'] == self.program
                assert receipt['method'] == 'claim' and envelope['from'] == self.operator
                assert envelope['op_type'] == ('circle_call' if self.application == 'circle' else 'call')
                assert hashlib.sha256(base64.b64decode(tx['identity'], validate=True)).hexdigest() == tx['hash']
                assert tx['proof'] == 'exact'
                charges = [row for row in receipt['events'] if row['event'] == 'UsageCharged']
                assert charges and all(row['contract'] == self.program for row in charges)
                for index in range(1, 4):
                    peer = g.ROOT / f'chain/node-{index}/exex' / path.name
                    g.until(peer.exists, 60, 'matching real claim ExEx')
                    assert json.loads(peer.read_text()) == event
                rows.extend(charges)
        return rows

    def command(self, command):
        action = command['action']
        if action == 'preauth':
            import http.client
            connection = http.client.HTTPConnection('127.0.0.1', 51821, timeout=10)
            connection.request('POST', '/admin/preauth', json.dumps({'user': 'stock-tester', 'ttl_secs': 900}),
                {'Authorization': 'Bearer ' + pathlib.Path('/config/admin.token').read_text().strip(), 'Content-Type': 'application/json'})
            response = connection.getresponse(); body = response.read(16385); connection.close()
            assert response.status == 200 and len(body) <= 16384
            return json.loads(body)
        if action == 'blocked_purchase':
            self.peer = {'node_key': command['node_key'], 'ipv4': command['ipv4']}
            self.launch(False)
            g.until(lambda: self.control.metrics()['usage_received'] > 0, 20, 'held real signed purchase')
            state = self.state()
            assert state['purchased'] == [0, 0, 0] and state['earnings'] == self.initial_earnings
            assert state['meter'] is not None and p.exposure(state['meter']) == [0, 0, 0]
            self.baseline = state
            return state
        if action == 'release_purchase':
            self.control.release(); g.until(self.ready, 120, 'canonical stock prepaid purchases')
            state = self.state(); assert state['purchased'] == p.PREPAID_BYTES
            assert state['journal']['authorized_bytes'] == p.PREPAID_BYTES
            assert state['journal']['local_bytes'] == [0, 0, 0], 'control-only client invented delivery'
            return state
        if action == 'state':
            return self.state()
        if action == 'restart':
            assert self.ready()
            before = self.state()
            self.controller.kill(); self.controller.wait(timeout=15); self.controller_stream.close(); self.controller = None
            epoch = p.crash_operator()
            g.start(0); p.route_server(epoch)
            self.launch(True); g.until(self.ready, 120, 'same stock plan controller resume')
            after = self.state()
            assert after['purchased'] == before['purchased'] == p.PREPAID_BYTES
            assert after['journal']['authorized_bytes'] == before['journal']['authorized_bytes']
            assert after['journal']['connection_sequence'] > before['journal']['connection_sequence']
            assert all(a >= b for a, b in zip(p.exposure(after['meter']), p.exposure(before['meter']), strict=True))
            return after
        if action == 'pause_rotation':
            self.control.hold_status()
            g.until(lambda: self.control.metrics()['status_waiting'] >= 1, 20, 'stock controller status held for registration rotation')
            assert self.view('can_forward', [json.loads(self.plan.read_text())['binding']['plan']]) is True
            return self.state()
        if action == 'rotated_plan':
            assert self.controller.poll() is None, 'local controller stop hid registration revocation'
            old_binding = json.loads(self.plan.read_text())['binding']
            assert self.view('can_forward', [old_binding['plan']]) is True, 'chain revocation masked registration rotation'
            self.control.release_status(); self.controller.wait(timeout=30); self.controller_stream.close()
            assert self.controller.returncode != 0, 'rotated registration reused old paid transport'
            self.controller = None
            payer = self.view('get_plan_payer', [old_binding['plan']])
            self.send('reset reservations after independent registration rotation', self.faucet, 'withdraw_channel', [1])
            self.withdrawn += 1
            opened = self.send('new canonical plan for rotated stock registration', self.faucet, 'open_plan', [0, p.BUDGET])
            plan_id = int(next(row['values'][0] for row in opened['events'] if row['event'] == 'PlanOpened'))
            accepted = json.loads(self.plan.read_text())
            accepted['binding']['plan'] = plan_id
            accepted['binding']['generation'] = int(self.view('get_generation', [payer]))
            self.plan.write_text(json.dumps(accepted))
            (g.ROOT / 'client-journal').rename(g.ROOT / 'client-journal-before-registration-rotation')
            self.peer = {'node_key': command['node_key'], 'ipv4': command['ipv4']}
            self.launch(False); g.until(self.ready, 120, 'canonical new registration prepaid plan')
            return self.state()
        if action == 'withdraw':
            self.control.hold_status()
            g.until(lambda: self.control.metrics()['status_waiting'] >= 1, 20, 'stock controller status held')
            payer = self.view('get_plan_payer', [json.loads(self.plan.read_text())['binding']['plan']]); generation = int(self.view('get_generation', [payer]))
            self.send('instant partial stock channel withdrawal', self.faucet, 'withdraw_channel', [1])
            assert int(self.view('get_generation', [payer])) == generation + 1
            self.withdrawn += 1
            assert self.view('can_forward', [json.loads(self.plan.read_text())['binding']['plan']]) is False
            return self.state()
        if action == 'finish':
            state = self.state()
            assert state['purchased'] == p.PREPAID_BYTES and state['earnings'] > 0
            assert self.controller.poll() is None, 'client termination hid server revocation'
            self.control.release_status(); self.controller.wait(timeout=30); self.controller_stream.close()
            assert self.controller.returncode != 0, 'revoked stock controller accepted old plan'
            self.controller = None
            claims = self.claims()
            paid = [0, 0, 0]
            for row in claims:
                values = list(map(int, row['values'])); assert values[0] in (0, 1); paid[values[1]] += values[4]
            assert sum(paid) == state['earnings'] and paid[0] > 0 and paid[1] > 0 and paid[2] == 0
            payer = self.view('get_plan_payer', [json.loads(self.plan.read_text())['binding']['plan']]); remaining = int(self.view('get_channel_balance', [payer]))
            self.send('instant remaining stock channel withdrawal', self.faucet, 'withdraw_remaining', [])
            assert int(self.view('get_channel_balance', [payer])) == 0
            assert state['earnings'] + self.withdrawn + remaining == p.FUND
            assert int(self.view('get_locked_value')) == p.STAKE + state['earnings']
            self.launch(True)
            self.controller.wait(timeout=30); self.controller_stream.close()
            assert self.controller.returncode != 0, 'stock revoked-generation replay succeeded'
            self.controller = None
            g.step('stock canonical claims match four ExEx archives and final channel accounting', paid=paid)
            return {'paid': paid, 'state': state, 'claims': len(claims)}
        if action == 'stop':
            g.JOURNAL['qualified'] = True; g.save(); return {'stopped': True}
        raise ValueError('unknown fixed fixture command')

    def close(self):
        if self.controller is not None:
            self.controller.terminate(); self.controller.wait(timeout=15); self.controller_stream.close()
        self.control.close(); self.hop.close()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--application', choices=['program', 'circle'], required=True)
    args = parser.parse_args(); fixture = None
    try:
        fixture = Fixture(args.application)
        commands = pathlib.Path('/commands'); assert commands.is_dir()
        index = 1
        while True:
            path = commands / f'{index}.json'
            g.until(path.exists, 300, 'stock harness command')
            request = json.loads(path.read_text())
            try:
                result = fixture.command(request)
                atomic(commands / f'{index}.result.json', {'ok': result})
            except BaseException:
                atomic(commands / f'{index}.result.json', {'error': traceback.format_exc()}); raise
            index += 1
            if request['action'] == 'stop':
                break
    finally:
        if fixture is not None: fixture.close()
        for index in list(g.PROCESSES): g.stop(index)


if __name__ == '__main__':
    try: main()
    except BaseException:
        if g.EVIDENCE.exists():
            g.JOURNAL['failure'] = traceback.format_exc(); g.save()
        traceback.print_exc(); raise SystemExit(1)
