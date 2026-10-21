#!/usr/bin/env python3
"""Shielded extension of the real four-validator, separate-kernel fixture."""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import signal
import stat
import subprocess
import traceback

import multi_fixture as multi
import payments_qualify as p
import qualify as g
from stock_operator import atomic

MATERIAL = pathlib.Path('/material/private-material')


def install(index, application, pool):
    path = g.ROOT / f'chain/node-{index}/config.json'
    config = json.loads(path.read_text())
    for name in ['payments', 'vpn', 'stock_portal', 'stock_circle_gateway', 'mesh', 'payer', 'private_route']:
        config[name] = None
    master = path.parent / 'private-master.key'
    if not master.exists():
        master.write_bytes(os.urandom(32)); master.chmod(0o600)
    config['shielded'] = {
        'application': application, 'pool': pool,
        'wallet': str(path.parent / 'private-wallet'), 'master_key': str(master),
        'purchases': {'max_channels': 16, 'max_requests': 1024,
                      'max_ceiling_ou': 100_000_000, 'max_invoice_lifetime_ms': 120_000},
        'ip_tunnel': {'name': multi.ENTRY if index == 0 else multi.EXIT},
    }
    g.stop(index)
    path.write_text(json.dumps(config))
    g.command(['octra-node', 'init-private-wallet', '--config', path])
    g.start(index)
    multi.ready(index, config['shielded']['ip_tunnel']['name'], 1)
    return config


def extra_links(role, mapping):
    path = g.ROOT / ('private-links-' + role + '.json'); path.write_text(json.dumps(mapping))
    log = g.EVIDENCE / ('private-links-' + role + '.log'); stream = log.open('x')
    child = subprocess.Popen(['python3', '-u', '/usr/local/bin/multi_link.py', str(path)],
                             stdout=stream, stderr=subprocess.STDOUT)
    g.until(lambda: '"ready": true' in log.read_text(), 20, 'private native peer links')
    return child, stream


class A(multi.A):
    def __init__(self, exhaust):
        super().__init__(exhaust, 'circle', True)
        origin = self.fixture['application']['domain']
        atomic(g.EVIDENCE / 'private-material-request.json', {'origin': origin, 'custody_cap_ou': 1_000_000})
        g.until(lambda: (MATERIAL / 'manifest.json').is_file(), 600, 'isolated public proving material')
        material = json.loads((MATERIAL / 'manifest.json').read_text())
        assert material['fixture_only'] is True and material['production_setup_qualified'] is False
        assert material['origin'] == origin
        for name, expected in material['files'].items():
            assert pathlib.PurePath(name).name == name
            assert hashlib.sha256((MATERIAL / name).read_bytes()).hexdigest() == expected
        created = g.cli('cast', 'circle', 'deploy', '--payload', MATERIAL / 'factory-payload.json',
                        '--key', self.faucet, '--rpc-url', g.RPC, '--ou', g.FEE)
        g.record('deploy isolated native shielded pool factory', created, vm=False)
        factory = created['circle_id']
        payload = base64.b64encode((MATERIAL / 'pool-payload.json').read_bytes()).decode()
        spawned = self.send('spawn isolated native shielded pool', self.faucet, 'deploy_pool', [payload], target=factory)
        circle = next(event['values'][0] for event in spawned['events'] if event['event'] == 'ShieldedPoolDeployed')
        self.send('initialize isolated native shielded pool', self.faucet, 'initialize', [], target=circle)
        self.pool = {'circle': circle, 'factory': factory, 'custody_cap_ou': material['custody_cap_ou'],
                     'verification_key_b64': material['verification_key_b64'],
                     'verification_key_sha256': material['verification_key_sha256']}
        self.private_tariffs = [self.a_tariff, {**self.b_tariff,
            'classes': self.b_tariff['classes'][:2],
            'selectors': [rule for rule in self.b_tariff['selectors'] if rule['traffic_class'] < 2]}]
        self.private_caps = [[33_554_432, 131_072 if exhaust == 0 else 1_048_576],
                             [131_072, 1_048_576 if exhaust == 0 else 65_536]]
        self.private_offers = []
        for index, (tariff, key) in enumerate(zip(self.private_tariffs, [self.fixture['operator_key'], self.operator_b_key], strict=True)):
            encoded = p.canonical(tariff); digest = hashlib.sha256(encoded).hexdigest()
            file = g.ROOT / f'private-tariff-{index}.json'; file.write_bytes(encoded)
            g.record('publish canonical private hop tariff', g.cli('cast', 'circle', 'put', '--circle', self.circle,
                     '--path', f'/offers/{digest}/tariff.json', '--file', file, '--content-type', 'application/json',
                     '--key', self.fixture['operator_key'], '--rpc-url', g.RPC, '--ou', g.FEE), vm=False)
            offered = self.send('create private hop offer', key, 'create_offer', [digest])
            offer = int(next(e['values'][0] for e in offered['events'] if e['event'] == 'OfferCreated'))
            for rate in tariff['classes']:
                self.send('append private hop class', key, 'append_class', [offer, rate['rate_ou_per_mib']])
            self.send('seal private hop offer', key, 'seal_offer', [offer])
            self.private_offers.append({'offer': offer, 'manifest_hash': digest,
                                        'operator_generation': int(self.view('get_offer_generation', [offer]))})
        self.private_configs = []
        app = {**self.fixture['application'], 'offer': self.private_offers[0]['offer']}
        self.private_configs.append(install(0, app, self.pool))
        # The selected native peer sockets are visible independently from TLS.
        self.extra, self.extra_stream = extra_links('A', [
            {'listen': [multi.A_IP, port + 1000], 'target': ['127.0.0.1', port], 'observe_peer': True}
            for port in [19870, 19890]])
        g.command(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '198.18.0.0/15',
                   '-d', multi.B_IP + '/32', '-p', 'tcp', '--dport', '20880', '-o', 'eth0',
                   '-j', 'SNAT', '--to-source', multi.INTERNAL['A']])
        g.command(['iptables', '-I', 'FORWARD', '1', '-i', multi.ENTRY, '-d', multi.B_IP + '/32',
                   '-p', 'tcp', '--dport', '20880', '-j', 'ACCEPT'])
        domain = hashlib.sha256(b'Octranet shielded pool v1|' + origin.encode() + b'|' + circle.encode()).hexdigest()
        self.private = {'pool': self.pool, 'pool_domain': domain, 'origin': origin,
                        'directory': self.program, 'application': self.fixture['application'],
                        'tariffs': self.private_tariffs, 'caps': self.private_caps, 'offers': self.private_offers,
                        'operators': [self.operator_a, self.operator_b],
                        'minimum_epoch': g.epoch(), 'shielded_payments': True,
                        'stopped_B_continuity': self.stopped_b_hashes}
        for index in [0, 1]:
            self.private.setdefault('operator_public', []).append(list(base64.b64decode(
                g.command(['octra', 'cast', 'wallet', 'pubkey', '--key', self.fixture['operator_key'] if index == 0 else self.operator_b_key]), validate=True)))
        atomic(g.EVIDENCE / 'shielded-ready.json', self.private)

    def command(self, request):
        if request['action'] == 'accounting': return observe('A')
        if request['action'] == 'client_checkpoint':
            g.until(lambda: g.epoch(3) >= self.private['minimum_epoch'], 240, 'client imports pool and tariff history')
            g.stop(3)
            return {'continuity': self.continuity(3), 'epoch': g.epoch(), 'key_source': 'retained node-3'}
        if request['action'] == 'hold_private':
            self.control.hold_status(); return {'held': True}
        if request['action'] == 'restart':
            before = g.epoch(); p.crash_operator(); g.start(0); multi.ready(0, multi.ENTRY, before)
            return self.command({'action': 'private_state'})
        if request['action'] == 'private_state':
            body, _ = g.get(g.RPC.removesuffix('/rpc') + '/operator/status')
            exchanges = []
            for path in sorted((g.ROOT / 'chain/node-0/exex').glob('*.json')):
                event = json.loads(path.read_text())
                for tx in event.get('events', []):
                    envelope = json.loads(base64.b64decode(tx['transaction'], validate=True))
                    if envelope.get('to_') != self.pool['circle']: continue
                    if envelope.get('encrypted_data') != 'exchange': continue
                    receipt = json.loads(base64.b64decode(tx['receipt'], validate=True))
                    assert receipt['success'] is True and receipt['error'] is None
                    assert envelope['op_type'] == 'circle_call' and tx['proof'] == 'exact'
                    assert hashlib.sha256(base64.b64decode(tx['identity'], validate=True)).hexdigest() == tx['hash']
                    transitions = [e for e in receipt['events'] if e['event'] == 'ShieldedTransition']
                    assert len(transitions) == 1
                    exchanges.append({'hash': tx['hash'], 'exex': path.name, 'transition': transitions[0]})
            assert len({row['hash'] for row in exchanges}) == len(exchanges)
            return {'node': json.loads(body), 'pool': self.pool, 'control': self.control.metrics(),
                    'exchanges': exchanges, 'target': fresh_target()}
        return super().command(request)

    def close(self):
        if hasattr(self, 'extra'):
            self.extra.terminate(); self.extra.wait(timeout=15); self.extra_stream.close()
        super().close()


class B(multi.B):
    def __init__(self):
        super().__init__()
        value = json.loads((g.EVIDENCE / 'shielded-ready.json').read_text())
        g.until(lambda: g.epoch(1) >= value['minimum_epoch'], 240, 'B imports native private pool deployment')
        app = {**value['application'], 'offer': value['offers'][1]['offer']}
        install(1, app, value['pool'])
        self.extra, self.extra_stream = extra_links('B', [
            {'listen': [multi.B_IP, 20880], 'target': ['127.0.0.1', 19880], 'observe_peer': True}])
        atomic(g.EVIDENCE / 'shielded-B-ready.json', {'native_pool_imported': True, 'private_wallet_initialized': True,
                                                     'epoch': g.epoch(1)})

    def command(self, request):
        if request['action'] == 'accounting': return observe('B')
        if request['action'] == 'hold_private':
            self.control.hold_status(); return {'held': True}
        if request['action'] == 'pause':
            process = g.PROCESSES.pop(1); process.kill(); process.wait(timeout=20); g.FILES.pop(1).close()
            return {'paused': True}
        if request['action'] == 'resume':
            g.start(1); multi.ready(1, multi.EXIT, 1); return {'resumed': True}
        return super().command(request)

    def close(self):
        if hasattr(self, 'extra'):
            self.extra.terminate(); self.extra.wait(timeout=15); self.extra_stream.close()
        super().close()


def observe(role):
    assert role in ['A', 'B', 'C']
    sample = json.loads((g.EVIDENCE / f'private-accounting-{role}.json').read_text())['sample']
    assert type(sample) is int and 1 <= sample <= 1024
    current = g.EVIDENCE / f'private-accounting-{role}-result.json'
    retained = g.EVIDENCE / f'private-accounting-{role}-{sample}-result.json'
    assert not current.exists() and not current.is_symlink()
    assert not retained.exists() and not retained.is_symlink()
    process = g.PROCESSES[{'A': 0, 'B': 1, 'C': 3}[role]]
    assert process.poll() is None, 'accounting requires its actual live writer'
    process.send_signal(signal.SIGSTOP)
    try:
        pid, status = os.waitpid(process.pid, os.WUNTRACED)
        assert pid == process.pid and os.WIFSTOPPED(status)
        # The collector intentionally has no writer lease. Pause this isolated
        # writer so its SQLite and atomically replaced meter observations are
        # stable; never change production immutable-artifact checks for it.
        g.command(['env', 'OCTRA_ACCOUNTING_ROLE=' + role, '/usr/local/bin/private-kernel-test',
            'vpn::payments::canonical_tests::shielded::runner_flow::multi_observe::observe_isolated_multihop_private_accounting',
            '--exact', '--ignored', '--nocapture'], timeout=30)
    finally:
        if process.poll() is None: process.send_signal(signal.SIGCONT)
    descriptor = os.open(current, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 262144
        result = json.loads(stream.read(262145))
    # The native observer intentionally publishes immutable records. Archive
    # each completed sample before the next invocation, preserving every result
    # without changing custody files or weakening the publisher's equality rule.
    os.link(current, retained)
    current.unlink()
    directory = os.open(g.EVIDENCE, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return result


def fresh_target():
    # The target atomically publishes counters every 500ms. Wait for a newer
    # file after the probe, including negative probes, rather than accepting a
    # stale sample as evidence of delivery or blocking.
    path = g.EVIDENCE / 'target.json'
    previous = path.stat().st_ino
    return g.until(lambda: p.target() if path.stat().st_ino != previous else None,
                   3, 'fresh independent target counters')


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--role', choices=['A', 'B'], required=True)
    parser.add_argument('--exhaust-hop', type=int, choices=[0, 1], default=1); args = parser.parse_args()
    g.ROOT = pathlib.Path('/state/native-vpn'); fixture = None
    try:
        fixture = A(args.exhaust_hop) if args.role == 'A' else B()
        directory = pathlib.Path('/commands') / args.role; number = 1
        while True:
            path = directory / f'{number}.json'; g.until(path.exists, 900, 'shielded fixture command')
            request = json.loads(path.read_text())
            try: atomic(path.with_suffix('.result.json'), {'ok': fixture.command(request)})
            except BaseException:
                atomic(path.with_suffix('.result.json'), {'error': traceback.format_exc()}); raise
            number += 1
            if request['action'] == 'stop': break
    finally:
        if fixture: fixture.close()
        for index in list(g.PROCESSES): g.stop(index)


if __name__ == '__main__': main()
