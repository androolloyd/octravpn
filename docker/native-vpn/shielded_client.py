#!/usr/bin/env python3
"""A retained Rust observer, native private payer and paid route in one kernel."""
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import time
import traceback

import multi_client
import multi_fixture as multi
import payments_qualify as p
import qualify as g
from stock_operator import atomic
from shielded_fixture import observe


def write(path, value):
    atomic(path, value); path.chmod(0o600)


class Client(multi_client.Client):
    def __init__(self):
        g.ROOT = pathlib.Path('/state/native-vpn'); g.ROOT.mkdir(mode=0o700)
        g.RPC = 'http://127.0.0.1:19901/rpc'
        self.private = json.loads((g.EVIDENCE / 'shielded-ready.json').read_text())
        self.endpoints = json.loads(pathlib.Path('/config/private-endpoints.json').read_text())
        source = pathlib.Path('/source/native-vpn/chain/node-3')
        snapshot = json.loads((g.EVIDENCE / 'shielded-client-checkpoint.json').read_text())
        actual = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in source.rglob('*') if p.is_file() and p.name != 'config.json'}
        assert actual == snapshot['continuity'], 'client canonical/signing state changed during relocation'
        target = g.ROOT / 'chain/node-3'; target.parent.mkdir()
        shutil.copytree(source, target)
        shutil.copyfile('/source/native-vpn/chain/faucet.key', target.parent / 'faucet.key')
        (target.parent / 'faucet.key').chmod(0o600)
        self.config_path = target / 'config.json'
        self.config = json.loads(self.config_path.read_text())
        self.config.update(voting=False, peers=[multi.A_IP + ':20870', multi.B_IP + ':20880', multi.A_IP + ':20890'])
        for name in ['payments', 'vpn', 'shielded', 'mesh', 'stock_portal', 'stock_circle_gateway', 'payer', 'private_route']:
            self.config[name] = None
        self.fees = {'fee_ou': g.FEE, 'lifetime_budget_ou': 32 * g.FEE, 'max_attempts': 32}
        self.master = g.ROOT / 'payer-master.key'; self.master.write_bytes(os.urandom(32)); self.master.chmod(0o600)
        self.signer = target.parent / 'faucet.key'
        public = self.config['genesis']['funded_public']
        self.relayer = list(base64.b64decode(public, validate=True))
        self.settings = [self.payer(index) for index in range(2)]
        self.process = None; self.stream = None; self.launches = 0
        self.expected_outage = False
        self.udp_calls = 0; self.udp_events = 0; self.udp_log_errors = []; self.last_udp_event = None
        p.ip('link', 'set', 'lo', 'up')
        p.ip('route', 'replace', 'default', 'via', multi.INTERNAL['A'], 'dev', 'eth0')
        p.ip('route', 'replace', multi.A_IP + '/32', 'via', multi.INTERNAL['A'], 'dev', 'eth0')
        p.ip('route', 'replace', multi.B_IP + '/32', 'via', multi.INTERNAL['B'], 'dev', 'eth0')
        self.config['payer'] = self.settings[0]
        write(self.config_path, self.config)
        g.command(['octra-node', 'init-private-payer', '--config', self.config_path])
        now = int(time.time() * 1000) - 60_000
        terms = {'amount_ou': 100_000, 'valid_from_ms': now, 'expires_ms': now + 86_400_000,
                 'relayer_public': self.relayer, 'fees': self.fees}
        requests = g.ROOT / 'deposit.json'
        write(requests, [{'kind': 'Deposit', 'id': [205] * 32, 'terms': terms}])
        g.command(['octra-node', 'private-payer-consent', '--config', self.config_path, '--requests', requests])
        self.start()
        g.until(self.funded, 600, 'real canonical deposit reconciled by native payer')
        g.stop(3); self.process = None
        self.config['payer'] = None
        self.config['private_route'] = {'id': [206] * 32, 'hops': self.settings, 'chain_dns': {}}
        write(self.config_path, self.config)
        intents = g.ROOT / 'route-consent.json'
        write(intents, [self.intent(index, now) for index in range(2)])
        g.command(['octra-node', 'private-route-consent', '--config', self.config_path, '--requests', intents])
        atomic(g.EVIDENCE / 'shielded-client-ready.json', {'retained_client_node': True,
               'deposit_reconciled': True, 'route_sealed': True, 'shielded_payments': True})

    def payer(self, index):
        endpoint = self.endpoints[index]
        return {'application': {**self.private['application'], 'offer': self.private['offers'][index]['offer']},
                'pool': self.private['pool'], 'operator_public': self.private['operator_public'][index],
                'wallet': str(g.ROOT / 'payer'), 'index': str(g.ROOT / 'payer-index'),
                'master_key': str(self.master), 'relayer_key': str(self.signer),
                'proving_key': '/material/private-material/pool.pk',
                'index_limits': {'max_notes': 65_536, 'max_updates': 65_536},
                'control_url': endpoint['control_url'], 'control_ca_pem': endpoint['control_ca_pem'],
                'control_spki': endpoint['control_spki'], 'control_pin': endpoint['pins']['control'],
                'spend_operator_income': False}

    def intent(self, index, now):
        tariff = self.private['tariffs'][index]; caps = self.private['caps'][index]
        allowances = [{'traffic_class': i, 'bytes': size,
                       'max_cost_ou': (size * tariff['classes'][i]['rate_ou_per_mib'] + 1_048_575) // 1_048_576}
                      for i, size in enumerate(caps) if size]
        assert allowances and all(a['max_cost_ou'] > 0 for a in allowances)
        terms = {'target': {'chain_origin': list(bytes.fromhex(self.private['origin'])),
                  'pool': {'domain': self.private['pool_domain'], 'program': self.private['pool']['circle']},
                  'directory': self.private['directory'],
                  'operator': base64.b64encode(bytes(self.private['operator_public'][index])).decode()},
                 **self.private['offers'][index], 'ceiling_ou': sum(a['max_cost_ou'] for a in allowances),
                 **allowances[0], 'additional': allowances[1:],
                 'valid_from_ms': now, 'expires_ms': now + 86_400_000, 'invoice_lifetime_ms': 120_000,
                 'relayer_public': self.relayer, 'fees': self.fees}
        return {'purchase_id': [207 + index] * 32, 'terms': terms, 'tariff': tariff,
                'endpoint': self.endpoints[index], 'journal': str(g.ROOT / f'private-hop-{index}'),
                'interface_name': multi_client.NAMES[index]}

    def start(self):
        self.launches += 1
        log = g.EVIDENCE / 'node-3.log'
        self.log_offset = log.stat().st_size if log.exists() else 0
        g.start(3); self.process = g.PROCESSES[3]

    def expected_transport_stop(self, process):
        text = (g.EVIDENCE / 'node-3.log').read_bytes()[self.log_offset:].decode(errors='replace')
        error = text.rsplit('\nError: ', 1)[-1]
        return (self.expected_outage and process.poll() == 1
                and error.startswith(('paid route hop 0 failed; blockers retained',
                                      'paid route hop 1 failed; blockers retained'))
                and '\n    WireGuard transport unavailable; reconnect with --resume' in error)

    def wait_command(self, path):
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            for index, process in g.PROCESSES.items():
                if process.poll() is not None:
                    assert index == 3 and self.expected_transport_stop(process), \
                        f'unexpected qualification process exit: {index} {process.returncode}'
            if path.exists(): return
            time.sleep(.05)
        raise TimeoutError('shielded client command')

    def stop_for_resume(self):
        process = g.PROCESSES.pop(3)
        try:
            if process.poll() is None: process.send_signal(signal.SIGINT)
            process.wait(timeout=30)
            assert process.returncode == 0 or self.expected_transport_stop(process), \
                f'unexpected client stop: {process.returncode}'
        finally: g.FILES.pop(3).close()
        self.process = None

    def funded(self):
        text = (g.EVIDENCE / 'node-3.log').read_bytes()[self.log_offset:].decode(errors='replace')
        for line in text.splitlines():
            if 'private payer progress' not in line: continue
            fields = {key: int(value) for key, value in re.findall(r'\b(completed|remaining|blocked|paused)=(\d+)\b', line)}
            if fields == {'completed': 1, 'remaining': 0, 'blocked': 0, 'paused': 0}: return True
        return False

    def interface(self, index):
        rows = json.loads(p.ip('-j', '-4', 'addr', 'show', 'dev', multi_client.NAMES[index]))
        return next(a['local'] for row in rows for a in row['addr_info'] if a['family'] == 'inet')

    def state(self):
        body, _ = g.get(g.RPC.removesuffix('/rpc') + '/operator/status')
        # Entry payment can finalize before the route owner installs its
        # private table. Query all tables so that this valid pre-arm state is
        # an empty route set; an actual query failure must still propagate.
        routes = [row for row in json.loads(p.ip('-j', '-4', 'route', 'show', 'table', 'all'))
                  if str(row.get('table')) == '186']
        return {'node': json.loads(body), 'process_alive': self.process is not None and self.process.poll() is None,
                'links': json.loads(p.ip('-j', 'link', 'show')),
                'rules': json.loads(p.ip('-j', 'rule', 'show')),
                'routes': routes}

    def command(self, request):
        action = request['action']
        if action == 'launch': self.start(); return {'started': True}
        if action == 'ready':
            def ready():
                state = self.state()
                return state if (state['node']['serving'] and state['process_alive']
                    and all(any(row['ifname'] == n for row in state['links']) for n in multi_client.NAMES)
                    and any(row.get('dev') == multi_client.NAMES[-1] for row in state['routes'])) else None
            return g.until(ready, 600, 'all private-funded TUNs and final route with current native chain')
        if action == 'state': return self.state()
        if action == 'accounting': return observe('C')
        if action == 'traffic': return {'udp': self.udp(3), 'tcp_payload_bytes': p.tcp_and_icmp(self.interface(1))}
        if action == 'blocked':
            links = json.loads(p.ip('-j', 'link', 'show'))
            udp = (self.udp(2, 900, expect=False)
                   if any(row['ifname'] == multi_client.NAMES[-1] for row in links)
                   else {'exit_interface_absent': True})
            return {'udp': udp, 'physical': self.command({'action': 'privacy'})}
        if action == 'near_mtu': return self.udp(2, 1047)
        if action == 'exhaust_probe':
            try: return {'delivered': True, 'traffic': self.udp(1, 900)}
            except socket.timeout: return {'delivered': False}
        if action == 'privacy':
            # Deliberately force eth0 to exercise the packet guard, independent
            # of route selection. No raw sockets or privileged bypass mark.
            return json.loads(g.command(['python3', '/usr/local/bin/shielded_probe.py']))
        if action == 'expect_outage':
            assert not self.expected_outage and self.process.poll() is None
            self.expected_outage = True
            return {'expected_transport_outage': True}
        if action == 'crash':
            process = g.PROCESSES.pop(3); process.kill(); process.wait(timeout=20); g.FILES.pop(3).close()
            self.process = None; return {'crashed': True}
        if action == 'resume': self.start(); return {'started': True}
        if action == 'restart':
            if 3 in g.PROCESSES: self.stop_for_resume()
            self.expected_outage = False
            self.start()
            return {'started': True, 'original_consent_resumed': True}
        if action == 'stop': return {'stopped': True}
        raise ValueError('unknown fixed shielded client action')

    def close(self):
        if 3 in g.PROCESSES: self.stop_for_resume()


def main():
    client = None
    try:
        client = Client(); directory = pathlib.Path('/commands/C'); number = 1
        while True:
            path = directory / f'{number}.json'; client.wait_command(path)
            request = json.loads(path.read_text())
            try: atomic(path.with_suffix('.result.json'), {'ok': client.command(request)})
            except BaseException:
                atomic(path.with_suffix('.result.json'), {'error': traceback.format_exc()}); raise
            number += 1
            if request['action'] == 'stop': break
    finally:
        if client: client.close()


if __name__ == '__main__': main()
