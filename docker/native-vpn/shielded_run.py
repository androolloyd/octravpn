#!/usr/bin/env python3
"""Real shielded funding, native chain sync and nested traffic in separate kernels.

Every invocation owns its internal network and state. Test parameters are made
in a separate network-none container. No public RPC, faucet or user wallet is
used. This gate never qualifies production proving parameters or public sync.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import subprocess
import time
import uuid

from private_control import identities
from fixture_network import addresses
from stock_run import atomic, cleanup_owned, command, until


class FixtureExited(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--context', type=pathlib.Path, required=True)
    parser.add_argument('--exhaust-hop', type=int, choices=[0, 1], required=True)
    parser.add_argument('--subnet', default='172.31.237.0/24')
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.image = command(['docker', 'image', 'inspect', '--format', '{{.Id}}', args.image])
    underlay = addresses(args.subnet)
    os.umask(0o077); args.out.mkdir(mode=0o700); output = args.out.resolve()
    private = output / 'private'; private.mkdir()
    evidence = output / 'evidence'; evidence.mkdir()
    for name in ['state', 'client-state', 'client-config', 'commands', 'material']: (private / name).mkdir()
    commands = private / 'commands'
    for role in ['A', 'B', 'C']: (commands / role).mkdir()
    identifier = 'octra-shielded-' + uuid.uuid4().hex[:12]
    network = identifier; containers = []; volume = None; requests = dict(A=0, B=0, C=0)
    health_checked = {}
    accounting_sample = 0
    report = {'qualified': False, 'transport_qualified': False, 'independent_accounting_qualified': False,
              'image': args.image,
              'shielded_payments': True, 'public_network_qualified': False,
              'production_setup_qualified': False, 'exhaustion_hop': args.exhaust_hop, 'steps': [],
              'fixture_memory_limit': '6g', 'fixture_swap_limit': '6g',
              'limitations': ['Ephemeral isolated proof setup; no production ceremony qualification',
                              'Two-hop gate only; no three-hop or public-chain qualification',
                              'No cryptographic proof of arbitrary Web non-delivery']}
    def save(): atomic(output / 'qualification.json', report)
    def step(name, **values):
        report['steps'].append({'name': name, **values}); save(); print(name, flush=True)
    def document(path, role):
        try: return json.loads(path.read_text())
        except FileNotFoundError:
            if time.monotonic() - health_checked.get(role, 0) >= 2:
                state = json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', identifier + '-' + role]))
                health_checked[role] = time.monotonic()
                if state['Running'] is False:
                    raise FixtureExited(f'{role} exited {state["ExitCode"]}; retained logs and owned cleanup follow')
            return None
    def call(role, action, **values):
        requests[role] += 1; path = commands / role / f'{requests[role]}.json'
        atomic(path, {'action': action, **values})
        value = until(lambda: document(path.with_suffix('.result.json'), role),
                      f'{role} {action}', timeout=660)
        if 'error' in value: raise RuntimeError(value['error'])
        return value['ok']
    def current(): return call('A', 'private_state')
    def accounting(ready, state):
        nonlocal accounting_sample
        accounting_sample += 1
        assert accounting_sample <= 1024, 'accounting observation count bound'
        material = json.loads((private / 'material/private-material/manifest.json').read_text())
        for role in ['A', 'B', 'C']:
            observation = {'fixture_only': True, 'sample': accounting_sample,
                           'ready': ready, 'exchanges': state['exchanges'],
                           'pool_code_sha256': material['pool_code_sha256']}
            retained = evidence / f'private-accounting-{role}-{accounting_sample}.json'
            assert not retained.exists(), 'accounting input observation already exists'
            atomic(retained, observation)
            atomic(evidence / f'private-accounting-{role}.json', observation)
        snapshots = {role: call(role, 'accounting') for role in ['A', 'B', 'C']}
        operators = [snapshots['A'], snapshots['B']]; payer = snapshots['C']
        assert payer['held_ou'] == 0
        assert payer['available_ou'] + sum(op['unspent_income_ou'] for op in operators) == 100_000
        assert all(op['paid_ou'] == op['unspent_income_ou'] for op in operators)
        assert payer['native_attempts'] >= len(state['exchanges'])
        return snapshots
    def payer_funds(snapshot):
        fields = {'available_ou', 'held_ou', 'native_attempts', 'reserved_fees_ou'}
        assert set(snapshot) == fields | {'transport'}
        return {name: snapshot[name] for name in fields}
    def remaining(snapshot):
        selected = snapshot['A' if args.exhaust_hop == 0 else 'B']
        local = snapshot['C']['transport'][args.exhaust_hop]
        assert local['hop'] == args.exhaust_hop and local['purchased'] == selected['purchased']
        # Both budgets are finite. The client retains confirmed local handoffs,
        # crash uncertainty and pending writes; the provider measures its own
        # delivery boundary. A loss must never restore either side's capacity.
        return min(selected['purchased'][1] - selected['used'][1],
                   local['purchased'][1] - local['used'][1])
    def tcp_peers(name, field):
        rows = [json.loads(line) for line in (evidence / name).read_text().splitlines() if line.startswith('{')]
        return [row[field] for row in rows if field in row]
    def exex_agree(state):
        locations = [private / 'state/native-vpn/chain' / f'node-{i}/exex' for i in [0, 1, 2]]
        locations.append(private / 'client-state/native-vpn/chain/node-3/exex')
        def agreed():
            for exchange in state['exchanges']:
                paths = [root / exchange['exex'] for root in locations]
                if not all(path.is_file() for path in paths): return False
                bodies = [json.loads(path.read_text()) for path in paths]
                assert all(body == bodies[0] for body in bodies)
            return True
        until(agreed, 'all four physical native ExEx stores agree on private exchanges', timeout=180)
    tls = private / 'tls'; report['tls'] = identities(tls)
    endpoints = []
    for role, ip, port, udp in [('entry', '93.184.216.11', 20879, 19874),
                               ('exit', '93.184.216.21', 20889, 19884)]:
        pubkey = subprocess.check_output(['openssl', 'x509', '-in', str(tls / role / 'server.crt'), '-pubkey', '-noout'])
        encoded = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pubkey,
                                 check=True, capture_output=True).stdout
        endpoints.append({'control_url': f'https://{role}.octra.invalid:{port}/',
                          'control_ca_pem': (tls / 'ca.pem').read_text(),
                          'control_spki': [list(hashlib.sha256(encoded).digest())],
                          'wireguard_endpoint': f'{role}.octra.invalid:{udp}',
                          'pins': {'control': f'{ip}:{port}', 'wireguard': f'{ip}:{udp}'}})
    atomic(private / 'client-config/private-endpoints.json', endpoints)
    try:
        inspection = json.loads(command(['docker', 'image', 'inspect', args.image]))[0]
        report['image_id'] = inspection['Id']
        source = json.loads(command(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat',
                                     args.image, '/usr/local/share/private-multihop-source.json']))
        for relative, digest in source['source_sha256'].items():
            path = pathlib.PurePosixPath(relative)
            assert not path.is_absolute() and '..' not in path.parts
            candidate = args.context / path
            assert candidate.is_file() and not candidate.is_symlink()
            assert hashlib.sha256(candidate.read_bytes()).hexdigest() == digest, relative
        report['source'] = source
        report['binaries'] = json.loads(command(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat',
                                                args.image, '/usr/local/share/private-multihop-binaries.json']))
        for name, digest in report['binaries'].items():
            assert name in ['octra-node', 'private-kernel-test']
            value = command(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'sha256sum',
                             args.image, '/usr/local/bin/' + name]).split()[0]
            assert value == digest
        command(['docker', 'network', 'create', '--internal', '--subnet', underlay['subnet'], network])
        volume = command(['docker', 'volume', 'create'])
        common = ['--memory=6g', '--memory-swap=6g', '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW', '--device=/dev/net/tun', '--read-only',
                  '-e', 'RAYON_NUM_THREADS=4', '-e', 'RUST_LIB_BACKTRACE=1',
                  '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m', '-v', f'{evidence}:/evidence']
        target = identifier + '-target'; containers.append(target)
        command(['docker', 'run', '-d', '--name', target, '--network', 'none', *common, '-v', f'{volume}:/hop',
                 '--entrypoint', 'python3', args.image, '-u', '/usr/local/bin/multi_target.py'])
        until(lambda: command(['docker', 'exec', target, 'test', '-S', '/hop/target.sock']) is not None,
              'independent target kernel')
        def operator(role, address):
            name = identifier + '-' + role; containers.append(name)
            command(['docker', 'run', '-d', '--name', name, '--network', network, '--ip', address, *common,
                '-e', 'OCTRA_FIXTURE_SUBNET=' + underlay['subnet'],
                '-v', f'{tls / ("entry" if role == "A" else "exit")}:/control-tls:ro',
                '-v', f'{private / "material"}:/material:ro',
                '-e', 'OCTRA_NATIVE_VPN_LOG=info,octra_node::vpn::payments::shielded::payer=debug,octravpn_node::payments=debug',
                '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv4.conf.all.rp_filter=0',
                '--sysctl', 'net.ipv4.conf.default.rp_filter=0', '--sysctl', 'net.ipv4.conf.all.route_localnet=1',
                '--sysctl', 'net.ipv4.conf.default.route_localnet=1', '-v', f'{private / "state"}:/state',
                '-v', f'{commands}:/commands', '-v', f'{volume}:/hop', '--entrypoint', 'python3', args.image,
                '-u', '/usr/local/bin/shielded_fixture.py', '--role', role, '--exhaust-hop', str(args.exhaust_hop)])
        operator('A', underlay['A'])
        report['native_binary_sha256'] = command(['docker', 'exec', identifier + '-A',
            'sha256sum', '/usr/local/bin/octra-node']).split()[0]
        material = private / 'material'
        request = until(lambda: document(evidence / 'private-material-request.json', 'A'), 'real Circle directory origin', timeout=900)
        atomic(material / 'private-material-input.json', request)
        atomic(material / 'kernel-scope.json', {'fixture_only': True, 'network_none': True})
        generator = identifier + '-material'; containers.append(generator)
        command(['docker', 'run', '--name', generator, '--network', 'none', '--memory=6g', '--memory-swap=6g', '--cap-drop=ALL', '--read-only',
            '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m', '-e', 'RAYON_NUM_THREADS=8',
            '-v', f'{material}:/evidence', '--entrypoint', '/usr/local/bin/private-kernel-test', args.image,
            'vpn::payments::canonical_tests::shielded::runner_flow::multi_material::prepare_isolated_multihop_pool_material',
            '--exact', '--ignored', '--nocapture'], timeout=600)
        ready = until(lambda: document(evidence / 'shielded-ready.json', 'A'), 'native private pool and operator A', timeout=900)
        step('actual native factory/pool deployed with independently generated isolated proving material', pool=ready['pool']['circle'])
        operator('B', underlay['B'])
        until(lambda: document(evidence / 'shielded-B-ready.json', 'B'), 'relocated B imports pool and resumes private service', timeout=300)
        checkpoint = call('A', 'client_checkpoint'); atomic(evidence / 'shielded-client-checkpoint.json', checkpoint)
        client = identifier + '-C'; containers.append(client)
        command(['docker', 'run', '-d', '--name', client, '--network', network, '--ip', underlay['C'], *common,
            '-e', 'OCTRA_FIXTURE_SUBNET=' + underlay['subnet'],
            '--cap-add=SETUID', '--cap-add=SETGID',
            '--tmpfs', '/run:rw,nosuid,nodev,size=16m', '-v', f'{private / "client-state"}:/state',
            '-v', f'{private / "state"}:/source:ro', '-v', f'{commands}:/commands',
            '-v', f'{private / "client-config"}:/config:ro', '-v', f'{material}:/material:ro',
            '-e', 'OCTRA_NATIVE_VPN_LOG=info,octra_node::vpn::payments::shielded::payer=debug',
            '-e', 'OCTRA_OBSERVER_RELAY_SUBMITS=1',
            '--entrypoint', 'python3', args.image, '-u', '/usr/local/bin/shielded_client.py'])
        until(lambda: document(evidence / 'shielded-client-ready.json', 'C'), 'real native payer reconciles shielded deposit and seals route', timeout=900)
        initial = current(); assert len(initial['exchanges']) == 1
        call('B', 'hold_private'); call('C', 'launch')
        waiting = until(lambda: (s if len(s['exchanges']) == 3 else None) if (s := current()) else None,
                        'both entry class purchases are canonical before downstream funding', timeout=600)
        c = call('C', 'state')
        assert not any(row['ifname'] == 'route-exit' for row in c['links'])
        assert waiting['target'].get('udp_payload_bytes', 0) == 0
        call('B', 'release_status'); opened = call('C', 'ready')
        funded = current(); assert len(funded['exchanges']) == 5
        exex_agree(funded)
        funded_accounting = accounting(ready, funded)
        step('one deposit and four real private class payments precede final route activation',
             exchanges=[row['hash'] for row in funded['exchanges']], client_epoch=opened['node']['epoch'])
        before = funded['target'].get('udp_payload_bytes', 0)
        traffic = call('C', 'traffic'); call('C', 'near_mtu')
        after = current(); assert after['target']['udp_payload_bytes'] >= before + 4794
        assert after['target']['tcp_payload_bytes'] > 0
        traffic_accounting = accounting(ready, after)
        for role in ['A', 'B']:
            assert traffic_accounting[role]['used'][1] > funded_accounting[role]['used'][1]
        privacy = call('C', 'privacy')
        peers = tcp_peers('links-B.log', 'tls_peer')
        assert peers and set(peers) == {underlay['A']}, peers
        native = tcp_peers('private-links-A.log', 'tcp_peer')
        assert any(ipaddress.ip_address(peer) in ipaddress.ip_network('198.18.0.0/15') for peer in native), \
            'no actual native P2P through accepted entry observed'
        step('real nested TCP/UDP/ICMP and near-MTU return traffic; unprivileged physical negatives',
             traffic=traffic, privacy=privacy, downstream_tls_peers=sorted(set(peers)))
        hashes = [row['hash'] for row in after['exchanges']]
        call('C', 'crash'); call('A', 'restart'); call('B', 'restart')
        call('C', 'resume'); resumed = call('C', 'ready'); call('C', 'traffic')
        recovered = current(); assert [row['hash'] for row in recovered['exchanges']] == hashes
        assert resumed['node']['epoch'] >= opened['node']['epoch']
        exex_agree(recovered)
        recovered_accounting = accounting(ready, recovered)
        assert payer_funds(recovered_accounting['C']) == payer_funds(funded_accounting['C']), 'restart changed payer custody or lifetime fee reservations'
        for role in ['A', 'B']:
            old, new = traffic_accounting[role], recovered_accounting[role]
            assert new['purchased'] == old['purchased'] and new['paid_ou'] == old['paid_ou']
            assert new['connection_sequence'] > old['connection_sequence']
            assert all(a >= b for a,b in zip(new['used'],old['used'],strict=True))
        step('all actual providers and local payer node recover original custody and consent with no duplicate spending')
        call('C', 'expect_outage'); call('B', 'pause')
        stopped = current()['target']['udp_payload_bytes']; call('C', 'blocked')
        assert current()['target']['udp_payload_bytes'] == stopped
        call('B', 'resume')
        call('C', 'restart'); call('C', 'ready')
        call('C', 'traffic')
        restored = current()
        assert [row['hash'] for row in restored['exchanges']] == hashes
        assert payer_funds(accounting(ready, restored)['C']) == payer_funds(funded_accounting['C'])
        step('provider outage retains physical blockers; explicit resume preserves custody without replacement spending')
        # A bounded finite purchase must eventually stop. A failed expected echo
        # is only the exhaustion boundary after positive traffic and recovery.
        successes = 0
        for _ in range(512):
            sample = accounting(ready, current())
            minimum = 1129 if args.exhaust_hop == 0 else 928
            if remaining(sample) < minimum: break
            if not call('C', 'exhaust_probe')['delivered']:
                boundary = accounting(ready, current())
                assert remaining(boundary) < minimum, \
                    'route stopped before selected finite allowance exhausted'
                break
            successes += 1
        else: raise AssertionError('finite route never exhausted')
        last = current(); target_bytes = last['target']['udp_payload_bytes']
        call('C', 'blocked')
        final = current()
        assert final['target']['udp_payload_bytes'] == target_bytes
        assert [row['hash'] for row in final['exchanges']] == hashes
        assert call('C', 'state')['process_alive']
        exex_agree(final)
        final_accounting = accounting(ready, final)
        assert payer_funds(final_accounting['C']) == payer_funds(funded_accounting['C'])
        for role in ['A','B']:
            assert final_accounting[role]['purchased'] == funded_accounting[role]['purchased']
        report['accounting'] = {'funded':funded_accounting, 'traffic':traffic_accounting,
                                'recovered':recovered_accounting, 'final':final_accounting}
        step('finite shielded allowances stop without topup or physical fallback', successful_exhaustion_probes=successes)
        report['final'] = final
        call('C', 'stop'); call('B', 'stop'); call('A', 'stop')
        report['transport_qualified'] = True
        report['independent_accounting_qualified'] = True
        report['qualified'] = True
    except BaseException as error:
        report['failure'] = {'type': type(error).__name__, 'message': str(error)[:4096]}
        raise
    finally:
        report['container_states'] = {}
        for name in reversed(containers):
            state = subprocess.run(['docker', 'inspect', '--format', '{{json .State}}', name],
                                   capture_output=True, timeout=30)
            if state.returncode == 0:
                report['container_states'][name] = json.loads(state.stdout)
            else:
                report['container_states'][name] = {'inspect_error': state.stderr.decode(errors='replace')[-512:]}
            result = subprocess.run(['docker', 'logs', name], capture_output=True, timeout=30)
            (output / (name + '.log')).write_bytes(result.stdout + result.stderr)
        report['cleanup'] = cleanup_owned(output, containers, volume, network)
        if not report['cleanup']['verified']: report['qualified'] = False
        save()
        if not report['cleanup']['verified']: raise RuntimeError('owned cleanup was not verified')


if __name__ == '__main__': main()
