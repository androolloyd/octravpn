#!/usr/bin/env python3
"""Two real native operators in separate kernels and explicit nested purchases.

Run both --exhaust-hop0 and1 as fresh gates. This is a two-hop Program custody
qualification, not a claim of three-hop, Circle custody, public deployment or
per-socket management isolation.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import uuid

from json_snapshot import read_object, read_array

from stock_run import atomic, cleanup_owned, command, until

SUITE = pathlib.Path(__file__).resolve().parent
A_IP = '93.184.216.11'; B_IP = '93.184.216.21'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-image', required=True); parser.add_argument('--context', type=pathlib.Path, required=True)
    parser.add_argument('--headscale-commit', required=True); parser.add_argument('--exhaust-hop', type=int, choices=[0, 1], required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True); args = parser.parse_args()
    assert len(args.headscale_commit) == 40 and all(c in '0123456789abcdef' for c in args.headscale_commit)
    os.umask(0o077); args.out.mkdir(mode=0o700); output = args.out.resolve()
    evidence = output / 'evidence'; evidence.mkdir(); private = output / 'private'; private.mkdir()
    commands = private / 'commands'; commands.mkdir()
    for role in ['A', 'B', 'C']: (commands / role).mkdir()
    state = private / 'state'; state.mkdir(); client_state = private / 'client-state'; client_state.mkdir()
    client_config = private / 'client-config'; client_config.mkdir()
    identifier = 'octra-nested-' + uuid.uuid4().hex[:12]; image = identifier + ':local'; network = identifier
    containers = []; volume = None; requests = {'A': 0, 'B': 0, 'C': 0}
    report = {'qualified': False, 'steps': [], 'scope': 'two independent native Program operators, two prepaid channels and real nested kernel traffic',
              'exhaustion_and_revocation_hop': args.exhaust_hop, 'public_network_qualified': False,
              'limitations': ['No three-hop or Circle-custody multihop qualification in this gate',
                'Existing local HTTP management controls are bridged opaquely over an isolated underlay; no public TLS claim',
                'Entry/operator-control destination IPs are explicit physical management exceptions, not per-socket isolation',
                'Explicit verified owned-route cleanup before crash resume; no automatic stale-rule deletion',
                'Finite final purchases and no trustless Web delivery proof or non-delivery slashing']}
    def save(): atomic(output / 'qualification.json', report)
    def step(name, **values): report['steps'].append({'name': name, **values}); save(); print(name, flush=True)
    def execute(container, *argv, timeout=90): return command(['docker', 'exec', container, *argv], timeout=timeout)
    def call(role, action, **values):
        requests[role] += 1; path = commands / role / f'{requests[role]}.json'
        atomic(path, {'action': action, **values})
        value = until(lambda: json.loads(path.with_suffix('.result.json').read_text()), role + ' ' + action, timeout=240)
        if 'error' in value: raise RuntimeError(value['error'])
        return value['ok']
    def current(): return call('A', 'state')
    def used(state, hop, class_id):
        row = state['hops'][hop]['meter']; return sum(row[name][class_id] for name in ['committed', 'uncertain', 'pending'])
    def target_after(before_bytes, additional, label):
        def advanced():
            candidate = current()
            return candidate if candidate['target'].get('udp_payload_bytes', 0) >= before_bytes + additional else None
        return until(advanced, label)
    def traffic():
        before = current(); value = call('C', 'traffic')
        after = target_after(before['target'].get('udp_payload_bytes', 0), 2700, 'real target counters after nested echoes')
        for index in range(2):
            assert used(after, index, 1) > used(before, index, 1), 'one operator did not meter the actual UDP path'
        assert after['target']['udp_payload_bytes'] > before['target'].get('udp_payload_bytes', 0)
        return value
    try:
        source = json.loads(command(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat', args.node_image,
                                     '/usr/local/share/native-source.json']))
        for row in source['files']:
            relative = pathlib.PurePosixPath(row['path']); assert not relative.is_absolute() and '..' not in relative.parts
            path = args.context / relative
            assert path.is_file() and not path.is_symlink() and path.stat().st_size == row['bytes']
            assert hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256'], path
        assert args.headscale_commit in (args.context / 'octra/Cargo.lock').read_text()
        report['native_source'] = source; report['headscale_commit'] = args.headscale_commit
        report['suite_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in SUITE.glob('multi*') if path.is_file()}
        command(['docker', 'build', '-f', SUITE / 'multi_Dockerfile', '--build-arg', 'NODE_IMAGE=' + args.node_image,
                 '-t', image, SUITE], timeout=300)
        report['image'] = json.loads(command(['docker', 'image', 'inspect', image]))[0]['Id']
        command(['docker', 'network', 'create', '--internal', '--subnet', '172.31.237.0/24', network])
        volume = command(['docker', 'volume', 'create'])
        target = identifier + '-target'; containers.append(target)
        common = ['--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW', '--device=/dev/net/tun', '--read-only',
                  '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m', '-v', f'{evidence}:/evidence']
        command(['docker', 'run', '-d', '--name', target, '--network', 'none', *common, '-v', f'{volume}:/hop', image,
                 'python3', '-u', '/usr/local/bin/multi_target.py'])
        until(lambda: execute(target, 'test', '-S', '/hop/target.sock') is not None, 'independent target kernel')
        for role, address in [('A', '172.31.237.2'), ('B', '172.31.237.4')]:
            if role == 'B':
                ready = until(lambda: json.loads((evidence / 'multi-ready.json').read_text()), 'actual four-validator preparation', timeout=900)
                for key in ['receipt-A.hex', 'receipt-B.hex']: shutil.copyfile(commands / key, client_config / key); (client_config / key).chmod(0o600)
            name = identifier + '-' + role; containers.append(name)
            command(['docker', 'run', '-d', '--name', name, '--network', network, '--ip', address, *common,
                '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv4.conf.all.rp_filter=0',
                '--sysctl', 'net.ipv4.conf.default.rp_filter=0', '--sysctl', 'net.ipv4.conf.all.route_localnet=1',
                '--sysctl', 'net.ipv4.conf.default.route_localnet=1', '-v', f'{state}:/state', '-v', f'{commands}:/commands',
                '-v', f'{volume}:/hop', image, 'python3', '-u', '/usr/local/bin/multi_fixture.py', '--role', role,
                '--exhaust-hop', str(args.exhaust_hop)])
        b_ready = until(lambda: json.loads((evidence / 'multi-B-ready.json').read_text()), 'relocated native B writer', timeout=240)
        assert b_ready['retained_state_verified'] is True
        client = identifier + '-C'; containers.append(client)
        command(['docker', 'run', '-d', '--name', client, '--network', network, '--ip', '172.31.237.3', *common,
            '--tmpfs', '/run:rw,nosuid,nodev,size=16m', '-v', f'{client_state}:/state', '-v', f'{commands}:/commands',
            '-v', f'{client_config}:/config:ro', image, 'python3', '-u', '/usr/local/bin/multi_client.py'])
        until(lambda: (evidence / 'multi-client-ready.json').is_file(), 'real composite client fixture')
        call('C', 'foreign_rule')
        initial = current(); assert all(not any(row['purchased']) for row in initial['hops'])
        step('foreign priority1 policy rule refuses before any canonical purchase')
        call('C', 'launch'); call('A', 'release')
        until(lambda: current()['hops'][0]['purchased'] == ready['plans'][0]['prepaid_bytes'], 'entry canonical prepaid floor')
        waiting = call('C', 'state'); assert not any(row['ifname'] == 'route-exit' for row in waiting['links'])
        assert not any(current()['hops'][1]['purchased'])
        assert current()['target'].get('udp_payload_bytes', 0) == 0
        call('B', 'release'); opened = call('C', 'ready')
        assert [row['authorized_bytes'] for row in opened['journals']] == [plan['prepaid_bytes'] for plan in ready['plans']]
        assert all(row['connection_sequence'] > 0 for row in opened['journals'])
        step('every independently signed canonical purchase precedes final route activation', plans=[plan['binding'] for plan in ready['plans']])
        traffic(); before_near = current()['target']['udp_payload_bytes']; call('C', 'near_mtu')
        until(lambda: current()['target']['udp_payload_bytes'] >= before_near + 2094, 'nearMTU actual target receive')
        before = current(); call('C', 'oversize')
        after = target_after(before['target']['udp_payload_bytes'], 500, 'oversize positive control target receive')
        # One500B positive-control echo is allowed; the1048B oversize probe
        # must not appear in target bytes. Never call this a wire-format limit.
        assert after['target']['udp_payload_bytes'] - before['target']['udp_payload_bytes'] == 500
        mss = read_array(evidence / 'tcp-mss.json'); assert mss and all(value <= 1035 for value in mss)
        step('conservative finalMTU1075 carries near-boundary traffic bothways, TCPMSS<=1035, oversized profile packets refused', client_mss=mss)
        prior = current(); call('C', 'crash'); call('A', 'restart'); call('B', 'restart')
        call('C', 'launch', resume=True); resumed = call('C', 'ready')
        assert [row['authorized_bytes'] for row in resumed['journals']] == [row['authorized_bytes'] for row in opened['journals']]
        assert all(new['connection_sequence'] > old['connection_sequence'] for new, old in zip(resumed['journals'], opened['journals'], strict=True))
        assert [row['purchased'] for row in current()['hops']] == [row['purchased'] for row in prior['hops']]
        traffic(); step('both actual native operators and client restart with original independent journals and purchases')
        call('C', 'carrier_loss'); call('C', 'launch', resume=True); call('C', 'ready'); traffic()
        step('deleted carrierTUN cannot reveal a deliberately installed physical downstream route; exact owned cleanup then explicit resume')
        selected = args.exhaust_hop
        # Pinned unpadded emitter: raw exitUDP900B payload is928IP bytes;
        # authenticated downstream carrier adds201bytes on outgoing entry.
        minimum = 1129 if selected == 0 else 928
        for _ in range(256):
            state_now = current(); record = state_now['hops'][selected]['meter']
            if record['purchased'][1] - used(state_now, selected, 1) < minimum: break
            try: call('C', 'exhaust_probe')
            except RuntimeError: pass
        else: raise AssertionError('selected hop allowance did not exhaust')
        call('B', 'state')
        exhausted = current(); target_before = exhausted['target']['udp_payload_bytes']
        call('C', 'blocked')
        assert current()['target']['udp_payload_bytes'] == target_before
        assert [row['purchased'] for row in current()['hops']] == [row['purchased'] for row in exhausted['hops']]
        assert call('C', 'state')['process_alive'] is True
        step('selected operator independently exhausts finite capacity without buying more', selected_hop=selected, remaining=record['purchased'][1]-used(exhausted, selected, 1))
        call('C', 'clean_stop'); replacement = call('A', 'reset'); call('C', 'reset', plans=replacement['plans'])
        call('C', 'launch'); call('C', 'ready'); traffic()
        call('A', 'hold_status'); call('B', 'hold_status')
        revoked = call('A', 'revoke', hop=selected); target_before = revoked['target']['udp_payload_bytes']
        call('C', 'blocked')
        assert current()['target']['udp_payload_bytes'] == target_before
        assert call('C', 'state')['process_alive'] is True, 'client shutdown hid operator revocation'
        call('A', 'release_status'); call('B', 'release_status'); call('C', 'wait_failure')
        claims = call('A', 'claims')
        final = current(); target_state = read_object(evidence / 'target.json')
        assert target_state['udp_payload_bytes'] > 0 and target_state['tcp_payload_bytes'] > 0
        assert not target_state['errors'] and not target_state['hop']['errors']
        assert all(sources and set(sources) == {'192.0.2.1'} for sources in target_state['observed_sources'].values())
        report['final'] = {'state': final, 'claims': claims, 'target': target_state, 'tcp_mss': mss}
        step('selected hop canonical withdrawal blocks live nested traffic and four exact ExEx sinks agree', hop=selected, claims=claims)
        call('C', 'stop'); call('B', 'stop'); call('A', 'stop'); report['qualified'] = True; save()
    finally:
        for name in reversed(containers):
            log = subprocess.run(['docker', 'logs', name], capture_output=True, text=True)
            (output / (name + '.log')).write_text(log.stdout + log.stderr)
        report['cleanup'] = cleanup_owned(output, containers, volume, network)
        if not report['cleanup']['verified']: report['qualified'] = False
        save()
        if not report['cleanup']['verified']: raise RuntimeError('owned Docker resource cleanup could not be verified')


if __name__ == '__main__': main()
