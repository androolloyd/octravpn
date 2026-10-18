#!/usr/bin/env python3
"""Explicit OUT-only two-Rust/two-native BFT fixture; no public launch action."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback
import urllib.request
import uuid

import genesis_verify as v

INTENDED_OCTRA_ENV = {
    'OCTRA_PROPOSAL_PROTOCOL_ACTIVATION_EPOCH': '2',
    'OCTRA_PREVERIFY_RECEIPT_ACTIVATION_EPOCH': '0',
    'OCTRA_PRIVATE_RESULT_ACTIVATION_EPOCH': '0',
    'OCTRA_BFT_RELEASE_PROFILE': 'devnet_full_v1',
    'OCTRA_EMISSION_GUARD': '1',
    'OCTRA_SENDER_KEY_ACTIVATION_EPOCH': '0',
}


def fixture_environment():
    inherited = {key: value for key, value in os.environ.items() if key.startswith('OCTRA_')}
    rejected = [key for key, value in inherited.items()
                if key not in INTENDED_OCTRA_ENV or value != INTENDED_OCTRA_ENV[key]]
    policy = {'schema': 'octra_mixed_fixture_child_environment_v1',
        'inherited_octra': {key: {'value': value} if key in INTENDED_OCTRA_ENV and key not in rejected else
            {'value_sha256': hashlib.sha256(value.encode()).hexdigest()} for key, value in inherited.items()},
        'rejected_inherited_keys': sorted(rejected), 'intended_octra': INTENDED_OCTRA_ENV,
        'unlisted_inherited_consensus_toggles_allowed': False}
    # Record names and hashes of unknown values, never potential secret material.
    save(Path('/evidence') / 'child-environment.json', policy)
    v.require(not rejected, 'unsafe/unlisted inherited OCTRA environment: ' + ','.join(sorted(rejected)))
    child = {key: value for key, value in os.environ.items() if not key.startswith('OCTRA_')}
    child.update(INTENDED_OCTRA_ENV)
    child['RUST_LOG'] = 'info'
    v.require({key: value for key, value in child.items() if key.startswith('OCTRA_')} == INTENDED_OCTRA_ENV,
              'child consensus environment differs')
    return child


def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def bound(path):
    return {'path': str(Path(path).resolve()), 'sha256': v.sha(path)}


def command(argv, *, timeout=120, log=None, environment=None):
    try:
        result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=timeout, env=environment)
    except subprocess.TimeoutExpired as error:
        if log is not None:
            with Path(log).open('xb') as stream:
                stream.write(error.stdout or b'')
                stream.write(error.stderr or b'')
        raise
    if log is not None:
        with Path(log).open('xb') as stream:
            stream.write(result.stdout)
            stream.write(result.stderr)
    v.require(result.returncode == 0, f'fixture command failed: {argv[0]} exit {result.returncode}')
    return result.stdout


def get(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=2) as response:
        raw = response.read(4_000_001)
    v.require(len(raw) <= 4_000_000, 'HTTP evidence bound exceeded')
    return v.decode(raw)


def rpc(config, method, params):
    request = urllib.request.Request('http://' + config['rpc'] + '/rpc',
        data=v.compact({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}),
        headers={'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=2) as response:
        raw = response.read(4_000_001)
    v.require(len(raw) <= 4_000_000, 'RPC evidence bound exceeded')
    value = v.decode(raw)
    v.require(type(value.get('id')) is int and value['id'] == 1
              and 'error' not in value and 'result' in value, 'fixture RPC refused')
    return value['result']


def worker_probe(expected):
    raw = Path('/usr/local/share/native-source.json').read_bytes()
    manifest = v.decode(raw)
    actual = {name: v.sha('/usr/local/bin/' + name) for name in expected['rust_binaries']}
    v.require(manifest == expected['full_manifest'] and actual == expected['rust_binaries']
              and hashlib.sha256(raw).hexdigest() == expected['raw_manifest_sha256'],
              'copied actual Linux production artifacts differ')
    return {'six_binaries': actual, 'raw_manifest_sha256': hashlib.sha256(raw).hexdigest(),
        'native_host_binary': bound('/usr/local/bin/octra-native-mixed-host'),
        'cryptography_version': __import__('cryptography').__version__}


def verify_history(genesis, validators, rust, native, expected_epoch, tx_hashes):
    authority = list(validators)
    rust_set, native_set = set(authority[:2]), set(authority[2:])
    native_rows = []
    for audit in native:
        v.require(audit['chain_id'] == genesis['chain']['chain_id']
                  and audit['genesis_root'] == v.genesis_root(genesis)
                  and len(audit['history']) == expected_epoch, 'native retained history differs')
        rows, previous = [], v.genesis_root(genesis)
        prior_txid = -1
        for index, entry in enumerate(audit['history'], 1):
            checked = v.verify_certificate(v.b64(entry['finalize_wire_b64']), validators, genesis['chain']['chain_id'])
            txs, hashes = entry['txs'], entry['txhashes']
            tx_list = v.header_transaction_root(hashes)
            v.require(checked['epoch'] == index and checked['prev_state_root'] == previous
                      and checked['state_root'] == entry['state_root']
                      and checked['creator'] == entry['creator']
                      and set(checked['signers']) == set(entry['signers'])
                      and checked['txid_hi'] == int(entry['txid_hi']) == prior_txid + len(txs)
                      and len(txs) == len(hashes)
                      and entry['receipts'] == []
                      and checked['receipt_root'] == v.domain_hash(b'octra:preverify_receipt_root:v1', bytes(4)).hex()
                      and checked['tx_list_hash'] == tx_list,
                      'native header, bundle or global transaction IDs differ')
            v.require(set(checked['signers']) & rust_set and set(checked['signers']) & native_set,
                      'mixed signer quorum absent')
            rows.append({**checked, 'txs': txs, 'txhashes': hashes})
            previous, prior_txid = checked['state_root'], checked['txid_hi']
        native_rows.append(rows)
    all_rows = [*rust, *native_rows]
    v.require(all(len(rows) == expected_epoch for rows in all_rows), 'bounded finalized epoch count differs')
    consensus_keys = ['epoch', 'commit_round', 'protocol', 'creator', 'prev_state_root', 'state_root',
                      'tx_list_hash', 'receipt_root', 'txid_hi', 'timestamp', 'proposal_id', 'parent_proposal_id']
    for epoch_rows in zip(*all_rows):
        same = [{key: row[key] for key in consensus_keys} for row in epoch_rows]
        v.require(all(row == same[0] for row in same), 'cross-implementation finalized header differs')
        expected_txs = native_rows[0][epoch_rows[0]['epoch'] - 1]['txs']
        for row in epoch_rows[:2]:
            v.require([v.decode(tx) for tx in row['txs_json']] == expected_txs,
                      'Rust immutable ExEx transactions differ from actual native execution')
    creators = {row['creator'] for row in native_rows[0]}
    v.require(creators & rust_set and creators & native_set, 'both implementations must create finalized proposals')
    observed_signers = {signer for rows in all_rows for row in rows for signer in row['signers']}
    v.require(observed_signers == set(validators), 'every configured validator must actually sign finalized quorums')
    finalized = [tx for row in native_rows[0] for tx in row['txhashes']]
    v.require(all(finalized.count(tx) == 1 for tx in tx_hashes), 'submitted transfers absent/replayed')
    return {'epoch_count': expected_epoch, 'last_state_root': all_rows[0][-1]['state_root'],
        'last_txid_hi': all_rows[0][-1]['txid_hi'], 'creators': sorted(creators),
        'rust_creator_present': bool(creators & rust_set), 'native_creator_present': bool(creators & native_set),
        'every_qc_independently_ed25519_verified': True, 'every_qc_has_mixed_signers': True,
        'all_four_validators_signed_finalized_quorums': True, 'observed_signers': sorted(observed_signers),
        'submitted_transfers': tx_hashes, 'rust_exex_matches_native_transactions': True,
        'native_and_rust_standard_receipts_observed_empty': True}


def inside():
    evidence = Path('/evidence')
    v.require(evidence.is_dir() and not (evidence / 'report.json').exists(), 'fresh evidence required')
    expected = v.load('/mixed-fixture/expected.json')
    processes, files, stopped, steps, txs = {}, {}, [], [], []
    report = {'schema': 'octra_mixed_native_validator_runtime_v1', 'qualified': False,
        'source_sha256': expected['source_sha256'], 'native_pin': expected['native_pin'],
        'public_network_or_stock_launcher_qualified': False, 'private_or_circle_operations_qualified': False,
        'consensus_or_native_body_changes': False, 'host_adaptation': True}
    chain = Path('/state/network')
    barrier = Path('/state/barrier.json')

    def set_barrier(epoch):
        temporary = barrier.with_suffix('.staged')
        with temporary.open('x') as stream:
            json.dump({'max_epoch': epoch}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, barrier)
        steps.append({'barrier_max_epoch': epoch})

    def alive():
        v.require(all(child.poll() is None for child in processes.values()), 'mixed validator stopped unexpectedly')

    def statuses():
        alive()
        return [get('http://' + config['rpc'] + '/operator/status') for config in configs]

    def wait(fn, label, timeout=180):
        end, last = time.monotonic() + timeout, None
        while time.monotonic() < end:
            alive()
            try:
                result = fn()
                if result:
                    return result
            except (OSError, ValueError, KeyError, RuntimeError) as error:
                last = type(error).__name__ + ': ' + str(error)
            time.sleep(.1)
        raise RuntimeError(label + ' timed out: ' + str(last))

    def at_epoch(epoch):
        rows = statuses()
        v.require(all(row['epoch'] <= epoch for row in rows), 'native barrier finalized past target')
        return rows if all(row['epoch'] == epoch and row['serving'] is True for row in rows) else None

    def start_all(generation):
        for index, config in enumerate(configs):
            log = evidence / f'node-{index}-generation-{generation}.log'
            stream = log.open('xb')
            argv = (['/usr/local/bin/octra-node', 'run', '--config', str(chain / f'node-{index}/config.json')]
                    if index < 2 else ['/usr/local/bin/octra-native-mixed-host', '--config',
                        str(chain / f'node-{index}/config.json'), '--barrier', str(barrier)])
            processes[index] = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                start_new_session=True, env=child_environment)
            files[index] = stream

    def stop_all():
        identities = [(index, child) for index, child in processes.items()]
        for _, child in identities:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
        clean = True
        for index, child in identities:
            forced = False
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                forced = True
                v.require(os.getpgid(child.pid) == child.pid, 'owned process group differs')
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
            files[index].close()
            clean &= child.returncode == 0 and not forced
            stopped.append({'index': index, 'pid': child.pid, 'exit_code': child.returncode,
                            'forced': forced, 'reaped': child.poll() is not None})
        processes.clear()
        files.clear()
        return clean

    def transfer(label, amount):
        rows = statuses()
        v.require(rows[0]['serving'] is True, 'Rust canonical admission unavailable')
        value = v.decode(command(['/usr/local/bin/octra', 'cast', 'transfer', recipient, str(amount),
            '--key', str(faucet_hex), '--rpc-url', 'http://' + configs[0]['rpc'] + '/rpc',
            '--ou', '1000'], timeout=30, log=evidence / (label + '-submit.log'), environment=child_environment))
        def find(item):
            if type(item) is dict:
                if 'tx_hash' in item:
                    return item['tx_hash']
                for child in item.values():
                    found = find(child)
                    if found:
                        return found
            return None
        hash_ = find(value)
        v.require(type(hash_) is str and len(hash_) == 64 and len(bytes.fromhex(hash_)) == 32,
                  'transfer submission lacks exact hash')
        txs.append(hash_)
        steps.append({'submitted_transfer': hash_, 'amount': amount, 'recipient': recipient})
        return hash_

    def confirmed(hash_):
        result = rpc(configs[0], 'octra_transaction', [hash_])
        v.require(result.get('status') not in ['rejected', 'dropped'], 'submitted transfer rejected')
        return result if result.get('status') == 'confirmed' else None

    def native_audits(label):
        values = [get('http://' + configs[index]['rpc'] + '/fixture/audit') for index in [2, 3]]
        for index, value in zip([2, 3], values):
            save(evidence / f'{label}-native-{index}.json', value)
        return values

    try:
        child_environment = fixture_environment()
        report['child_environment'] = bound(evidence / 'child-environment.json')
        report['production_artifacts_before'] = worker_probe(expected)
        Path('/state').mkdir(exist_ok=True)
        command(['/usr/local/bin/octra-node', 'init-devnet', '--directory', str(chain), '--base-port', '27870'],
                log=evidence / 'init-devnet.log', environment=child_environment)
        genesis, configs, validators = v.verify_configs(chain)
        faucet_hex = Path('/state/faucet.hex')
        descriptor = os.open(faucet_hex, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write((chain / 'faucet.key').read_bytes().hex())
            stream.flush()
            os.fsync(stream.fileno())
        v.require(faucet_hex.stat().st_mode & 0o077 == 0, 'private CLI faucet permissions differ')
        recipient = genesis['validators'][2].split(':')[0]
        save(evidence / 'genesis.json', genesis)
        key_hashes = {str(Path(config['key']).relative_to(chain)): v.sha(config['key']) for config in configs}
        set_barrier(0)
        start_all(1)
        wait(lambda: all((chain / f'node-{index}/genesis-proof.json').exists() for index in [2, 3]), 'native genesis preparation')
        proofs = [v.verify_genesis_proof(genesis, v.load(chain / f'node-{index}/genesis-proof.json')) for index in [2, 3]]
        for index in [0, 1]:
            wait(lambda index=index: (chain / f'node-{index}/canonical.db').exists(), 'Rust genesis preparation')
        observed_genesis = wait(lambda: at_epoch(0), 'zero-height genesis agreement')
        v.require(all(row['state_root'] == v.genesis_root(genesis) for row in observed_genesis),
                  'actual four-way pre-vote genesis roots differ')
        report['four_way_pre_vote_status'] = observed_genesis
        report['independent_genesis'] = proofs
        set_barrier(2)
        wait(lambda: at_epoch(2), 'mixed initial quorums')
        first = transfer('phase-one', 1_000_000)
        set_barrier(8)
        wait(lambda: confirmed(first), 'first canonical transfer')
        statuses8 = wait(lambda: at_epoch(8), 'first barrier')
        native8 = native_audits('before-restart')
        report['independent_qc_negative_controls'] = v.qc_negative_controls(
            v.b64(native8[0]['history'][-1]['finalize_wire_b64']), validators, genesis['chain']['chain_id'])
        v.require(stop_all(), 'first shutdown was not clean')
        rust8 = [v.read_rust_store(chain / f'node-{i}', genesis, validators) for i in [0, 1]]
        report['before_restart'] = verify_history(genesis, validators, rust8, native8, 8, txs)
        save(evidence / 'before-restart-rust.json', rust8)
        save(evidence / 'before-restart-status.json', statuses8)
        start_all(2)
        wait(lambda: at_epoch(8), 'restart retained head')
        restarted = native_audits('after-restart')
        v.require(restarted == native8, 'native retained history mutated across restart')
        set_barrier(10)
        wait(lambda: at_epoch(10), 'postrestart mixed quorums')
        second = transfer('phase-two', 2_000_000)
        set_barrier(16)
        wait(lambda: confirmed(second), 'second canonical transfer')
        statuses16 = wait(lambda: at_epoch(16), 'final barrier')
        native16 = native_audits('final')
        v.require(stop_all(), 'final shutdown was not clean')
        rust16 = [v.read_rust_store(chain / f'node-{i}', genesis, validators) for i in [0, 1]]
        v.require(all(after[:8] == before for before, after in zip(rust8, rust16)), 'Rust retained prefix mutated')
        for before, after in zip(native8, native16):
            v.require(after['history'][:8] == before['history'], 'native retained prefix mutated')
        v.require(all(v.sha(chain / name) == expected_hash for name, expected_hash in key_hashes.items()), 'validator identity changed')
        report['final'] = verify_history(genesis, validators, rust16, native16, 16, txs)
        report['final_status'] = statuses16
        save(evidence / 'final-rust.json', rust16)
        report['production_artifacts_after'] = worker_probe(expected)
        v.require(report['production_artifacts_before'] == report['production_artifacts_after'], 'production artifact drift')
        report['qualified'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        traceback.print_exc()
    finally:
        if processes:
            report['cleanup_shutdown_clean'] = stop_all()
        report['stopped_processes'] = stopped
        report['all_owned_children_reaped'] = all(row['reaped'] for row in stopped) and not processes
        report['no_forced_stop'] = not any(row['forced'] for row in stopped)
        report['steps'] = steps
        report['qualified'] &= report['all_owned_children_reaped'] and report['no_forced_stop']
        save(evidence / 'report.json', report)
    return 0 if report['qualified'] else 1


def docker_inventory():
    return {key: command(argv, timeout=30).decode().splitlines() for key, argv in {
        'containers': ['docker', 'container', 'ls', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}}'],
        'networks': ['docker', 'network', 'ls', '--no-trunc', '--format', '{{.ID}} {{.Name}}'],
        'volumes': ['docker', 'volume', 'ls', '--format', '{{.Name}}']}.items()}


def outside(args):
    prepared = args.prepared.resolve(strict=True)
    preparation = v.load(prepared / 'preparation.json')
    context = prepared / 'context'
    expected = v.load(context / 'expected.json')
    for name, binding in preparation['context_files'].items():
        v.require(v.sha(context / name) == binding['sha256'], 'prepared input drift')
    output = args.output
    v.require(args.execute and output.is_absolute() and output.parent.resolve(strict=True) == output.parent
              and not output.exists(), 'explicit execution and fresh output required')
    output.mkdir(mode=0o700)
    (output / 'evidence').mkdir(mode=0o700)
    before = docker_inventory()
    save(output / 'resources-before.json', before)
    token = uuid.uuid4().hex
    label = 'org.octra.mixed-validator-qualification=' + token
    image_tag, name = 'octra-mixed-validator:' + token, 'octra-mixed-' + token
    container, result = None, {'schema': 'octra_mixed_validator_qualification_v1', 'qualified': False,
        'preparation': bound(prepared / 'preparation.json'), 'runner': bound(__file__), 'owner_label': label,
        'source_sha256': expected['source_sha256'], 'native_pin': expected['native_pin'],
        'stock_launcher_public_network_or_application_profile_qualification': False}

    def tag_identity(binding):
        value = v.decode(command(['docker', 'image', 'inspect', binding['tag']]))[0]['Id']
        v.require(value == binding['image_id'], 'local FROM/COPY tag identity differs')
        return {'tag': binding['tag'], 'image_id': value}

    try:
        result['from_tags_before'] = [tag_identity(expected[key]) for key in ['native_builder', 'rust_image']]
        command(['docker', 'build', '--label', label, '--build-arg', 'NATIVE_BUILDER=' + expected['native_builder']['tag'],
            '--build-arg', 'RUST_IMAGE=' + expected['rust_image']['tag'], '-t', image_tag, '-f', str(context / 'Dockerfile'),
            str(context)], timeout=1800, log=output / 'build.log')
        image_id = v.decode(command(['docker', 'image', 'inspect', image_tag]))[0]['Id']
        result['derived_image_id'] = image_id
        image_configuration = v.decode(command(['docker', 'image', 'inspect', image_id]))[0]['Config']
        v.require(not image_configuration.get('Volumes'), 'inherited anonymous volumes refused before create')
        container = command(['docker', 'create', '--name', name, '--label', label, '--network', 'none',
            '--mount', 'type=bind,source=' + str(output / 'evidence') + ',target=/evidence', image_id]).decode().strip()
        result['container_id'] = container
        created = v.decode(command(['docker', 'container', 'inspect', container]))[0]
        mounts = created['Mounts']
        v.require(created['Image'] == image_id and created['HostConfig']['NetworkMode'] == 'none'
                  and not created['HostConfig'].get('PortBindings')
                  and created['HostConfig'].get('PublishAllPorts') is False
                  and created['HostConfig'].get('Privileged') is False
                  and len(mounts) == 1 and mounts[0]['Type'] == 'bind'
                  and mounts[0]['Source'] == str(output / 'evidence')
                  and mounts[0]['Destination'] == '/evidence' and mounts[0]['RW'] is True,
                  'created fixture network/port/mount isolation differs')
        result['created_isolation'] = {'image_id': created['Image'], 'network_mode': 'none',
            'port_bindings': created['HostConfig'].get('PortBindings'), 'mounts': mounts,
            'anonymous_image_volumes': image_configuration.get('Volumes'), 'verified': True}
        command(['docker', 'start', container])
        code = int(command(['docker', 'wait', container], timeout=900).decode().strip())
        command(['docker', 'logs', container], log=output / 'container.log')
        report = v.load(output / 'evidence/report.json')
        result['child_report'] = bound(output / 'evidence/report.json')
        result['container_exit_code'] = code
        result['from_tags_after'] = [tag_identity(expected[key]) for key in ['native_builder', 'rust_image']]
        v.require(code == 0 and report['qualified'] is True and report['all_owned_children_reaped'] is True
                  and report['no_forced_stop'] is True, 'mixed runtime did not qualify')
        v.require(result['from_tags_before'] == result['from_tags_after'], 'local image tag changed')
        for relative, binding in preparation['context_files'].items():
            v.require(v.sha(context / relative) == binding['sha256'], 'prepared source changed during run')
        result['qualified'] = True
    except BaseException as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        traceback.print_exc()
    finally:
        try:
            # A create timeout may occur after Docker created the resource but
            # before it returned the CID. Recover only this unpredictable label.
            owned = command(['docker', 'container', 'ls', '-a', '--no-trunc', '--filter',
                             'label=' + label, '--format', '{{.ID}}']).decode().splitlines()
            if container:
                v.require(container in owned, 'concrete owned CID unexpectedly disappeared')
            removed_owned, absence = [], []
            for identifier in owned:
                inspected = v.decode(command(['docker', 'container', 'inspect', identifier]))[0]
                v.require(inspected['Config']['Labels'].get('org.octra.mixed-validator-qualification') == token,
                          'refuse cleanup of foreign container')
                if inspected['State']['Running']:
                    command(['docker', 'stop', '--time', '20', identifier], timeout=30)
                command(['docker', 'rm', identifier])
                absent = subprocess.run(['docker', 'container', 'inspect', identifier],
                                        capture_output=True, text=True, timeout=30)
                known = absent.returncode != 0 and any(term in absent.stderr.casefold()
                    for term in ['no such object', 'no such container'])
                absence.append({'container_id': identifier, 'exit_code': absent.returncode,
                                'stderr': absent.stderr, 'known_absent': known})
                removed_owned.append(identifier)
            remaining = command(['docker', 'container', 'ls', '-a', '--filter', 'label=' + label,
                                 '--format', '{{.ID}}']).decode().splitlines()
            after = docker_inventory()
            save(output / 'resources-after.json', after)
            added = {key: sorted(set(after[key]) - set(before[key])) for key in before}
            removed = {key: sorted(set(before[key]) - set(after[key])) for key in before}
            result['cleanup'] = {'removed_owned_containers': removed_owned, 'exact_absence': absence,
                'remaining_owned_containers': remaining, 'added_remaining': added,
                'removed_preexisting': removed,
                'verified': not remaining and not any(added.values()) and not any(removed.values())
                    and all(row['known_absent'] for row in absence)}
            result['qualified'] &= result['cleanup']['verified'] and container in removed_owned
        except BaseException as error:
            result['qualified'] = False
            result['cleanup'] = {'verified': False, 'error': type(error).__name__ + ': ' + str(error)}
        result['build_image_retained_as_evidence'] = image_tag
        save(output / 'report.json', result)
    print(json.dumps({'qualified': result['qualified'], 'report': bound(output / 'report.json')}))
    return 0 if result['qualified'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--prepared', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.inside:
        return inside()
    v.require(args.prepared is not None and args.output is not None, 'prepared/output required')
    return outside(args)


if __name__ == '__main__':
    raise SystemExit(main())
