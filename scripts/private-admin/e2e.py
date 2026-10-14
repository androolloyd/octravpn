#!/usr/bin/env python3
"""Fresh private credentials -> real prover -> unchanged native AML host + worker.

Native contract deployment, factory spawning, metadata upgrade policy, journal
rollback and Irmin persistence are exercised. This is an activated-profile VM
host integration, not a public-chain transaction/deployment certification.
Balances and the terminal-nonce seeding operation are explicit test fixtures.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prover', type=pathlib.Path, default=ROOT/'target/release/octravpn-private-admin')
    parser.add_argument('--image', default='octra-private-admin-vm')
    parser.add_argument('--setup', type=pathlib.Path, help='Optional existing DEVELOPMENT setup')
    parser.add_argument('--evidence', type=pathlib.Path, required=True)
    args = parser.parse_args()
    prover = args.prover.resolve(strict=True)
    evidence = {'passed': False, 'scope': 'native activated-profile VM; unchanged consensus; fixture balances',
                'checks': [], 'source_sha256': hashlib.sha256((ROOT/'program/main-v5.aml').read_bytes()).hexdigest(),
                'factory_sha256': hashlib.sha256((ROOT/'program/private-admin-factory.aml').read_bytes()).hexdigest()}
    records = evidence['checks']
    host = None
    with tempfile.TemporaryDirectory(prefix='octra-private-admin-e2e-') as raw:
        work = pathlib.Path(raw)
        setup = args.setup or work/'setup'
        def command(*parts):
            result = subprocess.run([str(p) for p in parts], check=True, capture_output=True, text=True)
            return result.stdout.strip()
        if not args.setup:
            command(prover, 'setup', '--development', '--out', setup)
        manifest = json.loads((setup/'manifest.json').read_text())
        assert manifest['development_only'] is True and manifest['production_ready'] is False
        evidence['setup'] = {k: manifest[k] for k in ('circuit', 'verification_key_sha256', 'development_only')}
        commitments = {}
        for role in ('a', 'b', 'c', 'outsider'):
            commitments[role] = json.loads(command(prover, 'credential', '--out', work/f'{role}.credential'))['commitment']
            assert (work/f'{role}.credential').stat().st_mode & 0o777 == 0o600
        state = work/'state'
        state.mkdir()
        domain = hashlib.sha256(b'OctraVPN private admin native VM fixture domain v1').hexdigest()
        deployer = 'oct' + '1'*44
        relay = 'oct' + '2'*44
        another_relay = 'oct' + '3'*44
        circle = 'oct' + '4'*44
        payout = 'oct' + '5'*44
        count = 0
        def start():
            return subprocess.Popen(['docker', 'run', '--rm', '--init', '-i', '--network', 'none', '--read-only',
                '--user', '0', '--tmpfs', '/tmp', '-v', f'{ROOT}:/vpn:ro', '-v', f'{state}:/state', args.image,
                '/vpn/program/main-v5.aml', '/vpn/program/private-admin-factory.aml', '/state'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=host_log, text=True, bufsize=1)
        def stop():
            nonlocal host
            if host:
                host.stdin.close()
                host.wait(timeout=30)
                assert host.returncode == 0
                host = None
        def rpc(op, **params):
            host.stdin.write(json.dumps({'op': op, **params})+'\n'); host.stdin.flush()
            line = host.stdout.readline()
            if not line:
                raise RuntimeError('native VM adapter stopped; inspect native-host.log')
            result = json.loads(line)
            if isinstance(result, dict) and 'adapter_error' in result:
                raise RuntimeError(result['adapter_error'])
            return result
        def check(name, condition):
            if not condition:
                raise AssertionError(name)
            records.append(name)
            print('PASS:', name, flush=True)
        def call(method, params, address=None, **extras):
            return rpc('call', address=address or program, caller=extras.pop('caller', relay), method=method, params=params, **extras)
        def view(method, address=None):
            result = call(method, [], address)
            assert result['success'], result
            return result['result']
        def nonce():
            return int(view('get_admin_nonce'))
        def authorize(role, method, params, n=None, address=None, realm=None):
            nonlocal count
            count += 1
            request = work/f'request-{count}.json'
            output = work/f'authorization-{count}.json'
            request.write_text(json.dumps({'method': method, 'params': params}))
            command(prover, 'authorize', '--credential', work/f'{role}.credential', '--proving-key', setup/'proving-key.bin',
                '--request', request, '--domain', realm or domain, '--program', address or program,
                '--nonce', nonce() if n is None else n, '--out', output)
            result = json.loads(output.read_text())
            # Neither secret bytes nor their hexadecimal rendering may enter any proof package.
            secret = (work/f'{role}.credential').read_bytes()
            assert secret.hex() not in output.read_text() and base64.b64encode(secret).decode() not in output.read_text()
            return result
        def send(auth, **extras):
            return call(auth['method'], auth['params'], **extras)
        def reject(name, auth, reason=None, **extras):
            previous = rpc('storage', address=extras.get('address') or program)
            result = send(auth, **extras)
            reasons = [v for e in result.get('events', []) if e['name'] == 'Require' for v in e['values']]
            check(name, result['success'] is False and (reason is None or reason in reasons))
            check(name+' leaves storage unchanged', previous == rpc('storage', address=extras.get('address') or program))
        def success(name, auth, **extras):
            result = send(auth, **extras)
            check(name, result['success'] is True and result['result'] is True)
            return result
        def spawn(realm):
            result = rpc('spawn', factory=factory, caller=deployer,
                params=[1, 1, 100_000_000, 10, 1000, commitments['a'], manifest['verification_key_b64'], realm, 200_000_000])['receipt']
            assert result['success'], result
            deployed = [e['values'][0] for e in result['events'] if e['name'] == 'VPNDeployed']
            assert deployed == [result['result']], 'native chain receipts need the explicit child-address event'
            return result['result']
        def mutate(auth, index, value):
            changed = dict(auth, params=list(auth['params']))
            changed['params'][index] = value
            return changed

        host_log_path = args.evidence.with_suffix('.native-host.log')
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        with host_log_path.open('w') as host_log:
            try:
                host = start()
                result = rpc('deploy_factory', caller=deployer)
                assert result['receipt']['success'], result
                factory = result['address']
                program = spawn(domain)
                twin = spawn(domain)
                other_domain = hashlib.sha256(b'other network/genesis fixture').hexdigest()
                foreign = spawn(other_domain)
                evidence.update(program=program, factory=factory, domain=domain, metadata=rpc('metadata', address=program))
                check('native factory owns upgrade metadata', evidence['metadata']['owner'] == factory)
                check('deployer cannot bypass private administration by native upgrade', rpc('upgrade', address=program, caller=deployer)['success'] is False)
                check('relayer cannot upgrade child', rpc('upgrade', address=program, caller=relay)['success'] is False)
                storage = rpc('storage', address=program)
                check('public program owner removed', 'owner' not in storage and call('get_owner', [])['success'] is False)
                check('immutable circuit verification key is pinned', view('get_admin_verification_key_hash') == hashlib.sha256(manifest['verification_key_b64'].encode()).hexdigest())
                check('recipient creates a fresh private credential', len(set(commitments.values())) == 4)
                auth = authorize('a', 'set_paused', [1])
                reject('cross-program replay rejected', auth, 'invalid admin proof', address=twin)
                foreign_auth = authorize('a', 'set_paused', [1], n=0, address=foreign, realm=domain)
                reject('cross-network domain replay rejected', foreign_auth, 'invalid admin proof', address=foreign)
                reject('parameter substitution rejected', mutate(auth, 0, 0), 'invalid admin proof')
                tag = auth['params'][-2]
                reject('action tag mutation rejected', mutate(auth, -2, ('0' if tag[0] != '0' else '1')+tag[1:]), 'invalid admin proof')
                proof = bytearray(base64.b64decode(auth['params'][-1])); proof[-1] ^= 1
                reject('proof mutation rejected', mutate(auth, -1, base64.b64encode(proof).decode()), 'invalid admin proof')
                reject('noncanonical digest rejected', mutate(auth, -2, tag.upper()), 'invalid admin digest')
                reject('outsider cannot administer', authorize('outsider', 'set_paused', [1]), 'invalid admin proof')
                reject('prior profile refuses proof operations', auth, profile='prior')
                success('native activated-profile proof succeeds through independent relayer', auth, caller=another_relay)
                reject('exact replay rejected', auth, 'admin nonce mismatch')
                reject('rerandomized proof cannot replay old nonce', authorize('a', 'set_paused', [1], n=0), 'admin nonce mismatch')
                success('private admin can unpause', authorize('a', 'set_paused', [0]))

                success('private handoff proposed', authorize('a', 'propose_admin', [commitments['b'], 0]))
                handoff = view('get_admin_handoff_id')
                queued_accept = authorize('b', 'accept_admin', [commitments['b'], handoff])
                reject('ordinary governance freezes during pending handoff', authorize('a', 'set_paused', [1]), 'admin handoff pending')
                reject('wrong recipient cannot accept', authorize('c', 'accept_admin', [commitments['b'], handoff]), 'invalid admin proof')
                reject('sender cannot impersonate recipient', authorize('a', 'accept_admin', [commitments['b'], handoff]), 'invalid admin proof')
                reject('outsider cannot cancel handoff', authorize('outsider', 'cancel_admin', [handoff]), 'invalid admin proof')
                success('current credential can cancel pending handoff', authorize('a', 'cancel_admin', [handoff]))
                reject('cancelled acceptance cannot execute', queued_accept, 'no admin handoff')
                success('fresh proposal after cancellation', authorize('a', 'propose_admin', [commitments['b'], 0]))
                next_handoff = view('get_admin_handoff_id')
                check('reproposal gets a new handoff identifier', next_handoff != handoff)
                reject('cancelled handoff cannot hijack a later proposal', authorize('b', 'accept_admin', [commitments['b'], handoff]), 'admin handoff mismatch')
                accepted = authorize('b', 'accept_admin', [commitments['b'], next_handoff])
                success('recipient proves acceptance and replaces administration atomically', accepted)
                check('private handoff changes commitment and clears pending state', view('get_admin_commitment') == commitments['b'] and view('get_pending_admin_commitment') == '')
                reject('accepted handoff cannot replay', accepted, 'no admin handoff')
                reject('old credential revoked even with fresh nonce', authorize('a', 'set_paused', [1]), 'invalid admin proof')
                success('recipient now administers', authorize('b', 'set_paused', [1]))
                success('credential rotation proposed', authorize('b', 'propose_admin', [commitments['c'], 1]))
                check('rotation records its purpose', int(view('get_admin_handoff_kind')) == 1)
                success('fresh rotation credential accepted', authorize('c', 'accept_admin', [commitments['c'], view('get_admin_handoff_id')]))
                reject('rotated credential revoked', authorize('b', 'set_paused', [0]), 'invalid admin proof')
                success('fresh credential administers after rotation', authorize('c', 'set_paused', [0]))
                reject('same credential rotation rejected', authorize('c', 'propose_admin', [commitments['c'], 1]), 'admin credential must change')

                reject('retired initial credential cannot be reused', authorize('c', 'propose_admin', [commitments['a'], 1]), 'admin credential already used')
                reject('retired recipient credential cannot be reused', authorize('c', 'propose_admin', [commitments['b'], 0]), 'admin credential already used')

                params = [1, 1, 10, 10, 100, 100_000_000, 1000, 9000, 1000, 0]
                auth = authorize('c', 'set_params', params)
                for i, value in enumerate(params):
                    reject(f'governance parameter {i} bound', mutate(auth, i, value+1), 'invalid admin proof')
                success('all ten governance parameters authorized together', auth)
                commission = params.copy()
                commission[-1] = 50
                reject('private admin cannot enable protocol commission', authorize('c', 'set_params', commission), 'protocol fee disabled')
                reject('business-rule failure rolls nonce back', authorize('c', 'set_paused', [2]), 'p must be 0 or 1')
                auth = authorize('c', 'approve_circle_registration', [circle, deployer])
                reject('operator approval binds circle', mutate(auth, 0, payout), 'invalid admin proof')
                reject('operator approval binds operator', mutate(auth, 1, relay), 'invalid admin proof')
                success('private administration approves operator', auth)
                rpc('fund_fixture', address=deployer, amount=100_000_000)
                result = call('register_circle', [circle, 'a'*64, 'fixture-receipt-key'], caller=deployer, value=100_000_000)
                check('native AML stake registration uses private-admin approval', result['success'])
                reject('private governance cannot replace a registered operator', authorize('c', 'approve_circle_registration', [circle, relay]), 'circle already registered')
                check('canary cap is immutable constructor state', int(view('get_max_locked_value')) == 200_000_000)
                rpc('fund_fixture', address=deployer, amount=100_000_001)
                before_storage = rpc('storage', address=program)
                before_balance = int(rpc('balance', address=program))
                result = call('create_tailnet', ['b'*64], caller=deployer, value=100_000_001)
                check('funding over 200 OCT cap reverts', not result['success'])
                check('cap failure restores attached value and storage', before_storage == rpc('storage', address=program) and int(rpc('balance', address=program)) == before_balance and int(rpc('balance', address=deployer)) == 100_000_001)
                result = call('create_tailnet', ['b'*64], caller=deployer, value=100_000_000)
                check('exact 200 OCT boundary accepts attached value once', result['success'] and int(rpc('balance', address=program)) == 200_000_000)
                tailnet = int(result['result'])
                result = call('deposit_to_tailnet', [tailnet], caller=deployer, value=1)
                check('tailnet topup cannot bypass cap', not result['success'] and int(rpc('balance', address=program)) == 200_000_000)
                success('pause canary for recovery rehearsal', authorize('c', 'set_paused', [1]))
                check('tailnet can retire while paused', call('retire_tailnet', [tailnet], caller=deployer)['success'])
                check('tailnet funds recover while paused', call('withdraw_tailnet_treasury', [tailnet, 100_000_000], caller=deployer)['success'] and int(rpc('balance', address=program)) == 100_000_000)
                success('resume after recovery rehearsal', authorize('c', 'set_paused', [0]))
                auth = authorize('c', 'gov_slash_operator', [circle, payout])
                reject('relayer cannot redirect slash bounty', mutate(auth, 1, relay), 'invalid admin proof')
                reject('failed bounty transfer rolls back credential nonce and slash state', auth, 'bounty transfer failed', fail_transfer=True)
                success('same authorization succeeds after host transfer recovers', auth, caller=another_relay)
                check('slash bounty goes to proven beneficiary', int(rpc('balance', address=payout)) == 10_000_000 and int(rpc('balance', address=another_relay)) == 0)
                auth = authorize('c', 'withdraw_program_treasury', [payout, 1000])
                reject('treasury recipient bound', mutate(auth, 0, relay), 'invalid admin proof')
                reject('treasury amount bound', mutate(auth, 1, 1001), 'invalid admin proof')
                reject('failed treasury transfer rolls nonce and funds back', auth, 'transfer failed', fail_transfer=True)
                success('private admin treasury withdrawal succeeds', auth)
                check('treasury accounting and native host payout agree', int(view('get_program_treasury')) == 89_999_000 and int(rpc('balance', address=payout)) == 10_001_000)
                queued_a = authorize('c', 'set_paused', [0])
                queued_b = authorize('c', 'set_paused', [1])
                success('one authorization wins a nonce race', queued_a)
                reject('second authorization at the same nonce loses', queued_b, 'admin nonce mismatch')
                persisted_nonce = nonce()
                stop(); host = start()
                check('commitment and nonce survive native store restart', nonce() == persisted_nonce and view('get_admin_commitment') == commitments['c'])
                reject('replay remains rejected after restart', queued_a, 'admin nonce mismatch')
                success('fresh credential works after restart', authorize('c', 'set_paused', [0]))
                current = authorize('c', 'set_paused', [0])
                rpc('seed_nonce_fixture', address=program, nonce=str(2**64-1))
                reject('u64 terminal nonce fails closed without wrapping', mutate(current, -3, 2**64-1), 'admin nonce exhausted')
                storage = rpc('storage', address=program)
                check('private witnesses absent from persisted state', all((work/f'{role}.credential').read_bytes().hex() not in json.dumps(storage) for role in commitments))
                evidence['passed'] = True
                evidence['checks_count'] = len(records)
                evidence['final_nonce'] = nonce()
                stop()
            finally:
                if host:
                    host.stdin.close()
                    try:
                        host.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        host.terminate(); host.wait(timeout=10)
                args.evidence.write_text(json.dumps(evidence, indent=2)+'\n')
    print(f"PASS: {len(records)} checks; evidence: {args.evidence}")


if __name__ == '__main__':
    main()
