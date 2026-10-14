#!/usr/bin/env python3
"""Real native AML money tests on an isolated private Single chain only.

Deploys v4 plus one fixture method that matures an unbond. It changes no
production method, clock, consensus engine, activation plan or epoch rule.
The fixture artifact is never a deploy candidate. The harness creates a real native circle and verifies its owner before governance
approves registration.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpc', required=True)
    parser.add_argument('--octra', required=True, type=pathlib.Path)
    parser.add_argument('--devkeys', required=True, type=pathlib.Path)
    parser.add_argument('--evidence', required=True, type=pathlib.Path)
    args = parser.parse_args()
    url = urllib.parse.urlparse(args.rpc)
    if url.hostname not in ('127.0.0.1', 'localhost', '::1') or url.scheme != 'http':
        raise SystemExit('Native fixture tests require an explicit loopback HTTP endpoint')

    def rpc(method, params):
        req = urllib.request.Request(args.rpc, data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(), headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.load(response)
        if data.get('id') != 1 or 'error' in data or 'result' not in data:
            raise RuntimeError(f'{method}: {data}')
        return data['result']

    profile = rpc('octra_runtimeVersion', [])
    if not profile.get('chain_id', '').startswith('octra-local-'):
        raise SystemExit('Refusing public/unknown chain: isolated octra-local-* required')
    records = []
    with tempfile.TemporaryDirectory(prefix='octra-native-v4-') as directory:
        directory = pathlib.Path(directory)
        wallets = []
        # Only genesis key 0 is a validator. Other actors are fresh accounts so
        # epoch emissions cannot mask missing transfers in balance-delta checks.
        genesis = json.loads(subprocess.check_output([str(args.devkeys), 'wallet-json', '0']))
        key = directory / 'public-devkey-0.key'
        key.write_text(base64.b64decode(genesis['priv']).hex())
        key.chmod(0o600)
        wallets.append((key, genesis['address'], genesis['pub']))
        for i in range(1, 4):
            key = directory / f'actor-{i}.key'
            subprocess.check_output([str(args.octra), 'cast', 'wallet', 'new', '--out', str(key)])
            key.chmod(0o600)
            address = subprocess.check_output([str(args.octra), 'cast', 'wallet', 'addr', '--key', str(key)]).decode().strip()
            public = subprocess.check_output([str(args.octra), 'cast', 'wallet', 'pubkey', '--key', str(key)]).decode().strip()
            funded = json.loads(subprocess.check_output([str(args.octra), 'cast', 'transfer', address, '1000000000', '--key', str(wallets[0][0]), '--rpc-url', args.rpc, '--ou', '1000']))
            until = time.monotonic() + 60
            while rpc('octra_transaction', [funded['tx_hash']]).get('status') != 'confirmed':
                if time.monotonic() >= until:
                    raise RuntimeError('funding failed to confirm')
                time.sleep(0.5)
            wallets.append((key, address, public))
        source = (ROOT / 'program/main-v4.aml').read_text()
        fixture = directory / 'v4-native-fixture.aml'
        fixture.write_text(source.rstrip().removesuffix('}') + '''
  // Test-only fixture. Never deploy this artifact outside the isolated chain.
  fn test_mature_unbond(circle: address): bool {
    require(caller == self.owner, "fixture owner only")
    self.circle_unbond_unlock_epoch[circle] = epoch
    return true
  }
}
''')
        deploy = json.loads(subprocess.check_output([str(args.octra), 'forge','create',str(fixture),'--key',str(wallets[0][0]),'--rpc-url',args.rpc,'--constructor-args','100','1000','100000000','2','1000']))
        assert deploy['confirmed'] is True
        program = deploy['address']
        records.append({'method':'deploy','tx_hash':deploy['tx_hash'],'success':True})

        def view(method, *params):
            result = rpc('contract_call', [program, method, list(params)])
            assert isinstance(result, dict) and 'result' in result, result
            value = result['result']
            return int(value) if isinstance(value, str) and value.isdecimal() else value

        def send(index, method, *params, value=0, revert=None):
            argv = [str(args.octra),'cast','send','--key',str(wallets[index][0]),'--rpc-url',args.rpc,'--fee','1000','--value',str(value),program,method]
            argv.extend(json.dumps(param, separators=(',',':')) for param in params)
            submitted = json.loads(subprocess.check_output(argv))
            tx_hash = submitted['tx_hash']
            receipt = None
            until = time.monotonic() + 60
            while time.monotonic() < until:
                try:
                    receipt = rpc('contract_receipt', [tx_hash])
                    break
                except RuntimeError as error:
                    if 'receipt not found' not in str(error):
                        raise
                time.sleep(0.5)
            assert isinstance(receipt, dict), f'No execution receipt: {tx_hash}'
            if revert:
                assert receipt['success'] is False, receipt
                reasons = [event.get('values') for event in receipt.get('events', []) if event.get('event') == 'Require']
                assert [revert] in reasons, receipt
            else:
                assert receipt['success'] is True, receipt
            records.append({'method':method,'tx_hash':tx_hash,'success':receipt['success'], 'expected_revert':revert,'epoch':receipt.get('epoch')})
            print(f'PASS {method}' + (f' rejects {revert}' if revert else ''), flush=True)
            return receipt

        governor, operator, client, attacker = [wallet[1] for wallet in wallets]
        circle_deploy = json.loads(subprocess.check_output([str(args.octra), 'cast', 'circle', 'deploy', '--key', str(wallets[1][0]), '--rpc-url', args.rpc]))
        circle = circle_deploy['circle_id']
        until = time.monotonic() + 60
        while True:
            try:
                info = rpc('circle_info', [circle])
                break
            except RuntimeError as error:
                if 'circle not found' not in str(error) or time.monotonic() >= until:
                    raise
                time.sleep(0.5)
        assert info['owner'] == operator, info
        assert view('get_owner') == governor
        send(3, 'approve_circle_registration', circle, attacker, revert='not owner')
        send(1, 'register_circle', circle, 'ab'*32, wallets[1][2], value=100_000_000, revert='registration not approved')
        send(0, 'approve_circle_registration', circle, operator)
        send(3, 'register_circle', circle, 'ab'*32, wallets[3][2], value=100_000_000, revert='not approved circle owner')
        send(1, 'register_circle', circle, 'ab'*32, wallets[1][2], value=100_000_000)
        assert view('endpoint_stake_of', circle) == 100_000_000
        send(2, 'create_tailnet', 'cd'*32, value=1000)
        send(2, 'open_session', 0, circle, 1000, value=1000)
        assert view('get_circle_open_sessions', circle) == 1
        send(1, 'unbond_endpoint', circle, revert='retire circle before unbonding')
        send(1, 'settle_claim', 0, 5)
        send(2, 'settle_confirm', 0, 5, 600, 'settle-native')
        assert view('get_circle_open_sessions', circle) == 0
        assert view('get_earnings_total', circle) == 600
        send(2, 'settle_confirm', 0, 5, 600, 'settle-native', revert='session not open')
        before_earnings = int(rpc('octra_balance', [operator])['balance_raw'])
        send(1, 'claim_earnings', circle, 600)
        after_earnings = int(rpc('octra_balance', [operator])['balance_raw'])
        assert after_earnings - before_earnings == 600 - 1000
        assert view('get_earnings_claimed', circle) == view('get_earnings_total', circle)
        # Actual host transfer must credit earnings minus this transaction's fee.
        # Relay claim credits the full traffic payment and closes the stake liability.
        preimage = 'native-escrow-preimage'
        commitment = hashlib.sha256(preimage.encode()).hexdigest()
        send(2, 'open_relay_session', 0, circle, 1000, commitment, 600, 100, value=1000)
        send(3, 'relay_claim', 1, preimage, revert='not circle owner')
        send(1, 'relay_claim', 1, preimage)
        assert view('get_earnings_total', circle) == 1200
        assert view('get_session_status', 1) == 4
        assert view('get_circle_open_sessions', circle) == 0
        send(2, 'open_session', 0, circle, 1000, value=1000)
        send(1, 'retire_circle', circle)
        send(1, 'unbond_endpoint', circle)
        send(1, 'finalize_unbond', circle, revert='funded sessions still open')
        send(3, 'register_circle', circle, 'ef'*32, wallets[3][2], value=100_000_000, revert='not approved circle owner')
        send(2, 'claim_no_show', 2)
        assert view('get_circle_open_sessions', circle) == 0
        send(1, 'finalize_unbond', circle, revert='unbond grace not elapsed')
        send(0, 'test_mature_unbond', circle)
        before = rpc('octra_balance', [operator])
        send(1, 'finalize_unbond', circle)
        after = rpc('octra_balance', [operator])
        assert view('endpoint_stake_of', circle) == 0
        # Balance strings are display values; exact deltas are checked via decimal units.
        def units(balance):
            return int(balance['balance_raw'])
        assert units(after) - units(before) == 100_000_000 - 1000, (before, after)
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps({'scope':'native host money paths under private prior profile; test-only maturity fixture', 'source_sha256':hashlib.sha256(source.encode()).hexdigest(), 'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(), 'runtime':profile,'program':program,'records':records,'pass':True},indent=2)+'\n')
        print(f'Native money paths PASS; evidence={args.evidence}', flush=True)

if __name__ == '__main__':
    main()
