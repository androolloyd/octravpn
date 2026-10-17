#!/usr/bin/env python3
"""Read-only FHE diagnostics. A legacy response is not deployment qualification."""
import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import urllib.error
import urllib.request

WALLET = 'oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm'
PROGRAM = 'octaUNQtHpsmGrd4m4pftsjhE7zYwK4fVEgsDTKQ4BsXDRB'
METHOD = 'probe_addr_view'
LIMIT = 8 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('RPC redirect refused')


def unique(pairs):
    value = {}
    for key, entry in pairs:
        if key in value:
            raise ValueError('duplicate RPC JSON member')
        value[key] = entry
    return value


def rpc(endpoint, method, params):
    request = urllib.request.Request(endpoint, data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params,
    }).encode(), headers={'Content-Type': 'application/json', 'User-Agent': 'octra-canary/1.0'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=20) as response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('RPC response exceeds bound')
    envelope = json.loads(raw, object_pairs_hook=unique)
    if (not isinstance(envelope, dict) or envelope.get('jsonrpc') != '2.0'
            or type(envelope.get('id')) is not int or envelope['id'] != 1
            or ('error' in envelope) == ('result' in envelope)):
        raise ValueError('invalid RPC envelope')
    if 'error' in envelope:
        error = envelope['error']
        message = error.get('message') if isinstance(error, dict) else None
        raise ValueError(f'RPC error: {str(message)[:240]}')
    return envelope['result']


def check(endpoint, wallet=WALLET, program=PROGRAM, method=METHOD, call=rpc):
    status = {'schemaVersion': 1, 'label': 'fhe_load_pk', 'message': 'unverified',
              'color': 'lightgrey', 'bridge_status': 'inconclusive',
              'last_check': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'rpc_url': endpoint, 'wallet': wallet, 'program': program, 'method': method,
              'probes': {}, 'errors': {},
              'scope': 'Read-only legacy program diagnostic; no paid traffic, encrypted settlement or Mainnet qualification.'}

    def read(label, operation, params):
        try:
            return call(endpoint, operation, params)
        except (OSError, ValueError, urllib.error.URLError) as error:
            status['errors'][label] = str(error)[:300]
            return None

    public = read('baseline', 'octra_pvacPubkey', [wallet])
    raw = public.get('pvac_pubkey') if isinstance(public, dict) else None
    if not isinstance(raw, str) or not raw:
        status['probes']['baseline'] = 'inconclusive' if 'baseline' in status['errors'] else 'false'
        status['message'] = 'RPC unavailable' if 'baseline' in status['errors'] else 'test key not registered'
        status['errors'].setdefault('baseline', 'No registered PVAC key for the selected test wallet')
        return status
    try:
        decoded = base64.b64decode(raw, validate=True)
        if not decoded or len(decoded) > 5_000_000:
            raise ValueError('registered key size outside bound')
    except ValueError as error:
        status['errors']['baseline'] = str(error)
        return status
    status['probes']['baseline'] = 'true'
    status['public_key'] = {'bytes': len(decoded), 'sha256': hashlib.sha256(decoded).hexdigest()}
    info = read('program', 'vm_contract', [program])
    if not isinstance(info, dict) or not isinstance(info.get('code_hash'), str):
        status['message'] = 'probe program unavailable'
        return status
    status['code_hash'] = info['code_hash']
    abi = read('abi', 'octra_contractAbi', [program])
    methods = abi.get('methods') if isinstance(abi, dict) else None
    if not isinstance(methods, list) or not any(
            isinstance(entry, dict) and entry.get('name') == method and entry.get('view') is True
            for entry in methods):
        status['message'] = 'probe view unavailable'
        return status
    value = read('probe_load_pk', 'contract_call', [program, method, [wallet], wallet])
    if 'probe_load_pk' in status['errors']:
        status['probes']['probe_load_pk'] = 'inconclusive'
        if status['errors']['probe_load_pk'] == 'RPC error: execution reverted':
            status.update(bridge_status='blocked', message='probe reverts with registered key', color='yellow')
            status['probes']['probe_load_pk'] = 'false'
        return status
    if isinstance(value, dict):
        value = value.get('result')
    if value is None or value is False or value == '' or value == {} or value == []:
        status['errors']['probe_load_pk'] = 'Empty or unsuccessful result is not execution evidence'
        return status
    status['probes']['probe_load_pk'] = 'candidate'
    status.update(bridge_status='candidate', message='response observed; qualify bytecode', color='blue')
    status['result_sha256'] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpc', default='https://devnet.octrascan.io/rpc',
                        choices=['https://devnet.octrascan.io/rpc', 'https://octra.network/rpc'])
    parser.add_argument('--wallet', default=WALLET)
    parser.add_argument('--program', default=PROGRAM)
    parser.add_argument('--method', default=METHOD)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    status = check(args.rpc, args.wallet, args.program, args.method)
    args.output.write_text(json.dumps(status, indent=2) + '\n')
    print(json.dumps(status))


if __name__ == '__main__':
    main()
