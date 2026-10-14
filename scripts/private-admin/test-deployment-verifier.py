#!/usr/bin/env python3
"""Exercise the read-only deployment verifier against native-shaped RPC replies."""
import http.server
import json
import pathlib
import subprocess
import threading

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROGRAM = 'oct'+'1'*44
FACTORY = 'oct'+'2'*44
CODE = 'a'*64
FACTORY_CODE = 'b'*64
COMMITMENT = 'c'*64
DOMAIN = 'd'*64
KEY_HASH = 'e'*64
state = {}
calls = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method, params = request['method'], request['params']
        calls.append((method, params))
        if method == 'vm_contract':
            result = {'code_hash': state['factory_code']} if params[0] == FACTORY else {'code_hash': CODE, 'owner': state['metadata_owner']}
        elif method == 'contract_call':
            result = {'result': state[params[1]]}
        else:
            raise AssertionError('verifier attempted a non-read operation')
        body = json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)


with http.server.HTTPServer(('127.0.0.1', 0), Handler) as server:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command = ['python3', str(ROOT/'scripts/ceremony/verify-deployment.py'), PROGRAM,
               '--rpc-url', f'http://127.0.0.1:{server.server_port}', '--expected-code-hash', CODE,
               '--expected-admin-commitment', COMMITMENT, '--expected-admin-domain', DOMAIN,
               '--expected-admin-verification-key-hash', KEY_HASH, '--expected-factory', FACTORY,
               '--expected-max-locked-value', '200000000', '--expected-factory-code-hash', FACTORY_CODE]
    valid = {'metadata_owner': FACTORY, 'factory_code': FACTORY_CODE,
             'get_admin_commitment': COMMITMENT, 'get_admin_domain': DOMAIN,
             'get_admin_verification_key_hash': KEY_HASH, 'get_pending_admin_commitment': '', 'get_max_locked_value': '200000000'}
    state.update(valid)
    assert subprocess.run(command, capture_output=True).returncode == 0
    assert not any(params[1] == 'get_owner' for method, params in calls if method == 'contract_call')
    for field in valid:
        state.clear(); state.update(valid); state[field] = 'wrong'
        result = subprocess.run(command, capture_output=True)
        assert result.returncode != 0, f'verifier accepted wrong {field}'
    state.clear(); state.update(valid)
    assert subprocess.run(command[:-2], capture_output=True).returncode != 0
    server.shutdown(); thread.join()
print('PASS: private deployment verification; seven state/metadata mutations and missing factory evidence rejected')
