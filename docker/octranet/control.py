"""Private four-validator node with embedded mesh and canonical website backend."""
import http.client
import http.server
import json
import pathlib
import signal
import subprocess
import threading
import urllib.request

ROOT = pathlib.Path('/state/chain')


def request(port, path, method='GET', body=None, admin=False):
    headers = {'Content-Type': 'application/json'}
    if admin:
        headers['Authorization'] = 'Bearer ' + pathlib.Path('/config/admin.token').read_text().strip()
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read()
    if response.status >= 400:
        raise RuntimeError(f'HTTP {response.status}: {data[:200]!r}')
    return json.loads(data)


def rpc(method, params):
    result = request(19871, '/rpc', 'POST', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}))
    if 'error' in result:
        raise RuntimeError(result['error'])
    return result['result']


class Gateway(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        conn = http.client.HTTPConnection('127.0.0.1', 19875, timeout=8)
        conn.request('GET', self.path, headers={'Host': self.headers.get('Host', '')})
        reply = conn.getresponse()
        self.send_response(reply.status)
        for key, value in reply.getheaders():
            if key.lower() not in ('transfer-encoding', 'connection'):
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(reply.read())

    def log_message(self, *args):
        pass


def main():
    if not ROOT.exists():
        subprocess.run(['octra-node', 'init-devnet', '--directory', str(ROOT), '--activated-applications'], check=True)
        for index in range(4):
            path = ROOT / f'node-{index}/config.json'
            config = json.loads(path.read_text())
            if index == 0:
                config['mesh'] = json.loads(pathlib.Path('/config/mesh.json').read_text())
                config['gateway'] = {'listen': '127.0.0.1:19875', 'origin': 'https://octra.to',
                                     'sites': {'octra.to': config['genesis']['circle']}}
            path.write_text(json.dumps(config))
    children = [subprocess.Popen(['octra-node', 'run', '--config', str(ROOT / f'node-{index}/config.json')]) for index in range(4)]
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 20803), Gateway)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        while not stopped.wait(.2):
            if any(child.poll() is not None for child in children):
                raise RuntimeError('native validator exited')
    finally:
        server.shutdown()
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        payload = json.load(sys.stdin)
        if sys.argv[1] == 'rpc':
            value = rpc(payload['method'], payload.get('params', []))
        else:
            value = request(51821, payload['path'], payload.get('method', 'GET'), payload.get('body'), True)
        print(json.dumps(value))
    else:
        main()
