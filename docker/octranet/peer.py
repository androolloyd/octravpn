"""TLS website proxy and normal application read inside a real Tailscale TUN."""
import http.client
import http.server
import json
import socket
import ssl
import urllib.request


class Proxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        conn = http.client.HTTPConnection('control.mesh.test', 20803, timeout=8)
        conn.request('GET', self.path, headers={'Host': self.headers.get('Host', '')})
        response = conn.getresponse()
        self.send_response(response.status)
        for key, value in response.getheaders():
            if key.lower() not in ('transfer-encoding', 'connection'):
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(response.read())

    def log_message(self, *args):
        pass


def main():
    import sys
    if sys.argv[1] == 'serve':
        server = http.server.ThreadingHTTPServer(('0.0.0.0', 443), Proxy)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('/config/cert.pem', '/config/tls.key')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
    elif sys.argv[1] == 'dns':
        print(json.dumps({'address': socket.gethostbyname(sys.argv[2])}))
    else:
        context = ssl.create_default_context(cafile='/config/ca.pem')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        with opener.open('https://octra.to/index.html', timeout=8) as response:
            print(json.dumps({'status': response.status, 'chain': response.headers.get('x-octra-chain'),
                              'epoch': response.headers.get('x-octra-epoch'), 'body': response.read(8192).decode()}))


if __name__ == '__main__':
    main()
