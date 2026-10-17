"""Bounded, loopback-only control fault injection for the isolated payment gate.

This fixture independently delays usage and status without changing signed
bodies. It grants no admission itself and is not a deployable control service.
"""

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import time


BODY_LIMIT = 131_072
ROUTES = frozenset(('/payments/connect', '/payments/status', '/payments/usage'))


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 32

    def __init__(self, proxy, port):
        self.proxy = proxy
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(('127.0.0.1', port), _Handler)

    def process_request(self, request, client_address):
        # Bound threads before ThreadingMixIn starts one, including slow bodies
        # and held usage requests. Status requests use independent workers.
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b'HTTP/1.0 503 Service Unavailable\r\n'
                                b'Content-Length: 0\r\nConnection: close\r\n\r\n')
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        if not self.proxy._track(request):
            self.slots.release()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.proxy._untrack(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.proxy._untrack(request)
            self.slots.release()

    def handle_error(self, request, client_address):
        # No request bodies, signatures, or socket exceptions enter logs.
        self.proxy._count('errors')


class _Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, _format, *args):
        pass

    def _reply(self, status, body=b'', content_type='application/json'):
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Type', content_type)
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass  # Cancellation/disconnect cannot cause another submission.

    def _method_refused(self):
        self._reply(405)

    do_GET = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _method_refused

    def do_POST(self):
        proxy = self.server.proxy
        if self.path not in ROUTES:
            self._reply(404)
            return
        lengths = self.headers.get_all('Content-Length', [])
        if self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Content-Encoding'):
            self._reply(400)
            return
        if not lengths:
            self._reply(411)
            return
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            self._reply(400)
            return
        if len(lengths[0]) > 6:
            self._reply(413)
            return
        length = int(lengths[0])
        if length > BODY_LIMIT:
            self._reply(413)
            return
        if self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower() != 'application/json':
            self._reply(415)
            return
        try:
            body = self.rfile.read(length)
        except (OSError, socket.timeout):
            self._reply(408)
            return
        if len(body) != length:
            self._reply(400)
            return
        kind = 'usage' if self.path == '/payments/usage' else 'status'
        gate = proxy._gate if kind == 'usage' else proxy._status_gate
        proxy._count(kind + '_received')
        if not proxy._wait(gate, kind):
            self._reply(503)
            return
        upstream = http.client.HTTPConnection('127.0.0.1', proxy.upstream_port, timeout=5)
        channel = None
        try:
            # HTTPConnection has neither redirects nor environment proxy support.
            # Signed request and response bytes are forwarded without decoding.
            upstream.connect()
            channel = upstream.sock
            channel.settimeout(60)
            if not proxy._track(channel):
                self._reply(503)
                return
            if not gate.is_set():
                proxy._count(kind + '_refused')
                self._reply(503)
                return
            upstream.request('POST', self.path, body=body,
                             headers={'Content-Type': 'application/json', 'Connection': 'close'})
            proxy._count(kind + '_forwarded')
            response = upstream.getresponse()
            raw = response.read(BODY_LIMIT + 1)
            if len(raw) > BODY_LIMIT:
                raise ValueError('upstream response exceeds fixture bound')
            self._reply(response.status, raw, response.getheader('Content-Type', 'application/json'))
        except (OSError, http.client.HTTPException, ValueError):
            proxy._count('errors')
            self._reply(502)
        finally:
            if channel is not None:
                proxy._untrack(channel)
            upstream.close()


class ControlProxy:
    """Start with usage held and status released; both gates are independent."""

    def __init__(self, port=19879, upstream_port=19873):
        if not (0 <= port <= 65535 and 1 <= upstream_port <= 65535):
            raise ValueError('invalid loopback fixture port')
        self.upstream_port = upstream_port
        self._gate = threading.Event()
        self._status_gate = threading.Event()
        self._status_gate.set()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._channels = set()
        self._counts = {'usage_received': 0, 'usage_forwarded': 0, 'usage_refused': 0,
                        'status_received': 0, 'status_forwarded': 0, 'status_refused': 0,
                        'status_waiting': 0, 'errors': 0}
        self._server = _Server(self, port)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={'poll_interval': .1}, daemon=True,
                                        name='payment-control-proxy')
        self._thread.start()

    def _count(self, name, delta=1):
        with self._lock:
            self._counts[name] += delta

    def _wait(self, gate, kind):
        deadline = time.monotonic() + 60
        waiting = False
        try:
            while not gate.is_set():
                if kind == 'status' and not waiting:
                    self._count('status_waiting')
                    waiting = True
                if self._stop.is_set() or time.monotonic() >= deadline:
                    self._count(kind + '_refused')
                    return False
                gate.wait(min(.1, max(0, deadline - time.monotonic())))
            if self._stop.is_set():
                self._count(kind + '_refused')
                return False
            return True
        finally:
            if waiting:
                self._count('status_waiting', -1)

    def _track(self, channel):
        with self._lock:
            if self._stop.is_set():
                return False
            self._channels.add(channel)
            return True

    def _untrack(self, channel):
        with self._lock:
            self._channels.discard(channel)

    def release(self):
        self._gate.set()

    def hold(self):
        self._gate.clear()

    def hold_status(self):
        self._status_gate.clear()

    def release_status(self):
        self._status_gate.set()

    def metrics(self):
        with self._lock:
            return {**self._counts, 'held': not self._gate.is_set(),
                    'status_held': not self._status_gate.is_set(),
                    'closed': self._stop.is_set()}

    def close(self):
        with self._lock:
            if self._stop.is_set():
                return
            self._stop.set()
            channels = tuple(self._channels)
        self._gate.set()
        self._status_gate.set()
        for channel in channels:
            try:
                channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def __enter__(self):
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.close()
