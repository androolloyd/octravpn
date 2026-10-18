"""Local oracle regressions; no chain, kernel TUN or public qualification."""

from contextlib import contextmanager
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, call, patch

import payments_qualify as gate
import payment_control
import stock_operator
import json_snapshot


@contextmanager
def echo_server(reply):
    stop = threading.Event()
    received = []
    errors = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1', 0))
        server.settimeout(.05)

        def run():
            while not stop.is_set():
                try:
                    data, peer = server.recvfrom(2048)
                    received.append(data)
                    for body in reply(data, len(received)):
                        server.sendto(body, peer)
                except socket.timeout:
                    continue
                except OSError as error:
                    if not stop.is_set():
                        errors.append(error)
                    return

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        try:
            with patch.object(gate, 'UDP_PORT', server.getsockname()[1]):
                yield received
        finally:
            stop.set()
            worker.join(timeout=1)
            assert not worker.is_alive() and not errors


class PaymentQualificationTests(unittest.TestCase):
    def setUp(self):
        self.patches = [
            patch.multiple(gate.g, PUBLIC='127.0.0.1', JOURNAL={}, PROCESSES={}, save=Mock()),
            patch.object(gate, 'target', return_value={}),
            patch.object(gate, 'UDP_TIMEOUT', .05),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_udp_retries_same_id_and_ignores_older_duplicate_echo(self):
        def reply(data, count):
            if count == 1:
                return []
            return [data, data] if count == 2 else [data]

        with echo_server(reply) as received:
            total = gate.udp('127.0.0.1', 2, b'retry:')
        report = gate.g.JOURNAL['udp_probes'][0]
        self.assertEqual(received[0], received[1])
        self.assertNotEqual(received[1], received[2])
        self.assertEqual(report['unique_echoes'], 2)
        self.assertEqual(report['timeouts'], 1)
        self.assertEqual(report['stale_duplicates'], 1)
        self.assertEqual([row['id'] for row in report['attempts']], [0, 0, 1])
        self.assertEqual(total, len(received[0]) + len(received[2]))
        self.assertEqual(report['sent_payload_bytes'], sum(map(len, received)))

    def test_udp_exhaustion_remains_failure_and_records_every_attempt(self):
        with echo_server(lambda _data, _count: []) as received:
            with self.assertRaisesRegex(TimeoutError, 'exhausted 3 attempts'):
                gate.udp('127.0.0.1', 1, b'blocked:')
        report = gate.g.JOURNAL['udp_probes'][0]
        self.assertEqual(len(received), gate.UDP_ATTEMPTS)
        self.assertEqual(len(set(received)), 1)
        self.assertEqual(report['timeouts'], gate.UDP_ATTEMPTS)
        self.assertEqual(report['unique_echoes'], 0)
        self.assertEqual(report['failure'], 'TimeoutError')

    def test_udp_unrecognized_body_is_not_treated_as_loss_or_a_duplicate(self):
        with echo_server(lambda _data, _count: [b'not-the-fixture']):
            with self.assertRaisesRegex(AssertionError, 'fixture ID or body'):
                gate.udp('127.0.0.1', 1, b'invalid:')
        report = gate.g.JOURNAL['udp_probes'][0]
        self.assertEqual(len(report['attempts']), 1)
        self.assertEqual(report['failure'], 'AssertionError')

    def test_paid_purchase_requires_reconciled_entitlement_and_never_borrows_unsigned_capacity(self):
        state = {'authorized_bytes': [32164], 'local_bytes': [0]}
        tariff = {'classes': [{'rate_ou_per_mib': 10000}]}
        record = {'committed': [0], 'purchased': [0], 'authorizations': [None],
                  'uncertain': [0], 'pending': [0]}
        with patch.object(gate, 'PREPAID_BYTES', [32164]), \
                patch.object(gate, 'settled', return_value=(state, 307)), \
                patch.object(gate, 'meter', return_value=record):
            self.assertIsNone(gate.settled_prepaid('program', 'operator', tariff, [32164]))
            record['purchased'] = [32164]
            self.assertEqual(gate.settled_prepaid('program', 'operator', tariff, [32164]), (state, 307))
            # A signature or already paid rounding bucket cannot stand in for
            # the exact authenticated canonical byte entitlement.
            record['purchased'] = [32163]
            record['authorizations'] = [{'usage': {'total_bytes': 32164}}]
            self.assertIsNone(gate.settled_prepaid('program', 'operator', tariff, [32164]))
            record['purchased'] = [32164]
            record['uncertain'] = [32165]
            with self.assertRaises(AssertionError):
                gate.settled_prepaid('program', 'operator', tariff, [32164])

    def test_failure_snapshot_copies_only_public_journals_before_teardown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'root'
            evidence = Path(directory) / 'evidence'
            evidence.mkdir()
            source = root / 'client-journal/state.json'
            source.parent.mkdir(parents=True)
            source.write_text('{"payload":{"local_bytes":[1]}}')
            (root / 'operator.hex').write_text('must-never-be-copied')
            process = Mock(pid=123)
            process.poll.return_value = None
            control = Mock()
            control.metrics.return_value = {'closed': False}
            with patch.multiple(gate.g, ROOT=root, EVIDENCE=evidence, PROCESSES={'payer': process}), \
                    patch.object(gate, 'public_status', return_value={'http': 503, 'body': {'reason': 'fixture'}}):
                gate.failure_snapshot(control)
            report = json.loads((evidence / 'failure/diagnostics.json').read_text())
            self.assertEqual(report['processes']['payer'], {'pid': 123, 'exit': None})
            self.assertEqual(report['proxy'], {'closed': False})
            self.assertEqual(report['copied'], ['client.json'])
            self.assertEqual(sorted(path.name for path in (evidence / 'failure').iterdir()),
                             ['client.json', 'diagnostics.json'])


    def test_operator_readiness_requires_serving_retained_epoch_and_public_200(self):
        observations = []
        for serving, epoch, public in [(False, 7, 200), (True, 6, 200),
                                       (True, 7, 503), (True, 7, 200)]:
            observations.extend([{'http': 200, 'body': {'serving': serving, 'epoch': epoch}},
                                 {'http': public, 'body': {}}])

        def poll(check, seconds, label):
            self.assertEqual(seconds, 120)
            self.assertIn('Serving', label)
            for _ in range(3):
                self.assertFalse(check())
            self.assertTrue(check())

        journal = {}
        with patch.object(gate, 'public_status', side_effect=observations), \
                patch.object(gate.g, 'JOURNAL', journal), \
                patch.object(gate.g, 'until', side_effect=poll), \
                patch.object(gate.g, 'save') as save:
            gate.operator_ready(7)
        report = journal['operator_readiness'][0]
        self.assertTrue(report['ready'])
        self.assertEqual(report['attempts'], 4)
        self.assertEqual(report['minimum_epoch'], 7)
        self.assertEqual(report['last']['/operator/status']['body']['epoch'], 7)
        save.assert_called_once()


class ReadonlySnapshotRetryTests(unittest.TestCase):
    BUSY = {'contract_call': (-32005, 'program snapshot unavailable'),
            'circle_view': (110, 'service unavailable')}

    def busy(self, method, **changes):
        code, message = self.BUSY[method]
        value = {'jsonrpc': '2.0', 'id': 1,
                 'error': {'code': code, 'message': message}}
        value.update(changes)
        return value

    @contextmanager
    def responses(self, values):
        replies = iter(values)
        requests = []

        def open_request(request, *, timeout):
            # Exercise actual request construction, JSON parsing, response bound
            # and error classification without contacting a validator.
            requests.append((request.full_url, request.get_method(), request.data, timeout))
            value = next(replies)
            if isinstance(value, BaseException):
                raise value
            raw = value if isinstance(value, bytes) else json.dumps(value).encode()
            return io.BytesIO(raw)

        with patch.object(gate.g.urllib.request, 'urlopen', side_effect=open_request), \
                patch.object(gate.g.time, 'sleep') as sleep:
            yield requests, sleep

    def invoke(self, rpc_method, method='get_plan', params=None):
        if rpc_method == 'contract_call':
            return gate.g.view('program', method, params)
        fixture = stock_operator.Fixture.__new__(stock_operator.Fixture)
        fixture.application = 'circle'
        fixture.program = 'program'
        return fixture.view(method, params)

    def test_both_view_callers_retry_only_busy_with_identical_request_and_normalization(self):
        for rpc_method in self.BUSY:
            for method in ['get_plan', 'can_forward']:
                with self.subTest(rpc_method=rpc_method, method=method):
                    params = [7, {'nested': ['unchanged', 9]}]
                    before = json.dumps(params)
                    ok = {'id': 1, 'result': {'result': [12, {'capacity': 34}]}}
                    with self.responses([self.busy(rpc_method), ok]) as (requests, sleep):
                        self.assertEqual(self.invoke(rpc_method, method, params), [12, {'capacity': 34}])
                    self.assertEqual(len(requests), 2)
                    self.assertEqual(requests[0], requests[1])
                    self.assertEqual(requests[0][3], 10)
                    self.assertEqual(json.loads(requests[0][2]),
                                     {'jsonrpc': '2.0', 'id': 1, 'method': rpc_method,
                                      'params': ['program', method, params]})
                    self.assertEqual(json.dumps(params), before)
                    sleep.assert_called_once_with(.1)

    def test_each_busy_predicate_has_exact_ten_call_bound(self):
        for rpc_method in self.BUSY:
            for succeeds in [False, True]:
                with self.subTest(rpc_method=rpc_method, succeeds=succeeds):
                    replies = [self.busy(rpc_method) for _ in range(10)]
                    if succeeds:
                        replies[-1] = {'id': 1, 'result': {'result': 42}}
                    with self.responses(replies) as (requests, sleep):
                        if succeeds:
                            self.assertEqual(self.invoke(rpc_method), 42)
                        else:
                            with self.assertRaises(gate.g.SnapshotBusy):
                                self.invoke(rpc_method)
                    self.assertEqual(len(requests), 10)
                    self.assertTrue(all(request == requests[0] for request in requests))
                    self.assertEqual(sleep.call_args_list, [call(.1)] * 9)

    def test_wrong_code_message_id_or_crossed_view_predicate_is_terminal(self):
        for rpc_method, (code, message) in self.BUSY.items():
            other = 'circle_view' if rpc_method == 'contract_call' else 'contract_call'
            wrong = [self.busy(rpc_method, id=value) for value in [2, '1', None, True, 1.0]]
            wrong += [self.busy(rpc_method, error=error) for error in [
                {'code': code + 1, 'message': message},
                {'code': str(code), 'message': message},
                {'code': float(code), 'message': message},
                {'code': code, 'message': message + ' '},
                self.busy(other)['error'], None]]
            wrong.append(self.busy(rpc_method, result={'result': 42}))
            for value in wrong:
                with self.subTest(rpc_method=rpc_method, response=value):
                    with self.responses([value]) as (requests, sleep):
                        with self.assertRaises(RuntimeError):
                            self.invoke(rpc_method)
                    self.assertEqual(len(requests), 1)
                    sleep.assert_not_called()

    def test_nongetter_and_general_rpc_methods_never_retry(self):
        for rpc_method in self.BUSY:
            for method in ['purchase', 'get', 'can_forward_more', 'Get_plan', 'withdraw']:
                with self.subTest(rpc_method=rpc_method, method=method):
                    with self.responses([self.busy(rpc_method)]) as (requests, sleep):
                        with self.assertRaises(RuntimeError):
                            self.invoke(rpc_method, method)
                    self.assertEqual(len(requests), 1)
                    sleep.assert_not_called()
            # rpc() itself remains one call, even with a known busy response.
            with self.responses([self.busy(rpc_method)]) as (requests, sleep):
                with self.assertRaises(gate.g.SnapshotBusy):
                    gate.g.rpc(rpc_method, ['program', 'get_plan', []])
            self.assertEqual(len(requests), 1)
            sleep.assert_not_called()
        for rpc_method in ['octra_submit', 'contract_call_other', 'circle_view_other']:
            with self.subTest(rpc_method=rpc_method):
                with self.responses([self.busy('contract_call')]) as (requests, sleep):
                    with self.assertRaises(RuntimeError):
                        gate.g.readonly_view(rpc_method, 'program', 'get_plan', [])
                self.assertEqual(len(requests), 1)
                sleep.assert_not_called()

    def test_malformed_oversized_transport_and_result_errors_are_terminal(self):
        for rpc_method in self.BUSY:
            for response, exception in [(b'{', ValueError), (b' ' * 4_500_001, ValueError),
                                        (TimeoutError('fixture transport timeout'), TimeoutError),
                                        ({'id': 1, 'result': {}}, (ValueError, AssertionError))]:
                with self.subTest(rpc_method=rpc_method, error=exception):
                    with self.responses([response]) as (requests, sleep):
                        with self.assertRaises(exception):
                            self.invoke(rpc_method)
                    self.assertEqual(len(requests), 1)
                    sleep.assert_not_called()

    def test_signed_write_cli_is_not_retried(self):
        with patch.object(gate.g, 'cli', side_effect=gate.g.SnapshotBusy('fixture')) as cli, \
                patch.object(gate.g, 'record') as record, \
                patch.object(gate.g.time, 'sleep') as sleep:
            with self.assertRaises(gate.g.SnapshotBusy):
                gate.g.send('purchase', 'key', 'program', 'purchase', [7], value=11)
        cli.assert_called_once_with('cast', 'send', 'program', 'purchase', '7',
                                    '--key', 'key', '--rpc-url', gate.g.RPC,
                                    '--fee', gate.g.FEE, '--value', 11)
        record.assert_not_called()
        sleep.assert_not_called()

    def test_usage_proxy_forwards_exact_body_once_and_preserves_503(self):
        from email.message import Message
        from types import SimpleNamespace

        body = b'{"usage":{"total_bytes":1280},"signature":"unchanged-fixture"}'
        headers = Message()
        headers['Content-Length'] = str(len(body))
        headers['Content-Type'] = 'application/json'
        proxy = Mock(upstream_port=12345)
        proxy._wait.return_value = True
        proxy._track.return_value = True
        proxy._gate.is_set.return_value = True
        reply = Mock(status=503)
        reply.read.return_value = b'busy'
        reply.getheader.return_value = 'text/plain'
        upstream = Mock()
        upstream.getresponse.return_value = reply
        handler = SimpleNamespace(path='/payments/usage', headers=headers,
                                  rfile=io.BytesIO(body), server=SimpleNamespace(proxy=proxy),
                                  _reply=Mock())
        with patch.object(payment_control.http.client, 'HTTPConnection', return_value=upstream) as connection, \
                patch.object(gate.g, 'readonly_view', side_effect=AssertionError('getter helper reached usage')), \
                patch.object(gate.g.time, 'sleep') as sleep:
            payment_control._Handler.do_POST(handler)
        connection.assert_called_once_with('127.0.0.1', 12345, timeout=5)
        upstream.request.assert_called_once_with('POST', '/payments/usage', body=body,
                                                headers={'Content-Type': 'application/json',
                                                         'Connection': 'close'})
        handler._reply.assert_called_once_with(503, b'busy', 'text/plain')
        upstream.close.assert_called_once()
        sleep.assert_not_called()


class JsonSnapshotTests(unittest.TestCase):
    path = Path('/owned-fixture/target.json')

    def test_absence_retries_exactly_nine_times_then_reads_current_object(self):
        failures = [FileNotFoundError(str(index)) for index in range(9)]
        with patch.object(Path, 'open', side_effect=[*failures, io.BytesIO(b'{"bytes":17}')]) as opened, \
                patch.object(Path, 'exists', side_effect=AssertionError('snapshot used exists precheck')), \
                patch.object(json_snapshot.time, 'sleep') as sleep:
            self.assertEqual(json_snapshot.read_object(self.path), {'bytes': 17})
        self.assertEqual(opened.call_args_list, [call('rb')] * 10)
        self.assertEqual(sleep.call_args_list, [call(.1)] * 9)

    def test_absence_exhaustion_reraises_exact_last_error_without_default(self):
        failures = [FileNotFoundError(str(index)) for index in range(10)]
        with patch.object(Path, 'open', side_effect=failures) as opened, \
                patch.object(json_snapshot.time, 'sleep') as sleep:
            with self.assertRaises(FileNotFoundError) as caught:
                json_snapshot.read_object(self.path)
        self.assertIs(caught.exception, failures[-1])
        self.assertEqual(opened.call_count, 10)
        self.assertEqual(sleep.call_args_list, [call(.1)] * 9)

    def test_permission_and_other_io_errors_are_terminal(self):
        for error in [PermissionError('denied'), OSError(5, 'I/O failure')]:
            with self.subTest(error=type(error)), \
                    patch.object(Path, 'open', side_effect=error) as opened, \
                    patch.object(json_snapshot.time, 'sleep') as sleep:
                with self.assertRaises(type(error)) as caught:
                    json_snapshot.read_object(self.path)
                self.assertIs(caught.exception, error)
                opened.assert_called_once_with('rb')
                sleep.assert_not_called()

    def test_invalid_utf8_json_duplicate_keys_and_nonfinite_numbers_are_terminal(self):
        invalid = [b'', b'{', b'\xff', b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}',
                   b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}', b'{"n":1e9999}']
        for raw in invalid:
            with self.subTest(raw=raw), \
                    patch.object(Path, 'open', return_value=io.BytesIO(raw)) as opened, \
                    patch.object(json_snapshot.time, 'sleep') as sleep:
                with self.assertRaises((ValueError, UnicodeDecodeError)):
                    json_snapshot.read_object(self.path)
                opened.assert_called_once_with('rb')
                sleep.assert_not_called()

    def test_object_and_array_wrappers_require_exact_json_container_types(self):
        cases = [(json_snapshot.read_object, b'{"bytes":23}', {'bytes': 23}),
                 (json_snapshot.read_array, b'[1035,1035]', [1035, 1035])]
        for reader, raw, expected in cases:
            with self.subTest(reader=reader), patch.object(Path, 'open', return_value=io.BytesIO(raw)):
                self.assertEqual(reader(self.path), expected)
        for reader, invalid in [(json_snapshot.read_object, [b'[]', b'null', b'false', b'0', b'"text"']),
                                (json_snapshot.read_array, [b'{}', b'null', b'true', b'1', b'"text"'])]:
            for raw in invalid:
                with self.subTest(reader=reader, raw=raw), \
                        patch.object(Path, 'open', return_value=io.BytesIO(raw)), \
                        patch.object(json_snapshot.time, 'sleep') as sleep:
                    with self.assertRaisesRegex(ValueError, 'snapshot must be a JSON'):
                        reader(self.path)
                    sleep.assert_not_called()

    def test_reads_one_bounded_file_and_rejects_oversize_before_parsing(self):
        stream = Mock()
        stream.__enter__ = Mock(return_value=stream)
        stream.__exit__ = Mock(return_value=False)
        stream.read.return_value = b'{"bytes":29}'
        with patch.object(Path, 'open', return_value=stream):
            self.assertEqual(json_snapshot.read_object(self.path), {'bytes': 29})
        stream.read.assert_called_once_with(1024 * 1024 + 1)
        exact = b'{"pad":"' + b'x' * (json_snapshot.MAX_BYTES - 10) + b'"}'
        self.assertEqual(len(exact), json_snapshot.MAX_BYTES)
        with patch.object(Path, 'open', return_value=io.BytesIO(exact)):
            self.assertEqual(len(json_snapshot.read_object(self.path)['pad']), json_snapshot.MAX_BYTES - 10)
        with patch.object(Path, 'open', return_value=io.BytesIO(exact + b' ')), \
                patch.object(json_snapshot.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'snapshot exceeds one MiB'):
                json_snapshot.read_object(self.path)
            sleep.assert_not_called()

    def test_each_read_observes_current_file_and_never_reuses_prior_counters(self):
        with patch.object(Path, 'open', side_effect=[io.BytesIO(b'{"bytes":31}'), io.BytesIO(b'{"bytes":37}')]):
            self.assertEqual(json_snapshot.read_object(self.path), {'bytes': 31})
            self.assertEqual(json_snapshot.read_object(self.path), {'bytes': 37})
        with patch.object(Path, 'open', side_effect=FileNotFoundError('gone')), \
                patch.object(json_snapshot.time, 'sleep'):
            with self.assertRaises(FileNotFoundError):
                json_snapshot.read_object(self.path)

    def test_paid_target_reader_uses_shared_object_reader_without_fallback(self):
        expected = {'udp_payload_bytes': 41}
        with patch.object(gate, 'read_object', return_value=expected) as read:
            self.assertIs(gate.target(), expected)
            read.assert_called_once_with(gate.g.EVIDENCE / 'target.json')
        with patch.object(gate, 'read_object', side_effect=FileNotFoundError('missing')):
            with self.assertRaises(FileNotFoundError):
                gate.target()


if __name__ == '__main__':
    unittest.main()
