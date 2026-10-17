"""Local oracle regressions; no chain, kernel TUN or public qualification."""

from contextlib import contextmanager
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import payments_qualify as gate


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

    def test_canonical_payment_does_not_imply_meter_credit_is_restored(self):
        state = {'authorized_bytes': [32164]}
        tariff = {'classes': [{'rate_ou_per_mib': 10000}]}
        record = {'committed': [32164], 'redeemed': [0], 'authorizations': [None],
                  'uncertain': [0], 'pending': [0],
                  'credit': {'max_unacknowledged_ou': 100000}}
        with patch.object(gate, 'settled', return_value=(state, 307)), \
                patch.object(gate, 'meter', return_value=record):
            self.assertIsNone(gate.settled_credit('program', 'operator', tariff, [32164]))
            record['redeemed'] = [32164]
            self.assertEqual(gate.settled_credit('program', 'operator', tariff, [32164]), (state, 307))
            # Same-charge and zero-rate receipts can be durably acknowledged
            # after canonical payment while its raw byte floor still lags.
            record['redeemed'] = [32163]
            record['authorizations'] = [{'usage': {'total_bytes': 32164}}]
            self.assertEqual(gate.settled_credit('program', 'operator', tariff, [32164]), (state, 307))
            record['uncertain'] = [gate.CREDIT_BYTES + 1]
            with self.assertRaises(AssertionError):
                gate.settled_credit('program', 'operator', tariff, [32164])

    def test_credit_readiness_preserves_one_sided_usage_and_requires_roundtrip_headroom(self):
        state = {'authorized_bytes': [32164]}
        tariff = {'classes': [{'rate_ou_per_mib': 10000}]}
        record = {'committed': [33164], 'redeemed': [32164], 'authorizations': [None],
                  'uncertain': [0], 'pending': [0],
                  'credit': {'max_unacknowledged_ou': 100000}}
        with patch.object(gate, 'settled', return_value=(state, 307)), \
                patch.object(gate, 'meter', return_value=record):
            # The extra successful server handoff was lost before the client
            # observed it. It stays unacknowledged, without blocking readiness.
            self.assertEqual(gate.settled_credit('program', 'operator', tariff, [32164]), (state, 307))
            self.assertEqual(record['committed'], [33164])
            self.assertEqual(record['redeemed'], [32164])
            record['uncertain'] = [gate.CREDIT_BYTES - 1000 - 2 * gate.PAID_MTU + 1]
            self.assertIsNone(gate.settled_credit('program', 'operator', tariff, [32164]))
            record['uncertain'] = [0]
            # 1,000 held bytes cost 10 OU here; another worst-class full-MTU
            # round trip needs 26 OU. A 35 OU limit leaves insufficient room.
            record['credit']['max_unacknowledged_ou'] = 35
            self.assertIsNone(gate.settled_credit('program', 'operator', tariff, [32164]))
            record['credit']['max_unacknowledged_ou'] = 36
            self.assertEqual(gate.settled_credit('program', 'operator', tariff, [32164]), (state, 307))

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
            with patch.multiple(gate.g, ROOT=root, EVIDENCE=evidence, PROCESSES={'payer': process}):
                gate.failure_snapshot(control)
            report = json.loads((evidence / 'failure/diagnostics.json').read_text())
            self.assertEqual(report['processes']['payer'], {'pid': 123, 'exit': None})
            self.assertEqual(report['proxy'], {'closed': False})
            self.assertEqual(report['copied'], ['client.json'])
            self.assertEqual(sorted(path.name for path in (evidence / 'failure').iterdir()),
                             ['client.json', 'diagnostics.json'])


if __name__ == '__main__':
    unittest.main()
