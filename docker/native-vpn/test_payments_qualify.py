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


if __name__ == '__main__':
    unittest.main()
