import base64
import unittest
from fhe_load_pk import check


class Probe(unittest.TestCase):
    def run_case(self, overrides):
        results = {'octra_pvacPubkey': {'pvac_pubkey': base64.b64encode(b'public fixture').decode()},
                   'vm_contract': {'code_hash': 'a' * 64},
                   'octra_contractAbi': {'methods': [{'name': 'probe_addr_view', 'view': True}]},
                   'contract_call': {'result': '42'}}
        results.update(overrides)
        self.calls = []

        def rpc(endpoint, method, params):
            self.calls.append((method, params))
            value = results[method]
            if isinstance(value, Exception):
                raise value
            return value
        return check('https://example.invalid/rpc', call=rpc)

    def test_missing_key_never_calls_program(self):
        status = self.run_case({'octra_pvacPubkey': {'pvac_pubkey': None}})
        self.assertEqual(status['bridge_status'], 'inconclusive')
        self.assertEqual(len(self.calls), 1)

    def test_missing_program_or_method_never_calls_view(self):
        for method in ['vm_contract', 'octra_contractAbi']:
            self.run_case({method: {}})
            self.assertNotIn('contract_call', [call[0] for call in self.calls])

    def test_transport_failure_is_inconclusive(self):
        for method in ['octra_pvacPubkey', 'contract_call']:
            self.assertEqual(self.run_case({method: OSError('HTTP 403')})['bridge_status'], 'inconclusive')

    def test_empty_results_cannot_turn_green(self):
        for value in [None, False, '', {}, [], {'result': None}, {'unrelated': 'value'}]:
            self.assertEqual(self.run_case({'contract_call': value})['bridge_status'], 'inconclusive')

    def test_revert_requires_registered_key_and_valid_abi(self):
        status = self.run_case({'contract_call': ValueError('RPC error: execution reverted')})
        self.assertEqual(status['bridge_status'], 'blocked')

    def test_positive_legacy_result_requires_further_qualification(self):
        status = self.run_case({})
        self.assertEqual(status['bridge_status'], 'candidate')
        self.assertEqual(self.calls[-1][0], 'contract_call')
        self.assertIsInstance(self.calls[-1][1], list)
        self.assertEqual(self.calls[-1][1][1], 'probe_addr_view')


if __name__ == '__main__':
    unittest.main()
