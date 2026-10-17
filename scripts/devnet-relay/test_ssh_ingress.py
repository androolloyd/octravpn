"""Exact firewall transition and real TCP half-close/cancellation controls."""
import asyncio
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import relay
import ssh_ingress


def fixture():
    base = {"nftables": [{"chain": {"family": "inet", "table": "hlx_relay",
                                    "name": "input", "policy": "drop"}}]}
    config = {"wan": "eth0", "public_ipv4": "8.8.8.8",
              "hlx_ruleset_sha256": relay.fingerprint(base)}
    expressions = ssh_ingress.ingress_expressions(config)
    for handle, chain in enumerate(("forward", "prerouting"), 30):
        base["nftables"].append({"rule": {"chain": chain, "handle": handle,
            "comment": relay.TAG, "expr": expressions[chain]}})
    for handle in range(40, 46):
        base["nftables"].append({"rule": {"chain": "forward", "handle": handle,
            "comment": relay.TAG, "expr": [{"drop": None}]}})
    return base, config


class FirewallTests(unittest.TestCase):
    def test_replaces_only_exact_owned_p2p_forwarding(self):
        value, config = fixture()
        original = copy.deepcopy(value)
        batch = ssh_ingress.transition(value, config)
        self.assertEqual(value, original)
        self.assertEqual(batch.splitlines(), [
            'delete rule inet hlx_relay prerouting handle 31',
            'delete rule inet hlx_relay forward handle 30',
            'add rule inet hlx_relay input iifname eth0 tcp dport 20800 accept '
            'comment "octra-devnet-relay-v1"'])

    def test_refuses_foreign_firewall_drift_and_owned_rule_mutation(self):
        value, config = fixture()
        value['nftables'][0]['chain']['policy'] = 'accept'
        with self.assertRaises(ValueError):
            ssh_ingress.transition(value, config)
        value, config = fixture()
        value['nftables'][1]['rule']['expr'][-1] = {'drop': None}
        with self.assertRaises(ValueError):
            ssh_ingress.transition(value, config)

    def test_completed_transition_is_idempotent_but_partial_is_refused(self):
        value, config = fixture()
        value['nftables'] = value['nftables'][:1] + value['nftables'][3:]
        with self.assertRaises(ValueError):
            ssh_ingress.transition(value, config)
        value['nftables'].append({'rule': {'chain': 'input', 'handle': 55,
            'comment': relay.TAG, 'expr': ssh_ingress.ingress_expressions(config)['input']}})
        self.assertEqual(ssh_ingress.transition(value, config), '')


class TcpTests(unittest.IsolatedAsyncioTestCase):
    async def test_half_close_delivers_full_reply_and_cleanup(self):
        async def target(reader, writer):
            request = await reader.read()
            writer.write(request[::-1])
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(target, '127.0.0.1', 0)
        bridge = ssh_ingress.Bridge(target_port=server.sockets[0].getsockname()[1])
        ingress = await asyncio.start_server(bridge.connect, '127.0.0.1', 0)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', ingress.sockets[0].getsockname()[1])
            payload = b'authenticated frames' * 8192
            writer.write(payload)
            await writer.drain()
            writer.write_eof()
            self.assertEqual(await asyncio.wait_for(reader.read(), 3), payload[::-1])
            writer.close()
            await writer.wait_closed()
        finally:
            ingress.close()
            server.close()
            await ingress.wait_closed()
            await server.wait_closed()
            await bridge.close()
        self.assertFalse(bridge.clients)

    async def test_shutdown_closes_stalled_client_and_capacity_rejects(self):
        accepted = asyncio.Event()
        async def target(reader, writer):
            accepted.set()
            await reader.read()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(target, '127.0.0.1', 0)
        bridge = ssh_ingress.Bridge(target_port=server.sockets[0].getsockname()[1], capacity=1)
        ingress = await asyncio.start_server(bridge.connect, '127.0.0.1', 0)
        reader, writer = await asyncio.open_connection('127.0.0.1', ingress.sockets[0].getsockname()[1])
        try:
            await asyncio.wait_for(accepted.wait(), 3)
            other, sender = await asyncio.open_connection('127.0.0.1', ingress.sockets[0].getsockname()[1])
            self.assertEqual(await asyncio.wait_for(other.read(), 3), b'')
            sender.close()
            await sender.wait_closed()
            await bridge.close()
            self.assertEqual(await asyncio.wait_for(reader.read(), 3), b'')
        finally:
            writer.close()
            await writer.wait_closed()
            ingress.close()
            server.close()
            await ingress.wait_closed()
            await server.wait_closed()
            await bridge.close()
        self.assertFalse(bridge.clients)


if __name__ == '__main__':
    unittest.main()
