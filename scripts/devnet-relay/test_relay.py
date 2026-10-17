#!/usr/bin/env python3
"""Offline constraints for the Octra-only relay and observer config."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


relay = module("relay")
prepare = module("prepare")


class RelayTests(unittest.TestCase):
    def test_fingerprint_rejects_baseline_mutation_but_ignores_owned_rules(self):
        base = {"nftables": [
            {"metainfo": {"version": "1.1"}},
            {"chain": {"name": "input", "policy": "drop", "handle": 1}},
            {"rule": {"chain": "input", "handle": 2, "expr": [{"accept": None}]}},
        ]}
        expected = relay.fingerprint(base)
        base["nftables"].append({"rule": {"chain": "input", "handle": 3,
                                           "comment": relay.TAG, "expr": [{"accept": None}]}})
        self.assertEqual(relay.fingerprint(base, exclude_octra=True), expected)
        base["nftables"][1]["chain"]["policy"] = "accept"
        self.assertNotEqual(relay.fingerprint(base, exclude_octra=True), expected)

    def test_rules_touch_only_octra_ports_and_tunnel(self):
        config = {"wan": "eth0", "public_ipv4": "8.8.8.8"}
        rules = relay.rules(config)
        self.assertEqual(len(rules), 8)
        self.assertEqual({chain for chain, _ in rules}, set(relay.CHAINS))
        joined = " ".join(" ".join(expr) for _, expr in rules)
        self.assertIn("51821", joined)
        self.assertIn("20800", joined)
        self.assertIn("@non_public_v4", joined)
        for forbidden in ("51820", "4001", "4002", "hlx-wg", "flush", "100.64.0.0/10"):
            self.assertNotIn(forbidden, joined)
        self.assertIn("ct status dnat tcp dport 20800 accept", joined)
        self.assertIn("iifname octra-wg ip daddr @non_public_v4 drop", joined)

    def test_config_rejects_extra_fields_and_private_address(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "relay.json"
            value = {"wan": "eth0", "public_ipv4": "10.0.0.1",
                     "node_public_key": "AA==", "relay_private_key_file": "/root/wg.key",
                     "hlx_ruleset_sha256": "0" * 64, "backup_path": "/root/hlx-before-octra.json"}
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                relay.read_config(path)
            value["public_ipv4"] = "8.8.8.8"
            value["unexpected"] = True
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                relay.read_config(path)

    def test_observer_preparation_preserves_trust_and_services(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "network.json"
            original = {"voting": False, "publisher": False, "p2p": "127.0.0.1:20800",
                        "advertised": "127.0.0.1:20800", "data": "/old/state",
                        "key": "/old/key", "environment": "/old/env",
                        "network": {"identity": {"chain_id": "octra-devnet"}},
                        "gateway": {"listen": "127.0.0.1:20805"}, "vpn": None}
            source.write_text(json.dumps(original))
            prepared = prepare.prepare(source, "8.8.8.8", Path("/node/state"),
                                       Path("/secrets/observer.key"), Path("/config/network.env"))
            self.assertEqual(prepared["p2p"], "10.203.1.2:20800")
            self.assertEqual(prepared["advertised"], "8.8.8.8:20800")
            for unchanged in ("network", "gateway", "vpn", "voting", "publisher"):
                self.assertEqual(prepared[unchanged], original[unchanged])
            original["voting"] = True
            source.write_text(json.dumps(original))
            with self.assertRaises(ValueError):
                prepare.prepare(source, "8.8.8.8", Path("/node/state"),
                                Path("/secrets/observer.key"), Path("/config/network.env"))


if __name__ == "__main__":
    unittest.main()
