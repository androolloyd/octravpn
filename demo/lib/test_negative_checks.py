#!/usr/bin/env python3
"""Isolated outcome-oracle tests. These mocks do not qualify Docker or crypto."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("negative_checks", Path(__file__).with_name("negative-checks.py"))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
CIRCLE = "oct" + "A" * 44


def result(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


class NegativeControls(unittest.TestCase):
    def test_sealed_uses_same_nonempty_target_for_both_passphrases(self):
        with patch.object(checks, "call", side_effect=[result(stdout=CIRCLE), result(stdout="demo asset"),
                          result(5, stderr=checks.DECRYPT_ERROR+"\n")]) as call:
            checks.sealed()
        good, wrong = call.call_args_list[1:]
        self.assertEqual(good.args[0][-1], f"oct://{CIRCLE}/sealed.json")
        self.assertEqual(wrong.args[0][-1], good.args[0][-1])
        self.assertIn("OCTRAVPN_SEALED_PASSPHRASE=wrong", wrong.args[0])

    def test_bad_url_rpc_missing_passphrase_and_unexpected_success_do_not_pass(self):
        for code in (0, 1, 2, 3, 4, 127):
            with self.subTest(code=code), patch.object(checks, "call", side_effect=[
                    result(stdout=CIRCLE), result(stdout="asset"), result(code, stderr=checks.DECRYPT_ERROR)]):
                with self.assertRaisesRegex(ValueError, "decrypt exit 5"):
                    checks.sealed()

    def test_sealed_requires_positive_control_no_plaintext_and_decrypt_diagnostic(self):
        cases = [(result(3), result(5, stderr=checks.DECRYPT_ERROR)),
                 (result(stdout="asset"), result(5, stdout="unexpected plaintext", stderr=checks.DECRYPT_ERROR)),
                 (result(stdout="asset"), result(5, stderr="RPC failed"))]
        for good, wrong in cases:
            with self.subTest(good=good, wrong=wrong), patch.object(checks, "call", side_effect=[
                    result(stdout=CIRCLE), good, wrong]):
                with self.assertRaises(ValueError): checks.sealed()
        with patch.object(checks, "call", return_value=result(stdout="")) as call:
            with self.assertRaisesRegex(ValueError, "Circle ID"):
                checks.sealed()
        self.assertEqual(call.call_count, 1)

    def test_audit_requires_original_key_and_exact_mac_failure(self):
        clean = result(stdout="audit log: OK 8 entries, HMAC chain valid\nverification PASSED\n")
        broken = result(1, "audit log: FAIL /tmp/audit.tampered.log: MAC mismatch at line 1: mismatch\nverification FAILED\n")
        with patch.object(checks, "call", side_effect=[clean, result(), broken]) as call:
            checks.audit()
        for invocation in (call.call_args_list[0], call.call_args_list[2]):
            args = invocation.args[0]
            self.assertEqual(args[args.index("--hmac-key")+1], "/work/node/audit.log.key")
        self.assertIn("record_json", call.call_args_list[1].args[0][-1])

    def test_audit_does_not_accept_missing_key_parse_failure_or_swallowed_failure(self):
        for code, text in ((0, "verification FAILED"), (2, "parse error"), (3, "missing key"),
                           (1, "audit log: FAIL parse error\nverification FAILED\n")):
            clean = result(stdout="8 entries, HMAC chain valid\nverification PASSED\n")
            with self.subTest(code=code, text=text), patch.object(checks, "call", side_effect=[
                    clean, result(), result(code, text)]):
                with self.assertRaises(ValueError): checks.audit()

    def test_failed_clean_audit_never_stages_a_negative_control(self):
        with patch.object(checks, "call", return_value=result(1, "verification FAILED")) as call:
            with self.assertRaisesRegex(ValueError, "clean eight-record"):
                checks.audit()
        self.assertEqual(call.call_count, 1)


if __name__ == "__main__":
    unittest.main()
