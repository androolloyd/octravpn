#!/usr/bin/env python3
"""Replay pristine Single modules against explicit private-prior test fixtures.

This does not patch the upstream CLI to accept a private chain, enable Single on
public profiles, or create BFT finality. The material file contains deterministic
public test keys/ciphertexts/proofs, never a secret key.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def transaction(sender=1, to=2, amount='1', nonce=1, ou='1000', op='standard', **kw):
    return dict({'from': sender, 'to': to, 'amount': amount, 'nonce': nonce,
                 'ou': ou, 'op': op, 'message': None, 'encrypted': None}, **kw)


def case(name, txs, **kw):
    return dict({'name': name, 'epoch': 1, 'txs': txs, 'fee': None, 'fhe': 32,
                 'stealth': 32, 'max_defer': 3, 'defer_counts': []}, **kw)


def inputs(material):
    tx = transaction
    cases = [case('empty-' + str(epoch), [], epoch=epoch)
             for epoch in [1, 2, 10, 63, 64, 100]]
    cases += [case('one-sender', [tx()]),
              case('same-sender-sequential', [tx(), tx(nonce=2)]),
              case('nonce-gap', [tx(nonce=2)]),
              case('duplicate-nonce', [tx(), tx(amount='2')]),
              case('wrong-nonce-source-order', [tx(nonce=2), tx()]),
              case('self-transfer', [tx(to=1)]), case('zero-amount', [tx(amount='0')]),
              case('overspend', [tx(amount='1000001')]),
              case('insufficient-fee', [tx(ou='1000001')]),
              case('bad-recipient', [tx(to='invalid')]),
              case('same-sender-rejection-keeps-next', [tx(amount='0'), tx(nonce=2)]),
              case('same-sender-failed-first-and-retry', [tx(amount='1000001'), tx(amount='2')]),
              case('defer-then-next', [tx(to='stealth', op='stealth', amount='0', ou='5000'), tx(nonce=2)]),
              case('stealth-missing-defer', [tx(to='stealth', op='stealth', amount='0', ou='5000')]),
              case('stealth-timeout', [tx(to='stealth', op='stealth', amount='0', ou='5000')], defer_counts=[[0, 3]]),
              case('stealth-fhe-cap', [tx(to='stealth', op='stealth', amount='0', ou='5000')], fhe=0),
              case('stealth-slot-cap', [tx(to='stealth', op='stealth', amount='0', ou='5000')], stealth=0),
              case('encrypt-fhe-cap', [tx(to=1, op='encrypt', amount='0', ou='5000')], fhe=0),
              case('decrypt-fhe-cap', [tx(to=1, op='decrypt', amount='0', ou='5000')], fhe=0),
              case('fee-override', [tx()], fee='octFEE'), case('fee-ignored-short', [tx()], fee='oct'),
              case('two-sender-order-a', [tx(sender=1, to=4), tx(sender=2, to=4)]),
              case('two-sender-order-b', [tx(sender=2, to=4), tx(sender=1, to=4)])]
    raw = {key: bytes.fromhex(value) for key, value in material.items()}
    def wrapped(prefix, key):
        return prefix + base64.b64encode(raw[key]).decode()
    payload = dict(version=5, delta_cipher=wrapped('hfhe_v1|', 'delta'),
                   commitment=base64.b64encode(raw['cipher_commitment']).decode(),
                   range_proof_delta=wrapped('rp_v1|', 'delta_range'),
                   range_proof_balance=wrapped('rp_v1|', 'range'),
                   eph_pub='ephemeral', stealth_tag='aa' * 16, enc_amount='encrypted',
                   claim_pub='ab' * 32, amount_commitment=base64.b64encode(raw['commitment']).decode(),
                   send_zero_proof=wrapped('zkzp_v2|', 'proof'))
    for valid in [True, False]:
        body = payload if valid else payload | dict(range_proof_delta=payload['range_proof_balance'])
        cases.append(case('genuine-stealth' if valid else 'false-cached-range',
                          [tx(to='stealth', op='stealth', amount='0', ou='5000',
                              encrypted=json.dumps(body, separators=(',', ':')))],
                          private=dict(public=base64.b64encode(raw['public']).decode(),
                                       current=base64.b64encode(wrapped('hfhe_v1|', 'current').encode()).decode())))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--material', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('oracle', HERE / 'resource-native-oracle.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    result = oracle.run(args.upstream, args.builder_image, HERE / 'single-oracle.ml',
                        inputs(json.loads(args.material.read_text())),
                        'octra_core octra_node_runtime octra_consensus octra_vm yojson lwt.unix')
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'cases': len(result['cases']), 'fixture_sha256': hashlib.sha256(args.out.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
