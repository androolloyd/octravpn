#!/usr/bin/env python3
"""Run the mandatory private kernel branch and accept only its actual evidence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

EVIDENCE = Path('/evidence')
TEST = 'vpn::payments::canonical_tests::shielded::canonical_shielded_kernel_transport_survives_client_operator_restart'
CONTROL_TEST = 'vpn::payments::canonical_tests::shielded::canonical_shielded_purchase_requires_real_history_and_survives_spend_expiry_and_resume'


def interfaces():
    result = subprocess.run(['ip', '-j', 'link', 'show'], check=True, capture_output=True, text=True, timeout=10)
    return sorted(row['ifname'] for row in json.loads(result.stdout))


def main():
    journal = {'qualified': False, 'scope': 'canonical signed-QC private payments, pinned HTTPS, real WireGuard/TUN, isolated second kernel and client/operator restart; no public-network or multi-hop claim'}
    path = EVIDENCE / 'journal.json'
    path.write_text(json.dumps(journal, indent=2) + '\n')
    (EVIDENCE / 'kernel-scope.json').write_text(json.dumps({'fixture_only': True, 'network_none': True}))
    binary = Path('/usr/local/bin/private-kernel-test')
    expected = json.loads(Path('/usr/local/share/private-kernel-binary.json').read_text())['test_sha256']
    if hashlib.sha256(binary.read_bytes()).hexdigest() != expected:
        raise ValueError('kernel test binary hash differs')
    listed = subprocess.run([str(binary), '--list', '--ignored'], check=True,
                            capture_output=True, text=True, timeout=10)
    if TEST + ': test' not in listed.stdout:
        raise ValueError('privileged test is not explicitly ignored by ordinary runs')
    with (EVIDENCE / 'native-test.log').open('w') as log:
        result = subprocess.run([str(binary), '--ignored', '--exact', TEST, '--nocapture'],
                                stdout=log, stderr=subprocess.STDOUT, timeout=1800,
                                env={**os.environ, 'RAYON_NUM_THREADS': '8', 'RUST_BACKTRACE': '1'})
    journal['native_test_exit'] = result.returncode
    path.write_text(json.dumps(journal, indent=2) + '\n')
    if result.returncode:
        raise RuntimeError('canonical private kernel test failed; inspect native-test.log')
    log = (EVIDENCE / 'native-test.log').read_text()
    if 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in log:
        raise ValueError('exact canonical test did not execute')
    if interfaces() != ['lo']:
        raise ValueError('native test left an owned tunnel interface alive')
    flow = json.loads((EVIDENCE / 'private-kernel.json').read_text())
    if flow.get('kernel_flow_passed') is not True or flow.get('shielded_payments') is not True:
        raise ValueError('native private kernel evidence missing')
    exex = json.loads((EVIDENCE / 'exex-reopen.json').read_text())
    if exex.get('canonical_and_checkpoint_reopened') is not True or exex.get('sink_files_unchanged') is not True or exex.get('purchase_transactions') != 2:
        raise ValueError('private payment ExEx recovery evidence missing')
    link = json.loads((EVIDENCE / 'private-link.json').read_text())['hop']
    if link['errors'] or link['rejected_packets'] or min(link['sent_bytes'], link['received_bytes']) <= 0:
        raise ValueError('private raw packet link failed')
    expected_udp = sum(flow[p]['traffic']['udp_echoed_bytes'] for p in ['before', 'after'])
    expected_tcp = sum(flow[p]['traffic']['tcp_echoed_bytes'] for p in ['before', 'after'])
    deadline = time.monotonic() + 5
    while True:
        target = json.loads((EVIDENCE / 'target.json').read_text())
        if target['udp_payload_bytes'] >= expected_udp and target['tcp_payload_bytes'] >= expected_tcp:
            break
        if time.monotonic() >= deadline:
            raise ValueError('second kernel did not observe the echoed traffic')
        time.sleep(.1)
    if target['errors'] or target['hop']['errors'] or target['hop']['rejected_packets']:
        raise ValueError('second kernel reported a transport failure')
    for protocol in ['udp', 'tcp']:
        if target['observed_sources'][protocol] != ['192.0.2.1']:
            raise ValueError('target saw an unexpected exit source')
    if target['udp_payload_bytes'] != expected_udp or target['tcp_payload_bytes'] != expected_tcp:
        raise ValueError('target application counters differ from the actual sent payload')
    with (EVIDENCE / 'native-control.log').open('w') as log:
        ordinary = subprocess.run([str(binary), '--exact', CONTROL_TEST, '--nocapture'],
                                  stdout=log, stderr=subprocess.STDOUT, timeout=1800,
                                  env={**os.environ, 'RAYON_NUM_THREADS': '8', 'RUST_BACKTRACE': '1'})
    if ordinary.returncode or 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in (EVIDENCE / 'native-control.log').read_text():
        raise ValueError('ordinary canonical private regression failed')
    if interfaces() != ['lo']:
        raise ValueError('ordinary private test left a tunnel interface alive')
    journal.update(qualified=True, test_sha256=expected, kernel=flow,
                   exex_reopen=exex, ordinary_control_case_passed=True,
                   target_udp_payload_bytes=target['udp_payload_bytes'],
                   target_tcp_payload_bytes=target['tcp_payload_bytes'])
    path.write_text(json.dumps(journal, indent=2) + '\n')
    print(json.dumps({'qualified': True, 'scope': journal['scope']}), flush=True)


if __name__ == '__main__':
    main()
