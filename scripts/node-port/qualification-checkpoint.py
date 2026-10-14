#!/usr/bin/env python3
"""Record a reproducible local node test checkpoint with before/after sources.

This qualifies the implemented boundaries, not full consensus or funded VPN
operation. Local HTTP/TCP/WireGuard tests need loopback socket permission.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGES = ['octra-node', 'octra-node-protocol', 'octra-node-runtime', 'octra-exex', 'octra-browser']
DIRECTORIES = [
    'crates', 'program',
    'crates/octravpn-node', 'crates/octravpn-core', 'crates/octravpn-tun',
    'crates/octra-hfhe', 'vendor/octra-circle-wasm-host',
    'scripts/node-port', 'scripts/devnet', 'scripts/circle-apps', 'crates/octravpn-circle-registry',
    '../headscale-rs', '../octra-foundry',
]
SUFFIXES = {'.rs', '.json', '.js', '.mjs', '.toml', '.ml', '.aml', '.py', '.proto', '.bin'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot():
    # Rescan on both sides so newly created/deleted inputs are also detected.
    paths = {ROOT / name for name in [
        'Cargo.lock', 'Cargo.toml', 'docs/rust-node/source-map.json',
        'target/wasm32-unknown-unknown/release/octravpn_circle_registry.wasm',
    ]}
    for directory in DIRECTORIES:
        paths.update(p for p in (ROOT / directory).rglob('*')
                     if p.is_file() and p.suffix in SUFFIXES
                     and not any(x in {'target', '__pycache__', '.git'} for x in p.parts))
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--log', type=pathlib.Path, required=True)
    parser.add_argument('--evidence', type=pathlib.Path, action='append', default=[])
    parser.add_argument('--package', action='append', dest='packages')
    parser.add_argument('--test', action='append', dest='targets')
    parser.add_argument('--scope', default='Local canonical node services, browser HTTP, WireGuard admission, ExEx, authenticated peers and native protocol boundaries; development validators and synthetic settlement')
    args = parser.parse_args()
    if args.out.exists() or args.log.exists():
        raise SystemExit('Require fresh report and log paths')
    before = snapshot()
    evidence = {str(path): digest(path) for path in args.evidence}
    command = ['cargo', 'test', '--offline', '--locked']
    for package in args.packages or PACKAGES:
        command += ['-p', package]
    if args.targets:
        for target in args.targets:
            command += ['--test', target]
    else:
        command += ['--all-targets']
    with args.log.open('x') as log:
        result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    after = snapshot()
    suites = [tuple(map(int, m)) for m in re.findall(
        r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;', args.log.read_text())]
    unchanged = before == after
    report = {
        'scope': args.scope,
        'full_node_end_to_end': False,
        'funded_vpn_end_to_end': False,
        'upstream_commit': json.loads((ROOT / 'docs/rust-node/source-map.json').read_text())['upstream_commit'],
        'source_sha256': before,
        'sources_unchanged': unchanged,
        'changed_sources': sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p)),
        'tests': {
            'command': command, 'exit_code': result.returncode, 'suites': len(suites),
            'passed': sum(s[0] for s in suites), 'failed': sum(s[1] for s in suites),
            'ignored': sum(s[2] for s in suites), 'log': str(args.log.resolve()),
            'log_sha256': digest(args.log),
        },
        'evidence_sha256': evidence,
    }
    report['status'] = 'passed' if result.returncode == 0 and unchanged and suites else 'failed'
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k not in {'source_sha256', 'evidence_sha256'}}))
    if report['status'] != 'passed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
