#!/usr/bin/env python3
"""Fingerprint the exact copied source and compiler used by the test image."""
import hashlib
import json
import pathlib
import subprocess

base = pathlib.Path('/work')
roots = [base/'octra'/name for name in (
    'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'crates', 'program',
    'vendor', 'tests', 'pvac-sidecar', 'docker/vpn-transport',
)] + [base/'octra-foundry', base/'headscale-rs']
skip = {'target', 'out', '.git', 'node_modules', '.cargo-cache', '.codex', '.agents'}
paths = []
for root in roots:
    paths.extend([root] if root.is_file() else (
        path for path in root.rglob('*')
        if path.is_file() and not path.is_symlink()
        and not skip.intersection(path.relative_to(root).parts)
    ))
records = []
aggregate = hashlib.sha256(b'octra:vpn:qualification-source:v1\0')
for path in sorted(set(paths)):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1024*1024), b''):
            digest.update(part)
    name = str(path.relative_to(base))
    size = path.stat().st_size
    record = {'path': name, 'bytes': size, 'sha256': digest.hexdigest()}
    aggregate.update(json.dumps(record, sort_keys=True, separators=(',', ':')).encode()+b'\n')
    records.append(record)
print(json.dumps({
    'source_sha256': aggregate.hexdigest(),
    'test_binary_sha256': hashlib.sha256(pathlib.Path('/tmp/vpn-transport-tests').read_bytes()).hexdigest(),
    'rustc': subprocess.check_output(['rustc', '-vV'], text=True),
    'files': records,
}, indent=2))
