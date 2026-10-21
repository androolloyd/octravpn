#!/usr/bin/env python3
"""Regenerate wire vectors with actual pinned wallet code; no network access."""
import argparse
import hashlib
import json
import pathlib
import shlex
import subprocess

PIN = '549536d6fbe265a4aace02bc9b85b5313ebb4868'
ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = ['lib/stealth.hpp', 'crypto_utils.hpp', 'lib/tweetnacl.c', 'lib/tweetnacl.h']


def run(argv):
    return subprocess.check_output(list(map(str, argv)), text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    upstream = args.upstream.resolve()
    assert run(['git', '-C', upstream, 'rev-parse', 'HEAD']) == PIN
    assert not run(['git', '-C', upstream, 'status', '--porcelain', '--', *SOURCES])
    args.out.mkdir(parents=True)
    obj = args.out.resolve() / 'tweetnacl.o'; binary = args.out.resolve() / 'native-stealth-oracle'
    shim = pathlib.Path(__file__).with_name('native-stealth-oracle.cpp')
    flags = shlex.split(run(['pkg-config', '--cflags', '--libs', 'openssl']))
    subprocess.run(['clang', '-O2', '-c', str(upstream / 'lib/tweetnacl.c'), '-o', str(obj)], check=True)
    subprocess.run(['clang++', '-std=c++17', '-O2', '-I', str(upstream), str(shim), str(obj), *flags, '-o', str(binary)], check=True)
    value = json.loads(run([binary]))
    value['oracle'] = {'upstream_commit': PIN, 'sources': {name: hashlib.sha256((upstream / name).read_bytes()).hexdigest() for name in SOURCES},
                       'shim_sha256': hashlib.sha256(shim.read_bytes()).hexdigest(),
                       'randomness': 'Deterministic test-only linked randombytes callback; unchanged native AES/encoding/view/claim implementations',
                       'compiler': run(['clang++', '--version']), 'openssl': run(['pkg-config', '--modversion', 'openssl'])}
    path = args.out / 'native-stealth.json'; path.write_text(json.dumps(value, indent=2) + '\n')
    print(path)


if __name__ == '__main__':
    main()
