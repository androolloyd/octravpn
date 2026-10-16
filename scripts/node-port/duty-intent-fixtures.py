#!/usr/bin/env python3
"""Public deterministic DEVELOPMENT key vectors for native validator exit intent."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    base = dict(key=7, private_key=7, chain='devnet-intent-oracle', epoch='0', expected_epoch='0',
                bad_address=False, bad_public=False, other_chain=False, mutation='none')
    cases = [dict(base, **change) for change in [
        {}, dict(epoch='42', expected_epoch='42'), dict(epoch='42', expected_epoch='43'),
        dict(epoch='42', expected_epoch='41'), dict(epoch=str(2**63-1), expected_epoch=str(2**63-1)),
        dict(epoch='-1'), dict(chain=''), dict(chain='x'*128), dict(chain='x'*129),
        dict(chain='a\x00b'), dict(bad_address=True), dict(bad_public=True),
        dict(private_key=8), dict(other_chain=True),
    ]]
    cases.extend(dict(base, mutation=mutation) for mutation in
                 ['oversized', 'standard', 'epoch_zero', 'signature', 'unknown', 'duplicate'])
    spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    report = native.run(args.upstream, args.builder_image, ROOT/'scripts/node-port/duty-intent-oracle.ml',
                        cases, 'octra_core octra_consensus yojson base64 mirage-crypto-ec')
    report['generator_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['scope'] = ('Signed local validator exit intent encoding, identity/registration binding, canonical '
                       'serialization, signature and malformed input refusal. Public deterministic development '
                       'seed only. Does not qualify durable host locks or duty delivery.')
    args.out.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS native validator intent', len(report['cases']), 'cases')


if __name__ == '__main__':
    main()
