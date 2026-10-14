#!/usr/bin/env python3
"""Large-dispatcher regression against a real standalone compiler, no VM stub."""
import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--amlc', required=True)
p.add_argument('--expect-collision', action='store_true', help='Negative control against unpatched compiler')
a = p.parse_args()
with tempfile.TemporaryDirectory(prefix='aml-label-regression-') as raw:
    source = pathlib.Path(raw)/'large.aml'
    source.write_text('contract LargeDispatcher {\n'+''.join(
        f'fn test_method_{i}(): bool {{\n  require(epoch >= 0, "epoch")\n  return true\n}}\n' for i in range(105))+'}\n')
    result = subprocess.run([a.amlc, 'abi', str(source)], capture_output=True, text=True)
    if a.expect_collision:
        assert result.returncode != 0 and 'jump destination ' in result.stderr and ' is repeated' in result.stderr, result.stderr
        print('PASS: unpatched compiler reproduces duplicate jump destination')
        sys.exit(0)
    assert result.returncode == 0, result.stderr
    abi = json.loads(result.stdout)
    assert len(abi['functions']) == 105
    for method in ('test_method_0', 'test_method_98', 'test_method_100', 'test_method_104'):
        run = subprocess.run([a.amlc, 'run', str(source), '--method', method], check=True, capture_output=True, text=True)
        assert 'result = bool:true ' in run.stdout, run.stdout
    print('PASS: 105-method dispatcher ABI and early/late method execution')
