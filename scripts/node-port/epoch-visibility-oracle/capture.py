"""Capture unchanged native Epoch_visibility in a fresh owned host directory.

Requires an existing opam/Dune/Lwt/Yojson installation. No packages are installed,
no Docker is used and the adopted native checkout is never written.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = '7f9be4489870645cfcc95439638cde40f5da9f50'
MODULE_SHA = 'b8829fea1ee36c5712cebd3beb98196e3b977e19136ab0d468655c1e777d6426'
ORACLE_SHA = '97b4f90e7cfd685f239f887f97d5cda8bcc2f29143069678787d79ef66499f81'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def read(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-source', required=True, type=pathlib.Path)
    parser.add_argument('--source-map', type=pathlib.Path, default=ROOT / 'docs/rust-node/source-map.json')
    parser.add_argument('--opam', default='opam')
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    native = args.native_source.resolve(strict=True)
    module = native / 'node_runtime/epoch_visibility.ml'
    inventory = read(args.source_map.read_bytes())
    pin = subprocess.check_output(['git', '-C', str(native), 'rev-parse', 'HEAD'], text=True).strip()
    assert pin == inventory['upstream_commit'] == PIN
    assert inventory['files']['node_runtime/epoch_visibility.ml'] == sha(module) == MODULE_SHA
    assert sha(HERE / 'main.ml') == ORACLE_SHA
    opam = shutil.which(args.opam)
    assert opam is not None, 'existing opam installation required; no packages are installed'
    out = args.out.absolute()
    assert out.parent.resolve(strict=True) == out.parent and not out.exists() and not out.is_symlink()
    assert not out.is_relative_to(native) and not out.is_relative_to(HERE)
    out.mkdir(mode=0o700)
    context = out / 'context'
    context.mkdir()
    for name in ['main.ml', 'dune', 'dune-project']:
        shutil.copyfile(HERE / name, context / name)
    shutil.copyfile(module, context / 'epoch_visibility.ml')
    before = {name: sha(context / name) for name in ['main.ml', 'dune', 'dune-project', 'epoch_visibility.ml']}
    command = [opam, 'exec', '--', 'dune', 'exec', '--root', str(context), '-j', '4',
               './main.exe', '--', MODULE_SHA, ORACLE_SHA]
    environment = {key: value for key, value in os.environ.items() if not key.startswith('OCTRA_')}
    environment['OPAMLOGS'] = str(out / 'opam-logs')
    (out / 'opam-logs').mkdir()
    started = time.monotonic()
    code, failure, process = None, None, None
    with (out / 'stdout.json').open('xb') as stdout, (out / 'stderr.log').open('xb') as stderr:
        try:
            process = subprocess.Popen(command, cwd=context, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            code = process.wait(timeout=120)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            failure = type(error).__name__
        except Exception as error:
            failure = type(error).__name__ + ': ' + str(error)
        finally:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
    after = {name: sha(context / name) for name in before}
    qualified = False
    try:
        assert before == after and sha(module) == MODULE_SHA, 'consumed native/oracle input changed'
        raw = (out / 'stdout.json').read_bytes()
        assert len(raw) <= 65_536
        result = read(raw)
        assert set(result) == {'schema', 'native_pin', 'native_source_sha256', 'oracle_source_sha256', 'cases'}
        assert result['schema'] == 'octra_epoch_visibility_native_fixture_v1'
        assert result['native_pin'] == PIN and result['native_source_sha256'] == MODULE_SHA
        assert result['oracle_source_sha256'] == ORACLE_SHA
        cases = result['cases']
        assert len(cases) == len({case['case'] for case in cases}) == 7
        assert all(set(case) == {'case', 'calls', 'result'} and type(case['calls']) is int
                   and case['calls'] >= 0 and (case['result'] is None or type(case['result']) is str)
                   for case in cases)
        qualified = code == 0 and failure is None
    except Exception as error:
        failure = type(error).__name__ + ': ' + str(error)
    binary = context / '_build/default/main.exe'
    executable = None
    if binary.is_file():
        copied = out / 'native-visibility-oracle'
        shutil.copyfile(binary, copied)
        copied.chmod(0o500)
        executable = {'path': str(copied), 'sha256': sha(copied)}
    report = {'schema': 'octra_native_visibility_reproduction_capture_v1',
              'status': 'PASS_NATIVE_ONLY' if qualified else 'FAILED', 'qualified_native_only': qualified,
              'native_pin': PIN, 'command': command, 'exit_code': code, 'failure': failure,
              'elapsed_seconds': time.monotonic() - started, 'sources_before': before, 'sources_after': after,
              'native_source_sha256': sha(module), 'oracle_source_sha256': ORACLE_SHA,
              'source_map_sha256': sha(args.source_map), 'producer_sha256': sha(pathlib.Path(__file__)),
              'stdout_sha256': sha(out / 'stdout.json'), 'stderr_sha256': sha(out / 'stderr.log'),
              'executable': executable, 'owned_process_reaped': process is not None and process.poll() is not None,
              'rust_comparator_executed': False, 'whole_node_qualified': False,
              'scope': 'Unchanged Epoch_visibility component and read-dispatch class counter control; no financial submission or whole-node qualification.'}
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(out / 'report.json'),
                      'report_sha256': sha(out / 'report.json'), 'fixture_sha256': sha(out / 'stdout.json')}))
    return 0 if qualified else 1


if __name__ == '__main__':
    raise SystemExit(main())
