"""Convert a completed real native capture to a path-free regression fixture.

No oracle is executed and no expected results are synthesized. Every case is
copied from its hash-checked actual stdout after validating the completed report.
"""
import argparse
import hashlib
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
PIN = '7f9be4489870645cfcc95439638cde40f5da9f50'
SOURCE_SHA = 'ddefd67b70c877129f1678655715abf6a6a0a1b652c0394be552a4eb8c31e141'
ORACLE_SHA = '0c6a9bb1a34c3e457008c7d41f0ebd4f2dee587f448d8f71d14178f091f39925'
INPUTS_SHA = '998eeabecce66b4c3660dc539d9b63333d3b5e7a5894b5ff0c19652ef61c6a23'
RUNNER_SHA = '6270153a7a6b30e7a30c4595c9e53f90fcbfe7adf30ab5ea4b77e598fdcc320b'
SCOPE = 'epoch-only compatibility profile; not authenticated execution-rule activation'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pairs(values):
    result = {}
    for name, value in values:
        if name in result:
            raise ValueError('duplicate JSON field')
        result[name] = value
    return result


def read(path):
    raw = path.read_bytes()
    assert len(raw) <= 16 * 1024 * 1024, 'fixture size bound'
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', required=True, type=pathlib.Path)
    parser.add_argument('--source-map', required=True, type=pathlib.Path)
    parser.add_argument('--build-provenance', required=True, type=pathlib.Path)
    parser.add_argument('--native-bin', required=True, type=pathlib.Path)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    assert not args.out.exists(), 'append-only output required'
    capture = read(args.capture)
    inputs = read(HERE / 'cases.json')
    source_map = read(args.source_map)
    assert sha(HERE / 'cases.json') == INPUTS_SHA
    assert sha(HERE / 'profile.ml') == ORACLE_SHA
    assert sha(HERE / 'run_profile.py') == RUNNER_SHA
    assert source_map['upstream_commit'] == PIN and len(source_map['files']) == 1158
    source_bytes = json.dumps(source_map['files'], sort_keys=True, separators=(',', ':')).encode()
    assert hashlib.sha256(source_bytes).hexdigest() == SOURCE_SHA
    assert capture['schema'] == 'octra_native_consensus_profile_capture_v1'
    assert capture['status'] == 'PASS_NATIVE_ONLY' and capture['native_component_cases_passed'] is True
    assert capture['failure'] is None and capture['case_count'] == 96
    assert capture['rust_comparator_executed'] is False and capture['whole_node_qualified'] is False
    assert capture['native_pin'] == PIN and capture['native_sources_sha256'] == SOURCE_SHA
    assert capture['sources_before'] == source_map['files'] == capture['sources_after']
    assert capture['oracle_source']['sha256'] == ORACLE_SHA
    assert capture['case_inputs']['sha256'] == INPUTS_SHA
    assert capture['producer']['sha256'] == RUNNER_SHA
    assert capture['build_provenance']['sha256'] == sha(args.build_provenance)
    assert capture['native_binary']['sha256'] == sha(args.native_bin)
    assert inputs['schema'] == 'octra_native_consensus_profile_inputs_v1'
    assert len(inputs['cases']) == len(capture['cases']) == len(capture['case_records']) == 96
    assert len({case['id'] for case in inputs['cases']}) == 96
    assert sum(case['expect_valid'] is True for case in inputs['cases']) == 57
    copied = []
    for index, (case, record, output) in enumerate(zip(inputs['cases'], capture['case_records'], capture['cases'])):
        folder = args.capture.parent / f'case-{index:03d}'
        assert record['id'] == case['id'] and record['exit_code'] == 0
        assert sha(folder / 'input.json') == record['input_sha256']
        assert read(folder / 'input.json') == case
        assert sha(folder / 'stdout.json') == record['stdout']['sha256']
        assert sha(folder / 'stderr.log') == record['stderr']['sha256']
        assert read(folder / 'stdout.json') == output
        assert output['schema'] == 'octra_native_consensus_profile_case_v1'
        assert output['id'] == case['id'] and output['env'] == case['env']
        assert output['chain_id'] == case['chain_id'] and output['valid'] is case['expect_valid']
        assert output['native_pin'] == PIN and output['native_sources_sha256'] == SOURCE_SHA
        assert output['oracle_source_sha256'] == ORACLE_SHA and output['selector_scope'] == SCOPE
        copied.append(output)
    fixture = {
        'schema': 'octra_native_consensus_profile_fixture_v1',
        'native_pin': PIN, 'native_sources_sha256': SOURCE_SHA,
        'oracle_source_sha256': ORACLE_SHA, 'case_inputs_sha256': INPUTS_SHA,
        'capture_sha256': sha(args.capture),
        'build_provenance_sha256': sha(args.build_provenance),
        'native_binary_sha256': sha(args.native_bin),
        'native_capture_status': capture['status'], 'case_count': len(copied), 'cases': copied,
        'rust_comparator_executed_at_capture': False, 'whole_node_qualified': False,
        'selector_scope': SCOPE,
    }
    with args.out.open('x', encoding='utf-8') as handle:
        handle.write(json.dumps(fixture, indent=2, ensure_ascii=True) + '\n')
    print(json.dumps({'fixture': str(args.out.resolve()), 'sha256': sha(args.out),
                      'cases': len(copied), 'rust_comparator_executed': False}))


if __name__ == '__main__':
    main()
