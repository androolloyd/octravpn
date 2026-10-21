#!/usr/bin/env python3
"""Check pool AML emitters and real proof vectors against pristine native code.

Input is public-only output from tests/pool_circle.rs. The existing offline
runner verifies the complete adopted runtime source inventory before execution.
No RPC, network transaction, wallet or proving key is used.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    # Resolve an already present image. A missing historical tag must not cause
    # Docker to contact a registry during an explicitly offline qualification.
    image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format',
        '{{.Id}}', args.builder_image], text=True).strip()
    data = json.loads(args.input.read_text())
    assert data['native_public_inputs'] == 17
    assert data['note_depth'] == 32 and data['spent_depth'] == 254
    assert len(data['transitions']) == 6
    assert data['source_sha256'] == hashlib.sha256(data['source'].encode()).hexdigest()
    key = base64.b64decode(data['native_key'], validate=True)
    cases = []
    expected = []

    def add(name, operands, valid, *, view=True):
        cases.append(dict(name=name,
            args=[{'str': base64.b64encode(x).decode()} for x in operands],
            view=view, strict=True, bytes=True, proof_exec=True, fhe_work=True,
            math=True, limit=1_000_000))
        expected.append(valid)

    for index, row in enumerate(data['transitions']):
        proof = base64.b64decode(row['proof'], validate=True)
        inputs = base64.b64decode(row['inputs'], validate=True)
        assert len(inputs) == 17 * 32
        for view in [True, False]:
            add(f'pool {index} valid view={view}', [key, proof, inputs], True, view=view)
        for slot in range(17):
            changed = bytearray(inputs)
            changed[slot * 32 + 31] ^= 1
            add(f'pool {index} mutated input {slot}', [key, proof, changed], False)
        changed = bytearray(proof)
        changed[6] ^= 1
        add(f'pool {index} mutated proof', [key, changed, inputs], False)

    original = ROOT / 'scripts/node-port/groth16-oracle.ml'
    prefix, _ = original.read_text().split('let () =\n', 1)
    source = prefix + r'''
let compile source =
 match Octra_vm.Aml_source.compile ~loops:true ~syntax:Octra_vm.Oct_gen.Source source with
 | Ok compiled -> compiled.octb | Error reason -> failwith reason
let () =
 if Sys.command "opam exec -- dune build bin/octra_pvac_worker.exe >&2" <> 0 then failwith "native worker build";
 Zk_ffi.initialize ();
 let input = Yojson.Basic.from_channel stdin in
 List.iter (fun (source, bytecode) ->
   if compile (member source input |> to_string) <> raw (member bytecode input)
   then failwith ("native pool emitter differs: " ^ source))
   ["source", "bytecode"; "factory", "factory_bytecode"];
 let cases = member "proofs" input |> to_list |> List.map case in
 Yojson.Basic.to_channel stdout (`List cases); print_newline ()
'''
    payload = {name: data[name] for name in ['source', 'bytecode', 'factory', 'factory_bytecode']}
    payload['proofs'] = cases
    runner = load(ROOT / 'scripts/node-port/native-oracle.py')
    with tempfile.TemporaryDirectory(prefix='octra-private-pool-oracle-') as directory:
        path = Path(directory) / 'oracle.ml'
        path.write_text(source)
        report = runner.run(args.upstream, image_id, path, payload,
            'octra_vm octra_core yojson lwt.unix zk_ffi')
    report.update(input_sha256=hashlib.sha256(args.input.read_bytes()).hexdigest(),
        requested_builder_image=args.builder_image, resolved_builder_image=image_id,
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        native_base_oracle_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
        exact_app_emitter=True, exact_factory_emitter=True,
        scope='Unchanged native AML emitters and full-depth pool proof verification in synchronous/stepped VM and real worker. Rust Circle transaction/value qualification is separate; no native full epoch or public deployment is claimed.')
    # Preserve actual native output even when an assertion fails.
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    assert len(report['cases']) == len(expected)
    for row, valid in zip(report['cases'], expected, strict=True):
        result = row['expected']
        assert result['ok'] is True and result['result'] == {'bool': valid}, row
    print(f'PASS {len(expected)} native pool proof cases; exact app/factory AML emitters')


if __name__ == '__main__':
    main()
