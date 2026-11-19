#!/usr/bin/env python3
"""Native c49 startup/profile oracle using exact dependency declaration slices.

Consensus_profile and all hash/activation implementations are unchanged. Unused
execution/store code is excluded, with every original source and compiled slice
hashed. The KAT calls the original native PVAC AES implementation, not a constant.
This captures profile commitments, not state execution or whole-node parity.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PIN = "8f785a93a4e7392a0f3e65674f9de89854d33dbc"
ROOT = Path(__file__).resolve().parents[2]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--upstream", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--ocaml-bin", type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    out = a.out.resolve()
    paths = subprocess.check_output(["git", "-C", str(a.upstream), "ls-tree", "-r", "--name-only", PIN], text=True).splitlines()
    originals, generated, extracts = {}, {}, {}

    def read(path):
        if path not in originals:
            originals[path] = subprocess.check_output(["git", "-C", str(a.upstream), "show", f"{PIN}:{path}"])
        return originals[path].decode()

    def source(name):
        return next(path for path in paths if path.endswith("/" + name + ".ml"))

    def whole(name):
        generated[name + ".ml"] = read(source(name))

    def sliced(name, spans, path=None):
        path = path or source(name)
        body = read(path)
        chunks = []
        for start, end in spans:
            lo = body.index(start) if start is not None else 0
            hi = body.index(end, lo) if end is not None else len(body)
            chunks.append(body[lo:hi])
        text = "\n".join(chunks)
        generated[name + ".ml"] = text
        extracts[name + ".ml"] = dict(source=path, spans=spans, compiled_sha256=sha(text.encode()))

    def declarations(name, labels, path=None):
        path = path or source(name)
        body = read(path)
        starts = list(re.finditer(r"^(?:type|let(?: rec)?|module|external) [^\n]+", body, re.M))
        selected = []
        for label in labels:
            found = [i for i, m in enumerate(starts) if m.group().startswith(label)]
            if len(found) != 1:
                raise ValueError((name, label, len(found)))
            i = found[0]
            selected.append((starts[i].group(), starts[i+1].group() if i+1 < len(starts) else None))
        sliced(name, selected, path)

    for name in ["oce1", "hash_domain", "c_protocol", "epoch_time", "c_epoch_time_policy", "c_quorum_policy", "rule_graph",
                 "private_result_policy", "epoch_cadence", "scalar_work"]:
        whole(name)
    # Everything but the store-backed parent check, which is not a commitment.
    sliced("consensus_profile", [(None, "let check_execution_parent "), ("let epochs ?policy", None)])
    sliced("transaction", [(None, "type t ="), ("let stealth_min_ou_default", "let program_deploy_min_ou_from_wire_len")])
    sliced("preverify_receipt_policy", [(None, "let check ~rejections")])
    sliced("emission_schedule", [(None, "let parse_nonnegative")])
    declarations("validator_entry", ["type parameters ="])
    sliced("validator_policy", [(None, "let withdraw_epoch"), ("let parse_activation", "let lifecycle_enabled")])
    declarations("validator_ready_policy", ["let window =", "let window_id ="])
    whole("validator_participation")
    declarations("set_fold", ["type cfg =", "let marks_id =", "let standard =", "let participating =", "let validate_cfg ", "let consensus_id "])
    declarations("set_rule", ["let consensus_id ="])
    declarations("private_transition", ["let consensus_id ="])
    declarations("circle_cell_transition", ["let consensus_id ="])
    declarations("circle_hfhe_transcript", ["let consensus_id ="])
    declarations("circle_runtime_storage", ["let consensus_id ="])
    declarations("consensus_reward_attribution", ["let consensus_id ="])
    declarations("fee_policy", ["let consensus_id ="])
    whole("reward_policy")
    declarations("private_ledger", ["let cipher_proof_id ="])
    declarations("circle_wasm_host", ["let float_id ="])
    declarations("compute_bill", ["let max_wire =", "let max_fuel =", "let model_limit =", "let consensus_id ="])
    declarations("tx_envelope", ["let consensus_id ="])
    declarations("tx_signature", ["type t =", "let at_plan ", "let at ", "let consensus_id ="])
    declarations("resource_lanes", ["type lane =", "type budget =", "let to_string =", "let all =", "let default_budget ="])
    declarations("tx_staging", ["let max_ou_per_epoch ="])
    sliced("startup_runtime_limits", [(None, "let consensus_limits env"), ("let proposal_limits env", None)])
    declarations("consensus_proposal", ["type limits =", "let limits "])
    declarations("int_work", ["let consensus_id ="])
    declarations("byte_work", ["type limits =", "let consensus_limits =", "let consensus_id ="])
    declarations("fhe_memory", ["let limit =", "let image_factor =", "let key_factor =", "let key_scratch =", "let public_cells =", "let cell_bytes =", "let key_io_bytes =", "let consensus_id ="])
    declarations("fhe_view_policy", ["let base_effort =", "let base_layer_pairs =", "let edge_divisor =", "let cell_limit =", "let layer_limit =", "let word_limit =", "let cell_effort =", "let product_edges =", "let sample_factor =", "let memory_cell =", "let memory_item =", "let memory_word =", "let consensus_id ="])
    declarations("program_package", ["let source_id =", "let preview_id =", "let compiler_profile_id =", "let standard_id ="])
    declarations("program_record", ["let identity ", "let consensus_id =", "let prior_id =", "let released_id ="])
    sliced("contract_vm", [(None, "type mem ="), ("let effort_cost =", "let is_valid_addr ")])
    sliced("fhe_image", [(None, "let key_size ")])
    sliced("pvac_ffi", [(None, "external isolate_worker"), ("external aes_kat :", None)])
    sliced("crypto_fhe_balance", [("  let aes_kat_hex_cache", "  let derive_pvac_keys")], "lib/core/crypto.ml")
    generated["crypto.ml"] = "module FheBalance = Crypto_fhe_balance\n"
    declarations("pvac_registry", ["module FB =", "let expected_kat "])
    generated["octra_net.ml"] = "module Oce1 = Oce1\nmodule Hash_domain = Hash_domain\n"
    groups = {
        "octra_consensus": ["C_protocol", "C_quorum_policy", "C_epoch_time_policy", "Epoch_time"],
        "octra_circle_runtime": ["Circle_runtime_storage"],
        "octra_vm": ["Program_package", "Int_work", "Contract_vm", "Fhe_view_policy", "Byte_work", "Program_record", "Scalar_work"],
        "octra_node_runtime": ["Consensus_profile", "Startup_runtime_limits", "Consensus_proposal", "Epoch_cadence"],
        "octra_core": ["Rule_graph", "Transaction", "Preverify_receipt_policy", "Private_result_policy", "Emission_schedule",
            "Validator_policy", "Pvac_registry", "Resource_lanes", "Tx_staging", "Fee_policy", "Set_fold", "Reward_policy",
            "Private_transition", "Circle_cell_transition", "Circle_hfhe_transcript", "Validator_ready_policy", "Circle_wasm_host",
            "Tx_envelope", "Compute_bill", "Private_ledger", "Tx_signature", "Fhe_image"],
    }
    for group, names in groups.items():
        generated[group + ".ml"] = "\n".join(f"module {name} = {name}" for name in names) + "\n"
    stamp = re.search(r"expected = '([a-f0-9]{64})'", read("lib/vm/dune")).group(1)
    stamp_hash = hashlib.sha256()
    for path in sorted(path for path in paths if any(path.startswith("lib/vm/" + group + "/") for group in ["compiler", "aml", "policy", "wire", "runtime"])
                       and Path(path).suffix in [".ml", ".mli", ".c", ".h"]):
        read(path)
        header = ("// SPDX-License-Identifier: BSD-3-Clause\n// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>\n\n" if Path(path).suffix in [".c", ".h"]
                  else "(* SPDX-License-Identifier: BSD-3-Clause *)\n(* Copyright (c) 2023-2026 Octra Labs <dev@octra.org> *)\n\n").encode()
        body = originals[path].removeprefix(header).rstrip(b"\n")
        stamp_hash.update((sha(body) + "  " + path.removeprefix("lib/vm/") + "\n").encode())
    assert stamp_hash.hexdigest() == stamp
    generated["source_stamp.ml"] = f'let id = "{stamp}"\n'
    wrapper = Path(__file__).with_suffix(".ml").read_bytes()
    generated["oracle.ml"] = wrapper.decode()
    for name, body in generated.items():
        (out / name).write_text(body)
    # Original AES KAT entry point, with only its required native headers.
    native = read("pvac_ffi/pvac_stubs.cpp")
    begin = native.index("CAMLprim value caml_pvac_aes_kat(")
    end = native.index("\n}", begin) + 2
    kat = 'extern "C" {\n#include <caml/mlvalues.h>\n#include <caml/memory.h>\n#include <caml/alloc.h>\n}\n#include "pvac/pvac.hpp"\n#include <cstring>\nextern "C" {\n' + native[begin:end] + "\n}\n"
    (out / "kat.cpp").write_text(kat)
    extracts["kat.cpp"] = dict(source="pvac_ffi/pvac_stubs.cpp", start=begin, end=end, compiled_sha256=sha(kat.encode()))
    for path in paths:
        if path.startswith("pvac/include/") and Path(path).suffix in [".hpp", ".h"]:
            target = out / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(read(path))
    env = {k: v for k,v in os.environ.items() if not k.startswith("OCTRA_")}
    env["PATH"] = str(a.ocaml_bin) + os.pathsep + env["PATH"]
    names = list(generated)
    dependency_text = subprocess.check_output([str(a.ocaml_bin / "ocamldep"), "-modules", *names], cwd=out, env=env, text=True)
    deps = dict(line.split(":", 1) for line in dependency_text.splitlines())
    modules = {Path(name).stem.capitalize(): name for name in names}
    order, visiting, done = [], set(), set()
    def visit(name):
        if name in done: return
        if name in visiting: raise ValueError("module cycle: " + name)
        visiting.add(name)
        for module in deps[name].split():
            if module in modules: visit(modules[module])
        visiting.remove(name)
        done.add(name)
        order.append(name)
    visit("oracle.ml")
    find = str(a.ocaml_bin / "ocamlfind")
    ocamlwhere = subprocess.check_output([str(a.ocaml_bin / "ocamlc"), "-where"], text=True).strip()
    packages = "zarith,yojson,base64,digestif.c,unix"
    commands = [["clang++", "-std=c++17", "-O2", "-I", ocamlwhere, "-I", str(out / "pvac/include"), "-c", "kat.cpp", "-o", "kat.o"]]
    commands += [[find, "ocamlopt", "-package", packages, "-w", "-a", "-c", name] for name in order]
    commands += [[find, "ocamlopt", "-package", packages, "-linkpkg", *[str(Path(name).with_suffix(".cmx")) for name in order], "kat.o", "-cclib", "-lc++", "-o", "oracle"]]
    with (out / "build.log").open("w") as log:
        for command in commands:
            result = subprocess.run(command, cwd=out, env=env, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode: raise SystemExit(f"native build failed: {command}; see {out / 'build.log'}")
    source_hashes = {path: sha(data) for path,data in sorted(originals.items())}
    source_digest = sha(json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode())
    provenance = dict(upstream_commit=PIN, source_sha256=source_hashes, extraction=extracts, compiled_modules=order,
                      compiled_sha256={name: sha(generated[name].encode()) for name in order},
                      source_stamp=stamp, oracle_sha256=sha(wrapper), build_command=commands,
                      compiler_version=subprocess.check_output([str(a.ocaml_bin / "ocamlopt"), "-version"], text=True).strip(), scope=__doc__)
    provenance_data = (json.dumps(provenance, indent=2) + "\n").encode()
    a.fixture.with_name(a.fixture.stem + "-provenance.json").write_bytes(provenance_data)
    inputs_path = ROOT / "crates/octra-node-protocol/tests/fixtures/consensus-profile-inputs.json"
    inputs = json.loads(inputs_path.read_text())["cases"]
    results = []
    for index, case in enumerate(inputs):
        path = out / f"input-{index:03d}.json"
        path.write_text(json.dumps(case))
        result = subprocess.run([str(out / "oracle"), str(path), source_digest, sha(wrapper)], env={**env, **case["env"]}, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        (out / f"stderr-{index:03d}.log").write_text(result.stderr)
        if result.returncode: raise SystemExit(f"native case {index} failed: {result.stderr}")
        results.append(json.loads(result.stdout))
    capture = json.dumps(results, separators=(",", ":")).encode()
    (out / "capture.json").write_bytes(capture)
    report = dict(schema="octra_native_consensus_profile_fixture_v1", native_pin=PIN,
                  native_sources_sha256=source_digest, oracle_source_sha256=sha(wrapper), case_inputs_sha256=sha(inputs_path.read_bytes()),
                  capture_sha256=sha(capture), build_provenance_sha256=sha(provenance_data), native_binary_sha256=sha((out / "oracle").read_bytes()),
                  native_capture_status="PASS_NATIVE_ONLY", case_count=len(results), cases=results,
                  rust_comparator_executed_at_capture=False, whole_node_qualified=False,
                  selector_scope="epoch-only compatibility profile; not authenticated execution-rule activation")
    a.fixture.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(cases=len(results), modules=len(order), sources_sha256=source_digest, oracle_sha256=sha(wrapper), fixture=str(a.fixture))))


if __name__ == "__main__":
    main()
