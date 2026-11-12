#!/usr/bin/env python3
"""Candidate-only signed transition traces from unchanged upstream OCaml."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

PIN = "c49de45cf49ebbc2e5c0697eb956cbcada5845e7"
HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--upstream", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--ocaml-bin", type=Path, required=True)
    a = p.parse_args()
    spec = importlib.util.spec_from_file_location("baseline", HERE / "consensus-engine-fixtures.py")
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    source_paths = baseline.SOURCES + ["logging/octra_log_format.ml"]
    a.out.mkdir(parents=True, exist_ok=True)
    out = a.out.resolve()
    hashes = {}
    for path in source_paths:
        data = subprocess.check_output(["git", "-C", str(a.upstream), "show", f"{PIN}:{path}"])
        hashes[path] = hashlib.sha256(data).hexdigest()
        (out / Path(path).name).write_bytes(data)
    aliases = {
        "octra_net.ml": "module Oce1 = Oce1\nmodule Hash_domain = Hash_domain\n",
    }
    modules = ["C_types", "C_quorum_policy", "C_protocol", "C_config", "C_codec", "Epoch_time",
               "C_epoch_time_policy", "C_reward_source", "C_hash", "C_qc", "C_engine"]
    aliases["octra_consensus.ml"] = "\n".join(f"module {name} = {name}" for name in modules) + "\n"
    for name, body in aliases.items():
        (out / name).write_text(body)
    wrapper = (HERE / "consensus-engine-oracle.ml").read_bytes()
    (out / "oracle.ml").write_bytes(wrapper)
    env = os.environ.copy()
    env["PATH"] = str(a.ocaml_bin) + os.pathsep + env["PATH"]
    compiler = shutil.which("ocamlopt", path=env["PATH"])
    find = shutil.which("ocamlfind", path=env["PATH"])
    order = ["oce1", "hash_domain", "octra_net", "octra_log_format", "octra_log", "octra_ed25519",
             "c_protocol", "epoch_time", "c_epoch_time_policy", "c_quorum_policy", "c_types",
             "c_reward_source", "c_codec", "c_config", "c_hash", "c_qc", "c_engine",
             "octra_consensus", "oracle"]
    command = [find, "ocamlopt", "-package", "digestif.c,zarith,yojson,base64,unix,mirage-crypto-ec",
               "-linkpkg", *[m + ".ml" for m in order], "-o", "oracle"]
    build = subprocess.run(command, cwd=out, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / "build.log").write_text(build.stdout)
    if build.returncode:
        raise SystemExit(f"native build failed: {out / 'build.log'}")
    # Preserve the pre-activation cases as input provenance, then replay their
    # complete signed event streams at each new policy boundary.
    selected = [c for c in baseline.cases() if c["n"] == 4 and c["weighted"] and c["epoch"] == "1306547"]
    historical = baseline.cases()
    cases = historical + [dict(c, epoch=str(epoch)) for epoch in [1737332, 1737333, 1739999, 1740000, 1740001] for c in selected]
    (out / "inputs.json").write_text(json.dumps(cases))
    result = subprocess.run([str(out / "oracle"), str(out / "inputs.json")], env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    (out / "run.log").write_text(result.stderr)
    result.check_returncode()
    traces = json.loads(result.stdout)
    report = {"upstream_commit": PIN, "source_sha256": hashes,
              "oracle_sha256": hashlib.sha256(wrapper).hexdigest(),
              "input_generator_sha256": hashlib.sha256((HERE / "consensus-engine-fixtures.py").read_bytes()).hexdigest(),
              "aliases_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k,v in aliases.items()},
              "compiler": {"path": compiler, "version": subprocess.check_output([compiler, "-version"], text=True).strip()},
              "build_command": command,
              "scope": "signed C_engine state transitions at staged policy boundaries; execution callback is fixture boolean, not real state execution or live node qualification",
              "historical_case_count": len(historical), "cases": traces}
    a.fixture.parent.mkdir(parents=True, exist_ok=True)
    a.fixture.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print(json.dumps({"cases": len(traces), "transitions": sum(len(c["expected"]) for c in traces), "fixture": str(a.fixture)}))


if __name__ == "__main__":
    main()
