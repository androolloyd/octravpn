#!/usr/bin/env python3
"""Build bounded consensus/rule vectors from unchanged committed OCaml source.

This does not update the adopted source manifest or historical fixtures. The
small wrapper only exposes the same module aliases as Dune and serializes
observations; no protocol implementation is replaced by a test double.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

PIN = "8f785a93a4e7392a0f3e65674f9de89854d33dbc"
SOURCES = [
    "net/oce1.ml", "net/hash_domain.ml", "lib/consensus/c_protocol.ml",
    "lib/consensus/epoch_time.ml", "lib/consensus/c_epoch_time_policy.ml",
    "lib/consensus/c_quorum_policy.ml", "lib/consensus/c_measure.ml", "lib/consensus/c_types.ml",
    "lib/consensus/c_reward_source.ml", "lib/consensus/c_codec.ml",
    "lib/consensus/c_config.ml", "lib/consensus/c_light_validator_set.ml", "lib/core/rule_graph.ml",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--ocaml-bin", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out.resolve()
    env = os.environ.copy()
    if args.ocaml_bin:
        env["PATH"] = str(args.ocaml_bin) + os.pathsep + env["PATH"]
    find = shutil.which("ocamlfind", path=env["PATH"])
    compiler = shutil.which("ocamlopt", path=env["PATH"])
    if not find or not compiler:
        parser.error("ocamlfind and ocamlopt are required")
    resolved = subprocess.check_output(
        ["git", "-C", str(args.upstream), "rev-parse", PIN], text=True).strip()
    assert resolved == PIN
    hashes = {}
    for source in SOURCES:
        data = subprocess.check_output(
            ["git", "-C", str(args.upstream), "show", f"{PIN}:{source}"])
        (out / Path(source).name).write_bytes(data)
        hashes[source] = hashlib.sha256(data).hexdigest()
    aliases = {
        "octra_net.ml": "module Oce1 = Oce1\nmodule Hash_domain = Hash_domain\n",
        "octra_consensus.ml": "module C_quorum_policy = C_quorum_policy\nmodule C_epoch_time_policy = C_epoch_time_policy\nmodule Epoch_time = Epoch_time\n",
    }
    for name, text in aliases.items():
        (out / name).write_text(text)
    wrapper = Path(__file__).with_suffix(".ml").read_bytes()
    (out / "oracle.ml").write_bytes(wrapper)
    order = ["oce1", "hash_domain", "octra_net", "c_protocol", "epoch_time",
             "c_epoch_time_policy", "c_quorum_policy", "c_measure", "c_types",
             "c_reward_source", "c_codec", "c_config", "c_light_validator_set", "octra_consensus",
             "rule_graph", "oracle"]
    command = [find, "ocamlopt", "-package", "digestif.c,zarith,yojson,base64",
               "-linkpkg", *[name + ".ml" for name in order], "-o", "oracle"]
    build = subprocess.run(command, cwd=out, env=env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / "build.log").write_text(build.stdout)
    if build.returncode:
        raise SystemExit(f"native build failed; see {out / 'build.log'}")
    observations = json.loads(subprocess.check_output([str(out / "oracle")], env=env))
    result = {
        "upstream_commit": PIN,
        "scope": "unchanged native quorum policy and measure, validator-set shape/eviction/pending checks, authors codec/hash and anchored rule graph; not complete node/runtime qualification",
        "source_sha256": hashes,
        "oracle_sha256": hashlib.sha256(wrapper).hexdigest(),
        "aliases_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in aliases.items()},
        "compiler": {"path": compiler, "version": subprocess.check_output([compiler, "-version"], text=True).strip()},
        "build_command": command,
        **observations,
    }
    args.fixture.parent.mkdir(parents=True, exist_ok=True)
    args.fixture.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps({"fixture": str(args.fixture), "policy_cases": len(result["policy"]),
                      "graph_cases": len(result["graph"]), "measure_cases": len(result["measure"]),
                      "set_cases": len(result["sets"]), "commit": PIN}))


if __name__ == "__main__":
    main()
