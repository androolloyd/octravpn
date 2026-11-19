#!/usr/bin/env python3
"""Replay every historical validator control against the committed candidate native code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

PIN = "8f785a93a4e7392a0f3e65674f9de89854d33dbc"
ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--upstream", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--ocaml-bin", type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    out = a.out.resolve()
    modules = ["c_protocol", "epoch_time", "c_epoch_time_policy", "c_quorum_policy",
               "c_measure", "c_types", "c_reward_source", "c_codec", "c_config"]
    paths = ["net/oce1.ml", "net/hash_domain.ml"] + ["lib/consensus/" + m + ".ml" for m in modules]
    hashes = {}
    for path in paths:
        data = subprocess.check_output(["git", "-C", str(a.upstream), "show", f"{PIN}:{path}"])
        hashes[path] = hashlib.sha256(data).hexdigest()
        (out / Path(path).name).write_bytes(data)
    (out / "octra_net.ml").write_text("module Oce1 = Oce1\nmodule Hash_domain = Hash_domain\n")
    (out / "octra_consensus.ml").write_text("\n".join(f"module {m.capitalize()} = {m.capitalize()}" for m in modules) + "\n")
    old_wrapper = ROOT / "scripts/node-port/consensus-validator-oracle.ml"
    wrapper = old_wrapper.read_text().replace("~now ~previous ~candidate", "~now ~previous ~entry:candidate")
    # The weight-only and counted quorums are no longer separate functions:
    # both are the Quorum ask of C_measure under the prior and capped rules.
    for name, rule in [("has_weight_quorum", "Prior"), ("has_quorum", "Capped")]:
        call = f"T.{name} s signers"
        if wrapper.count(call) != 1:
            raise SystemExit("historical wrapper no longer calls " + name)
        wrapper = wrapper.replace(call, "(match T.signed_weight s signers with None -> false | Some weight -> "
            f"C_measure.meets (T.space_for_rule C_quorum_policy.{rule} s) C_measure.Quorum "
            "~seats:(T.unique_signer_count signers) ~weight)")
    (out / "oracle.ml").write_text(wrapper)
    historical = ROOT / "crates/octra-node-protocol/tests/fixtures/consensus-validators.json"
    inputs = [c["input"] for c in json.loads(historical.read_text())["cases"]]
    (out / "inputs.json").write_text(json.dumps(inputs))
    env = {**os.environ, "PATH": str(a.ocaml_bin) + os.pathsep + os.environ["PATH"]}
    order = ["oce1", "hash_domain", "octra_net"] + modules + ["octra_consensus", "oracle"]
    command = [str(a.ocaml_bin / "ocamlfind"), "ocamlopt", "-package", "digestif.c,zarith,yojson,base64",
               "-linkpkg", *[m + ".ml" for m in order], "-o", "oracle"]
    build = subprocess.run(command, cwd=out, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / "build.log").write_text(build.stdout)
    if build.returncode:
        raise SystemExit(f"native build failed: {out / 'build.log'}")
    cases = json.loads(subprocess.check_output([str(out / "oracle"), str(out / "inputs.json")], env=env))
    report = dict(upstream_commit=PIN, source_sha256=hashes,
                  historical_fixture_sha256=hashlib.sha256(historical.read_bytes()).hexdigest(),
                  historical_oracle_sha256=hashlib.sha256(old_wrapper.read_bytes()).hexdigest(),
                  oracle_sha256=hashlib.sha256(wrapper.encode()).hexdigest(),
                  wrapper_adaptation="Epoch_time.check_proposal named argument candidate renamed entry; "
                  "has_weight_quorum and has_quorum expressed as the C_measure Quorum ask under the prior and capped rules",
                  scope=__doc__, cases=cases)
    a.fixture.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print(json.dumps(dict(cases=len(cases), fixture=str(a.fixture))))


if __name__ == "__main__":
    main()
