#!/usr/bin/env python3
"""Qualify quarantine policy against unchanged adopted OCaml implementation.

The dependency-free module is compiled without its restrictive public interface
to observe internal policy functions as well as real entry/clear transitions.
No source prefix, adapter or replacement is used. This is pure policy evidence.
"""
import argparse
import base64
import collections
import hashlib
import itertools
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "node_runtime/consensus_runtime_state.ml"
REASONS = [
    b"peer_root_mismatch_at_head ", b"ahead_of_target_by_", b"lag_",
    b"prev_state_root_mismatch_streak = ", b"state_root_mismatch_streak = ",
    b"catchup_failed:", b"catchup_apply_failed:", b"catchup_",
    b"bundle_wait_timeout_epoch_",
]
HARD = [b"local_state_root_mismatch_at_head_10", b"finality_conflict", b"sync_finality_invalid", b"snapshot_plan_invalid",
        b"fork_snapshot_required:target_root_mismatch", b"fork_repair_staged",
        b"finality_backlog_head_root_missing"]
ROOT_EVIDENCE = [b"genesis_in_sync", b"in_sync", b"ahead_wait_current_head",
                 b"ahead_current_root_quorum", b"soft_lag_current_root"]
EVIDENCE = ROOT_EVIDENCE + [b"in_sync_consensus_quorum", b"fork_empty_rollback",
                          b"catchup_complete:root_verified:", b"direct_finalized_apply:"]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def blob(value):
    return base64.b64encode(value).decode()


def variants(tokens):
    values = {b"", b"\0", b"\xff", b"\xc0\xaf", bytes(range(256))}
    for token in tokens:
        values.update([token, token + b"1", token + b"\0tail", token + b"\xfftail",
                       b"x" + token, b"\0" + token, b"\xff" + token, token.upper(),
                       token.rstrip(b" :_="), token.replace(b"_", b"-"),
                       token + token, b"prefix:" + token])
        # Every truncation and every insertion/replacement position matters:
        # OCaml strings are bytes, and a NUL never terminates a prefix check.
        values.update(token[:length] for length in range(len(token)))
        values.update(token + bytes([byte]) for byte in range(256))
        for offset in range(len(token) + 1):
            for byte in [b"\0", b"\xff"]:
                values.add(token[:offset] + byte + token[offset:])
        for offset in range(len(token)):
            for byte in [b"X", b"\0", b"\xff"]:
                values.add(token[:offset] + byte + token[offset + 1:])
    return sorted(values)


def fixtures():
    rows = []
    seen = set()

    def add(group, op, **fields):
        value = dict(group=group, op=op, **fields)
        identity = json.dumps(value, sort_keys=True)
        if identity not in seen:
            seen.add(identity)
            rows.append(value)

    reason_bytes = variants(REASONS + HARD)
    evidence_bytes = variants(EVIDENCE)
    representatives = REASONS + [value + b"1" for value in REASONS] + HARD + [b"", b"\0\xff"]
    for index, reason in enumerate(reason_bytes):
        add("reason-bytes", "classify", reason=blob(reason))
        add("reason-recovery", "recovery", reason=blob(reason),
            evidence=blob(b"in_sync"), consensus=bool(index % 2))
    for index, evidence in enumerate(evidence_bytes):
        add("evidence-bytes", "evidence", evidence=blob(evidence))
        for reason in [b"lag_1", b"catchup_failed:1", b"finality_conflict"]:
            add("clear-evidence-bytes", "clear", reason=blob(reason), evidence=blob(evidence))
        add("evidence-recovery", "recovery",
            reason=blob([b"lag_1", b"catchup_failed:1"][index % 2]),
            evidence=blob(evidence), consensus=True)
    for reason in representatives:
        for evidence in EVIDENCE + [reason, b"", b"\0\xff"]:
            add("known-clear", "clear", reason=blob(reason), evidence=blob(evidence))
            for consensus in [False, True]:
                add("known-recovery", "recovery", reason=blob(reason), evidence=blob(evidence), consensus=consensus)
    # The byte predicates above are exhaustive over the mutation corpus. State
    # transitions use representative cross-products, keeping the oracle bounded.
    transition_reasons = representatives + [value + b"\0\xff" for value in REASONS]
    pairs = itertools.product(transition_reasons, transition_reasons)
    for old, incoming in pairs:
        add("entry-transitions", "transition", reason=blob(old), incoming=blob(incoming),
            evidence=blob(b"in_sync"), epoch="10", next_epoch="11")
    for old, incoming, evidence, epoch, next_epoch in itertools.product(
        representatives, [b"lag_1", b"finality_conflict"],
        [b"fork_empty_rollback", b"catchup_complete:root_verified:1", b"direct_finalized_apply:1"],
        ["-4611686018427387904", "-1", "0", "4611686018427387903"], ["-1", "12"],
    ):
        add("transition-clear", "transition", reason=blob(old), incoming=blob(incoming),
            evidence=blob(evidence), epoch=epoch, next_epoch=next_epoch)
    for evidence in evidence_bytes:
        add("inactive", "inactive", evidence=blob(evidence))
    return rows


def host_run(upstream, switch, inputs, directory):
    if directory.exists():
        raise SystemExit("require fresh host directory")
    directory.mkdir(parents=True)
    directory = directory.resolve()
    commands = []

    def command(name, arguments, *, stdin=None, environment=None):
        commands.append(dict(name=name, argv=arguments, cwd=str(directory), environment_overrides=environment or {}))
        (directory / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        result = subprocess.run(arguments, cwd=directory, input=stdin, text=True, capture_output=True,
                                env=None if environment is None else os.environ | environment)
        (directory / f"{name}.stdout").write_text(result.stdout)
        (directory / f"{name}.stderr").write_text(result.stderr)
        if result.returncode:
            raise RuntimeError(f"{name} failed with {result.returncode}: {result.stderr}")
        return result.stdout

    inventory_path = ROOT / "docs/rust-node/source-map.json"
    inventory = json.loads(inventory_path.read_text())
    upstream = upstream.resolve()
    pin = command("upstream-pin", ["git", "-C", str(upstream), "rev-parse", "HEAD"]).strip()
    if pin != inventory["upstream_commit"]:
        raise RuntimeError("upstream pin differs")
    for name, digest in inventory["files"].items():
        if sha256(upstream / name) != digest:
            raise RuntimeError(f"modified upstream: {name}")
    (directory / "verified-sources.json").write_text(json.dumps(dict(
        upstream_commit=pin, source_map_sha256=sha256(inventory_path), files=inventory["files"],
    ), indent=2) + "\n")
    shutil.copyfile(upstream / SOURCE, directory / Path(SOURCE).name)
    oracle = ROOT / "scripts/node-port/quarantine-oracle.ml"
    shutil.copyfile(oracle, directory / "main.ml")
    input_json = json.dumps(inputs, separators=(",", ":"))
    (directory / "input.json").write_text(input_json + "\n")
    opam_path = shutil.which("opam")
    if opam_path is None:
        raise RuntimeError("opam is unavailable")
    opam = str(Path(opam_path).resolve())
    execute = [opam, "exec", f"--switch={switch}", "--"]
    version = command("compiler-version", execute + ["ocamlopt", "-version"]).strip()
    if version != "4.14.2":
        raise RuntimeError("quarantine parity requires OCaml4.14.2")
    compiler_config = command("compiler-config", execute + ["ocamlopt", "-config"])
    opam_version = command("opam-version", [opam, "--version"]).strip()
    tools = {"opam": dict(path=opam, sha256=sha256(Path(opam)))}
    for name in ["ocamlopt", "ocamlfind"]:
        path = Path(command(f"{name}-path", execute + ["which", name]).strip()).resolve()
        tools[name] = dict(path=str(path), sha256=sha256(path))
    packages = ["yojson", "base64"]
    package_rows = command("packages", execute + ["ocamlfind", "query", "-recursive", "-format", "%p\t%v\t%d", *packages])
    resolved = {}
    for row in package_rows.splitlines():
        name, package_version, package_directory = row.split("\t", 2)
        package_path = Path(package_directory)
        artifacts = {str(path.relative_to(package_path)): sha256(path)
                     for path in sorted(package_path.rglob("*"))
                     if path.is_file() and (path.name == "META" or path.suffix in {
                         ".a", ".cmxa", ".cmx", ".cmi", ".cma", ".cmxs", ".so", ".dylib"})}
        resolved[name] = dict(version=package_version, directory=package_directory, artifact_sha256=artifacts)
    executable = directory / "quarantine-oracle"
    command("build", execute + ["ocamlfind", "ocamlopt", "-linkpkg", "-package", ",".join(packages),
                               Path(SOURCE).name, "main.ml", "-o", executable.name])
    output = command("oracle", [str(executable)], stdin=input_json, environment={"OCAMLRUNPARAM": ""})
    expected = json.loads(output)
    if len(expected) != len(inputs) or any(row["input"] != value for row, value in zip(expected, inputs)):
        raise RuntimeError("native oracle returned different input vectors")
    return dict(
        upstream_commit=pin, source_sha256=inventory["files"], oracle_sha256=sha256(oracle),
        generator_sha256=sha256(Path(__file__)), runner_kind="host-ocaml",
        runner_path="scripts/node-port/quarantine-fixtures.py", runner_sha256=sha256(Path(__file__)),
        instrumentation={}, adapters={}, cases=expected,
        host=dict(opam_switch=switch, compiler_version=version, compiler_config=compiler_config,
                  opam_version=opam_version, tools=tools, packages=resolved,
                  platform=platform.platform(), machine=platform.machine(),
                  source_map_sha256=sha256(inventory_path), verified_source_count=len(inventory["files"]),
                  compiled_sources={SOURCE: dict(original_sha256=inventory["files"][SOURCE],
                      compiled_sha256=sha256(directory / Path(SOURCE).name), copied_as=Path(SOURCE).name)},
                  omitted_interface=dict(path=SOURCE + "i", source_sha256=inventory["files"][SOURCE + "i"],
                      reason="Pinned public interface hides internal pure policy functions observed by this oracle"),
                  run_environment_overrides={"OCAMLRUNPARAM": ""}, commands=commands,
                  executable_sha256=sha256(executable)),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--opam-switch", required=True)
    parser.add_argument("--host-directory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.out.exists():
        raise SystemExit("require fresh output")
    inputs = fixtures()
    report = host_run(arguments.upstream, arguments.opam_switch, inputs, arguments.host_directory)
    report["vector_groups"] = dict(collections.Counter(row["group"] for row in inputs))
    report["qualification"] = dict(
        body="Unchanged adopted consensus_runtime_state.ml implementation; pinned public interface verified but omitted",
        scope="Byte-prefix reason/evidence predicates and actual native quarantine entry, replacement and clear transitions",
        excluded="No orchestrator, peer authentication, history rollback, public-network or mainnet qualification",
        runner="Host OCaml4.14.2 standalone module; no hermetic-build claim",
    )
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print(f"PASS: {len(report['cases'])} native quarantine policy cases: {arguments.out}")


if __name__ == "__main__":
    main()
