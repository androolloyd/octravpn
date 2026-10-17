#!/usr/bin/env python3
"""Qualify pure health policy against exact adopted OCaml function bodies.

This host-only oracle compiles unchanged consensus_health_probe.ml, Env and
Startup_runtime_limits. Recorded adapters supply the root record type and an
unused proposal API; they confer no network, finality or recovery authority.
"""
import argparse
import base64
import collections
import hashlib
import itertools
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = "node_runtime/consensus_health_probe.ml"
ENV = "node_runtime/env.ml"
LIMITS = "node_runtime/startup_runtime_limits.ml"
ENGINE = "lib/consensus/c_engine.ml"
LOW = -(1 << 62)
HIGH = (1 << 62) - 1
ENV_PREFIX = """(* Oracle-only environment acquisition; the native body follows unchanged. *)
module Health_oracle_env = struct
  let values : (string * string) list ref = ref []
  let getenv_opt name = List.assoc_opt name !values
end
module Sys = struct
  include Sys
  let getenv_opt = Health_oracle_env.getenv_opt
end
"""
CONSENSUS_ADAPTER = """(* Oracle-only type boundary; no consensus driver is executed. *)
module C_driver = struct
  type epoch_root_response_record = {{ state_root : string option }}
end
module C_engine = struct
  (* Exact pinned declaration, used only by unobserved liveness-floor output. *)
{engine_declaration}
end
"""
PROPOSAL_ADAPTER = """(* Unused dependency of unchanged Startup_runtime_limits.proposal_limits.
   The oracle never calls proposal_limits; no proposal behavior is qualified. *)
let limits ~max_txs:_ ~max_bytes:_ ~max_ou:_ = ()
"""


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def blob(value):
    return base64.b64encode(value).decode()


def row(group, op, **fields):
    return dict(group=group, op=op, **fields)


def fixtures():
    rows = []
    for f, n, configured in itertools.product(
        [LOW, -1, 0, 1, 2, 4, HIGH], [LOW, 0, 1, 2, 4, 7, HIGH],
        [LOW, -1, 0, 1, 2, 3, 100, HIGH],
    ):
        rows.append(row("required", "required", f=str(f), n=str(n), configured=str(configured)))

    roots = [
        [], [None], [b"a"], [b"a", None, b"a"], [b"a", b"b"],
        [b"b", b"a"], [b"a", b"b", b"b", b"a"],
        [b"", b"\x00", b"\xff", b"a", b"b"],
    ]
    # Table insertion, collision, replacement and resize order determine ties.
    for size in [15, 16, 17, 31, 32, 33, 63, 65, 100]:
        unique = [f"root-{index}".encode() for index in range(size)]
        roots.extend([unique, list(reversed(unique)), unique + unique,
                      unique + [unique[-1], unique[0]], unique[::2] + unique[1::2]])
    roots.extend([[bytes([index]) * 32 for index in range(40)],
                  [b"a" * 32, b"b" * 31, None, b"c" * 33]])
    for index, values in enumerate(roots):
        for required in [-1, 0, 1, 2, 3, HIGH]:
            for committed, genesis in [(False, False), (True, False), (False, True)]:
                rows.append(row("roots", "roots", label=str(index),
                                roots=[None if value is None else blob(value) for value in values],
                                required=str(required), local=blob(b"a"),
                                committed=committed, genesis=genesis))
    for retries, attested in itertools.product([LOW, -2, -1, 0, 1, 2, HIGH], [False, True]):
        rows.append(row("retry", "retry", retries=str(retries), attested=attested))
    for head, ahead, streak, quarantined in itertools.product(
        [0, 31, 32, 33, 100], [-1, 0, 1, 2, 3, 10], [0, 4, 5, 6], [False, True],
    ):
        rows.append(row("ahead", "ahead", head=str(head), ahead=str(ahead), streak=str(streak),
                        grace="32", tolerance="2", threshold="5", quarantined=quarantined))
    for head, ahead, grace, tolerance, threshold in [
        (LOW, LOW, LOW, LOW, LOW), (HIGH, HIGH, HIGH, HIGH, HIGH),
        (0, 0, 0, 0, 1), (1, 1, 0, 0, 1), (100, 3, 32, 2, 1),
    ]:
        for streak, quarantined in itertools.product([0, 1, 5, HIGH], [False, True]):
            rows.append(row("ahead-extremes", "ahead", head=str(head), ahead=str(ahead),
                            streak=str(streak), grace=str(grace), tolerance=str(tolerance),
                            threshold=str(threshold), quarantined=quarantined))
    for lag, soft in itertools.product([LOW, -1, 0, 1, 3, 4, 5, HIGH], [LOW, -1, 0, 4, HIGH]):
        rows.append(row("lag", "lag", lag=str(lag), soft=str(soft)))

    names = ["OCTRA_STATE_ATTEST_MIN_PEERS", "OCTRA_QUARANTINE_AHEAD_STREAK_THRESHOLD",
             "OCTRA_QUARANTINE_AHEAD_GRACE_EPOCHS", "OCTRA_QUARANTINE_AHEAD_DRIFT_TOLERANCE",
             "OCTRA_CATCHUP_SOFT_MAX_LAG"]
    values = [None, b"", b" ", b"\t5\n", b"5\x00", b"\x005", b"-1", b"0", b"1", b"2",
              b"4", b"5", b"32", b"100", b"101", b"10000", b"10001", b"100000", b"100001",
              b"+5", b"5_", b"5__0", b"_5", b"0x5", b"0b101", b"0o5", b"0u5", b"+0x5",
              b"-0x5", b"0x7fffffffffffffff", b"0x4000000000000000", b"0u9223372036854775807",
              str(LOW).encode(), str(HIGH).encode(), str(LOW - 1).encode(), str(HIGH + 1).encode()]
    rows.append(row("config", "config", environment={}))
    for name, value in itertools.product(names, values):
        rows.append(row("config", "config", environment={name: None if value is None else blob(value)}))
    rows.append(row("config", "config", environment=dict(zip(names, map(blob, [b"3", b"1", b"0", b"0", b"0"])))))
    return rows


def host_run(upstream, switch, oracle, inputs, directory):
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

    engine = (upstream / ENGINE).read_text()
    declaration = re.search(r"^let max_timeout_ms = [0-9_]+$", engine, re.MULTILINE)
    if declaration is None:
        raise RuntimeError("pinned engine timeout declaration is unavailable")
    adapters = {
        "octra_consensus.ml": CONSENSUS_ADAPTER.format(engine_declaration=declaration.group()),
        "consensus_proposal.ml": PROPOSAL_ADAPTER,
    }
    for name, source in adapters.items():
        (directory / name).write_text(source)
    copied = {}
    for name in [ENV, LIMITS, PROBE]:
        original = (upstream / name).read_bytes()
        output = (ENV_PREFIX.encode() if name == ENV else b"") + original
        destination = directory / Path(name).name
        destination.write_bytes(output)
        copied[name] = dict(original_sha256=inventory["files"][name],
                            compiled_sha256=sha256(destination), copied_as=destination.name)
    shutil.copyfile(oracle, directory / "main.ml")
    input_json = json.dumps(inputs, separators=(",", ":"))
    (directory / "input.json").write_text(input_json + "\n")
    opam_path = shutil.which("opam")
    if opam_path is None:
        raise RuntimeError("opam is unavailable")
    opam = str(Path(opam_path).resolve())
    execute = [opam, "exec", f"--switch={switch}", "--"]
    version = command("compiler-version", execute + ["ocamlopt", "-version"]).strip()
    compiler_config = command("compiler-config", execute + ["ocamlopt", "-config"])
    opam_version = command("opam-version", [opam, "--version"]).strip()
    tools = {}
    for name in ["ocamlopt", "ocamlfind"]:
        path = Path(command(f"{name}-path", execute + ["which", name]).strip()).resolve()
        tools[name] = dict(path=str(path), sha256=sha256(path))
    packages = ["zarith", "yojson", "base64"]
    rows = command("packages", execute + ["ocamlfind", "query", "-recursive", "-format", "%p\t%v\t%d", *packages])
    resolved = {}
    for row in rows.splitlines():
        name, package_version, package_directory = row.split("\t", 2)
        package_path = Path(package_directory)
        artifacts = {str(path.relative_to(package_path)): sha256(path)
                     for path in sorted(package_path.rglob("*"))
                     if path.is_file() and (path.name == "META" or path.suffix in {
                         ".a", ".cmxa", ".cmx", ".cmi", ".cma", ".cmxs", ".so", ".dylib"})}
        resolved[name] = dict(version=package_version, directory=package_directory, artifact_sha256=artifacts)
    executable = directory / "health-policy-oracle"
    build = execute + ["ocamlfind", "ocamlopt", "-linkpkg", "-package", ",".join(packages),
                       "octra_consensus.ml", "consensus_proposal.ml", "env.ml",
                       "startup_runtime_limits.ml", "consensus_health_probe.ml", "main.ml", "-o", executable.name]
    command("build", build)
    output = command("oracle", [str(executable)], stdin=input_json, environment={"OCAMLRUNPARAM": ""})
    expected = json.loads(output)
    if len(expected) != len(inputs):
        raise RuntimeError("native oracle returned a different case count")
    return dict(
        upstream_commit=pin, source_sha256=inventory["files"], oracle_sha256=sha256(oracle),
        generator_sha256=sha256(Path(__file__)), runner_kind="host-ocaml",
        runner_path="scripts/node-port/health-policy-fixtures.py", runner_sha256=sha256(Path(__file__)),
        cases=expected,
        instrumentation={ENV: dict(kind="test-only source prefix", prefix=ENV_PREFIX,
            prefix_sha256=hashlib.sha256(ENV_PREFIX.encode()).hexdigest(),
            original_sha256=inventory["files"][ENV], compiled_sha256=copied[ENV]["compiled_sha256"], replacements=[])},
        adapters={name: dict(source=source, sha256=sha256(directory / name)) for name, source in adapters.items()},
        host=dict(opam_switch=switch, opam_version=opam_version,
            opam=dict(path=opam, sha256=sha256(Path(opam))), platform=platform.platform(), machine=platform.machine(),
            compiler_version=version, compiler_config=compiler_config, tools=tools,
            requested_packages=packages, packages=resolved, compiled_sources=copied,
            engine_declaration=dict(path=ENGINE, source_sha256=inventory["files"][ENGINE], source=declaration.group()),
            build_command=build, run_command=[str(executable)],
            run_environment_overrides={"OCAMLRUNPARAM": ""},
            executable=dict(path=str(executable), sha256=sha256(executable)),
            input_sha256=sha256(directory / "input.json"), output_sha256=sha256(directory / "oracle.stdout"),
            source_map_sha256=sha256(inventory_path), verified_source_count=len(inventory["files"]),
            evidence_directory=str(directory), commands_sha256=sha256(directory / "commands.json")),
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
    report = host_run(arguments.upstream, arguments.opam_switch,
                      ROOT / "scripts/node-port/health-policy-oracle.ml", inputs, arguments.host_directory)
    report["vector_groups"] = dict(collections.Counter(row["group"] for row in inputs))
    report["qualification"] = dict(
        body="Unchanged adopted health_probe, Env and Startup_runtime_limits source bodies",
        environment="Test-only injected Sys.getenv_opt; process environment acquisition is not qualified",
        adapters="Type-only C_driver root record; exact pinned timeout constant for unobserved liveness output; unused proposal_limits dependency returns unit",
        scope="Pure seed-zero root count/table traversal, required/stale/ahead/lag policy and selected trusted configuration fields",
        excluded="No weighted consensus proof, signature validation, driver, network, orchestrator, rollback, public-network or mainnet qualification",
        runner="Host OCaml standalone modules; no Docker or hermetic-build claim",
    )
    arguments.out.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print(f"PASS: {len(report['cases'])} native health policy cases: {arguments.out}")


if __name__ == "__main__":
    main()
