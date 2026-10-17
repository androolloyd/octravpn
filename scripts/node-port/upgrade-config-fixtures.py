#!/usr/bin/env python3
"""Compare trusted upgrade configuration with the adopted native parser.

The recorded prefix replaces only Sys.getenv_opt with per-case bytes. Native
parser, validation, defaults and transport behavior bodies are left unchanged.
No public network, process-environment loading or whole-launcher parity claim.
"""
import argparse
import base64
import collections
import hashlib
import importlib.util
import itertools
import json
import platform
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NATIVE_SOURCE = "net/p2p_upgrade_plan.ml"
PREFIX = """(* Test-only getter injection; the original parser body follows unchanged. *)
module Octra_upgrade_env = struct
  let values : (string * string) list ref = ref []
  let reads : string list ref = ref []
  let getenv_opt name =
    reads := name :: !reads;
    List.assoc_opt name !values
end
module Sys = struct
  include Sys
  let getenv_opt = Octra_upgrade_env.getenv_opt
end
"""
UPGRADE_EPOCH = "OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH"
UPGRADE_BINARY = "OCTRA_P2P_UPGRADE_BINARY_HASH"
UPGRADE_CONFIG = "OCTRA_P2P_UPGRADE_CONFIG_HASH"
ROLLBACK_EPOCH = "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH"
ROLLBACK_BINARY = "OCTRA_P2P_ROLLBACK_BINARY_HASH"
ROLLBACK_CONFIG = "OCTRA_P2P_ROLLBACK_CONFIG_HASH"
BASE = bytes([1]) * 32
OLD_BINARY = bytes([2]) * 32
NEW_BINARY = bytes([3]) * 32
NEW_CONFIG = bytes([4]) * 32
ROLLBACK_BINARY_VALUE = bytes([5]) * 32
MAX = (1 << 63) - 1


def blob(value):
    return base64.b64encode(value).decode()


def probe(epoch, config=BASE, binary=OLD_BINARY, required=True):
    return dict(epoch=str(epoch), config=blob(config), binary=blob(binary), required=required)


def probes(epoch=10, rollback=20):
    rows = [probe(-(1 << 63)), probe(0)]
    for height in sorted({epoch - 1, epoch, min(MAX, epoch + 1), rollback - 1, rollback, min(MAX, rollback + 1), MAX}):
        for config, binary, required in [
            (BASE, OLD_BINARY, True),
            (NEW_CONFIG, NEW_BINARY, True),
            (BASE, ROLLBACK_BINARY_VALUE, True),
            (NEW_CONFIG, OLD_BINARY, False),
        ]:
            rows.append(probe(height, config, binary, required))
    return rows


def case(group, label, environment, *, required=True, base=BASE, observations=None):
    return dict(
        group=group,
        label=label,
        base_config=blob(base),
        required=required,
        environment={name: None if value is None else blob(value) for name, value in environment.items()},
        probes=probes() if observations is None else observations,
    )


def fixtures():
    rows = []
    upgrade = {UPGRADE_EPOCH: b"10", UPGRADE_BINARY: NEW_BINARY}
    complete = upgrade | {ROLLBACK_EPOCH: b"20", ROLLBACK_BINARY: ROLLBACK_BINARY_VALUE}

    # Disabled schedules do not even acquire inputs. Config-only values and
    # rollback-only values are ignored without an upgrade epoch/binary pair.
    for required in [False, True]:
        for name, environment in [
            ("absent", {}),
            ("explicit-null", {UPGRADE_EPOCH: None, UPGRADE_BINARY: None}),
            ("orphan-config", {UPGRADE_CONFIG: b"bad"}),
            ("orphan-rollback", {ROLLBACK_EPOCH: b"bad", ROLLBACK_BINARY: b"bad"}),
            ("all-orphans", {UPGRADE_CONFIG: b"bad", ROLLBACK_CONFIG: b"bad", ROLLBACK_EPOCH: b"bad"}),
        ]:
            rows.append(case("absence", f"{name}-{required}", environment, required=required, base=b"unused-invalid-default"))
    for index, environment in enumerate([
        {UPGRADE_EPOCH: b"bad"},
        {UPGRADE_BINARY: b"bad"},
        {UPGRADE_EPOCH: b"bad", UPGRADE_BINARY: b"bad", UPGRADE_CONFIG: b"bad"},
        complete | {UPGRADE_CONFIG: b"bad", ROLLBACK_CONFIG: b"bad"},
    ]):
        rows.append(case("disabled", str(index), environment, required=False, base=b"invalid"))
    for index, environment in enumerate([
        {UPGRADE_EPOCH: b"bad"},
        {UPGRADE_BINARY: b"bad"},
        {UPGRADE_EPOCH: b"10", UPGRADE_CONFIG: b"bad"},
        {UPGRADE_BINARY: NEW_BINARY, UPGRADE_CONFIG: b"bad"},
        upgrade | {ROLLBACK_EPOCH: b"bad", ROLLBACK_CONFIG: b"bad"},
        upgrade | {ROLLBACK_BINARY: b"bad", ROLLBACK_CONFIG: b"bad"},
    ]):
        rows.append(case("partial", str(index), environment))

    epochs = [
        b"", b" ", b"\t\r\n\x0c", b"\x0b10\x0b", b"\x0010", b"10\x00", b"1 0", b"\xc2\xa010",
        b"0", b"-0", b"+0", b"-1", b"+", b"-", b"++1", b"--1", b"-+1", b"_1", b"1_", b"1__0",
        b"10", b"010", b"+10", b"  \t10\r\n\x0c", b"1e1", b"1.0", b"0x", b"0x_1", b"0xA", b"0Xa",
        b"+0xA", b"-0xA", b"0b1010", b"0B1010", b"0o12", b"0O12", b"0u10", b"0U10",
        b"0xffffffffffffffff", b"0x8000000000000000", b"-0xffffffffffffffff", b"0u18446744073709551615",
        b"4611686018427387904", b"9223372036854775807", b"9223372036854775808",
        b"-9223372036854775808", b"-9223372036854775809", b"18446744073709551615", b"0x10000000000000000",
    ]
    for index, raw in enumerate(epochs):
        for binary in [NEW_BINARY, b"bad"]:
            rows.append(case("upgrade-epoch", f"{index}-{len(binary)}", {UPGRADE_EPOCH: raw, UPGRADE_BINARY: binary}))
            rows.append(case("rollback-epoch", f"{index}-{len(binary)}", upgrade | {ROLLBACK_EPOCH: raw, ROLLBACK_BINARY: binary}))

    # Hash lengths are checked before trimming: 32 spaces is a raw hash. Native
    # int_of_string also determines which two-byte hexadecimal chunks it accepts.
    hashes = [
        b"", b"bad", bytes(31), bytes(32), bytes(range(32)), bytes([255]) * 32, b" " * 32,
        b"\t" + BASE + b"\r", BASE + b"x", b"00" * 32, b"FF" * 32, b"aB" * 32,
        b" \t" + b"aB" * 32 + b"\r\n\x0c", b"\x0b" + b"aB" * 32, b"aB" * 32 + b"\x0b",
        b"1_" * 32, b"_1" * 32, b"0x" * 32, b"+1" * 32, b"++" * 32, b"GG" * 32,
        bytes(64), b"a" * 63, b"a" * 65,
    ]
    for index, raw in enumerate(hashes):
        for field in [UPGRADE_BINARY, UPGRADE_CONFIG, ROLLBACK_BINARY, ROLLBACK_CONFIG]:
            rows.append(case("hashes", f"{field}-{index}", complete | {field: raw}))

    # Rollback defaults to the original base, never the target configuration.
    for base, target, rollback in itertools.product(
        [BASE, b"Aa" * 32, b"bad"],
        [None, NEW_CONFIG, b"Bb" * 32],
        [None, BASE, b"Cc" * 32],
    ):
        rows.append(case("defaults", f"{len(base)}-{target is None}-{rollback is None}-{len(rows)}", complete | {
            UPGRADE_CONFIG: target, ROLLBACK_CONFIG: rollback,
        }, base=base))
    rows.append(case("defaults", "rollback-config-without-rollback", upgrade | {ROLLBACK_CONFIG: b"bad"}))

    # Competing invalid fields pin which error is returned first.
    for epoch, binary, config, rollback_epoch, rollback_binary, rollback_config in itertools.product(
        [b"bad", b"0", b"10"], [b"bad", NEW_BINARY], [b"bad", BASE],
        [b"bad", b"10", b"20"], [b"bad", ROLLBACK_BINARY_VALUE], [b"bad", BASE],
    ):
        rows.append(case("priority", str(len(rows)), {
            UPGRADE_EPOCH: epoch, UPGRADE_BINARY: binary, UPGRADE_CONFIG: config,
            ROLLBACK_EPOCH: rollback_epoch, ROLLBACK_BINARY: rollback_binary, ROLLBACK_CONFIG: rollback_config,
        }))

    for raw, epoch in [(b"1", 1), (b" \t+0x1_0\r\n\x0c", 16), (str(MAX - 1).encode(), MAX - 1), (str(MAX).encode(), MAX)]:
        for rollback_epoch in [None, min(MAX, epoch + 1), epoch]:
            environment = {UPGRADE_EPOCH: raw, UPGRADE_BINARY: NEW_BINARY, UPGRADE_CONFIG: NEW_CONFIG}
            if rollback_epoch is not None:
                environment |= {ROLLBACK_EPOCH: str(rollback_epoch).encode(), ROLLBACK_BINARY: ROLLBACK_BINARY_VALUE}
            rows.append(case("boundaries", f"{epoch}-{rollback_epoch}", environment,
                             observations=probes(epoch, rollback_epoch or min(MAX, epoch + 1))))
    return rows


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_run(upstream, switch, oracle, inputs, directory):
    """Compile the exact standalone dependency closure, with no native edits.

    The original upgrade module receives the same recorded getter prefix as the
    Docker path. Host dependency resolution is recorded, not called hermetic.
    All build inputs, logs and the executable remain in the fresh directory.
    """
    if directory.exists():
        raise SystemExit("require fresh host directory")
    directory.mkdir(parents=True)
    directory = directory.resolve()
    commands = []

    def command(name, arguments, *, stdin=None):
        commands.append(dict(name=name, argv=arguments, cwd=str(directory)))
        (directory / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        result = subprocess.run(arguments, cwd=directory, input=stdin, text=True, capture_output=True)
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

    sources = ["net/oce1.ml", "net/hash_domain.ml", "crypto_guard/octra_ed25519.ml",
               "net/p2p_peer_record.ml", NATIVE_SOURCE]
    compiled_sources = {}
    instrumentation = {}
    for name in sources:
        original = (upstream / name).read_bytes()
        compiled = PREFIX.encode() + original if name == NATIVE_SOURCE else original
        destination = directory / Path(name).name
        destination.write_bytes(compiled)
        compiled_sources[name] = dict(original_sha256=inventory["files"][name],
                                      compiled_sha256=sha256(destination), copied_as=destination.name)
        if name == NATIVE_SOURCE:
            instrumentation[name] = dict(
                kind="test-only source prefix", prefix=PREFIX,
                prefix_sha256=hashlib.sha256(PREFIX.encode()).hexdigest(), replacements=[],
                original_sha256=inventory["files"][name], compiled_sha256=sha256(destination),
            )
    wrapper = """(* Oracle-only aliases for the standalone, unchanged native modules. *)
module Oce1 = Oce1
module Hash_domain = Hash_domain
module P2p_peer_record = P2p_peer_record
module P2p_upgrade_plan = P2p_upgrade_plan
"""
    (directory / "octra_net.ml").write_text(wrapper)
    shutil.copyfile(oracle, directory / "main.ml")
    input_json = json.dumps(inputs, separators=(",", ":"))
    (directory / "input.json").write_text(input_json + "\n")
    opam = shutil.which("opam")
    if opam is None:
        raise RuntimeError("opam is unavailable")
    opam = str(Path(opam).resolve())
    execute = [opam, "exec", f"--switch={switch}", "--"]
    version = command("compiler-version", execute + ["ocamlopt", "-version"]).strip()
    compiler_config = command("compiler-config", execute + ["ocamlopt", "-config"])
    opam_version = command("opam-version", [opam, "--version"]).strip()
    tools = {}
    for name in ["ocamlopt", "ocamlfind"]:
        path = Path(command(f"{name}-path", execute + ["which", name]).strip()).resolve()
        tools[name] = dict(path=str(path), sha256=sha256(path))
    packages = ["digestif", "digestif.c", "mirage-crypto-ec", "zarith", "yojson", "base64"]
    package_rows = command("packages", execute + [
        "ocamlfind", "query", "-recursive", "-format", "%p\t%v\t%d", *packages,
    ])
    resolved_packages = {}
    for row in package_rows.splitlines():
        name, package_version, package_directory = row.split("\t", 2)
        package_path = Path(package_directory)
        artifacts = {}
        for path in sorted(package_path.rglob("*")):
            if path.is_file() and (path.name == "META" or path.suffix in {
                ".a", ".cmxa", ".cmx", ".cmi", ".cma", ".cmxs", ".so", ".dylib",
            }):
                artifacts[str(path.relative_to(package_path))] = sha256(path)
        resolved_packages[name] = dict(version=package_version, directory=str(package_path),
                                       artifact_sha256=artifacts)
    executable = directory / "upgrade-config-oracle"
    build = execute + ["ocamlfind", "ocamlopt", "-linkpkg", "-package", ",".join(packages),
                       *[Path(name).name for name in sources], "octra_net.ml", "main.ml",
                       "-o", executable.name]
    command("build", build)
    output = command("oracle", [str(executable)], stdin=input_json)
    expected = json.loads(output)
    if len(expected) != len(inputs):
        raise RuntimeError("native oracle returned a different case count")
    return dict(
        upstream_commit=pin, source_sha256=inventory["files"], oracle_sha256=sha256(oracle),
        runner_kind="host-ocaml", runner_path="scripts/node-port/upgrade-config-fixtures.py",
        runner_sha256=sha256(Path(__file__)), instrumentation=instrumentation, cases=expected,
        host=dict(
            opam_switch=switch, opam_version=opam_version,
            opam=dict(path=opam, sha256=sha256(Path(opam))),
            platform=platform.platform(), machine=platform.machine(),
            compiler_version=version, compiler_config=compiler_config, tools=tools,
            requested_packages=packages, packages=resolved_packages,
            compiled_sources=compiled_sources,
            wrapper=dict(path="octra_net.ml", sha256=sha256(directory / "octra_net.ml"), source=wrapper),
            build_command=build, run_command=[str(executable)],
            executable=dict(path=str(executable), sha256=sha256(executable)),
            input_sha256=sha256(directory / "input.json"),
            output_sha256=sha256(directory / "oracle.stdout"),
            source_map_sha256=sha256(inventory_path), verified_source_count=len(inventory["files"]),
            evidence_directory=str(directory), commands_sha256=sha256(directory / "commands.json"),
            scope="Host standalone dependency closure; no Docker execution or hermetic build claim",
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    runner = parser.add_mutually_exclusive_group(required=True)
    runner.add_argument("--builder-image")
    runner.add_argument("--opam-switch")
    parser.add_argument("--host-directory", type=Path,
                        help="fresh retained build/evidence directory; required with --opam-switch")
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.out.exists():
        raise SystemExit("require fresh output")
    inputs = fixtures()
    oracle = ROOT / "scripts/node-port/upgrade-config-oracle.ml"
    if arguments.opam_switch:
        if arguments.host_directory is None:
            parser.error("--host-directory is required with --opam-switch")
        report = host_run(arguments.upstream, arguments.opam_switch, oracle, inputs, arguments.host_directory)
    else:
        if arguments.host_directory is not None:
            parser.error("--host-directory is only used with --opam-switch")
        spec = importlib.util.spec_from_file_location("native", ROOT / "scripts/node-port/native-oracle.py")
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        report = native.run(
            arguments.upstream, arguments.builder_image, oracle,
            inputs, "octra_net yojson base64", prefixes={NATIVE_SOURCE: PREFIX},
        )
        report["runner_kind"] = "docker"
        report["runner_path"] = "scripts/node-port/native-oracle.py"
    report["generator_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report["scope"] = "Trusted native P2P upgrade/rollback parser, normalized plans, lazy getter acquisition, validation priority and transport hashes/readiness at activation boundaries"
    report["qualification"] = {
        "environment_acquisition": "test-only injected Sys.getenv_opt; process environment acquisition is not qualified",
        "original_function_body": "unchanged after a recorded source prefix; the selected runner verifies all original source hashes before injection",
        "getter_comparison": "sorted names retain duplicate reads; getter evaluation order is outside comparison scope",
        "excluded": "No integrated launcher, live peer, public-network, consensus execution or Mainnet qualification",
    }
    report["vector_groups"] = dict(collections.Counter(row["group"] for row in inputs))
    arguments.out.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print(f"PASS: {len(report['cases'])} instrumented-getter native upgrade configuration cases: {arguments.out}")


if __name__ == "__main__":
    main()
