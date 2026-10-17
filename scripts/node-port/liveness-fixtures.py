#!/usr/bin/env python3
"""Generate pure liveness parity with unchanged native code and real dependencies.

The immutable offline builder restores every adopted source-map entry before
compilation. Only the restrictive liveness .mli is omitted, so the oracle can
observe internal state. No source body, timeout policy or driver is stubbed.
"""
import argparse
import base64
import collections
import hashlib
import itertools
import json
import math
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "node_runtime/consensus_liveness.ml"
BUILDER = "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
MIN_INT = -(1 << 62)
MAX_INT = (1 << 62) - 1


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def blob(value):
    return base64.b64encode(value).decode()


def bits(value):
    return value if isinstance(value, str) else struct.pack(">d", value).hex()


def sample(now=0.0, **changes):
    value = dict(height="7", round="0", step=blob(b"propose"), expected="7",
                 now=bits(now), source=blob(b"periodic"), stall_sec=bits(150.0),
                 step_timeout_sec=bits(15.0), observer=False, voting=True,
                 catchup_active=False, quarantine_active=False, state_attested=True,
                 pending_finalized=False, proposal_active=False)
    for name, change in changes.items():
        if name in {"height", "round", "expected"}:
            change = str(change)
        elif name in {"step", "source"}:
            change = blob(change)
        elif name in {"now", "stall_sec", "step_timeout_sec"} and change is not None:
            change = bits(change)
        value[name] = change
    return value


def seed(*, key=b"7:0:propose", height_key=b"7", started=0.0,
         height_started=0.0, resets=0):
    return dict(key=blob(key), key_started_at=bits(started), height_key=blob(height_key),
                height_started_at=bits(height_started), resets=str(resets))


def fixtures():
    rows = []

    def sequence(group, label, values, **fields):
        rows.append(dict(group=group, label=label, op="record", created_at=bits(0.0),
                         seed=None, samples=values) | fields)

    sequence("timers", "repeat-and-reset", [sample(t) for t in [
        10.0, 159.999, 160.0, 160.0, 309.999, 310.0, 309.0, 460.0]])
    sequence("timers", "rounds-share-height-clock", [
        sample(0.0), sample(100.0, round=1, step_timeout_sec=100.0),
        sample(229.999, round=1, step_timeout_sec=100.0),
        sample(230.0, round=1, step_timeout_sec=100.0)])
    sequence("timers", "proposal-refreshes-state-only", [
        sample(0.0), sample(140.0, proposal_active=True), sample(200.0),
        sample(200.0, round=1), sample(244.999, round=1), sample(245.0, round=1)])
    sequence("timers", "changing-height-resets-both", [
        sample(0.0), sample(149.0, height=8, expected=8),
        sample(150.0, height=8, expected=8), sample(299.0, height=8, expected=8)])
    sequence("timers", "changing-step-and-source", [
        sample(0.0), sample(100.0, source=b"catchup"), sample(149.0, step=b"prevote"),
        sample(150.0, step=b"prevote"), sample(299.0, step=b"prevote")])
    flags = [dict(observer=True), dict(voting=False), dict(catchup_active=True),
             dict(quarantine_active=True), dict(state_attested=False),
             dict(pending_finalized=True), dict(proposal_active=True), dict(expected=8)]
    for mask in range(1 << len(flags)):
        changes = {}
        for index, fields in enumerate(flags):
            if mask & (1 << index):
                changes.update(fields)
        sequence("blockers", str(mask), [sample(150.0, **changes)], seed=seed())

    for raw, timeout in itertools.product(
        [-math.inf, -1.0, -0.0, 0.0, 1.0, 30.0, 45.0, 150.0, math.inf,
         "7ff8000000000042"],
        [None, -math.inf, -30.0, -0.0, 0.0, 15.0, 120.0, 300.0, math.inf,
         "fff8000000000017"],
    ):
        for round_number in [-1, 0, 1]:
            sequence("threshold-selection", f"{bits(raw)}-{timeout}-{round_number}",
                     [sample(150.0, round=round_number, stall_sec=raw,
                             step_timeout_sec=timeout)],
                     seed=seed(key=f"7:{round_number}:propose".encode()))
    for raw, timeout in [(150.0, None), (150.0, 15.0), (150.0, 120.0),
                         (150.0, 300.0), (0.0, -30.0), (30.0, 0.0), (45.0, 15.0)]:
        threshold = raw if timeout is None else max(raw, timeout + 30.0)
        for now in [math.nextafter(threshold, -math.inf), threshold,
                    math.nextafter(threshold, math.inf)]:
            for round_number in [0, 1]:
                sequence("threshold-boundaries", f"{raw}-{timeout}-{bits(now)}-{round_number}",
                         [sample(now, round=round_number, stall_sec=raw,
                                 step_timeout_sec=timeout)],
                         seed=seed(key=f"7:{round_number}:propose".encode()))

    special = ["0000000000000000", "8000000000000000", "0000000000000001",
               "8000000000000001", "7fefffffffffffff", "ffefffffffffffff",
               "7ff0000000000000", "fff0000000000000", "7ff8000000000042",
               "fff8000000000017"]
    for index, (started, now) in enumerate(itertools.product(special, special)):
        sequence("clock-bits", str(index), [sample(now)],
                 seed=seed(started=started, height_started=started))
    for height, round_number, step in itertools.product(
        [-(1 << 63), -1, 0, (1 << 63) - 1], [MIN_INT, -1, 0, 1, MAX_INT],
        [b"", b"propose", b"prevote\0precommit", b"\xff:\xc0\xaf", bytes(range(256))],
    ):
        sequence("byte-keys", f"{height}-{round_number}-{blob(step)}", [
            sample(0.0, height=height, expected=height, round=round_number,
                   step=step, source=bytes(reversed(range(256)))),
            sample(150.0, height=height, expected=height, round=round_number,
                   step=step, source=b"\0\xffsource")])
    for key, height_key in [(b"7:0:propose", b"7"), (b"7:0:propose\0", b"7"),
                             (b"7:0:propose", b"07"), (b"", b""),
                             (b"\xff7:0:propose", b"7\0")]:
        sequence("seed-keys", blob(key + b"/" + height_key), [sample(150.0)],
                 seed=seed(key=key, height_key=height_key))
    for resets in [MIN_INT, -1, 0, MAX_INT - 1, MAX_INT]:
        sequence("counter-wrap", str(resets), [sample(150.0), sample(300.0)],
                 seed=seed(resets=resets))
    sequence("timers", "deterministic-mixed-sequence", [
        sample(index * 17.0, height=7 + index // 19, expected=7 + index // 19,
               round=(index // 4) % 4, step=[b"propose", b"prevote", b"precommit"][index % 3],
               proposal_active=index % 11 == 0, quarantine_active=index % 13 == 0,
               step_timeout_sec=None if index % 5 == 0 else 15.0)
        for index in range(96)])

    configurations = [(3000, 3000, 1000), (100, 100, 100), (120000, 300000, 30000),
                      (3000, 14999, 1000), (3000, 15000, 1000), (3000, 15001, 1000)]
    for index, ((base, propose, per_round), round_number, step) in enumerate(itertools.product(
        configurations, [MIN_INT, -1, 0, 1, 14, 15, 116, 117, 284, 285, MAX_INT],
        ["propose", "prevote", "precommit"],
    )):
        rows.append(dict(group="timeouts", label=str(index), op="timeout",
                         height=str(-(1 << 63) if index % 2 else (1 << 63) - 1),
                         round=str(round_number), step=step, base=str(base),
                         propose=str(propose), per_round=str(per_round)))
    return rows


# Executed inside the immutable builder, not on the user's host. Every build
# command and its output is retained before failure; the worker never networks.
WORKER = r'''
import hashlib,json,os,pathlib,platform,shutil,subprocess
root=pathlib.Path.cwd()
output=pathlib.Path('/evidence')
commands=[]
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def command(name,argv,*,stdin=None,environment=None):
    commands.append(dict(name=name,argv=argv,cwd=str(root),environment_overrides=environment or {}))
    (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    result=subprocess.run(argv,cwd=root,input=stdin,text=True,capture_output=True,
                          env=None if environment is None else os.environ|environment)
    (output/(name+'.stdout')).write_text(result.stdout)
    (output/(name+'.stderr')).write_text(result.stderr)
    if result.returncode:raise RuntimeError(f'{name} failed ({result.returncode}): {result.stderr}')
    return result.stdout
inventory=json.loads(pathlib.Path('/oracle/source-map.json').read_text())
for name,expected in inventory['files'].items():
    path=root/name
    if not path.exists() or digest(path)!=expected:
        path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(pathlib.Path('/native')/name,path)
    if digest(path)!=expected:raise RuntimeError('source restore mismatch: '+name)
(output/'verified-sources.json').write_text(json.dumps(inventory,indent=2)+'\n')
program=root/'vpn_liveness_oracle'
program.mkdir()
for name in ['main.ml','dune','consensus_liveness.ml']:
    shutil.copyfile(pathlib.Path('/oracle')/name,program/name)
opam=str(pathlib.Path(shutil.which('opam')).resolve())
execute=[opam,'exec','--']
version=command('compiler-version',execute+['ocamlopt','-version']).strip()
if version!='4.14.2':raise RuntimeError('liveness parity requires OCaml4.14.2')
config=command('compiler-config',execute+['ocamlopt','-config'])
opam_version=command('opam-version',[opam,'--version']).strip()
tools={'opam':dict(path=opam,sha256=digest(pathlib.Path(opam)))}
for name in ['ocamlopt','ocamlfind','dune']:
    path=pathlib.Path(command(name+'-path',execute+['which',name]).strip()).resolve()
    tools[name]=dict(path=str(path),sha256=digest(path))
packages=command('packages',[opam,'list','--installed','--columns=name,version','--short'])
command('build',execute+['dune','build','./vpn_liveness_oracle/main.exe'])
executable=root/'_build/default/vpn_liveness_oracle/main.exe'
input_json=pathlib.Path('/oracle/input.json').read_text()
native=command('oracle',execute+[str(executable)],stdin=input_json,
               environment={'OCAMLRUNPARAM':''})
rows=json.loads(native)
inputs=json.loads(input_json)
if len(rows)!=len(inputs) or any(row['input']!=value for row,value in zip(rows,inputs)):
    raise RuntimeError('native oracle returned different vectors')
pathlib.Path('/evidence/cases.json').write_text(json.dumps(rows,separators=(',',':'))+'\n')
source='node_runtime/consensus_liveness.ml'
metadata=dict(compiler_version=version,compiler_config=config,opam_version=opam_version,
              tools=tools,packages=packages,platform=platform.platform(),machine=platform.machine(),
              source_map_sha256=digest(pathlib.Path('/oracle/source-map.json')),
              verified_source_count=len(inventory['files']),
              compiled_sources={source:dict(original_sha256=inventory['files'][source],
                  compiled_sha256=digest(program/'consensus_liveness.ml'),copied_as='consensus_liveness.ml')},
              omitted_interface=dict(path=source+'i',source_sha256=inventory['files'][source+'i'],
                  reason='Pinned public interface hides internal state and pure policy observed by this oracle'),
              run_environment_overrides={'OCAMLRUNPARAM':''},commands=commands,
              executable_sha256=digest(executable),worker_sha256=digest(pathlib.Path('/oracle/worker.py')))
(output/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
'''


def run(upstream, builder, directory, inputs):
    if directory.exists():
        raise SystemExit("require fresh host directory")
    directory.mkdir(parents=True)
    directory = directory.resolve()
    upstream = upstream.resolve()
    inventory_path = ROOT / "docs/rust-node/source-map.json"
    inventory = json.loads(inventory_path.read_text())
    pin = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if pin != inventory["upstream_commit"]:
        raise RuntimeError("upstream pin differs")
    for name, expected in inventory["files"].items():
        if sha256(upstream / name) != expected:
            raise RuntimeError(f"modified upstream: {name}")
    if not builder.startswith("sha256:") or len(builder) != 71:
        raise RuntimeError("require an immutable builder sha256 identity")
    inspect_command = ["docker", "image", "inspect", builder]
    inspected = subprocess.run(inspect_command, text=True, capture_output=True)
    (directory / "builder-inspect.stdout").write_text(inspected.stdout)
    (directory / "builder-inspect.stderr").write_text(inspected.stderr)
    inspected.check_returncode()
    image = json.loads(inspected.stdout)[0]
    if image["Id"] != builder:
        raise RuntimeError("builder image identity differs")
    oracle = ROOT / "scripts/node-port/liveness-oracle.ml"
    with tempfile.TemporaryDirectory(prefix="octra-liveness-oracle-") as temporary:
        work = Path(temporary)
        shutil.copyfile(oracle, work / "main.ml")
        shutil.copyfile(upstream / SOURCE, work / "consensus_liveness.ml")
        shutil.copyfile(inventory_path, work / "source-map.json")
        (work / "dune").write_text("(executable (name main) (libraries octra_consensus yojson base64))\n")
        (work / "input.json").write_text(json.dumps(inputs, separators=(",", ":")) + "\n")
        (work / "worker.py").write_text(WORKER)
        command = ["docker", "run", "--rm", "--network", "none", "--mount",
                   f"type=bind,source={work},target=/oracle,readonly", "--mount",
                   f"type=bind,source={upstream},target=/native,readonly", "--mount",
                   f"type=bind,source={directory},target=/evidence", builder,
                   "bash", "-lc", "python3 /oracle/worker.py"]
        (directory / "host-commands.json").write_text(json.dumps([
            dict(name="upstream-pin", argv=["git", "-C", str(upstream), "rev-parse", "HEAD"]),
            dict(name="builder-inspect", argv=inspect_command), dict(name="builder-run", argv=command),
        ], indent=2) + "\n")
        result = subprocess.run(command, text=True, capture_output=True)
        (directory / "builder-run.stdout").write_text(result.stdout)
        (directory / "builder-run.stderr").write_text(result.stderr)
        result.check_returncode()
    cases = json.loads((directory / "cases.json").read_text())
    return dict(upstream_commit=pin, source_sha256=inventory["files"],
                oracle_sha256=sha256(oracle), generator_sha256=sha256(Path(__file__)),
                runner_path="scripts/node-port/liveness-fixtures.py",
                runner_sha256=sha256(Path(__file__)), runner_kind="immutable-offline-builder",
                builder_image=builder, builder_platform=dict(os=image["Os"], architecture=image["Architecture"]),
                instrumentation={}, adapters={}, native=json.loads((directory / "metadata.json").read_text()),
                cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--builder-image", default=BUILDER)
    parser.add_argument("--host-directory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.out.exists():
        raise SystemExit("require fresh output")
    inputs = fixtures()
    report = run(arguments.upstream, arguments.builder_image, arguments.host_directory, inputs)
    report["input_sha256"] = hashlib.sha256(json.dumps(
        inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    report["vector_groups"] = dict(collections.Counter(value["group"] for value in inputs))
    report["qualification"] = dict(
        body="Unchanged adopted consensus_liveness.ml linked against restored adopted Octra_consensus",
        scope="Pure create/record/record_snapshot, keys, float bits, every admission blocker, step labels and real timeout_ms_with projection",
        excluded="No live C_driver acquisition, actor scheduling, reset side effects, network supervisor, public devnet or mainnet qualification",
        interface="Pinned .mli verified but omitted only to observe internal policy/state; no source body edits or stubs",
    )
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print(f"PASS: {len(report['cases'])} native liveness vectors: {arguments.out}")


if __name__ == "__main__":
    main()
