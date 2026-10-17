#!/usr/bin/env python3
"""Qualify offline legacy repair against actual native physical stores.

Runs only fresh private fixtures under --out. The host Rust CLI drives a pinned
test-only Docker bridge to the real backend; the native implementation remains
the independent full-finish oracle. No public state or network is selected.
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = "7f9be4489870645cfcc95439638cde40f5da9f50"
IMAGE = "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
CHAIN = "legacy-repair-fixture"
STAGE_TEST = "signed_peer_selection_stages_only_an_unprotected_native_empty_suffix"
WRONG_CHAIN = CHAIN + "-wrong"
LABEL = "org.octra.legacy-repair-qualification"
MAX_OUTPUT = 4 * 1024 * 1024
MUTATIONS = ["protected-prepare", "protected-commit", "protected-aborted", "torn-journal", "missing-finality",
             "bad-finality-root", "bad-finality-txid", "bad-index", "bad-offset", "bad-txlog",
             "missing-tag", "source-changed", "orphan-staged", "corrupt-plan"]


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write(path, value):
    with path.open("x") as handle:
        handle.write(json.dumps(value, indent=2) + "\n")


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"expected regular artifact: {path}")


class Command:
    def __init__(self, owner, name, argv, *, stdin=None, environment=None):
        self.owner, self.name = owner, name
        self.paths = [owner.logs / f"{name}.stdout", owner.logs / f"{name}.stderr"]
        self.exceeded = threading.Event()
        self.errors = []
        self.started = time.monotonic()
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                                        start_new_session=True)
        self.threads = []
        for pipe, path in zip([self.process.stdout, self.process.stderr], self.paths):
            thread = threading.Thread(target=self.drain, args=(pipe, path), daemon=True)
            thread.start(); self.threads.append(thread)
        if stdin is not None:
            if stdin is not HOLD:
                self.process.stdin.write(stdin); self.process.stdin.close()
        self.record = dict(name=name, argv=[str(value) for value in argv], pid=self.process.pid,
                           at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           environment=environment, stdout=str(self.paths[0]), stderr=str(self.paths[1]))
        owner.commands.append(self.record); owner.children.append(self)
        owner.save_commands()

    def drain(self, pipe, path):
        try:
            with path.open("xb") as output:
                total = 0
                while True:
                    # Buffered read(n) can wait for n bytes while a long-lived
                    # holder is already waiting for stdin after its short ACK.
                    block = os.read(pipe.fileno(), 8192)
                    if not block:
                        break
                    left = MAX_OUTPUT - total
                    output.write(block[:left]); output.flush()
                    total += len(block)
                    if total > MAX_OUTPUT:
                        self.exceeded.set()
                        break
        except Exception as error:
            self.errors.append(str(error)); self.exceeded.set()
        finally:
            pipe.close()

    def stop(self):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL); self.process.wait(timeout=5)

    def wait(self, *, timeout=120, expected=(0,)):
        try:
            while self.process.poll() is None:
                if self.exceeded.is_set():
                    raise RuntimeError(f"bounded command output exceeded: {self.name}")
                if time.monotonic() - self.started > timeout:
                    raise RuntimeError(f"command timed out: {self.name}")
                time.sleep(0.025)
        except BaseException:
            self.stop()
            raise
        finally:
            for thread in self.threads:
                thread.join(timeout=3)
            self.record.update(exit_code=self.process.poll(), elapsed_seconds=round(time.monotonic() - self.started, 3),
                               output_exceeded=self.exceeded.is_set(), drain_errors=self.errors)
            self.owner.save_commands()
        if self.exceeded.is_set() or self.errors or any(thread.is_alive() for thread in self.threads):
            raise RuntimeError(f"incomplete/oversized command capture: {self.name}")
        if expected is not None and self.process.returncode not in expected:
            raise RuntimeError(f"{self.name} exited {self.process.returncode}; inspect bounded logs")
        return self

    def output(self, index=0):
        return self.paths[index].read_bytes()

    def json(self):
        # Native helpers may print operational diagnostics before their final
        # machine value. Rust CLI prints one pretty JSON document.
        raw = self.output()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return json.loads(raw.splitlines()[-1])


HOLD = object()


class Qualification:
    def __init__(self, arguments):
        self.out = arguments.out.resolve()
        self.out.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.logs = self.out / "logs"; self.logs.mkdir()
        self.cases = self.out / "cases"; self.cases.mkdir(mode=0o700)
        self.tools = self.out / "tools"; self.tools.mkdir()
        self.children, self.commands, self.results = [], [], []
        self.run_id = uuid.uuid4().hex
        # Docker may be an argv[0]-selected multiplexer (for example OrbStack).
        # Hashing follows its symlink, but execution must retain the docker name.
        self.docker = str(Path(shutil.which("docker") or "missing-docker").absolute())
        self.container_number = 0
        self.environment = None
        self.report = dict(schema="octra_legacy_physical_qualification_v1", run_id=self.run_id,
                           upstream_commit=UPSTREAM, image=IMAGE, chain_id=CHAIN,
                           qualifier_sha256=sha(Path(__file__)), status="running", results=self.results)
        source = arguments.backend_directory.resolve()
        for name in ["backend", "cases", "manifest.json"]:
            regular(source / name)
        manifest = json.loads((source / "manifest.json").read_text())
        assert manifest["schema"] == "octra_legacy_backend_v1"
        assert manifest["upstream_commit"] == UPSTREAM and manifest["builder_image"] == IMAGE
        assert manifest["compiler"] == "4.14.2"
        assert manifest["platform"] == dict(os="linux", architecture="arm64")
        inventory_path = ROOT / "docs/rust-node/source-map.json"
        inventory = json.loads(inventory_path.read_text())
        assert inventory["upstream_commit"] == UPSTREAM and manifest["source_map_sha256"] == sha(inventory_path)
        assert all(manifest["source_sha256"].get(name) == digest for name, digest in inventory["files"].items())
        assert manifest["verified_source_count"] == len(manifest["source_sha256"])
        for name, digest in manifest["helper_source_sha256"].items():
            assert sha(ROOT / "scripts/node-port" / name) == digest, f"helper source changed: {name}"
        for name in ["backend", "cases"]:
            assert sha(source / name) == manifest[name + "_sha256"]
            shutil.copyfile(source / name, self.tools / name)
            (self.tools / name).chmod(0o555)
            assert sha(self.tools / name) == manifest[name + "_sha256"]
        shutil.copyfile(source / "manifest.json", self.tools / "manifest.json")
        regular(arguments.node)
        self.node = self.out / "octra-node"
        node_hash = sha(arguments.node)
        shutil.copyfile(arguments.node, self.node); self.node.chmod(0o555)
        assert sha(self.node) == node_hash == sha(arguments.node), "node changed while freezing"
        regular(arguments.stage_test_binary)
        stage_hash = sha(arguments.stage_test_binary)
        self.stage_test = self.tools / "legacy-stage-test"
        shutil.copyfile(arguments.stage_test_binary, self.stage_test); self.stage_test.chmod(0o555)
        assert sha(self.stage_test) == stage_hash == sha(arguments.stage_test_binary), "staging test binary changed while freezing"
        self.report["artifacts"] = dict(node_sha256=node_hash, node_source=str(arguments.node.resolve()),
                                        stage_test_sha256=stage_hash, stage_test_source=str(arguments.stage_test_binary.resolve()),
                                        stage_test_source_sha256=sha(ROOT / "crates/octra-node/tests/legacy_stage.rs"),
                                        native_manifest_sha256=sha(source / "manifest.json"),
                                        backend_sha256=manifest["backend_sha256"], cases_sha256=manifest["cases_sha256"])
        self.manifest = manifest

    def save_commands(self):
        path = self.out / "commands.json"
        temporary = path.with_suffix(".next")
        temporary.write_text(json.dumps(self.commands, indent=2) + "\n"); temporary.replace(path)

    def run(self, name, argv, **options):
        return Command(self, name, argv, environment=self.environment).wait(**options)

    def configure_docker(self):
        context = self.run("docker-context", [self.docker, "context", "inspect"]).json()[0]
        endpoint = context["Endpoints"]["docker"]["Host"]
        assert endpoint.startswith("unix://"), "qualification requires the selected local Unix Docker daemon"
        home = self.out / "bridge-home"; home.mkdir(mode=0o700)
        config = home / ".docker"; config.mkdir(mode=0o700)
        write(config / "config.json", {})
        self.environment = dict(HOME=str(home), DOCKER_CONFIG=str(config), DOCKER_HOST=endpoint,
                                PATH="/usr/bin:/bin", LANG="C.UTF-8")
        image = self.run("docker-image", [self.docker, "image", "inspect", IMAGE]).json()[0]
        assert image["Id"] == IMAGE and image["Os"] == "linux" and image["Architecture"] == "arm64"
        self.report["docker"] = dict(executable=self.docker, sha256=sha(Path(self.docker)),
                                      context=context["Name"], endpoint=endpoint, environment=self.environment,
                                      platform=dict(os=image["Os"], architecture=image["Architecture"]))
        self.bridge = self.out / "backend-bridge.py"
        python = str(Path(sys.executable).resolve())
        assert not any(character.isspace() for character in python), "absolute bridge interpreter needs a valid shebang"
        stderr = self.out / "bridge-stderr"; stderr.mkdir()
        cids = self.out / "container-ids"; cids.mkdir()
        # The runtime clears inherited environment. Every executable, daemon,
        # mount, hash and environment value used here is pinned in these bytes.
        code = f'''#!{python}
import hashlib,json,os,pathlib,resource,sys
record=pathlib.Path({str(stderr)!r})/(str(os.getpid())+'.log')
fd=os.open(record,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
os.dup2(fd,2);os.close(fd)
resource.setrlimit(resource.RLIMIT_FSIZE,({MAX_OUTPUT},{MAX_OUTPUT}))
directory=pathlib.Path(sys.argv[1]).resolve(strict=True)
assert directory.is_relative_to(pathlib.Path({str(self.cases)!r}))
assert sys.argv[2] in {[CHAIN, WRONG_CHAIN]!r}
tools=pathlib.Path({str(self.tools)!r})
assert hashlib.sha256((tools/'backend').read_bytes()).hexdigest()=={self.manifest['backend_sha256']!r}
name='octra-legacy-{self.run_id}-bridge-'+str(os.getpid())
argv=[{self.docker!r},'run','--rm','--init','--pull=never','--network','none','--platform','linux/arm64',
 '--name',name,'--label',{LABEL + '=' + self.run_id!r},'--cidfile',
 str(pathlib.Path({str(cids)!r})/(str(os.getpid())+'.cid')),'-i','--mount',
 'type=bind,source='+str(directory)+',target=/data','--mount',
 'type=bind,source='+str(tools)+',target=/tools,readonly','--entrypoint','/tools/backend',
 {IMAGE!r},'/data',sys.argv[2]]
os.execve({self.docker!r},argv,{self.environment!r})
'''
        self.bridge.write_text(code); self.bridge.chmod(0o555)
        self.bridge_sha = sha(self.bridge)
        self.report["bridge"] = dict(path=str(self.bridge), sha256=self.bridge_sha, interpreter=python,
                                      interpreter_sha256=sha(Path(python)), test_only=True,
                                      native_backend_sha256=self.manifest["backend_sha256"])

    def fixture(self, name, operation, directory, *arguments, expected=(0,), background=False):
        directory = directory.resolve()
        assert directory.parent == self.cases and directory.name not in ["", ".", ".."]
        self.container_number += 1
        container = f"octra-legacy-{self.run_id}-case-{self.container_number}"
        # The native crash helper must be an ordinary process: namespace PID1
        # ignores default-action signals, including its own SIGKILL.
        argv = [self.docker, "run", "--rm", "--init", "--pull=never", "--network", "none", "--platform", "linux/arm64",
                "--name", container, "--label", f"{LABEL}={self.run_id}", "-i", "--mount",
                f"type=bind,source={self.cases},target=/cases", "--mount",
                f"type=bind,source={self.tools},target=/tools,readonly", "--entrypoint", "/tools/cases",
                IMAGE, operation, f"/cases/{directory.name}", *arguments]
        if background:
            return Command(self, name, argv, stdin=HOLD, environment=self.environment)
        return self.run(name, argv, expected=expected)

    def inspect(self, name, directory):
        return self.fixture(name, "inspect", directory).json()

    def rust(self, name, directory, *, expected=(0,), chain=CHAIN):
        return self.run(name, [str(self.node), "legacy-repair", "--directory", str(directory),
                              "--chain-id", chain, "--backend", str(self.bridge),
                              "--backend-sha256", self.bridge_sha], expected=expected)

    def copy(self, seed, name):
        destination = self.cases / name
        shutil.copytree(seed, destination, symlinks=False)
        return destination

    def signing(self, directory):
        return {str(path.relative_to(directory)): dict(bytes=path.stat().st_size, sha256=sha(path))
                for name in ["consensus", "vote_log"] for path in sorted((directory / name).rglob("*"))
                if path.is_file()}

    def guard(self, directory):
        files = ["HEAD.json", "fork_repair.json", "fork_repair.json.staged", "commit_journal.log"]
        files += [str(path.relative_to(directory)) for name in ["finality", "chaindata/txlog", "chaindata/epochlog"]
                  for path in sorted((directory / name).rglob("*")) if path.is_file()]
        return dict(signing=self.signing(directory), files={name: None if not (directory / name).exists()
                    else dict(bytes=(directory / name).stat().st_size, sha256=sha(directory / name)) for name in files})

    def check_prefix(self, directory, protected):
        for name, value in protected.items():
            with (directory / name).open("rb") as handle:
                raw = handle.read(value["bytes"])
            assert len(raw) == value["bytes"] and hashlib.sha256(raw).hexdigest() == value["sha256"], name

    def repaired(self, value, target):
        assert value["head"] == target and value["chain_head"] == target["epoch_id"]
        assert value["ledger_root"] == target["ledger_state_root"]
        assert value["irmin_commit"] == target["irmin_commit"]
        assert value["next_txid"] == str(int(target["txid_hi"]) + 1)
        assert value["epochlog_offset"] == target["epochlog_off"]
        assert value["plan_present"] is False and value["target_tx_present"] is True
        assert value["tags"] and all(epoch <= target["epoch_id"] for epoch in value["tags"])
        assert value["finality"] and all(epoch <= target["epoch_id"] for epoch in value["finality"])

    def certified(self, seed, signing, protected):
        certified = self.copy(seed, "certified-seed")
        self.fixture("certify", "certify", certified)
        certified_plan = json.loads((certified / "fork_repair.json").read_bytes())
        target = certified_plan["head"]
        target_epoch = target["epoch_id"]
        source_epoch = certified_plan["source"]["epoch_id"]
        assert target_epoch == 0 and source_epoch == 1
        assert self.fixture("verify-certified-source", "verify-committed", certified).json() is True
        current_name = "finality/committed_finalized.json"
        target_name = f"finality/committed/{target_epoch}.json"
        source_name = f"finality/committed/{source_epoch}.json"
        target_proof = (certified / target_name).read_bytes()
        source_proof = (certified / source_name).read_bytes()
        current_proof = (certified / current_name).read_bytes()
        assert target_proof != source_proof
        # Native archives intentionally omit the bundle. The current record
        # retains its verified empty bundle; all certificate/set bytes agree.
        archived = json.loads(source_proof)
        current = json.loads(current_proof)
        assert archived["bundle"] is None
        assert current["bundle"] == dict(tx_hashes=[], txs=[], receipts_json=[])
        assert {**current, "bundle": None} == archived
        proofs = {name: dict(bytes=(certified / name).stat().st_size, sha256=sha(certified / name))
                  for name in [current_name, target_name, source_name]}
        assert self.signing(certified) == signing
        self.check_prefix(certified, protected)

        native = self.copy(certified, "certified-native")
        rust = self.copy(certified, "certified-rust")
        expected = self.fixture("certified-native-finish", "phase", native, "finish").json()
        response = self.rust("certified-rust-finish", rust).json()
        assert response["format"] == "octra-legacy-repair-resume-v1"
        assert response["target"] == response["store"] == response["chaindata"] == response["head"] == target_epoch
        actual = self.inspect("certified-rust-reopen", rust)
        assert actual == expected, "certified Rust finish differs from native full finish"
        for name, directory, value in [("native", native, expected), ("rust", rust, actual)]:
            self.repaired(value, target)
            assert (directory / current_name).read_bytes() == target_proof, "committed proof did not rewind1 to0"
            assert (directory / target_name).read_bytes() == target_proof
            assert (directory / source_name).read_bytes() == source_proof
            assert self.fixture("certified-" + name + "-verify-target", "verify-committed", directory).json() is True
            assert self.fixture("certified-" + name + "-repeat-native", "phase", directory, "finish").json() == value
            assert self.inspect("certified-" + name + "-repeat-reopen", directory) == value
            self.check_prefix(directory, protected); assert self.signing(directory) == signing
            self.results.append(dict(case="certified-" + name + "-positive", repaired=value,
                                     committed_before_epoch=source_epoch, committed_after_epoch=target_epoch,
                                     proofs_before=proofs, committed_after_sha256=sha(directory / current_name),
                                     native_committed_for_target=True))

        for name, tampered, chain in [("wrong-chain", False, WRONG_CHAIN), ("tampered-qc", True, CHAIN)]:
            directory = self.copy(certified, "certified-refuse-" + name)
            if tampered:
                self.fixture("certified-tamper-qc", "mutate", directory, "tampered-qc")
                assert (directory / target_name).read_bytes() != target_proof
                assert (directory / source_name).read_bytes() == source_proof
                assert (directory / current_name).read_bytes() == current_proof
            assert self.fixture("certified-" + name + "-verify-source", "verify-committed", directory).json() is True
            before = self.inspect("certified-" + name + "-before", directory)
            assert before["plan_present"] is True
            guard = self.guard(directory)
            refused = self.rust("certified-refuse-" + name, directory, expected=None, chain=chain)
            assert refused.process.returncode not in [0, 125, 126, 127]
            assert b"native legacy repair refused the operation" in refused.output(1)
            assert self.inspect("certified-" + name + "-after", directory) == before
            assert self.guard(directory) == guard
            assert self.fixture("certified-" + name + "-verify-source-after", "verify-committed", directory).json() is True
            self.check_prefix(directory, protected); assert self.signing(directory) == signing
            self.results.append(dict(case="certified-refuse-" + name, unchanged=True,
                                     marker_retained=before["plan_present"], preserved=guard,
                                     current_source_proof_still_valid=True, exit_code=refused.process.returncode))

    def stage_selection(self, seed, signing, protected):
        """Real authenticated TCP selection, then unchanged native physical stage.

        The Rust ignored test is an explicit fixture-only entry point. It calls
        the public staging API without a supplied quorum/target capability;
        fixed development peer keys match the native certified fixture.
        """
        certified = self.copy(seed, "stage-certified-seed")
        self.fixture("stage-certify", "certify", certified)
        plan = json.loads((certified / "fork_repair.json").read_bytes())
        modes = ["positive", "current-root", "weak-target", "bad-signature", "unknown-signer",
                 "target-mismatch", "source-changed", "protected-prepare", "protected-commit",
                 "protected-aborted", "missing-finality", "tampered-qc", "origin-mismatch", "environment-mismatch"]
        for mode in modes:
            directory = self.copy(certified, "stage-" + mode)
            if mode in ["protected-prepare", "protected-commit", "protected-aborted", "missing-finality", "tampered-qc"]:
                self.fixture("stage-mutate-" + mode, "mutate", directory, mode)
            self.fixture("stage-unstage-" + mode, "unstage", directory)
            assert not (directory / "fork_repair.json").exists()
            before = self.inspect("stage-before-" + mode, directory)
            guarded = self.guard(directory)
            metadata = self.out / ("stage-" + mode + ".json")
            result_path = self.out / ("stage-" + mode + "-result.json")
            write(metadata, dict(schema="octra-legacy-stage-test-v1", test=STAGE_TEST, test_only=True,
                                 directory=str(directory), source_head_sha256=sha(directory / "HEAD.json"),
                                 plan=plan, mode=mode, backend=str(self.bridge), backend_sha256=self.bridge_sha,
                                 report=str(result_path)))
            environment = {**self.environment, "OCTRA_LEGACY_STAGE_FIXTURE": str(metadata)}
            invocation = Command(self, "stage-signed-tcp-" + mode,
                                 [str(self.stage_test), "--ignored", "--exact", STAGE_TEST, "--nocapture"],
                                 environment=environment).wait(timeout=120)
            regular(result_path)
            report = json.loads(result_path.read_bytes())
            after = self.inspect("stage-after-" + mode, directory)
            after_guard = self.guard(directory)
            if mode == "positive":
                assert report["staged"] is True and report["restart_required"] is True
                assert report["source"] == plan["source"]["epoch_id"] and report["target"] == plan["head"]["epoch_id"]
                assert report["root"] == plan["head"]["state_root"]
                assert json.loads((directory / "fork_repair.json").read_bytes()) == plan
                assert after == {**before, "plan_present": True}, "staging changed physical head/store/chain"
                assert {name: value for name, value in after_guard["files"].items() if name != "fork_repair.json"} == {
                    name: value for name, value in guarded["files"].items() if name != "fork_repair.json"}
                expected = self.copy(directory, "stage-positive-native")
                native = self.fixture("stage-positive-native-finish", "phase", expected, "finish").json()
                self.rust("stage-positive-rust-resume", directory)
                resumed = self.inspect("stage-positive-resumed", directory)
                assert resumed == native
                self.repaired(resumed, plan["head"])
                assert self.fixture("stage-positive-verify-committed", "verify-committed", directory).json() is True
                self.results.append(dict(case="stage-" + mode, selection=report, resumed=resumed,
                                         stage_only_unchanged=True, native_finish_equal=True))
            else:
                assert not (directory / "fork_repair.json").exists()
                if mode == "source-changed":
                    assert report["refused"] is True
                    altered = json.loads(json.dumps(before))
                    altered["head"]["ts"] = 1.0
                    assert after == altered
                    assert {name: value for name, value in after_guard["files"].items() if name != "HEAD.json"} == {
                        name: value for name, value in guarded["files"].items() if name != "HEAD.json"}
                else:
                    assert after == before and after_guard == guarded
                self.results.append(dict(case="stage-" + mode, selection=report, marker_absent=True,
                                         physical_unchanged=mode != "source-changed", preserved=after_guard))
            assert self.signing(directory) == signing
            self.check_prefix(directory, protected)

    def qualify(self):
        self.configure_docker()
        seed = self.cases / "seed"
        prepared = self.fixture("prepare", "prepare", seed).json()
        plan = json.loads((seed / "fork_repair.json").read_bytes())
        target = plan["head"]
        assert prepared["head"] == plan["source"] and prepared["plan_present"]
        assert prepared["chain_head"] > target["epoch_id"] and prepared["target_tx_present"]
        signing = self.signing(seed)
        assert (seed / "vote_log/floor").read_bytes() == b"99\n"
        assert "vote_log/round_mark" in signing
        assert any(name.startswith("vote_log/") and name.endswith(".vote") for name in signing)
        assert len([name for name in signing if name.startswith("consensus/")]) == 3
        prefix_names = {"commit_journal.log": (seed / "commit_journal.log").stat().st_size,
                        f"chaindata/txlog/seg{target['txlog_seg']:06d}.dat": target["txlog_off"],
                        "chaindata/epochlog/epochs.dat": target["epochlog_off"]}
        protected = {}
        for name, count in prefix_names.items():
            with (seed / name).open("rb") as handle:
                raw = handle.read(count)
            assert len(raw) == count
            protected[name] = dict(bytes=count, sha256=hashlib.sha256(raw).hexdigest())
        write(self.out / "initial.json", dict(inspection=prepared, plan=plan, signing=signing, protected_prefix=protected))
        self.certified(seed, signing, protected)
        self.stage_selection(seed, signing, protected)

        native = self.copy(seed, "native-finish")
        rust = self.copy(seed, "rust-finish")
        expected = self.fixture("native-full-finish", "phase", native, "finish").json()
        response = self.rust("rust-full-finish", rust).json()
        assert response["format"] == "octra-legacy-repair-resume-v1" and response["target"] == target["epoch_id"]
        assert response["store"] == response["chaindata"] == response["head"] == response["target"]
        actual = self.inspect("rust-reopen", rust)
        assert actual == expected, "actual Rust finish differs from native physical finish"
        for name, directory, value in [("native", native, expected), ("rust", rust, actual)]:
            self.repaired(value, target); self.check_prefix(directory, protected)
            assert self.signing(directory) == signing
            assert self.fixture(name + "-repeat-native-boot", "phase", directory, "finish").json() == value
            advanced = self.fixture(name + "-genuine-successor", "advance", directory).json()
            assert advanced["head"]["epoch_id"] == target["epoch_id"] + 1
            assert int(advanced["head"]["txid_hi"]) == int(target["txid_hi"]) + 1
            assert advanced["chain_head"] == advanced["head"]["epoch_id"]
            assert advanced["next_txid"] == str(int(advanced["head"]["txid_hi"]) + 1)
            assert advanced["ledger_root"] == advanced["head"]["ledger_state_root"]
            assert advanced["irmin_commit"] == advanced["head"]["irmin_commit"]
            assert advanced["plan_present"] is False and advanced["target_tx_present"] is True
            assert self.inspect(name + "-successor-reopen", directory) == advanced
            self.check_prefix(directory, protected); assert self.signing(directory) == signing
            self.results.append(dict(case=name + "-positive", repaired=value, successor=advanced))

        for phase in ["stage", "pack", "store", "chain", "trim"]:
            directory = self.copy(seed, "crash-" + phase)
            self.fixture("crash-" + phase, "crash", directory, phase, expected=(137,))
            crash_state = self.inspect("crash-" + phase + "-reopen", directory)
            assert crash_state["plan_present"]
            self.check_prefix(directory, protected); assert self.signing(directory) == signing
            self.rust("resume-" + phase, directory)
            resumed = self.inspect("resumed-" + phase, directory)
            self.repaired(resumed, target)
            assert self.fixture("repeat-native-" + phase, "phase", directory, "finish").json() == resumed
            self.check_prefix(directory, protected); assert self.signing(directory) == signing
            self.results.append(dict(case="crash-" + phase, after_crash=crash_state, resumed=resumed))

        for mutation in MUTATIONS:
            directory = self.copy(seed, "refuse-" + mutation)
            self.fixture("mutate-" + mutation, "mutate", directory, mutation)
            before = self.inspect("before-" + mutation, directory)
            guard = self.guard(directory)
            result = self.rust("refuse-" + mutation, directory, expected=None)
            assert result.process.returncode not in [0, 125, 126, 127], "expected a real application refusal"
            if mutation == "orphan-staged":
                assert b"No such file" in result.output(1)
            elif mutation == "corrupt-plan":
                assert b"invalid native JSON" in result.output(1)
            else:
                assert b"native legacy repair refused the operation" in result.output(1), mutation
            assert self.inspect("after-" + mutation, directory) == before, mutation
            assert self.guard(directory) == guard, mutation
            self.check_prefix(directory, protected); assert self.signing(directory) == signing
            self.results.append(dict(case="refuse-" + mutation, before=before, unchanged=True,
                                     exit_code=result.process.returncode, preserved=guard))

        directory = self.copy(seed, "exclusive-owner")
        before = self.inspect("owner-before", directory); guard = self.guard(directory)
        held = self.fixture("first-native-owner", "hold", directory, background=True)
        deadline = time.monotonic() + 30
        while b"owned\n" not in (held.output() if held.paths[0].exists() else b""):
            assert held.process.poll() is None and not held.exceeded.is_set(), "owner exited before lease acknowledgement"
            assert time.monotonic() < deadline, "native owner did not acknowledge actual stores"
            time.sleep(0.025)
        refused = self.fixture("second-native-owner", "inspect", directory, expected=(2,))
        assert b"flock" in refused.output(1) and any(value in refused.output(1) for value in [b"EAGAIN", b"EWOULDBLOCK"])
        rust_refused = self.rust("rust-refuses-native-owner", directory, expected=None)
        assert rust_refused.process.returncode != 0 and held.process.poll() is None
        assert self.guard(directory) == guard
        held.process.stdin.write(b"release\n"); held.process.stdin.close(); held.wait()
        assert self.inspect("owner-released", directory) == before
        self.rust("resume-after-owner-release", directory)
        resumed = self.inspect("owner-final-reopen", directory); self.repaired(resumed, target)
        self.check_prefix(directory, protected); assert self.signing(directory) == signing
        self.results.append(dict(case="exclusive-native-owner", second_native_exit=refused.process.returncode,
                                 rust_refused_while_owned=True, resumed=resumed))

    def cleanup(self):
        errors = []
        for child in self.children:
            try:
                if child.process.stdin and not child.process.stdin.closed:
                    child.process.stdin.close()
                child.stop()
            except Exception as error:
                errors.append(str(error))
        # A killed Docker bridge may leave its daemon-owned native child alive.
        # Unique label scope is mandatory: never select unrelated containers.
        if self.environment is not None:
            try:
                selected = self.run("cleanup-list", [self.docker, "ps", "-a", "--filter",
                                                     f"label={LABEL}={self.run_id}", "--format", "{{.ID}}"], timeout=30)
                identifiers = selected.output().decode().split()
                assert all(len(value) in [12, 64] and all(byte in "0123456789abcdef" for byte in value)
                           for value in identifiers)
                if identifiers:
                    self.run("cleanup-containers", [self.docker, "rm", "--force", *identifiers], timeout=45)
                remaining = self.run("cleanup-verify", [self.docker, "ps", "-a", "--filter",
                                                        f"label={LABEL}={self.run_id}", "--format", "{{.ID}}"], timeout=30)
                assert not remaining.output().strip(), "owned containers survived cleanup"
            except Exception as error:
                errors.append(str(error))
        self.report["cleanup_errors"] = errors
        self.report["cleanup_complete"] = not errors
        return errors


def main():
    if sys.flags.optimize:
        raise RuntimeError("qualification assertions require an unoptimized Python interpreter")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--backend-directory", type=Path, required=True)
    parser.add_argument("--stage-test-binary", type=Path, required=True,
                        help="fresh `octra-node --test legacy_stage` executable built from the frozen sources")
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    qualification = Qualification(arguments)
    failure = None
    try:
        qualification.qualify()
    except BaseException as error:
        failure = error
        qualification.report["failure"] = dict(type=type(error).__name__, reason=str(error))
    finally:
        cleanup_errors = qualification.cleanup()
        qualification.report["status"] = "passed" if failure is None and not cleanup_errors else "failed"
        qualification.report["scope"] = (
            "Actual native Irmin-pack/chaindata legacy stores: Rust/native finish agreement, protected prefix and signing preservation, "
            "genuine quorum-signed committed-finality rewind and authentication refusals, genuine successor/reopen, "
            "SIGKILL after durable phase boundaries, native exclusive ownership and actual signed TCP peer-selected staging "
            "under a continuous native store lease. Fixed development keys and explicit trusted fixture network only. "
            "No full public node boot, arbitrary syscall/power-loss crash, public-network certificate or mainnet qualification.")
        qualification.report["bridge_logs"] = {str(path.relative_to(qualification.out)): dict(bytes=path.stat().st_size, sha256=sha(path))
                                                for path in sorted((qualification.out / "bridge-stderr").glob("*.log"))}
        if any(value["bytes"] >= MAX_OUTPUT for value in qualification.report["bridge_logs"].values()):
            qualification.report["status"] = "failed"
            failure = failure or RuntimeError("bridge stderr reached its bounded file limit")
            qualification.report.setdefault("failure", dict(type=type(failure).__name__, reason=str(failure)))
        write(qualification.out / "qualification.json", qualification.report)
    if failure is not None:
        raise failure
    if cleanup_errors:
        raise RuntimeError("qualification container cleanup failed")
    print(json.dumps(dict(status="passed", cases=len(qualification.results), evidence=str(qualification.out / "qualification.json"))))


if __name__ == "__main__":
    main()
