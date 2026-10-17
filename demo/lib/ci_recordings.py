#!/usr/bin/env python3
"""Stage only this run's successful VHS outputs; reject stale/overlapping artifacts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "recordings.json"
SUFFIXES = (".gif", ".mp4", ".vtt", "-captioned.mp4", "-narrated.mp4",
            "-narrated-captioned.mp4")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path):
    return not path.is_symlink() and path.is_file() and path.stat().st_size > 0


def digest(path):
    require(regular(path), f"missing/nonregular/empty recording: {path.name}")
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def read(stage):
    require(not stage.is_symlink(), "artifact directory is a symlink")
    path = stage / MANIFEST
    require(regular(path), "recording manifest is missing")
    state = json.loads(path.read_text())
    require(state["version"] == 1, "unsupported recording manifest")
    return state


def write(stage, state):
    (stage / MANIFEST).write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def initialize(stage, group, tapes, commit, run):
    require(re.fullmatch(r"[a-z][a-z0-9-]*", group), "invalid recording group")
    names = [Path(tape).name for tape in tapes]
    require(names and len(names) == len(set(names)), "empty/duplicate expected tapes")
    require(all(re.fullmatch(r"\d{2}-[a-z0-9-]+\.tape", name) for name in names),
            "invalid tape name")
    stage.mkdir(parents=True, exist_ok=False)
    write(stage, {"version": 1, "group": group, "commit": commit, "run": run,
                  "expected": names, "completed": [], "failures": {},
                  "files": {}, "complete": False})


def outputs(root, tape):
    name = Path(tape).name
    require(tape == f"demo/tapes/{name}", "tape must be directly under demo/tapes")
    path = root / tape
    require(regular(path), "missing/nonregular tape")
    declared = [line.split(maxsplit=1)[1].strip() for line in path.read_text().splitlines()
                if line.startswith("Output ")]
    expected = [f"demo/recordings/{path.stem}{suffix}" for suffix in (".gif", ".mp4")]
    require(len(declared) == 2 and set(declared) == set(expected),
            "tape must declare its own GIF and MP4 directly under demo/recordings")
    return [root / item for item in expected]


def render(root, stage, tape, skip_preflight):
    state = read(stage)
    name = Path(tape).name
    require(name in state["expected"], "tape is not assigned to this group")
    require(name not in state["completed"] and name not in state["failures"],
            "tape was already attempted")
    paths = outputs(root, tape)
    # A zero-exit renderer that writes nothing must not qualify tracked media.
    for path in paths:
        require(not path.is_symlink(), "recording output is a symlink")
        path.unlink(missing_ok=True)
    try:
        if not skip_preflight:
            subprocess.run(["bash", "demo/lib/preflight-tape.sh", tape], cwd=root, check=True)
        subprocess.run(["vhs", tape], cwd=root, check=True)
        for path in paths:
            digest(path)
        caption = root / "demo/recordings" / (Path(name).stem + ".vtt")
        for path in paths + ([caption] if regular(caption) else []):
            shutil.copyfile(path, stage / path.name)
        state["completed"].append(name)
        passed = True
    except (subprocess.CalledProcessError, OSError, ValueError) as error:
        state["failures"][name] = str(error)
        print(f"::error::{name} was not produced successfully", file=sys.stderr)
        passed = False
    write(stage, state)
    return passed


def finalize(stage, processing_failed=False):
    state = read(stage)
    allowed = {Path(name).stem + suffix for name in state["completed"] for suffix in SUFFIXES}
    files = {}
    for path in stage.iterdir():
        if path.name == MANIFEST:
            continue
        require(path.name in allowed, f"unexpected staged file: {path.name}")
        files[path.name] = digest(path)
    for name in state["completed"]:
        for suffix in (".gif", ".mp4"):
            require(Path(name).stem + suffix in files, "successful tape has missing media")
    state["files"] = files
    if processing_failed:
        state["failures"]["postprocess"] = "caption/audio processing failed"
    state["complete"] = not state["failures"] and set(state["expected"]) == set(state["completed"])
    write(stage, state)
    print(f"recordings {state['group']}: {len(state['completed'])}/{len(state['expected'])} tapes, "
          f"complete={state['complete']}")
    return state["complete"]


def verified(stage, commit, run):
    state = read(stage)
    require(state["commit"] == commit and state["run"] == run, "artifact run/commit differs")
    require(state["complete"] and not state["failures"], "recording group is incomplete")
    require(state["expected"] and set(state["expected"]) == set(state["completed"]),
            "expected tape coverage differs")
    allowed = {Path(name).stem + suffix for name in state["completed"] for suffix in SUFFIXES}
    require(set(state["files"]) <= allowed, "manifest lists another tape's file")
    require({path.name for path in stage.iterdir()} == set(state["files"]) | {MANIFEST},
            "artifact files differ from manifest")
    for name in state["completed"]:
        require(all(Path(name).stem + suffix in state["files"] for suffix in (".gif", ".mp4")),
                "manifest omits required tape output")
    for name, expected in state["files"].items():
        require(digest(stage / name) == expected, f"recording hash differs: {name}")
    return state


def merge(source, target, groups, commit, run):
    require(len(groups) == len(set(groups)), "duplicate artifact groups")
    states = []
    seen = set()
    for group in groups:
        stage = source / f"demo-recordings-{group}"
        state = verified(stage, commit, run)
        require(state["group"] == group, "artifact group differs")
        require(not seen.intersection(state["files"]), "groups contain overlapping recordings")
        seen.update(state["files"])
        states.append((stage, state))
    require(states, "no recording groups")
    target.mkdir(parents=True, exist_ok=False)
    merged = {"version": 1, "group": "heavy", "commit": commit, "run": run,
              "expected": [], "completed": [], "failures": {}, "files": {}, "complete": True}
    for stage, state in states:
        for name in state["files"]:
            shutil.copyfile(stage / name, target / name)
        merged["files"].update(state["files"])
        merged["expected"].extend(state["expected"])
        merged["completed"].extend(state["completed"])
    write(target, merged)


def publish(root, stage, commit, run):
    state = verified(stage, commit, run)
    for name in state["files"]:
        shutil.copyfile(stage / name, root / "demo/recordings" / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "render", "finalize", "merge", "publish"))
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--group")
    parser.add_argument("--tapes", nargs="+")
    parser.add_argument("--tape")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--processing-failed", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--groups", nargs="+")
    args = parser.parse_args()
    commit, run = os.environ["GITHUB_SHA"], os.environ["GITHUB_RUN_ID"]
    if args.action == "init":
        initialize(args.stage, args.group, args.tapes, commit, run)
    elif args.action == "render":
        return 0 if render(ROOT, args.stage, args.tape, args.skip_preflight) else 1
    elif args.action == "finalize":
        return 0 if finalize(args.stage, args.processing_failed) else 1
    elif args.action == "merge":
        merge(args.source, args.stage, args.groups, commit, run)
    else:
        publish(ROOT, args.stage, commit, run)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, ValueError) as error:
        print(f"recordings: {error}", file=sys.stderr)
        sys.exit(1)
