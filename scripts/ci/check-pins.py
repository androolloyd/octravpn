#!/usr/bin/env python3
"""Fail when a pinned dependency revision is written down inconsistently.

The Foundry and Headscale revisions appear in several places: the Cargo
manifests (what the workspace compiles against), the CI workflows (the
sibling checkouts whose binaries the Docker harness and parity jobs use)
and the README. If they disagree, CI tests one revision of a dependency
while the build ships another.

The manifest is the authority. Every other line that names the repository
and carries a 40-hex revision must carry the same one.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
REVISION = re.compile(r"\b[0-9a-f]{40}\b")
PINS = {
    "octra-foundry": "crates/octravpn-core/Cargo.toml",
    "headscale-rs": "crates/octravpn-mesh/Cargo.toml",
}
SEARCHED = [".github/workflows", ".github/actions", "README.md", "crates", "tests", "docker"]
SUFFIXES = {".yml", ".yaml", ".toml", ".md", ".sh"}


def files():
    for entry in SEARCHED:
        path = ROOT / entry
        if path.is_file():
            yield path
        elif path.is_dir():
            for found in path.rglob("*"):
                if found.is_file() and (found.suffix in SUFFIXES or found.name.startswith("Dockerfile")):
                    if "fixtures" not in found.parts and "target" not in found.parts:
                        yield found


def revisions(name):
    """{revision: [where it appears]} for every line naming `name`."""
    seen = {}
    for path in files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(lines, 1):
            if name in line:
                for revision in REVISION.findall(line):
                    seen.setdefault(revision, []).append(f"{path.relative_to(ROOT)}:{number}")
    return seen


def main():
    failed = False
    for name, manifest in PINS.items():
        authority = {
            revision
            for line in (ROOT / manifest).read_text(encoding="utf-8").splitlines()
            if name in line
            for revision in REVISION.findall(line)
        }
        if len(authority) != 1:
            print(f"pins: {name}: expected one revision in {manifest}, found {sorted(authority) or 'none'}", file=sys.stderr)
            failed = True
            continue
        (want,) = authority
        strays = {rev: where for rev, where in revisions(name).items() if rev != want}
        if strays:
            failed = True
            print(f"pins: {name} is {want} in {manifest}, but:", file=sys.stderr)
            for revision, where in sorted(strays.items()):
                print(f"  {revision} at {', '.join(where[:4])}{' …' if len(where) > 4 else ''}", file=sys.stderr)
        else:
            print(f"pins: {name} {want} everywhere ({sum(len(w) for w in revisions(name).values())} mentions)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
