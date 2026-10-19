#!/usr/bin/env python3
"""Build or check the exact public Circle asset manifest."""

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ASSETS = (
    ("index.html", "text/html"),
    ("join.html", "text/html"),
    ("browse.html", "text/html"),
    ("operators.html", "text/html"),
    ("style.css", "text/css"),
    ("logo.svg", "image/svg+xml"),
)


def bundle() -> str:
    assets = []
    for name, content_type in ASSETS:
        data = (ROOT / name).read_bytes()
        assets.append({
            "path": f"/{name}",
            "content_type": content_type,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return json.dumps({"version": 1, "assets": assets}, indent=2) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="update bundle.json")
    parser.add_argument("--check", action="store_true", help="verify bundle.json")
    args = parser.parse_args()
    if args.write and args.check:
        parser.error("choose --write or --check")
    expected = bundle()
    manifest = ROOT / "bundle.json"
    if args.write:
        manifest.write_text(expected)
    elif args.check:
        if manifest.read_text() != expected:
            raise SystemExit("bundle.json is stale; run bundle.py --write")
    else:
        print(expected, end="")


if __name__ == "__main__":
    main()
