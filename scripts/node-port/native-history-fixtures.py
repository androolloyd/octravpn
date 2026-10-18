#!/usr/bin/env python3
"""Exercise the read-only adapter against real native Irmin/chaindata stores."""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--builder-image", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    inventory = json.loads((ROOT / "docs/rust-node/source-map.json").read_text())
    pin = subprocess.check_output(["git", "-C", str(args.upstream), "rev-parse", "HEAD"], text=True).strip()
    if pin != inventory["upstream_commit"] or args.out.exists():
        raise SystemExit("require current native pin and a fresh output path")
    for name, digest in inventory["files"].items():
        if hashlib.sha256((args.upstream / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"modified upstream source: {name}")
    helpers = {
        "native-history-export.ml": "native_history_export.ml",
        "native-history-main.ml": "main.ml",
        "native-history-fixtures.ml": "fixtures.ml",
    }
    with tempfile.TemporaryDirectory(prefix="octra-native-history-") as temporary:
        fixture = pathlib.Path(temporary)
        for source, target in helpers.items():
            shutil.copyfile(ROOT / "scripts/node-port" / source, fixture / target)
        (fixture / "dune").write_text(
            "(executables (names main fixtures) (libraries octra_node_runtime octra_consensus octra_net octra_core octra_recovery_case lwt.unix unix yojson digestif))\n")
        (fixture / "runtime.sha256").write_text("".join(
            f"{digest}  {name}\n" for name, digest in inventory["files"].items()))
        (fixture / "restore.py").write_text(
            "import hashlib,pathlib,shutil\n"
            "for line in pathlib.Path('/fixture/runtime.sha256').read_text().splitlines():\n"
            " digest,name=line.split('  ',1); path=pathlib.Path(name)\n"
            " if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n"
            "  path.parent.mkdir(parents=True,exist_ok=True)\n"
            "  shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output = subprocess.check_output([
            "docker", "run", "--rm", "--network", "none", "--mount",
            f"type=bind,source={fixture},target=/fixture,readonly", "--mount",
            f"type=bind,source={args.upstream.resolve()},target=/native,readonly", args.builder_image,
            "bash", "-lc", "python3 /fixture/restore.py && sha256sum --check --quiet /fixture/runtime.sha256 && "
            "mkdir vpn_native_history_oracle && cp /fixture/*.ml /fixture/dune vpn_native_history_oracle/ && "
            "opam exec -- dune build ./vpn_native_history_oracle/main.exe && "
            "opam exec -- dune exec ./vpn_native_history_oracle/fixtures.exe -- /tmp/native-history-data"], text=True)
    report = {
        "upstream_commit": pin,
        "scope": "real native storage/recovery boundary and unchanged epoch_source on exact exported native header bytes under independent fixture keys; synthetic transactions, no consensus or peer finality qualification",
        "source_sha256": inventory["files"],
        "adapter_sha256": {name: hashlib.sha256((ROOT / "scripts/node-port" / name).read_bytes()).hexdigest() for name in helpers},
        "cases": json.loads(output.splitlines()[-1]),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: real native history, HEAD crash window, recovery and pruning: {args.out}")


if __name__ == "__main__":
    main()
