#!/usr/bin/env python3
"""Generate differential fixtures with the real pinned OCaml implementation."""
import argparse
import base64
import hashlib
import json
import pathlib
import random
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
    pin = json.loads((ROOT / "docs/rust-node/upstream.json").read_text())["commit"]
    actual = subprocess.check_output(["git", "-C", str(args.upstream), "rev-parse", "HEAD"], text=True).strip()
    if actual != pin or args.out.exists():
        raise SystemExit("require the pinned upstream and a fresh fixture path")
    name = "net/epoch_index_commitment.ml"
    source = subprocess.check_output(["git", "-C", str(args.upstream), "show", f"HEAD:{name}"])
    if (args.upstream / name).read_bytes() != source:
        raise SystemExit("modified upstream commitment source")
    encode = lambda value: base64.b64encode(value).decode()
    cases = [{"operation": "genesis"}]
    hashes = [bytes(range(32)), b"A" * 64, b"a" * 64, b"", b"z" * 64, b"f" * 63, b"f" * 65]
    roots = hashes + [b"A" * 128, b"a" * 64 + b"b" * 64, b"\x00irmin\xffroot", b"raw-root", b"abc\n:def"]
    for value in hashes:
        cases.append({"operation": "normalize_hash", "hash_b64": encode(value)})
    for value in roots:
        cases.append({"operation": "root_hex", "root_b64": encode(value)})
        cases.append({"operation": "fold", "ledger_b64": encode(value), "index_b64": encode(b"B" * 64)})
    for epoch in [0, 1, -1, -(1 << 63), (1 << 63) - 1]:
        cases.append({"operation": "epoch", "epoch": str(epoch), "items": []})
        for previous in [b"", b"F" * 64, bytes(range(32)), b"prior\x00root"]:
            cases.append({"operation": "next", "epoch": str(epoch), "previous_b64": encode(previous),
                "items": [{"txid": str(txid), "hash_b64": encode(value)}
                    for txid, value in [(9, b"A" * 64), (-3, bytes(range(32))), (0, b"f" * 64)]]})
    for value in hashes:
        cases.append({"operation": "root", "previous_b64": encode(b"prior"), "hash_b64": encode(value)})
    for items in [[(1, b"a" * 64), (1, b"b" * 64)], [(1, b"bad"), (1, b"a" * 64)], [(0, b"bad")]]:
        cases.append({"operation": "epoch", "epoch": "7",
            "items": [{"txid": str(txid), "hash_b64": encode(value)} for txid, value in items]})
    for start in [0, (1 << 63) - 1, -(1 << 63)]:
        cases.append({"operation": "next_from_hashes", "epoch": "7", "start_txid": str(start),
            "previous_b64": encode(b"previous"), "hashes_b64": [encode(value) for value in hashes[:3]]})
    rng = random.Random(20261012)
    for _ in range(64):
        ids = rng.sample(range(-1000, 1000), rng.randrange(12))
        cases.append({"operation": "next", "epoch": str(rng.randrange(1 << 63)),
            "previous_b64": encode(rng.randbytes(32)),
            "items": [{"txid": str(txid), "hash_b64": encode(rng.randbytes(32))} for txid in ids]})
    with tempfile.TemporaryDirectory(prefix="octra-eic-oracle-") as temporary:
        fixture = pathlib.Path(temporary)
        (fixture / "upstream.ml").write_bytes(source)
        (fixture / "cases.json").write_text(json.dumps(cases))
        shutil.copyfile(ROOT / "scripts/node-port/epoch-index-oracle.ml", fixture / "main.ml")
        (fixture / "dune").write_text("(executable (name main) (libraries octra_net yojson base64))\n")
        output = subprocess.check_output(["docker", "run", "--rm", "--network", "none",
            "--mount", f"type=bind,source={fixture},target=/fixture,readonly", args.builder_image,
            "bash", "-lc", "cmp net/epoch_index_commitment.ml /fixture/upstream.ml && mkdir vpn_epoch_index_oracle && cp /fixture/main.ml /fixture/dune vpn_epoch_index_oracle/ && opam exec -- dune exec ./vpn_epoch_index_oracle/main.exe -- /fixture/cases.json"], text=True)
    report = {"upstream_commit": pin, "source": name, "source_sha256": hashlib.sha256(source).hexdigest(),
        "oracle": "pinned OCaml implementation, isolated builder, no network", "cases": json.loads(output)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Generated {len(cases)} OCaml differential cases: {args.out}")


if __name__ == "__main__":
    main()
