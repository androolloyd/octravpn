#!/usr/bin/env python3
"""Unchanged native per-item preverification key, retention and FIFO lifecycle.

Proof verdicts are supplied fixtures. This qualifies reuse and invalidation,
not cryptographic proof correctness or native weak-reference GC timing.
"""
import argparse
import base64
import collections
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crates/octra-node-runtime/tests/fixtures/epoch-partition.json"
BUILDER = "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"


def fixtures():
    rows = []
    for purpose, epoch, root, tx_hash in itertools.product(
        ["build", "validate"], [-(1 << 62), -1, 0, 1, 2, 2**31, (1 << 62)-1],
        [b"", b"root", b"1:a", b"\x00", b"\xff:\x00", bytes(range(256))],
        [b"", b"hash", b"0:\x00\xff", b"1:"],
    ):
        rows.append(dict(group="key", epoch=str(epoch), purpose=purpose,
                         root=root.hex(), tx_hash=tx_hash.hex()))
    source = json.loads(SOURCE.read_bytes())
    template = json.loads(base64.b64decode(source["transaction_pool"][0]))
    txs = []
    for index in range(5):
        tx = dict(template, nonce=index+1, op_type="key_switch", message="cache:"+str(index))
        if index == 4:
            tx["encrypted_data"] = "0" * 2048
        txs.append(base64.b64encode(json.dumps(tx, separators=(",", ":")).encode()).decode())
    rng = random.Random(20261017)
    for cap, limit in itertools.product([0, 1, 2, 4], [0, 256, 1024, 32*1024*1024]):
        for scenario in ["retention", "namespaces", "random"]:
            steps = []
            def step(tx=0, verdict="ready", root=b"root", purpose="build", epoch=1):
                steps.append(dict(tx=tx, verdict=verdict, root=root.hex(), purpose=purpose, epoch=str(epoch)))
            if scenario == "retention":
                for verdict in ["ready", "invalid", "unavailable", "deferred", "error"]:
                    # New roots select a fresh result; repeated calls vary the
                    # factory to expose both retained and forgotten verdicts.
                    step(verdict=verdict, root=verdict.encode())
                    step(verdict="ready", root=verdict.encode())
                    step(verdict="error", root=verdict.encode())
                for tx in [0, 1, 0, 2, 1, 3, 4, 0, 4]:
                    step(tx=tx)
            elif scenario == "namespaces":
                for root, epoch, purpose, tx in itertools.product(
                    [b"root", b"next", b"root"], [0, 1, 2], ["build", "validate"], [0, 1, 0],
                ):
                    step(tx=tx, root=root, epoch=epoch, purpose=purpose)
                    step(tx=tx, root=root, epoch=epoch, purpose=purpose, verdict="invalid")
            else:
                for _ in range(60):
                    step(tx=rng.randrange(5), verdict=rng.choice(["ready", "invalid", "unavailable", "deferred", "error"]),
                         root=rng.choice([b"root"]*5+[b"next"]), purpose=rng.choice(["build", "validate"]),
                         epoch=rng.choice([0, 1, 1, 2]))
            rows.append(dict(group="trace", capacity=cap, limit=limit, transactions=txs, steps=steps))
    for cap, limit in itertools.product([0, 1, 2, 4], [0, 256, 1024, 32*1024*1024]):
        steps = [[0, 1], [0], [2], [1, 2], [3, 4], [0, 0, 1], [], [4, 3, 2, 1, 0]]
        steps += [[rng.randrange(5) for _ in range(rng.randrange(5))] for _ in range(20)]
        rows.append(dict(group="shared", capacity=cap, limit=limit, transactions=txs, steps=steps))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--builder-image", default=BUILDER)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists() or args.builder_image != BUILDER:
        raise SystemExit("require fresh output and pinned offline builder")
    spec = importlib.util.spec_from_file_location("native", ROOT / "scripts/node-port/native-oracle.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    inputs = fixtures()
    report = native.run(args.upstream, args.builder_image,
                        ROOT / "scripts/node-port/consensus-preverify-cache-oracle.ml", inputs,
                        "octra_core octra_node_runtime yojson base64 lwt.unix")
    report["generator_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report["transaction_fixture_sha256"] = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    report["input_sha256"] = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report["groups"] = dict(collections.Counter(row["group"] for row in inputs))
    report["scope"] = "Actual unchanged Consensus_bundle_cache: native item key; Ready/Invalid-only retention; root/epoch/purpose invalidation; FIFO count and byte accounting; shared transaction admission/eviction. Supplied proof verdicts, no cryptographic callback or weak-GC timing claim. Rust concurrent-owner cancellation and late ticket replacement are separate regressions."
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2)+"\n")
    print(f"Generated {len(inputs)} native consensus preverification cache comparisons: {args.out}")


if __name__ == "__main__":
    main()
