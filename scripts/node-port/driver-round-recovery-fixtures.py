#!/usr/bin/env python3
"""Source-bound pure C_driver round-cursor and duplicate-identity comparisons.

Calls the actual adopted C_driver module linked with its actual dependencies.
The oracle constructs a dormant native driver; no host callback or network
session is executed. No native source body or clock is replaced.
"""
import argparse
import collections
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDER = "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
LOW = -(1 << 62)
HIGH = (1 << 62) - 1


def fixtures():
    rows = []
    for generation, message, payload in itertools.product(
        [LOW, -1, 0, 1, 2, HIGH],
        [0, 1, 0x30, 0x31, 0x32, 0x3C, 0x3D, 0x3E, 0x3F, 255],
        [b"", b"\x00", b"0:", b"1:\x30", b"\xff\x00:\xc0\xaf", bytes(range(256))],
    ):
        rows.append(dict(group="frame", generation=str(generation), message=message,
                         payload=payload.hex()))

    def cursor(height=7, round_number=0, limit=1024, prior=None, now=5_000_000_000,
               group="cursor"):
        rows.append(dict(group=group, height=str(height), round=str(round_number),
                         limit=str(limit), prior=prior, now=str(now)))

    def prior(epoch=7, target=64, sent=0, tries=0):
        return dict(epoch=str(epoch), target=str(target), sent=str(sent), tries=str(tries))

    for round_number, limit in itertools.product(
        [LOW, -1, 0, 1, 63, 64, HIGH - 64, HIGH - 63, HIGH],
        [LOW, -1, 0, 1, 32, 64, 65, 1024, HIGH],
    ):
        cursor(round_number=round_number, limit=limit)
        cursor(round_number=round_number, limit=limit, prior=prior(epoch=6))
    for now, sent, round_number, tries in itertools.product(
        [-(1 << 63), -1, 0, 4_999_999_999, 5_000_000_000, 5_000_000_001, (1 << 63) - 1],
        [-(1 << 63), -1, 0, 1, (1 << 63) - 1],
        [0, 63, 64, 65], [0, 1, -1],
    ):
        cursor(round_number=round_number, prior=prior(sent=sent, tries=tries), now=now,
               group="clock")
    for height, epoch, target, tries, limit in itertools.product(
        [-(1 << 63), 7, (1 << 63) - 1],
        [-(1 << 63), 7, (1 << 63) - 1],
        [LOW, -1, 0, 64, HIGH - 63, HIGH], [0, 1], [64, HIGH],
    ):
        cursor(height=height, round_number=1, limit=limit,
               prior=prior(epoch=epoch, target=target, tries=tries), group="bounds")
    for current, delta in itertools.product([-(1 << 63), -1, 0, 1, 128, 200, (1 << 63) - 1],
                                             [-129, -128, -127, 0, 1, 2]):
        epoch = ((current + delta + (1 << 63)) % (1 << 64)) - (1 << 63)
        rows.append(dict(group="evidence-window", current=str(current), epoch=str(epoch)))
    def step(epoch=200, round_number=0, value=1):
        return dict(epoch=str(epoch), round=str(round_number), value=value)
    rows.append(dict(group="evidence-pool", steps=[step(), step(value=2), step(round_number=1),
        step(epoch=328, round_number=2), step(epoch=329, round_number=3), step(epoch=100, round_number=4)]))
    rows.append(dict(group="evidence-pool", steps=[step(round_number=i) for i in range(4097)] +
        [step(value=2), step(epoch=328, round_number=4097), step(epoch=329, round_number=4097)]))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--builder-image", default=BUILDER)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists() or args.builder_image != BUILDER:
        raise SystemExit("require fresh output and pinned offline builder")
    spec = importlib.util.spec_from_file_location("native_oracle", ROOT / "scripts/node-port/native-oracle.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    inputs = fixtures()
    report = native.run(args.upstream, args.builder_image,
                        ROOT / "scripts/node-port/driver-round-recovery-oracle.ml", inputs,
                        "octra_consensus octra_net yojson lwt.unix")
    report["scope"] = "Unchanged native C_driver.next_past_round, msg_id, vote_evidence_in_window and signing-slot retention; dormant real native driver, no source edits or simulated dependencies. Connected orchestration and cryptographic evidence admission are qualified separately."
    report["input_sha256"] = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report["groups"] = dict(collections.Counter(row["group"] for row in inputs))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Generated {len(inputs)} native driver round-recovery comparisons: {args.out}")


if __name__ == "__main__":
    main()
