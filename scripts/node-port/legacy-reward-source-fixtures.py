#!/usr/bin/env python3
"""Call unchanged native legacy Epochlog decoding and epoch_source attribution."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import random

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native", ROOT / "scripts/node-port/native-oracle.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def encode(value):
    # Native strings are bytes, including invalid UTF-8. The fixture envelope
    # carries only hex; these exact raw bytes go through Yojson in the oracle.
    if isinstance(value, bytes):
        out = bytearray(b'"')
        for byte in value:
            out.extend((b'\\"' if byte == 34 else b'\\\\' if byte == 92 else
                        ("\\u%04x" % byte).encode() if byte < 32 else bytes([byte])))
        return bytes(out) + b'"'
    if isinstance(value, str):
        return encode(value.encode())
    if isinstance(value, dict):
        return b"{" + b",".join(encode(k) + b":" + encode(v) for k, v in value.items()) + b"}"
    if isinstance(value, list):
        return b"[" + b",".join(map(encode, value)) + b"]"
    return json.dumps(value, separators=(",", ":")).encode()


def fixtures():
    rng = random.Random(2026101709)
    keys = [(b"octAlice", base64.b64encode(b"a" * 32)), (b"octBob", base64.b64encode(b"b" * 32))]
    base = dict(id=7, state_root="root", prev_state_root="previous", parent_commit="parent",
                start_txid="0", tx_count=0, finalized_by="octAlice", finalized_at=0.0,
                creator_addr="", validator_reward_each="0", reward_recipients=[], reward_source=None)
    recipient = lambda address, role="validator": dict(address=address, role=role, amount="1")
    source = dict(proposer_address="octAlice", proposer_public_key=None,
                  members=[dict(address="octBob", public_key=None, weight="17"),
                           dict(address="octAlice", public_key=None, weight="2")])
    out = []

    def add(header, chosen=keys, protocol=0, weighted=None):
        out.append(dict(header=encode(header).hex(), keys=[[a.hex(), k.hex()] for a, k in chosen],
                        protocol_activation=str(protocol), validator_activation=None if weighted is None else str(weighted)))

    # Deterministic cross-product of the defining branches and error precedence.
    for epoch in [-1, 0, 6, 7, 8, (1 << 62) - 1]:
        for protocol in [0, 7, 8]:
            for weighted in [None, 7, 8]:
                for explicit in [False, True]:
                    h = copy.deepcopy(base)
                    h.update(id=epoch, reward_source=source if explicit else None)
                    add(h, protocol=protocol, weighted=weighted)
    for creator in ["", "abc", "octBob", "x" * 129, b"raw\xff"]:
        for each in ["0", "00", "1", "", 0, None]:
            h = dict(base, creator_addr=creator, validator_reward_each=each)
            add(h)
    choices = [[], [recipient("octAlice")], [recipient("octBob", "proposer_validator")],
               [recipient("octBob"), recipient("octAlice"), recipient("octBob")],
               [recipient("octAlice", "Validator")], [recipient(b"raw\xff")],
               [dict(address="octAlice", role="validator")], [None], None, "bad"]
    key_choices = [keys, [], keys[::-1], keys + [keys[0]],
                   [(b"octAlice", b"%%%%")] + keys[1:], [(b"octAlice", b"AA==")] + keys[1:],
                   [(b"octBob", keys[0][1]), keys[0]],
                   [keys[0], (b"octAlice", b"%%%%"), keys[1]],
                   [(b"octBob", keys[1][1]), (b"raw\xff", base64.b64encode(b"c" * 32))]]
    for rows in choices:
        for chosen in key_choices:
            add(dict(base, reward_recipients=rows), chosen)
    # Required decoder fields versus legacy optional defaults and native ints.
    for field in list(base):
        for replacement in [None, [], {}, True, 1, "bad"]:
            h = copy.deepcopy(base); h[field] = replacement; add(h)
        h = copy.deepcopy(base); del h[field]; add(h)
    for start in ["-1", "0xFF", "0u18446744073709551615", "9_999", "9223372036854775808", "bad"]:
        add(dict(base, start_txid=start))
    for field in ["proposer_address", "proposer_public_key", "members"]:
        for replacement in [None, [], {}, 1, "bad"]:
            h = copy.deepcopy(base); h["reward_source"] = dict(source, **{field: replacement}); add(h)
    for weight in ["0", "-1", "0x10", "1_0", "0" * 257, "bad"]:
        h = copy.deepcopy(base); h["reward_source"] = copy.deepcopy(source)
        h["reward_source"]["members"][0]["weight"] = weight; add(h)
    # Random combinations are deterministic and supplement, not replace, all
    # named boundary vectors above.
    for _ in range(128):
        h = dict(base, id=rng.choice([0, 7, 8]), creator_addr=rng.choice(["", "abc", "octBob"]),
                 reward_recipients=rng.choice(choices), validator_reward_each=rng.choice(["0", "00", "1"]))
        add(h, rng.choice(key_choices), rng.choice([0, 8]), rng.choice([None, 7, 8]))
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--upstream", type=pathlib.Path, required=True)
    p.add_argument("--builder-image", required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    a = p.parse_args()
    if a.out.exists():
        raise SystemExit("require fresh report")
    report = native.run(a.upstream, a.builder_image, ROOT / "scripts/node-port/legacy-reward-source-oracle.ml",
                        fixtures(), "octra_node_runtime octra_consensus octra_core octra_net yojson unix")
    report["generator_sha256"] = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    report["scope"] = "Unchanged native Epochlog.epoch_of_json and Consensus_reward_attribution.epoch_source; independent historical policy/keys. Local compatibility only, no peer QC authentication or modern-history fallback."
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print("PASS", len(report["cases"]), "native legacy reward/header cases")


if __name__ == "__main__":
    main()
