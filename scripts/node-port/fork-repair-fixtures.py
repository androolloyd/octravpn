#!/usr/bin/env python3
"""Pure adopted repair records and exact finality finishing callback traces.

Actual pack/chaindata mutation and authenticated network evidence are qualified
separately. This invokes unchanged production modules in the real full builder.
"""
import argparse
import base64
import collections
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDER = "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"


def blob(value):
    return base64.b64encode(value).decode()


def raw_json(value):
    if isinstance(value, bytes):
        output = bytearray(b'"')
        for byte in value:
            if byte in [34, 92]:
                output.extend(b"\\" + bytes([byte]))
            elif byte < 32 or byte == 127:
                output.extend(f"\\u{byte:04x}".encode())
            else:
                output.append(byte)
        return bytes(output) + b'"'
    if isinstance(value, dict):
        return b"{" + b",".join(raw_json(key.encode()) + b":" + raw_json(item)
                                  for key, item in value.items()) + b"}"
    if isinstance(value, list):
        return b"[" + b",".join(raw_json(item) for item in value) + b"]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def head(epoch=1, **changes):
    return dict(schema_version=3, generation=epoch, epoch_id=epoch, state_root=b"a" * 64,
                ledger_state_root=b"ledger", irmin_commit=b"commit", txid_hi="1",
                txlog_seg=0, txlog_off=12, epochlog_off=34, commit_id=b"native", ts=1.0,
                quorum_cert_hash=None, epoch_index_hash=b"index", epoch_index_root=b"root") | changes


def plan():
    return dict(schema=1, source=head(2), target_root=b"a" * 64, next_txid="2", head=head())


def entry(height=1, root=b"a" * 64, txid=1):
    return dict(height=str(height), root=blob(root), txid=str(txid))


def fixtures():
    cases = []

    def parse(group, label, value):
        cases.append(dict(group=group, label=label, op="parse", raw=blob(raw_json(value))))

    parse("valid-records", "base", plan())
    for txid in [-1, 0, 1, (1 << 63) - 2]:
        value = plan(); value["head"]["txid_hi"] = str(txid); value["next_txid"] = str(txid + 1)
        parse("valid-records", f"txid-{txid}", value)
    for field in ["ledger_state_root", "irmin_commit", "epoch_index_hash", "epoch_index_root", "commit_id"]:
        value = plan(); value["head"][field] = bytes(range(256))
        parse("valid-records", field, value)
    for timestamp in [-0.0, 5e-324, 0.1, 1.2345678901234567, 1e300]:
        value = plan(); value["source"]["ts"] = timestamp; value["head"]["ts"] = timestamp
        parse("valid-records", str(timestamp), value)
    for number in ["+2", "02", "0x2", "2_", "0b10", "0u2"]:
        value = plan(); value["next_txid"] = number
        parse("int64-encoding", number, value)
    for field in ["schema", "source", "target_root", "next_txid", "head"]:
        for bad in [None, False, [], {}, 1.0]:
            value = plan(); value[field] = bad
            parse("scalar-shapes", f"{field}-{bad}", value)
    for field in ["schema_version", "generation", "epoch_id", "txid_hi", "txlog_seg", "txlog_off",
                  "epochlog_off", "state_root", "commit_id", "ts"]:
        for bad in [False, [], {}, None]:
            value = plan(); value["head"][field] = bad
            parse("head-shapes", f"{field}-{bad}", value)
    for root in [b"", b"a" * 63, b"a" * 65, b"A" * 64, b"0" * 63 + b"\0", b"0" * 63 + b"\xff"]:
        value = plan(); value["target_root"] = root
        parse("plan-guards", "root-" + blob(root), value)
    mutations = [
        ("source", "schema_version", 2), ("source", "generation", 1),
        ("source", "epoch_id", 1), ("head", "schema_version", 2), ("head", "generation", 2),
        ("head", "state_root", b"b" * 64), ("head", "ledger_state_root", None),
        ("head", "irmin_commit", None), ("head", "txlog_seg", None), ("head", "txlog_off", None),
        ("head", "epochlog_off", None), ("head", "epoch_index_hash", None),
        ("head", "epoch_index_root", None), ("head", "txid_hi", str((1 << 63) - 1)),
        ("head", "txid_hi", "-2"), ("head", "ts", -1.0), ("head", "ts", float("nan")),
        ("head", "ts", float("inf")), ("head", "txlog_seg", -1),
    ]
    for index, (section, field, value) in enumerate(mutations):
        changed = plan(); changed[section][field] = value
        parse("plan-guards", str(index), changed)
    for number in ["-1", "3", "9223372036854775808", "", " 2", "2x"]:
        value = plan(); value["next_txid"] = number
        parse("plan-guards", "next-" + number, value)
    for schema in [0, 2, 1 << 62, 1 << 63, "1", True]:
        value = plan(); value["schema"] = schema
        parse("plan-guards", "schema-" + str(schema), value)
    for label, value in [
        ("unknown-outer", raw_json(plan() | {"unknown": []})),
        ("duplicate-outer-first-valid", raw_json(plan()).replace(b'{"schema":1,', b'{"schema":1,"schema":9,', 1)),
        ("duplicate-outer-first-invalid", raw_json(plan()).replace(b'{"schema":1,', b'{"schema":9,"schema":1,', 1)),
        ("duplicate-head", raw_json(plan()).replace(b'"head":{', b'"head":{"generation":1,', 1)),
        ("unknown-head", raw_json(plan()).replace(b'"head":{', b'"head":{"unknown":0,', 1)),
        ("truncated", raw_json(plan())[:-1]), ("null", b"null"), ("list", b"[]"),
    ]:
        cases.append(dict(group="field-selection", label=label, op="parse", raw=blob(value)))

    base = plan()
    replacements = dict(schema_version=2, generation=3, epoch_id=3, state_root=b"b" * 64,
                        ledger_state_root=b"other", irmin_commit=b"other", txid_hi="2",
                        txlog_seg=1, txlog_off=13, epochlog_off=35, commit_id=b"other", ts=2.0,
                        quorum_cert_hash=b"qc", epoch_index_hash=b"other", epoch_index_root=b"other")
    currents = [("source", base["source"]), ("target", base["head"])]
    currents += [(field, base["source"] | {field: replacement}) for field, replacement in replacements.items()]
    currents += [("rewritten-both", base["source"] | {"irmin_commit": b"new", "commit_id": b"new"}),
                 ("signed-zero", base["source"] | {"ts": -0.0})]
    for label, current in currents:
        cases.append(dict(group="source-binding", label=label, op="source", plan=blob(raw_json(base)),
                          current=blob(raw_json(current))))

    def finish(label, **changes):
        value = dict(group="finish", label=label, op="finish", plan=blob(raw_json(plan())),
                     current=blob(raw_json(head())), entries=[entry()], fail=None, committed=True, dropped="3")
        value.update(changes); cases.append(value)
    finish("target")
    finish("target-no-committed-journal", committed=False)
    finish("idle", plan=None)
    finish("missing-head", current=None)
    finish("behind", current=blob(raw_json(head(0))))
    finish("missing-target-entry", entries=[])
    finish("wrong-target-root", entries=[entry(root=b"b" * 64)])
    finish("wrong-target-txid", entries=[entry(txid=2)])
    finish("wrong-target-head", current=blob(raw_json(head(state_root=b"b" * 64))))
    finish("advanced", current=blob(raw_json(head(4))), entries=[entry(), entry(4)])
    finish("advanced-missing-current", current=blob(raw_json(head(4))))
    finish("advanced-wrong-root", current=blob(raw_json(head(4))), entries=[entry(), entry(4, root=b"b" * 64)])
    finish("advanced-wrong-txid", current=blob(raw_json(head(4))), entries=[entry(), entry(4, txid=2)])
    for call in ["read_plan", "head", "finality:1", "journal_committed", "rewind:1", "drop_after:1", "clear"]:
        finish("fail-" + call, fail=call)
    for call in ["finality:4", "committed_for:4", "clear"]:
        finish("advanced-fail-" + call, current=blob(raw_json(head(4))), entries=[entry(), entry(4)], fail=call)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--builder-image", default=BUILDER)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.out.exists():
        raise SystemExit("require fresh output")
    if arguments.builder_image != BUILDER:
        raise SystemExit("require the recorded immutable full builder")
    module_path = ROOT / "scripts/node-port/native-oracle.py"
    spec = importlib.util.spec_from_file_location("fork_repair_native", module_path)
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    inputs = fixtures()
    report = native.run(arguments.upstream, arguments.builder_image,
                        ROOT / "scripts/node-port/fork-repair-oracle.ml", inputs,
                        "octra_core octra_node_runtime octra_consensus yojson base64")
    report["generator_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report["input_sha256"] = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":"),
                                                      ensure_ascii=False).encode()).hexdigest()
    report["vector_groups"] = dict(collections.Counter(value["group"] for value in inputs))
    report["scope"] = "Unchanged native plan/HEAD codecs, same_source and actual Fork_repair_boot callback order; trusted synthetic callback facts, no physical repair or signature qualification"
    report["adapters"] = {}
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print(f"PASS: {len(report['cases'])} native fork repair core vectors: {arguments.out}")


if __name__ == "__main__":
    main()
