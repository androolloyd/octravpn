#!/usr/bin/env python3
"""Exercise the real Circle commit path on an explicit private loopback chain."""
import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--chain-id", required=True)
    parser.add_argument("--octra", type=pathlib.Path, required=True)
    parser.add_argument("--devkeys", type=pathlib.Path)
    parser.add_argument("--package", type=pathlib.Path, required=True)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--check-reopen", type=pathlib.Path)
    args = parser.parse_args()
    url = urllib.parse.urlparse(args.rpc)
    if url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("private fixture tests require loopback HTTP")
    if not args.chain_id.startswith("octra-local-") or args.evidence.exists():
        raise SystemExit("use an explicit private chain and fresh evidence path")
    manifest = json.loads((args.package / "manifest.json").read_text())
    digest = hashlib.sha256((args.package / "vpn-registry.wasm").read_bytes()).hexdigest()
    if digest != manifest["wasm_sha256"]:
        raise SystemExit("package WASM hash mismatch")

    def rpc(method, params):
        request = urllib.request.Request(args.rpc,
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.load(response)
        if value.get("id") != 1 or "error" in value or "result" not in value:
            raise RuntimeError(f"{method}: {value}")
        return value["result"]

    profile = rpc("octra_runtimeVersion", [])
    if profile.get("chain_id") != args.chain_id:
        raise SystemExit("refusing mismatched chain identity")

    def command(*parts):
        return json.loads(subprocess.check_output([str(args.octra), *map(str, parts)], text=True))

    def operator(circle, address):
        value = command("cast", "circle", "call", circle, "operator", address, "--rpc-url", args.rpc)
        return json.loads(value["result"])

    def circle_info(circle, owner):
        info = rpc("circle_info", [circle])
        assert info["owner"] == owner, info
        assert info["code_hash"] == digest, info
        return info

    records = []

    def receipt(tx_hash, success):
        deadline = time.monotonic() + 90
        while True:
            try:
                result = rpc("contract_receipt", [tx_hash])
                break
            except RuntimeError as error:
                if "receipt not found" not in str(error) or time.monotonic() >= deadline:
                    raise
            time.sleep(0.5)
        assert result["success"] is success, result
        records.append({"tx_hash": tx_hash, **result})
        return result

    if args.check_reopen:
        earlier = json.loads(args.check_reopen.read_text())
        assert earlier["passed"] and earlier["chain_id"] == args.chain_id
        assert earlier["wasm_sha256"] == digest
        circle_info(earlier["circle"], earlier["operator"])
        assert operator(earlier["circle"], earlier["operator"]) == earlier["final_record"]
        report = {**earlier, "runtime_after_reopen": profile, "reopen_qualified": True}
    else:
        if not args.devkeys:
            raise SystemExit("--devkeys is required for fixture execution")
        with tempfile.TemporaryDirectory(prefix="octra-circle-registry-node-") as temp:
            key = pathlib.Path(temp) / "public-devkey-0.key"
            fixture = json.loads(subprocess.check_output([str(args.devkeys), "wallet-json", "0"]))
            key.write_text(base64.b64decode(fixture["priv"]).hex())
            key.chmod(0o600)
            address = fixture["address"]
            deployed = command("cast", "circle", "deploy", "--key", key, "--rpc-url", args.rpc,
                "--payload", args.package / "deploy-payload.json")
            circle = deployed["circle_id"]
            print(json.dumps({"deployment": deployed}), flush=True)
            deadline = time.monotonic() + 90
            # deploy_circle has canonical transaction metadata, not an AML receipt.
            while rpc("octra_transaction", [deployed["submit"]["tx_hash"]]).get("status") != "confirmed":
                if time.monotonic() >= deadline:
                    raise RuntimeError("Circle deployment failed to confirm")
                time.sleep(0.5)
            circle_info(circle, address)
            offer = {"settlement_circle": circle, "control_url": "https://vpn.example/control",
                "wireguard_endpoint": "203.0.113.7:51820", "wireguard_key_hex": "11" * 32,
                "receipt_key_hex": "22" * 32, "region": "CA", "exit": True,
                "relay": False, "price_ou_per_mib": 100}

            def send(method, value, success=True):
                # Publish takes a JSON string; the native wire ABI receives primitives.
                submitted = command("cast", "circle", "send", circle, method,
                    json.dumps(value, separators=(",", ":")), "--key", key, "--rpc-url", args.rpc)
                result = receipt(submitted["tx_hash"], success)
                print(f"PASS {method} success={success}", flush=True)
                return result

            def publish(revision, success=True):
                return send("publish", json.dumps({"expected_revision": revision, "offer": offer},
                    separators=(",", ":")), success)

            first = publish(0)
            record = operator(circle, address)
            assert record["revision"] == 1 and not record["retired"]
            assert record["updated_epoch"] == first["epoch"]
            events = [event for event in first["events"] if event["event"] == "octra.vpn.operator.v1"]
            assert len(events) == 1 and events[0]["contract"] == circle, first
            assert json.loads(events[0]["values"][0]) == record, events
            publish(0, False)
            assert operator(circle, address) == record
            send("retire", 0, False)
            assert operator(circle, address) == record
            send("retire", 1)
            assert operator(circle, address)["retired"] is True
            publish(2)
            final_record = operator(circle, address)
            assert final_record["revision"] == 3 and not final_record["retired"]
            try:
                rpc("circle_view", [circle, "retire", [3]])
            except RuntimeError:
                pass
            else:
                raise AssertionError("view RPC accepted a mutation")
            assert operator(circle, address) == final_record
            report = {"passed": True, "scope": "native Circle deploy, execution, events and rollback on private Single chain",
                "chain_id": args.chain_id, "runtime": profile, "upstream_commit": manifest["upstream_commit"],
                "wasm_sha256": digest, "circle": circle, "operator": address,
                "deployment": deployed, "final_record": final_record, "receipts": records, "reopen_qualified": False,
                "public_network_qualified": False, "live_exex_commit_hook": False}
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: native registry; evidence={args.evidence}")


if __name__ == "__main__":
    main()
