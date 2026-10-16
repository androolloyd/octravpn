#!/usr/bin/env python3
"""Signed mock transactions with real admission and staged receipt polling."""

import json
import os
import subprocess
import time
import urllib.request

RPC = os.environ.get("OCTRAVPN_E2E_RPC", "http://127.0.0.1:18080/rpc")
PROGRAM = "octAiTHXCqX84s2ExQFzZBFsxKwsijVmsmfmZ84LrurdPLB"
OWNER = "oct89dkqqjMw9HTi1pqHbANSNwioHuMhmpTCXapTmfUr1EW"
CLIENT = "octGatHn158giyza6HjzdcMBwE6bm5SY322D3AmFnrpabbT"
EXIT = "oct4XmjKEd9A96KhoMX94zWJmd28dcPisbWGYWtad1dQ9v5"
KEYS = {OWNER: "node2", CLIENT: "client", EXIT: "node1"}


def rpc(method, params=()):
    request = urllib.request.Request(
        RPC,
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        {"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(f"{method}: {result['error']}")
    return result["result"]


def wait_for(predicate, label):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise RuntimeError(f"timeout waiting for {label}")


def view(method, *args):
    return rpc("contract_call", [PROGRAM, method, args])["result"]


def send(sender, method, *args, value=0):
    command = [
        "docker", "compose", "exec", "-T", "mock-rpc", "octra", "cast", "send",
        PROGRAM, method, *[json.dumps(arg) for arg in args],
        "--key", f"/fixtures/{KEYS[sender]}/wallet.key", "--fee", "1000",
        "--value", str(value), "--rpc-url", "http://127.0.0.1:18080/rpc",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    accepted = json.loads(result.stdout)
    assert accepted["status"] == "accepted", accepted
    tx_hash = accepted["tx_hash"]

    def confirmed():
        tx = rpc("octra_transaction", [tx_hash])
        assert tx["status"] in ("pending", "confirmed"), tx
        return tx if tx["status"] == "confirmed" else None

    tx = wait_for(confirmed, f"{method} confirmation")
    receipt = rpc("contract_receipt", [tx_hash])
    assert receipt["success"] is True, receipt
    assert receipt["program"] == PROGRAM and receipt["method"] == method, receipt
    assert receipt["epoch"] == tx["epoch"], (receipt, tx)
    print(f"[tailnet-e2e] confirmed {method} at epoch {tx['epoch']}", flush=True)
    return receipt


def event(receipt, name, fields):
    # This mock serializes named event fields in sorted order. Native AML
    # execution and native event ordering are qualified by the paid suite.
    matches = [row for row in receipt["events"] if row["event"] == name]
    assert len(matches) == 1, receipt
    row = matches[0]
    assert row["program"] == PROGRAM and row["contract"] == PROGRAM, row
    assert len(row["values"]) == len(fields), row
    return dict(zip(sorted(fields), row["values"]))


def main():
    def ready():
        try:
            return rpc("node_status")
        except OSError:
            return None

    wait_for(ready, "mock RPC")
    for address in KEYS:
        assert rpc("octra_balance", [address])["balance_raw"] == "1000000"
    rpc("octra_test_grantValidator", [EXIT])
    rpc("octra_test_bondEndpoint", [EXIT])
    subprocess.run(["docker", "compose", "up", "-d", "node1"], check=True)
    wait_for(lambda: view("get_endpoint", EXIT).get("active") == 1, "exit registration")

    receipt = send(OWNER, "create_tailnet", "ab" + "00" * 31, value=5000)
    tailnet = event(receipt, "TailnetCreated", ["tailnet_id", "owner"])
    assert tailnet["owner"] == OWNER, tailnet
    tid = tailnet["tailnet_id"]
    send(OWNER, "add_member", tid, CLIENT)
    send(OWNER, "configure_tailnet_exit", tid, EXIT)
    receipt = send(CLIENT, "open_session", tid, EXIT, 1000)
    opened = event(receipt, "SessionOpened", ["session_id", "tailnet_id", "exit", "deposit", "opened_at"])
    assert opened["tailnet_id"] == tid and opened["exit"] == EXIT and opened["deposit"] == 1000
    sid = opened["session_id"]
    send(EXIT, "settle_claim", sid, 2)
    receipt = send(CLIENT, "settle_confirm", sid, 2)
    settled = event(receipt, "SessionSettled", ["session_id", "exit", "bytes_used", "total_paid", "refund"])
    assert settled == {"session_id": sid, "exit": EXIT, "bytes_used": 2, "total_paid": 200, "refund": 800}, settled
    assert view("get_tailnet", tid)["treasury"] == 4800
    assert view("get_program_treasury") == 0
    assert view("get_encrypted_earnings", EXIT) == "hfhe_v1|mock|00000000000000c8"
    print("[tailnet-e2e] ALL OK: signed calls, confirmed receipts, paid 200/refund 800, zero commission")


if __name__ == "__main__":
    main()
