#!/usr/bin/env python3
"""Run persistent local validators; commands never erase keys or chain state."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]

def command(pid):
    result = subprocess.run(["ps", "-ww", "-p", str(pid), "-o", "command="], capture_output=True, text=True)
    return result.stdout.strip()

def owned(record):
    actual = command(record["pid"])
    return actual == record["command"]

def status(config):
    try:
        with urllib.request.urlopen("http://" + config["rpc"] + "/operator/status", timeout=2) as response:
            return json.load(response)
    except (OSError, ValueError) as error:
        return {"error": str(error)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init", "start", "status", "stop"])
    parser.add_argument("--directory", type=Path, default=ROOT / "out/native-devnet")
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/octra-node")
    parser.add_argument("--base-port", type=int, default=19870)
    args = parser.parse_args()
    directory = args.directory.resolve()
    binary = args.binary.resolve()
    if args.action == "init":
        directory.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(binary), "init-devnet", "--directory", str(directory), "--base-port", str(args.base_port)], check=True)
        return
    configs = sorted(directory.glob("node-*/config.json"))
    if len(configs) != 4:
        raise SystemExit("Expected four initialized validator configurations")
    lock = (directory / "supervisor.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    records = directory / "processes.json"
    existing = json.loads(records.read_text()) if records.exists() else []
    if args.action == "start":
        if any(owned(record) for record in existing):
            raise SystemExit("Devnet processes are still running; use status or stop first")
        running = []
        try:
            for path in configs:
                argv = [str(binary), "run", "--config", str(path)]
                with (path.parent / "node.log").open("ab", buffering=0) as log:
                    process = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, close_fds=True)
                running.append({"pid": process.pid, "command": " ".join(argv), "config": str(path)})
                staged = records.with_suffix(".staged")
                staged.write_text(json.dumps(running, indent=2) + "\n")
                staged.replace(records)
            print("Started four validators. State and logs:", directory)
        except BaseException:
            for record in running:
                if owned(record):
                    os.kill(record["pid"], signal.SIGTERM)
            raise
    elif args.action == "stop":
        for record in existing:
            if owned(record):
                os.kill(record["pid"], signal.SIGTERM)
        deadline = time.monotonic() + 15
        while any(owned(record) for record in existing) and time.monotonic() < deadline:
            time.sleep(0.2)
        if any(owned(record) for record in existing):
            raise SystemExit("Some validators are still draining; state retained, no forced kill")
        print("Stopped validators; keys and chain state retained")
    else:
        for path in configs:
            config = json.loads(path.read_text())
            print(json.dumps({"node": path.parent.name, "rpc": config["rpc"], **status(config)}))

if __name__ == "__main__":
    main()
