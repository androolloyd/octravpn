#!/usr/bin/env python3
"""Make an isolated Linux-container Octra config from a retained observer config."""

import argparse
import ipaddress
import json
import os
from pathlib import Path


def prepare(source, relay_ip, data, key, environment):
    value = json.loads(source.read_text())
    if value.get("voting") is not False or value.get("publisher") is not False:
        raise ValueError("Only a nonvoting, nonpublishing observer may use this relay")
    if not ipaddress.IPv4Address(relay_ip).is_global:
        raise ValueError("Relay must have a public IPv4 address")
    for path in (data, key, environment):
        if not path.is_absolute():
            raise ValueError("Container paths must be absolute")
    value["data"] = str(data)
    value["key"] = str(key)
    value["environment"] = str(environment)
    value["p2p"] = "10.203.1.2:20800"
    value["advertised"] = f"{relay_ip}:20800"
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-config", required=True, type=Path)
    parser.add_argument("--relay-ip", required=True)
    parser.add_argument("--container-data", required=True, type=Path)
    parser.add_argument("--container-key", required=True, type=Path)
    parser.add_argument("--container-environment", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    value = prepare(args.source_config, args.relay_ip, args.container_data,
                    args.container_key, args.container_environment)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, indent=2)
        out.write("\n")


if __name__ == "__main__":
    main()
