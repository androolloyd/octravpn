#!/usr/bin/env python3
"""Manage only Octra's WireGuard interface and tagged rules on the HLX relay.

The existing `inet hlx_relay` table has default-drop input/forward chains, so a
new nftables table cannot admit Octra traffic. This tool adds exact tagged rules
to those chains; it never flushes or replaces the HLX ruleset.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


INTERFACE = "octra-wg"
TAG = "octra-devnet-relay-v1"
RELAY_CIDR = "10.203.1.1/30"
NODE_IP = "10.203.1.2"
WG_PORT = "51821"
P2P_PORT = "20800"
CHAINS = ("input", "forward", "prerouting", "postrouting")


def run(*args, input=None):
    return subprocess.run(args, input=input, text=True, capture_output=True,
                          check=True).stdout.strip()


def public_key(value):
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError("WireGuard public key must decode to 32 bytes")
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("Invalid WireGuard public key") from error
    return value


def read_config(path):
    config = json.loads(path.read_text())
    if set(config) != {"wan", "public_ipv4", "node_public_key",
                       "relay_private_key_file", "hlx_ruleset_sha256", "backup_path"}:
        raise ValueError("Unexpected relay configuration fields")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", config["wan"]):
        raise ValueError("Invalid WAN interface")
    address = ipaddress.IPv4Address(config["public_ipv4"])
    if not address.is_global:
        raise ValueError("Relay address must be a global IPv4 address")
    public_key(config["node_public_key"])
    key = Path(config["relay_private_key_file"])
    if not key.is_absolute():
        raise ValueError("Relay private key path must be absolute")
    config["relay_private_key_file"] = key
    if not re.fullmatch(r"[0-9a-f]{64}", config["hlx_ruleset_sha256"]):
        raise ValueError("Missing reviewed HLX ruleset SHA-256")
    backup = Path(config["backup_path"])
    if not backup.is_absolute():
        raise ValueError("Backup path must be absolute")
    config["backup_path"] = backup
    return config


def ruleset():
    return json.loads(run("nft", "-j", "-a", "list", "table", "inet", "hlx_relay"))


def fingerprint(value=None, exclude_octra=False):
    value = value or ruleset()

    def normalize(item):
        if isinstance(item, list):
            return [normalize(part) for part in item]
        if isinstance(item, dict):
            return {key: normalize(part) for key, part in item.items()
                    if key not in ("handle", "index", "packets", "bytes")}
        return item

    entries = [item for item in value["nftables"] if "metainfo" not in item]
    if exclude_octra:
        entries = [item for item in entries
                   if item.get("rule", {}).get("comment") != TAG]
    encoded = json.dumps(normalize(entries), sort_keys=True,
                         separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def tagged_rules(chain):
    rules = json.loads(run("nft", "-j", "-a", "list", "chain", "inet", "hlx_relay", chain))
    found = []
    for item in rules["nftables"]:
        rule = item.get("rule")
        if rule and rule.get("comment") == TAG:
            found.append(rule["handle"])
    return found


def remove_rules():
    statements = []
    for chain in reversed(CHAINS):
        for handle in reversed(tagged_rules(chain)):
            statements.append(f"delete rule inet hlx_relay {chain} handle {handle}")
    if statements:
        run("nft", "-f", "-", input="\n".join(statements) + "\n")


def interface_exists():
    return subprocess.run(["ip", "link", "show", "dev", INTERFACE],
                          capture_output=True, check=False).returncode == 0


def owned_interface():
    if not interface_exists():
        return False
    addresses = json.loads(run("ip", "-j", "address", "show", "dev", INTERFACE))
    assigned = {f'{item["local"]}/{item["prefixlen"]}'
                for link in addresses for item in link.get("addr_info", [])}
    return RELAY_CIDR in assigned and run("wg", "show", INTERFACE, "listen-port") == WG_PORT


def rules(config):
    wan = config["wan"]
    public_ip = config["public_ipv4"]
    return (
        ("input", ("iifname", wan, "udp", "dport", WG_PORT, "accept")),
        ("forward", ("iifname", INTERFACE, "ip", "saddr", "!=", NODE_IP, "drop")),
        ("forward", ("iifname", INTERFACE, "ip", "daddr", "@non_public_v4", "drop")),
        ("forward", ("iifname", INTERFACE, "oifname", wan, "ip", "saddr", NODE_IP, "accept")),
        ("forward", ("iifname", wan, "oifname", INTERFACE, "ip", "daddr", NODE_IP,
                     "ct", "state", "established,related", "accept")),
        ("forward", ("iifname", wan, "oifname", INTERFACE, "ip", "daddr", NODE_IP,
                     "ct", "status", "dnat", "tcp", "dport", P2P_PORT, "accept")),
        ("prerouting", ("iifname", wan, "ip", "daddr", public_ip, "tcp", "dport",
                        P2P_PORT, "dnat", "ip", "to", NODE_IP)),
        ("postrouting", ("oifname", wan, "ip", "saddr", NODE_IP, "snat", "ip", "to", public_ip)),
    )


def install_rules(config):
    statements = ["add rule inet hlx_relay " + chain + " " + " ".join(expression)
                  + f' comment "{TAG}"' for chain, expression in rules(config)]
    batch = "\n".join(statements) + "\n"
    run("nft", "-c", "-f", "-", input=batch)
    run("nft", "-f", "-", input=batch)


def save_backup(config, value):
    path = config["backup_path"]
    if path.exists() or path.is_symlink():
        raise ValueError("Backup path already exists; refusing to overwrite")
    if not path.parent.is_dir():
        raise ValueError("Backup parent directory does not exist")
    parent = path.parent.stat()
    if parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError("Backup parent must be root-owned and not writable by others")
    document = {"hlx_ruleset_sha256": fingerprint(value), "nftables": value}
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent,
                                     prefix=".octra-relay-", delete=False) as staged:
        try:
            os.fchmod(staged.fileno(), 0o600)
            json.dump(document, staged, sort_keys=True)
            staged.write("\n")
            staged.flush()
            os.fsync(staged.fileno())
            os.link(staged.name, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.unlink(staged.name)


def preflight(config):
    if os.geteuid() != 0:
        raise ValueError("Run on the dedicated relay as root")
    if interface_exists() or any(tagged_rules(chain) for chain in CHAINS):
        raise ValueError("Octra relay already exists or requires cleanup")
    if run("sysctl", "-n", "net.ipv4.ip_forward") != "1":
        raise ValueError("Existing relay IPv4 forwarding is disabled")
    addresses = json.loads(run("ip", "-j", "address", "show", "dev", config["wan"]))
    assigned = {item["local"] for link in addresses for item in link.get("addr_info", [])}
    if config["public_ipv4"] not in assigned:
        raise ValueError("Public IPv4 is not assigned to the configured WAN interface")
    for protocol, port in (("-lun", WG_PORT), ("-ltn", P2P_PORT)):
        if any(re.search(rf":{port}(?:\s|$)", line)
               for line in run("ss", "-H", protocol).splitlines()):
            raise ValueError(f"Relay port {port} is already in use")
    key = config["relay_private_key_file"]
    details = key.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o077:
        raise ValueError("Relay private key must be root-only")
    # Require the existing HLX firewall's non-public destination guard.
    run("nft", "list", "set", "inet", "hlx_relay", "non_public_v4")
    if fingerprint() != config["hlx_ruleset_sha256"]:
        raise ValueError("HLX ruleset differs from the reviewed fingerprint")
    if config["backup_path"].exists() or config["backup_path"].is_symlink():
        raise ValueError("Backup path already exists; refusing to overwrite")


def up(config):
    preflight(config)
    baseline = ruleset()
    if fingerprint(baseline) != config["hlx_ruleset_sha256"]:
        raise ValueError("HLX ruleset changed before backup")
    save_backup(config, baseline)
    created = False
    try:
        run("ip", "link", "add", INTERFACE, "type", "wireguard")
        created = True
        run("wg", "set", INTERFACE, "listen-port", WG_PORT, "private-key",
            str(config["relay_private_key_file"]), "peer", config["node_public_key"],
            "allowed-ips", f"{NODE_IP}/32")
        run("ip", "address", "add", RELAY_CIDR, "dev", INTERFACE)
        run("ip", "link", "set", INTERFACE, "mtu", "1380", "up")
        if fingerprint() != config["hlx_ruleset_sha256"]:
            raise ValueError("HLX ruleset changed before Octra activation")
        install_rules(config)
        if sum(len(tagged_rules(chain)) for chain in CHAINS) != len(rules(config)):
            raise ValueError("Octra relay installed an unexpected rule count")
        if fingerprint(exclude_octra=True) != config["hlx_ruleset_sha256"]:
            raise ValueError("HLX ruleset changed during Octra activation")
    except Exception:
        if created:
            remove_rules()
            run("ip", "link", "delete", INTERFACE)
        raise


def down():
    if os.geteuid() != 0:
        raise ValueError("Run on the dedicated relay as root")
    if interface_exists() and not owned_interface():
        raise ValueError("Refusing to delete a foreign interface with Octra's name")
    remove_rules()
    if interface_exists():
        run("ip", "link", "delete", INTERFACE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("fingerprint", "preflight", "up", "down", "status"))
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    if args.operation in ("preflight", "up") and args.config is None:
        parser.error("--config is required for preflight and up")
    config = read_config(args.config) if args.config else None
    if args.operation == "preflight":
        preflight(config)
    elif args.operation == "up":
        up(config)
    elif args.operation == "down":
        down()
    elif args.operation == "fingerprint":
        print(fingerprint())
    else:
        print(json.dumps({"interface": interface_exists(), "owned_interface": owned_interface(),
                          "tagged_rules": {chain: len(tagged_rules(chain)) for chain in CHAINS}}))


if __name__ == "__main__":
    main()
