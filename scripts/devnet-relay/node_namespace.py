#!/usr/bin/env python3
"""Create an isolated Linux network namespace before probing/running Octra.

Run only inside a dedicated container with one outer Docker interface. The
WireGuard UDP socket stays outside the namespace; the node sees only lo and WG.
"""

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import time


NAMESPACE = "octra-devnet"
INTERFACE = "octra-wg"
NODE_CIDR = "10.203.1.2/30"
RELAY_PORT = 51821


def run(*args, input=None):
    return subprocess.run(args, input=input, text=True, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("probe", "node"))
    parser.add_argument("--config", type=Path, default=Path("/config/relay.json"))
    parser.add_argument("--uid", type=int, default=10001)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid <= 0:
        parser.error("Owned container root and a non-root node UID are required")
    config = json.loads(args.config.read_text())
    if set(config) != {"public_ipv4", "relay_public_key", "node_private_key_file"}:
        parser.error("Unexpected node relay configuration fields")
    endpoint = ipaddress.IPv4Address(config["public_ipv4"])
    if not endpoint.is_global:
        parser.error("Relay address must be a global IPv4 address")
    try:
        if len(base64.b64decode(config["relay_public_key"], validate=True)) != 32:
            parser.error("Invalid relay public key")
    except (ValueError, base64.binascii.Error):
        parser.error("Invalid relay public key")
    key = Path(config["node_private_key_file"])
    details = key.stat()
    if (not key.is_absolute() or not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0 or details.st_mode & 0o077):
        parser.error("Node WireGuard private key must be a root-only absolute file")
    links = {item["ifname"] for item in json.loads(
        subprocess.check_output(["ip", "-j", "link"]))}
    if links != {"lo", "eth0"}:
        parser.error("Outer container must have only loopback and its Docker transport")
    if Path("/var/run/netns", NAMESPACE).exists():
        parser.error("Refusing to reuse a network namespace")

    run("ip", "netns", "add", NAMESPACE)
    dns = Path("/etc/netns") / NAMESPACE
    dns.mkdir(parents=True, exist_ok=False)
    (dns / "resolv.conf").write_text("nameserver 1.1.1.1\nnameserver 9.9.9.9\n")
    run("ip", "link", "add", INTERFACE, "type", "wireguard")
    run("ip", "link", "set", INTERFACE, "netns", NAMESPACE)
    run("ip", "netns", "exec", NAMESPACE, "wg", "set", INTERFACE,
        "private-key", str(key), "peer", config["relay_public_key"],
        "allowed-ips", "0.0.0.0/0", "endpoint", f"{endpoint}:{RELAY_PORT}",
        "persistent-keepalive", "25")
    run("ip", "-n", NAMESPACE, "address", "add", NODE_CIDR, "dev", INTERFACE)
    run("ip", "-n", NAMESPACE, "link", "set", "lo", "up")
    run("ip", "-n", NAMESPACE, "link", "set", INTERFACE, "mtu", "1380", "up")
    run("ip", "-n", NAMESPACE, "route", "add", "default", "dev", INTERFACE)
    run("ip", "netns", "exec", NAMESPACE, "nft", "-f", "-", input=(
        "table inet octra_ipv6_guard { chain output { type filter hook output "
        "priority 0; policy accept; meta nfproto ipv6 reject; }; }\n"))
    inner_links = {item["ifname"] for item in json.loads(
        subprocess.check_output(["ip", "-n", NAMESPACE, "-j", "link"]))}
    if inner_links != {"lo", INTERFACE}:
        parser.error("Unexpected inner network interface")
    routes = json.loads(subprocess.check_output(["ip", "-n", NAMESPACE, "-j", "route", "show", "default"]))
    if len(routes) != 1 or routes[0].get("dev") != INTERFACE or "gateway" in routes[0]:
        parser.error("Unexpected inner default route")
    # Prove the namespace has no route outside WireGuard, then trigger a
    # handshake against our own relay. An external IP-echo service would leak
    # the operator's address and is unnecessary for this isolation check.
    route = json.loads(subprocess.check_output([
        "ip", "-n", NAMESPACE, "-j", "route", "get", "1.1.1.1"
    ]))
    if len(route) != 1 or route[0].get("dev") != INTERFACE:
        parser.error("Node public egress route does not use WireGuard")
    subprocess.run([
        "ip", "netns", "exec", NAMESPACE, "setpriv", f"--reuid={args.uid}",
        f"--regid={args.uid}", "--clear-groups", "--bounding-set=-all",
        "--no-new-privs", "python3", "-c",
        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
        "s.sendto(b'probe',('10.203.1.1',51821))",
    ], check=True)
    deadline = time.monotonic() + 15
    while True:
        handshakes = subprocess.check_output([
            "ip", "netns", "exec", NAMESPACE,
            "wg", "show", INTERFACE, "latest-handshakes",
        ], text=True).splitlines()
        if any(line.startswith(config["relay_public_key"] + "\t")
               and int(line.rsplit("\t", 1)[1]) > 0 for line in handshakes):
            break
        if time.monotonic() >= deadline:
            parser.error("Authenticated relay WireGuard handshake unavailable")
        time.sleep(0.2)
    command = (["python3", "-c", "import json,socket; print(json.dumps({\"interfaces\": "
                "[name for _, name in socket.if_nameindex()]}))"] if args.operation == "probe" else
               ["/usr/local/bin/octra-node", "run-network", "--config", "/config/network.json"])
    argv = ["ip", "netns", "exec", NAMESPACE, "setpriv",
            f"--reuid={args.uid}", f"--regid={args.uid}", "--clear-groups",
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
            "--no-new-privs", "env", "-i", "HOME=/node",
            "PATH=/usr/local/bin:/usr/bin:/bin", *command]
    os.execvp(argv[0], argv)


if __name__ == "__main__":
    main()
