#!/usr/bin/env python3
"""Offline veth/WireGuard lab; run only in disposable `--network none` Linux."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile

import relay


NODE = "octra-test-node"
RELAY = "octra-test-relay"
PEER = "octra-test-peer"
PROCESSES = []
CHECKS = []


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)
    return result.stdout.strip()


def ns(name, *args, **kwargs):
    return run("ip", "netns", "exec", name, *args, **kwargs)


def check(label, passed):
    CHECKS.append({"test": label, "passed": bool(passed)})
    if not passed:
        raise AssertionError(label)


def server(namespace, port):
    code = ("import socket\n"
            "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
            f"s.bind(('0.0.0.0',{port}));s.listen();print('ready',flush=True)\n"
            "while True:\n c,a=s.accept();c.sendall(a[0].encode());c.close()\n")
    process = subprocess.Popen(["ip", "netns", "exec", namespace, "setpriv",
                                "--reuid=10001", "--regid=10001", "--clear-groups",
                                "--bounding-set=-all", "--no-new-privs", "python3", "-u",
                                "-c", code], stdout=subprocess.PIPE, text=True)
    PROCESSES.append(process)
    check(f"TCP {port} listener started", process.stdout.readline().strip() == "ready")


def connect(namespace, address, port):
    code = ("import socket\n"
            f"s=socket.create_connection(('{address}',{port}),2);"
            "print(s.recv(100).decode())")
    return ns(namespace, "setpriv", "--reuid=10001", "--regid=10001",
              "--clear-groups", "--bounding-set=-all", "--no-new-privs",
              "python3", "-c", code)


def base_firewall():
    return """table inet hlx_relay {
      set non_public_v4 {
        type ipv4_addr; flags interval;
        elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10,
                     127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
                     192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4,
                     240.0.0.0/4 }
      }
      chain input {
        type filter hook input priority filter; policy drop;
        ct state invalid drop
        iifname "lo" accept
        ct state established,related accept
        meta nfproto ipv6 drop
        iifname "wan0" tcp dport 4001 accept
      }
      chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid drop
        meta nfproto ipv6 drop
      }
      chain prerouting { type nat hook prerouting priority dstnat; }
      chain postrouting { type nat hook postrouting priority srcnat; }
    }
    """


def main():
    check("disposable outer container has no Internet interface",
          {item["ifname"] for item in json.loads(run("ip", "-j", "link"))} == {"lo"})
    run("ip", "link", "set", "lo", "up")
    for name in (NODE, RELAY, PEER):
        run("ip", "netns", "add", name)
        run("ip", "-n", name, "link", "set", "lo", "up")
    run("ip", "link", "add", "wan0", "type", "veth", "peer", "name", "peer0")
    run("ip", "link", "set", "wan0", "netns", RELAY)
    run("ip", "link", "set", "peer0", "netns", PEER)
    for name, interface, address in ((RELAY, "wan0", "192.0.2.1/24"),
                                     (PEER, "peer0", "192.0.2.2/24")):
        run("ip", "-n", name, "address", "add", address, "dev", interface)
        run("ip", "-n", name, "link", "set", interface, "up")
    with tempfile.TemporaryDirectory() as temporary:
        keys = {}
        for name in (NODE, RELAY):
            key = Path(temporary) / name
            key.write_text(run("wg", "genkey"))
            key.chmod(0o600)
            keys[name] = (key, run("wg", "pubkey", input=key.read_text()))
        for name, interface, address, port, peer_port, other, allowed in (
            (NODE, "node-temp", "10.203.1.2/30", "51822", "51821", RELAY, "0.0.0.0/0"),
            (RELAY, "relay-temp", "10.203.1.1/30", "51821", "51822", NODE,
             "10.203.1.2/32")):
            run("ip", "link", "add", interface, "type", "wireguard")
            run("ip", "link", "set", interface, "netns", name)
            run("ip", "-n", name, "link", "set", interface, "name", "octra-wg")
            ns(name, "wg", "set", "octra-wg", "listen-port", port,
               "private-key", str(keys[name][0]), "peer", keys[other][1],
               "allowed-ips", allowed, "endpoint", f"127.0.0.1:{peer_port}")
            run("ip", "-n", name, "address", "add", address, "dev", "octra-wg")
            run("ip", "-n", name, "link", "set", "octra-wg", "up")
        run("ip", "-n", NODE, "route", "add", "default", "dev", "octra-wg")
        ns(RELAY, "unshare", "--mount", "sh", "-c",
           "mount -t proc proc /proc; sysctl -qw net.ipv4.ip_forward=1")
        ns(RELAY, "nft", "-f", "-", input=base_firewall())
        server(RELAY, 4001)
        server(NODE, 20800)
        server(PEER, 20801)
        check("HLX-owned TCP 4001 works before Octra additions",
              connect(PEER, "192.0.2.1", 4001) == "192.0.2.2")
        config = {"wan": "wan0", "public_ipv4": "192.0.2.1"}
        relay.run = lambda *args, input=None: ns(RELAY, *args, input=input)
        baseline = relay.fingerprint()
        relay.install_rules(config)
        tagged_count = sum(len(relay.tagged_rules(chain)) for chain in relay.CHAINS)
        check("all eight Octra rules are tagged", tagged_count == 8)
        check("HLX baseline is byte-equivalent after Octra additions",
              relay.fingerprint(exclude_octra=True) == baseline)
        check("public P2P DNAT preserves peer source",
              connect(PEER, "192.0.2.1", 20800) == "192.0.2.2")
        check("node egress is SNATed to relay public IP",
              connect(NODE, "192.0.2.2", 20801) == "192.0.2.1")
        check("HLX-owned TCP 4001 still works",
              connect(PEER, "192.0.2.1", 4001) == "192.0.2.2")
        run("ip", "-n", NODE, "link", "set", "octra-wg", "down")
        try:
            connect(NODE, "192.0.2.2", 20801)
        except subprocess.CalledProcessError:
            check("tunnel loss has no egress fallback", True)
        else:
            check("tunnel loss has no egress fallback", False)
        relay.remove_rules()
        check("rollback removes only Octra tagged rules",
              all(not relay.tagged_rules(chain) for chain in relay.CHAINS))
        check("HLX baseline is byte-equivalent after rollback",
              relay.fingerprint() == baseline)
        check("rollback preserves HLX-owned TCP 4001",
              connect(PEER, "192.0.2.1", 4001) == "192.0.2.2")
    print(json.dumps({"scope": "offline synthetic network only", "checks": CHECKS}, indent=2))


if __name__ == "__main__":
    if sys.platform != "linux" or not Path("/.dockerenv").exists():
        raise SystemExit("run this lab only inside a disposable Linux container with --network none")
    try:
        main()
    finally:
        for process in PROCESSES:
            try:
                process.terminate()
                process.wait(timeout=5)
            except PermissionError:
                pass  # Disposable container exit reaps its namespaces and listeners.
        for name in (NODE, RELAY, PEER):
            subprocess.run(["ip", "netns", "delete", name], capture_output=True)
