#!/usr/bin/env python3
"""Bridge the approved Octra P2P port to an SSH reverse forward on loopback.

The firewall transition checks the original HLX fingerprint and replaces only
Octra's exact WireGuard P2P forwarding rules. Other tunnel rules are retained.
"""
import argparse
import asyncio
import os
from pathlib import Path
import signal

import relay


def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def ingress_expressions(config):
    wan = match({"meta": {"key": "iifname"}}, config["wan"])
    port = match({"payload": {"protocol": "tcp", "field": "dport"}}, 20800)
    return {
        "prerouting": [wan,
            match({"payload": {"protocol": "ip", "field": "daddr"}}, config["public_ipv4"]),
            port, {"dnat": {"family": "ip", "addr": relay.NODE_IP}}],
        "forward": [wan, match({"meta": {"key": "oifname"}}, relay.INTERFACE),
            match({"payload": {"protocol": "ip", "field": "daddr"}}, relay.NODE_IP),
            match({"ct": {"key": "status"}}, "dnat", "in"), port, {"accept": None}],
        "input": [wan, port, {"accept": None}],
    }


def transition(value, config):
    if relay.fingerprint(value, exclude_octra=True) != config["hlx_ruleset_sha256"]:
        raise ValueError("HLX ruleset differs from the reviewed fingerprint")
    expected = ingress_expressions(config)
    owned = [item["rule"] for item in value["nftables"]
             if item.get("rule", {}).get("comment") == relay.TAG]
    found = {}
    for chain, expression in expected.items():
        rows = [row for row in owned if row["chain"] == chain and row["expr"] == expression]
        if len(rows) > 1:
            raise ValueError("Duplicate Octra ingress rule")
        if rows:
            found[chain] = rows[0]
    if set(found) == {"input"} and len(owned) == 7:
        return ""
    if set(found) != {"prerouting", "forward"} or len(owned) != 8:
        raise ValueError("Octra ingress is not the expected WireGuard or SSH configuration")
    statements = [f'delete rule inet hlx_relay {chain} handle {found[chain]["handle"]}'
                  for chain in ("prerouting", "forward")]
    statements.append(f'add rule inet hlx_relay input iifname {config["wan"]} '
                      f'tcp dport 20800 accept comment "{relay.TAG}"')
    return "\n".join(statements) + "\n"


def activate(config):
    if os.geteuid() != 0:
        raise ValueError("Firewall activation requires root on the owned relay")
    before = relay.ruleset()
    batch = transition(before, config)
    if not batch:
        return
    backup = config["backup_path"].with_name("ssh-ingress-before.json")
    # Reuse the root-only, exclusive and durable backup writer.
    relay.save_backup({**config, "backup_path": backup}, before)
    relay.run("nft", "-c", "-f", "-", input=batch)
    relay.run("nft", "-f", "-", input=batch)
    if transition(relay.ruleset(), config):
        raise ValueError("SSH ingress did not activate")


class Bridge:
    def __init__(self, target_port=20880, capacity=128, timeout=120):
        self.target_port = target_port
        self.capacity = capacity
        self.timeout = timeout
        self.clients = set()

    async def pipe(self, reader, writer):
        while True:
            data = await asyncio.wait_for(reader.read(65536), self.timeout)
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
                return
            writer.write(data)
            await asyncio.wait_for(writer.drain(), self.timeout)

    async def connect(self, reader, writer):
        task = asyncio.current_task()
        upstream = None
        pumps = []
        if len(self.clients) >= self.capacity:
            writer.close()
            await writer.wait_closed()
            return
        self.clients.add(task)
        try:
            incoming, upstream = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.target_port), 5)
            pumps = [asyncio.create_task(self.pipe(reader, upstream)),
                     asyncio.create_task(self.pipe(incoming, writer))]
            await asyncio.gather(*pumps)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for pump in pumps:
                pump.cancel()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            for stream in (upstream, writer):
                if stream is not None:
                    stream.close()
                    try:
                        await stream.wait_closed()
                    except OSError:
                        pass
            self.clients.discard(task)

    async def close(self):
        tasks = list(self.clients)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def serve():
    bridge = Bridge()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    server = await asyncio.start_server(bridge.connect, "0.0.0.0", 20800)
    async with server:
        await stop.wait()
    await bridge.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("plan", "activate", "serve"))
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    if args.operation == "serve":
        asyncio.run(serve())
    else:
        if args.config is None:
            parser.error("--config is required")
        config = relay.read_config(args.config)
        if args.operation == "plan":
            print(transition(relay.ruleset(), config), end="")
        else:
            activate(config)
