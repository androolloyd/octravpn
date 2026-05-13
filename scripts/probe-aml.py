#!/usr/bin/env python3
"""Probe Octra's AML compiler with snippets to learn the grammar."""
import json, urllib.request

RPC = "https://octra.network/rpc"

PROBES = {
    # Struct field assignment — direct vs via map
    "direct struct assign":  'contract Probe { struct R { x: int } state { r: R } constructor() { self.r.x = 5 } }',
    "map struct assign":     'contract Probe { struct R { x: int } state { rs: map[int]R } constructor() { self.rs[0].x = 5 } }',
    "struct local-then-write": 'contract Probe { struct R { x: int } state { r: R } constructor() { let r2 = self.r r2.x = 5 self.r = r2 } }',

    # Fn invocation patterns
    "self.fn()":             'contract Probe { state { x: int } constructor() { self.x = self.helper(5) } private fn helper(n: int): int { return n * 2 } }',
    "bare fn()":             'contract Probe { state { x: int } constructor() { self.x = helper(5) } private fn helper(n: int): int { return n * 2 } }',
    "public fn from priv":   'contract Probe { state { x: int } constructor() { self.x = doubled(5) } fn doubled(n: int): int { return n * 2 } }',

    # Address literals
    "address as 0":          'contract Probe { state { a: address } constructor() { self.a = 0 } }',
    "address as int":        'contract Probe { state { a: address } constructor() { self.a = 1 } }',
    "address as hex":        'contract Probe { state { a: address } constructor() { self.a = 0xdeadbeef } }',
    "address from string":   'contract Probe { state { a: address } constructor() { self.a = "octABCD" } }',
    "compare addr 0":        'contract Probe { state { a: address ok: bool } constructor() { self.ok = (self.a == 0) } }',
    "literal address in cmp": 'contract Probe { state { ok: bool } constructor() { self.ok = caller != 0 } }',

    # Operators
    "logical &&":            'contract Probe { state { ok: bool } constructor() { self.ok = caller != 0 && true } }',
    "logical || ":           'contract Probe { state { ok: bool } constructor() { self.ok = false || true } }',
    "ternary if-else":       'contract Probe { state { x: int } constructor() { self.x = if true { 1 } else { 0 } } }',
    "let with type":         'contract Probe { state { x: int } constructor() { let v: int = 42 self.x = v } }',

    # Returns
    "early return":          'contract Probe { state { x: int } constructor() { } fn early(): int { if true { return 1 } return 2 } }',
    "no return type":        'contract Probe { state { x: int } constructor() { self.helper() } private fn helper() { self.x = 1 } }',
}

def probe(label, src):
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "octra_compileAml",
        "params": [src, "Probe"],
    }).encode("utf-8")
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(RPC, data=req, headers={"Content-Type": "application/json"}),
            timeout=30,
        )
        raw = r.read().decode("utf-8", errors="replace")
        cleaned = "".join(ch if (ord(ch) >= 32 or ch in "\t\n\r") else " " for ch in raw)
        d = json.loads(cleaned)
        if "result" in d:
            return "OK"
        return "ERR: " + d.get("error", {}).get("message", "?")
    except Exception as e:
        return "EXCEPTION: " + str(e)

if __name__ == "__main__":
    for label, src in PROBES.items():
        result = probe(label, src)
        print(f"{label:<28} {result}")
