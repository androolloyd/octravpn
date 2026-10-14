#!/usr/bin/env python3
"""Prepare an unsigned Circle deployment package from tested WASM."""
import argparse, base64, hashlib, json, pathlib, shutil
ROOT = pathlib.Path(__file__).resolve().parents[2]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wasm", type=pathlib.Path, default=ROOT / "target/wasm32-unknown-unknown/release/octravpn_circle_registry.wasm")
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--node-evidence", type=pathlib.Path, help="Optional private native-node execution and restart evidence")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    code = args.wasm.read_bytes()
    digest = hashlib.sha256(code).hexdigest()
    evidence = json.loads(args.evidence.read_text())
    pin = json.loads((ROOT / "docs/rust-node/upstream.json").read_text())
    if not code.startswith(b"\0asm\x01\0\0\0") or len(code) > 4_194_304: raise SystemExit("invalid or oversized WASM")
    if evidence.get("passed") is not True or evidence.get("wasm_sha256") != digest or evidence.get("upstream_commit") != pin["commit"]:
        raise SystemExit("native host evidence does not match WASM and upstream pin")
    sources = evidence.get("app_source_sha256", {})
    if not sources: raise SystemExit("application source evidence missing")
    for name, expected in sources.items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit("application source differs from tested snapshot")
    node = None
    if args.node_evidence:
        node = json.loads(args.node_evidence.read_text())
        if (node.get("passed") is not True or node.get("reopen_qualified") is not True
            or node.get("wasm_sha256") != digest or node.get("upstream_commit") != pin["commit"]
            or not node.get("chain_id", "").startswith("octra-local-")):
            raise SystemExit("native-node evidence does not match tested WASM, pin and recovery")
    if args.out.exists(): raise SystemExit("use a fresh package directory")
    args.out.mkdir(parents=True)
    shutil.copyfile(args.wasm, args.out / "vpn-registry.wasm")
    payload = {"runtime":"wasm_v1", "privacy_class":"public", "browser_mode":"gateway_allowed", "resource_mode":"public_resources",
        "code_b64":base64.b64encode(code).decode(), "policy_hash":None, "members_root":None, "export_policy":None,
        "limits":{"max_stable_bytes":"33554432","max_assets_bytes":"0","max_inline_value":"4096","max_wasm_bytes":"4194304"}}
    (args.out / "deploy-payload.json").write_text(json.dumps(payload, indent=2) + "\n")
    shutil.copyfile(args.evidence, args.out / "native-host-evidence.json")
    if node: shutil.copyfile(args.node_evidence, args.out / "native-node-evidence.json")
    report = {"app":"vpn-registry", "upstream_commit":pin["commit"], "wasm_sha256":digest,
        "unsigned":True,"broadcast":False,"chain_qualified":False,
        "native_private_node_qualified":bool(node),
        "scope":"operator discovery; offers confer no stake, funding or tunnel admission",
        "prerequisites":([] if node else ["Circle deployment/rollback/recovery test on native node"])
            + ["app upgrade authority policy", "finalized event projection", "settlement app eligibility checks"]}
    (args.out / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"package":str(args.out),"wasm_sha256":digest,"broadcast":False},indent=2))

if __name__ == "__main__": main()
