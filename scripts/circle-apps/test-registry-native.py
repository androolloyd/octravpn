#!/usr/bin/env python3
"""Execute the registry WASM against a pristine copy of the pinned upstream host."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
PIN = "7f9be4489870645cfcc95439638cde40f5da9f50"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--runtime-fixture", type=pathlib.Path, help="Optional golden native input/output cases for the Rust node")
    args = parser.parse_args()
    wasm = ROOT / "target/wasm32-unknown-unknown/release/octravpn_circle_registry.wasm"
    if args.out.exists(): raise SystemExit("use a fresh evidence path")
    if args.runtime_fixture and args.runtime_fixture.exists(): raise SystemExit("use a fresh runtime fixture path")
    subprocess.run(["cargo", "build", "--locked", "-p", "octravpn-circle-registry", "--release", "--target", "wasm32-unknown-unknown"], cwd=ROOT, check=True)
    commit = subprocess.check_output(["git", "-C", str(args.upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != PIN: raise SystemExit("upstream commit differs from reviewed pin")
    source = args.upstream / "lib/core/circle_wasm_native"
    paths = [source / "Cargo.toml", source / "Cargo.lock", *sorted((source / "src").glob("*.rs"))]
    for path in paths:
        relative = path.relative_to(args.upstream)
        canonical = subprocess.check_output(["git", "-C", str(args.upstream), "show", f"HEAD:{relative}"])
        if path.read_bytes() != canonical: raise SystemExit(f"modified upstream source: {relative}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="octra-vpn-circle-") as temporary:
        crate = pathlib.Path(temporary) / "host"
        shutil.copytree(source, crate, ignore=shutil.ignore_patterns("target"))
        shutil.copyfile(ROOT / "scripts/circle-apps/registry_native_tests.rs", crate / "src/vpn_compatibility.rs")
        with (crate / "src/lib.rs").open("a") as output: output.write("\n#[cfg(test)] mod vpn_compatibility;\n")
        evidence = pathlib.Path(temporary) / "evidence.json"
        env = dict(os.environ, OCTRA_VPN_REGISTRY_WASM=str(wasm), OCTRA_VPN_CIRCLE_EVIDENCE=str(evidence))
        fixture = pathlib.Path(temporary) / "runtime-fixture.json"
        if args.runtime_fixture: env["OCTRA_VPN_RUNTIME_FIXTURE"] = str(fixture)
        subprocess.run(["cargo", "test", "--locked", "--manifest-path", str(crate / "Cargo.toml"), "--target-dir", str(ROOT / "target/circle-native-compat"), "--lib", "vpn_registry_circle_abi", "--", "--nocapture"], env=env, check=True)
        report = json.loads(evidence.read_text())
        report.update(upstream_commit=commit, wasm_sha256=hashlib.sha256(wasm.read_bytes()).hexdigest(),
            source_sha256={str(path.relative_to(args.upstream)):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})
        app = ROOT / "crates/octravpn-circle-registry"
        report["app_source_sha256"] = {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [app / "Cargo.toml", ROOT / "Cargo.lock", *sorted((app / "src").glob("*.rs"))]}
        args.out.write_text(json.dumps(report, indent=2) + "\n")
        if args.runtime_fixture:
            args.runtime_fixture.parent.mkdir(parents=True, exist_ok=True)
            snapshot = {key: report[key] for key in ("upstream_commit", "wasm_sha256", "source_sha256", "app_source_sha256")}
            snapshot["scope"] = "golden outputs of unmodified native engine; HFHE backend unused by registry"
            snapshot["cases"] = json.loads(fixture.read_text())
            args.runtime_fixture.write_text(json.dumps(snapshot, indent=2) + "\n")
        print("PASS: registry Circle ABI against pinned upstream Rust host")

if __name__ == "__main__": main()
