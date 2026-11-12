#!/usr/bin/env python3
"""Execute the registry WASM against a pristine copy of the pinned upstream host."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
PIN = "7f9be4489870645cfcc95439638cde40f5da9f50"
SOURCE = pathlib.Path("lib/core/circle_wasm_native")

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def app_sources():
    app = ROOT / "crates/octravpn-circle-registry"
    workspace = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml")]
    return {str(path.relative_to(ROOT)): digest(path)
        for path in [app / "Cargo.toml", *workspace, *sorted((app / "src").rglob("*.rs"))]
        if path.is_file()}

def committed_sources(upstream, revision):
    commit = subprocess.check_output(
        ["git", "-C", str(upstream), "rev-parse", "--verify", f"{revision}^{{commit}}"], text=True).strip()
    paths = subprocess.check_output(
        ["git", "-C", str(upstream), "ls-tree", "-rz", "--name-only", commit, "--", str(SOURCE)]).split(b"\0")
    sources = {}
    for raw in paths:
        if not raw: continue
        path = pathlib.Path(os.fsdecode(raw))
        path.relative_to(SOURCE)
        sources[path] = subprocess.check_output(["git", "-C", str(upstream), "show", f"{commit}:{path}"])
    if SOURCE / "Cargo.toml" not in sources or SOURCE / "src/lib.rs" not in sources:
        raise SystemExit("committed native host is incomplete")
    return commit, sources

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--commit", default=PIN, help="Exact native host revision (defaults to the historical reviewed pin)")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--runtime-fixture", type=pathlib.Path, help="Optional golden native input/output cases for the Rust node")
    parser.add_argument("--target-dir", type=pathlib.Path, default=ROOT / "target/circle-native-compat", help="Standalone native-host build directory")
    parser.add_argument("--wasm-target-dir", type=pathlib.Path, default=ROOT / "target", help="Registry WASM build directory")
    args = parser.parse_args()
    wasm_target = args.wasm_target_dir.resolve()
    host_target = args.target_dir.resolve()
    wasm = wasm_target / "wasm32-unknown-unknown/release/octravpn_circle_registry.wasm"
    if args.out.exists(): raise SystemExit("use a fresh evidence path")
    if args.runtime_fixture and args.runtime_fixture.exists(): raise SystemExit("use a fresh runtime fixture path")
    commit, sources = committed_sources(args.upstream, args.commit)
    app_hashes = app_sources()
    wasm_build = ["cargo", "build", "--locked", "-p", "octravpn-circle-registry", "--release", "--target", "wasm32-unknown-unknown", "--target-dir", str(wasm_target)]
    subprocess.run(wasm_build, cwd=ROOT, check=True)
    if app_sources() != app_hashes: raise SystemExit("registry sources changed during artifact build")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="octra-vpn-circle-") as temporary:
        crate = pathlib.Path(temporary) / "host"
        for path, canonical in sources.items():
            output = crate / path.relative_to(SOURCE)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(canonical)
        harness = ROOT / "scripts/circle-apps/registry_native_tests.rs"
        shutil.copyfile(harness, crate / "src/vpn_compatibility.rs")
        with (crate / "src/lib.rs").open("a") as output: output.write("\n#[cfg(test)] mod vpn_compatibility;\n")
        evidence = pathlib.Path(temporary) / "evidence.json"
        env = dict(os.environ, OCTRA_VPN_REGISTRY_WASM=str(wasm), OCTRA_VPN_CIRCLE_EVIDENCE=str(evidence))
        fixture = pathlib.Path(temporary) / "runtime-fixture.json"
        if args.runtime_fixture: env["OCTRA_VPN_RUNTIME_FIXTURE"] = str(fixture)
        subprocess.run(["cargo", "test", "--locked", "--manifest-path", str(crate / "Cargo.toml"), "--target-dir", str(host_target), "--lib", "vpn_registry_circle_abi", "--", "--nocapture"], env=env, check=True)
        report = json.loads(evidence.read_text())
        if app_sources() != app_hashes: raise SystemExit("registry sources changed during native qualification")
        report.update(upstream_commit=commit, wasm_sha256=digest(wasm),
            source_sha256={str(path):hashlib.sha256(canonical).hexdigest() for path, canonical in sources.items()},
            app_source_sha256=app_hashes,
            generator_sha256=digest(pathlib.Path(__file__)), harness_sha256=digest(harness),
            build={"registry_command":wasm_build,
                "native_host":"cargo test --locked --lib vpn_registry_circle_abi -- --nocapture",
                "source":"git show; only the separately hashed test harness is added",
                "rustc":subprocess.check_output(["rustc", "--version", "--verbose"], text=True).strip(),
                "cargo":subprocess.check_output(["cargo", "--version"], text=True).strip()})
        args.out.write_text(json.dumps(report, indent=2) + "\n")
        if args.runtime_fixture:
            args.runtime_fixture.parent.mkdir(parents=True, exist_ok=True)
            snapshot = {key: report[key] for key in ("upstream_commit", "wasm_sha256", "source_sha256", "app_source_sha256", "generator_sha256", "harness_sha256", "build")}
            snapshot["scope"] = "golden outputs of unmodified native engine; HFHE backend unused by registry"
            snapshot["cases"] = json.loads(fixture.read_text())
            args.runtime_fixture.write_text(json.dumps(snapshot, indent=2) + "\n")
        print("PASS: registry Circle ABI against pinned upstream Rust host")

if __name__ == "__main__": main()
