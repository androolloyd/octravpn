#!/usr/bin/env python3
"""Public source and exact executable identity; never includes local key stores."""
import hashlib,json,pathlib,subprocess
def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda:stream.read(1048576),b''):value.update(part)
    return value.hexdigest()
base=pathlib.Path('/work'); paths=[]
roots=[base/'octra'/name for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','crates','program','vendor','tests','pvac-sidecar','licenses','docker/native-vpn','docs/rust-node/source-map.json','docs/rust-node/upstream.json','docs/rust-node/network-authority.json','.cargo/config.toml','scripts/node-port']]+[base/'octra-foundry',base/'headscale-rs']
skip={'target','out','.git','node_modules','.cargo-cache','.codex','.agents','.aws'}
for root in roots:
    paths.extend([root] if root.is_file() else [p for p in root.rglob('*') if p.is_file() and not p.is_symlink() and not skip.intersection(p.relative_to(root).parts)])
records=[]; combined=hashlib.sha256(b'octra:native-vpn:qualification:v1\0')
for path in sorted(set(paths)):
    row={'path':str(path.relative_to(base)),'sha256':digest(path),'bytes':path.stat().st_size}
    records.append(row);combined.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
binaries={p.name:digest(p) for p in pathlib.Path('/tmp/native-binaries').iterdir()}
print(json.dumps({'source_sha256':combined.hexdigest(),'binaries':binaries,'profiles':{'octravpn-private-admin':'release','octra-node':'dev','octravpn':'dev','octravpn-node':'dev','octra':'dev','octra-single-fixture':'dev-test'},'rustc':subprocess.check_output(['rustc','-vV'],text=True),'files':records},indent=2))
