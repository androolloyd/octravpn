#!/usr/bin/env python3
"""Freeze source inputs and derive the private kernel image from the real recipe."""
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
DEST = Path(sys.argv[1]).resolve()
DEST.mkdir(mode=0o700)
recipe = (ROOT / 'docker/native-vpn/Dockerfile').read_text()
prefix = recipe.split('RUN --mount=', 1)[0]
prefix = '\n'.join(line for line in prefix.splitlines() if not line.startswith('RUN apt-get '))
copies = []
for line in prefix.splitlines():
    if line.startswith('COPY '):
        copies.extend(shlex.split(line)[1:-1])
for file in ['private_kernel.py', 'private_kernel_qualify.py', 'packet_target.py']:
    copies.append('octra/docker/native-vpn/' + file)
skip = {'target', 'out', '.git', 'node_modules', '__pycache__', '.cargo-cache', '.codex', '.agents', '.aws', '.ssh', '.env'}
hashes = {}


def install(path, relative):
    if path.is_symlink() or skip.intersection(relative.parts) or path.suffix in {'.key', '.pk', '.sk', '.p12', '.pfx'}:
        return
    if path.is_file():
        target = DEST / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        hashes[str(relative)] = hashlib.sha256(target.read_bytes()).hexdigest()


for item in sorted(set(copies)):
    relative = Path(item)
    original = ROOT.parent / relative
    if original.is_file():
        install(original, relative)
    elif relative.parts[0] in {'headscale-rs', 'octra-foundry'}:
        paths = subprocess.check_output(['git', '-C', str(original), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'])
        for raw in paths.split(b'\0'):
            if raw:
                install(original / raw.decode(), relative / raw.decode())
    else:
        if not original.is_dir():
            raise ValueError('missing source directory: ' + item)
        for path in original.rglob('*'):
            install(path, relative / path.relative_to(original))

build = r'''
RUN --mount=type=cache,id=octra-private-sdk-qualification-v1,target=/work/octra/target \
    RAYON_NUM_THREADS=8 CARGO_BUILD_JOBS=2 cargo test --locked --offline --release -p octra-node --lib --features private-kernel-qualification --no-run --message-format=json > /tmp/private-kernel-build.json
RUN --mount=type=cache,id=octra-private-sdk-qualification-v1,target=/work/octra/target \
    python3 -c 'import json,shutil,hashlib; rows=[json.loads(s) for s in open("/tmp/private-kernel-build.json") if s.startswith("{")]; bins=[r["executable"] for r in rows if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="octra_node" and r.get("profile",{}).get("test") and r.get("executable")]; assert len(bins)==1; shutil.copy2(bins[0],"/tmp/private-kernel-test"); json.dump({"test_sha256":hashlib.sha256(open(bins[0],"rb").read()).hexdigest()},open("/tmp/private-kernel-binary.json","w"))'
FROM ${RUNTIME_IMAGE}
USER root
ENV PYTHONDONTWRITEBYTECODE=1
RUN mkdir -p /work/octra/out /work/octra/crates/octra-node
COPY --from=binaries /tmp/private-kernel-test /usr/local/bin/private-kernel-test
COPY --from=binaries /tmp/private-kernel-binary.json /usr/local/share/private-kernel-binary.json
COPY octra/docker/native-vpn/private_kernel.py octra/docker/native-vpn/private_kernel_qualify.py octra/docker/native-vpn/packet_target.py /usr/local/bin/
WORKDIR /tmp
ENTRYPOINT ["python3", "-u", "/usr/local/bin/private_kernel_qualify.py"]
'''
(DEST / 'Dockerfile').write_text('ARG RUNTIME_IMAGE=octra-private-route-20261019:v6-admission\n' + prefix + '\n' + build)
hashes['Dockerfile'] = hashlib.sha256((DEST / 'Dockerfile').read_bytes()).hexdigest()
(DEST.parent / 'source-context.json').write_text(json.dumps({
    'recipe_sha256': hashlib.sha256(recipe.encode()).hexdigest(),
    'source_sha256': dict(sorted(hashes.items())),
}, indent=2) + '\n')
print(json.dumps({'context': str(DEST), 'files': len(hashes)}))
