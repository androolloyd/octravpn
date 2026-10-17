#!/usr/bin/env python3
"""Generate native epoch-tag lifecycle and actual Irmin-pack capability evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BUILDER = "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
WORKER = r'''
import hashlib,json,pathlib,shutil,subprocess
root=pathlib.Path.cwd();out=pathlib.Path('/output')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
inventory=json.loads(pathlib.Path('/inputs/inventory.json').read_text())
for name,expected in inventory.items():
 path=root/name
 if not path.exists() or sha(path)!=expected:
  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)
 if sha(path)!=expected:raise RuntimeError('native source differs: '+name)
program=root/'vpn_epoch_tags_oracle';program.mkdir()
shutil.copyfile('/inputs/main.ml',program/'main.ml')
(program/'dune').write_text('(executable (name main) (libraries octra_core octra_node_runtime lwt.unix unix yojson))\n')
commands=[]
def run(name,argv):
 commands.append({'name':name,'argv':argv});(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 result=subprocess.run(argv,capture_output=True,text=True)
 (out/(name+'.stdout')).write_text(result.stdout);(out/(name+'.stderr')).write_text(result.stderr)
 result.check_returncode();return result.stdout
version=run('compiler',['opam','exec','--','ocamlopt','-version']).strip()
if version!='4.14.2':raise RuntimeError('compiler differs')
run('packages',['opam','list','--installed','--columns=name,version','--short'])
run('build',['opam','exec','--','dune','build','./vpn_epoch_tags_oracle/main.exe'])
binary=root/'_build/default/vpn_epoch_tags_oracle/main.exe'
raw=run('oracle',[str(binary),str(root/'epoch-tags-fixture')])
result=json.loads(raw)
(out/'native.json').write_text(json.dumps(result,indent=2)+'\n')
(out/'worker-manifest.json').write_text(json.dumps({'compiler':version,'source_sha256':inventory,
 'executable_sha256':sha(binary),'worker_sha256':sha(pathlib.Path('/inputs/worker.py'))},indent=2)+'\n')
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--builder-image", default=BUILDER)
    args = parser.parse_args()
    inventory_path = ROOT / "docs/rust-node/source-map.json"
    mapping = json.loads(inventory_path.read_text())
    upstream = args.upstream.resolve()
    pin = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if pin != mapping["upstream_commit"]:
        raise RuntimeError("native pin differs")
    for name, expected in mapping["files"].items():
        if sha(upstream / name) != expected:
            raise RuntimeError("native source differs: " + name)
    if not args.builder_image.startswith("sha256:") or len(args.builder_image) != 71:
        raise RuntimeError("require immutable builder identity")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    inspected = subprocess.run(["docker", "image", "inspect", args.builder_image], capture_output=True, text=True)
    (out / "builder-inspect.json").write_text(inspected.stdout)
    (out / "builder-inspect.stderr").write_text(inspected.stderr)
    inspected.check_returncode()
    image = json.loads(inspected.stdout)[0]
    if image["Id"] != args.builder_image:
        raise RuntimeError("builder identity differs")
    oracle = ROOT / "scripts/node-port/epoch-tags-native.ml"
    helper_sha = sha(oracle)
    script_sha = sha(Path(__file__))
    with tempfile.TemporaryDirectory(prefix="octra-epoch-tags-") as temporary:
        inputs = Path(temporary)
        shutil.copyfile(oracle, inputs / "main.ml")
        (inputs / "inventory.json").write_text(json.dumps(mapping["files"]))
        (inputs / "worker.py").write_text(WORKER)
        argv = ["docker", "run", "--rm", "--network", "none", "--mount",
                f"type=bind,source={inputs},target=/inputs,readonly", "--mount",
                f"type=bind,source={upstream},target=/native,readonly", "--mount",
                f"type=bind,source={out},target=/output", args.builder_image,
                "bash", "-lc", "python3 /inputs/worker.py"]
        (out / "host-command.json").write_text(json.dumps(argv, indent=2) + "\n")
        result = subprocess.run(argv, capture_output=True, text=True)
        (out / "builder.stdout").write_text(result.stdout)
        (out / "builder.stderr").write_text(result.stderr)
        result.check_returncode()
    if sha(oracle) != helper_sha or sha(Path(__file__)) != script_sha:
        raise RuntimeError("oracle/generator source changed during build")
    report = dict(upstream_commit=pin, builder_image=args.builder_image,
                  source_map_sha256=sha(inventory_path), oracle_sha256=helper_sha,
                  generator_sha256=script_sha, platform=dict(os=image["Os"], architecture=image["Architecture"]),
                  scope="native named epoch tags, cleanup and readonly reopen; observed Irmin-pack status is backend-specific, not SQLite pack-GC parity; no physical pack collection invoked",
                  **json.loads((out / "worker-manifest.json").read_text()),
                  **json.loads((out / "native.json").read_text()))
    args.fixture.parent.mkdir(parents=True, exist_ok=True)
    args.fixture.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: unchanged native epoch-tag evidence: {args.fixture}")


if __name__ == "__main__":
    main()
