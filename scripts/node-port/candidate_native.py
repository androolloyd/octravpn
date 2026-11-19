"""Run an oracle against unchanged upstream sources at the candidate commit.

The image `octra-candidate-native:<pin>` holds lite_node at the candidate
commit, already built with upstream's own storage build wrapper
(controls/lib/gc_build.py) and `mcl`. Every run first checks each source file
in the image against docs/rust-node/source-map-candidate.json, then builds the
oracle as an extra dune executable beside the tree and feeds it `inputs` as
JSON on stdin. Nothing in the upstream tree is modified.

Build the image once (see scripts/node-port/candidate-native-image.sh).
"""
import hashlib, json, pathlib, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAP = ROOT / 'docs/rust-node/source-map-candidate.json'


def pin():
    return json.loads(MAP.read_text())['upstream_commit']


def image():
    return f'octra-candidate-native:{pin()[:8]}'


def run(oracle, libraries, inputs, *, timeout=3600):
    """Return (stdout JSON, provenance) for `oracle` (.ml path) run on `inputs`."""
    inventory = json.loads(MAP.read_text())
    oracle = pathlib.Path(oracle)
    with tempfile.TemporaryDirectory(prefix='octra-candidate-oracle-') as directory:
        work = pathlib.Path(directory)
        (work / 'main.ml').write_bytes(oracle.read_bytes())
        (work / 'dune').write_text(f'(executable (name main) (libraries {libraries}))\n')
        (work / 'input.json').write_text(json.dumps(inputs))
        (work / 'sources.sha256').write_text(''.join(f'{digest}  {path}\n' for path, digest in sorted(inventory['files'].items())))
        script = ('set -euo pipefail; source ~/.cargo/env; cd /home/opam/pin;'
                  ' sha256sum --check --quiet /oracle/sources.sha256;'
                  ' rm -rf vpn_port_oracle && mkdir vpn_port_oracle && cp /oracle/main.ml /oracle/dune vpn_port_oracle/;'
                  ' opam exec -- python3 controls/lib/gc_build.py -- dune build ./vpn_port_oracle/main.exe > /tmp/build.log 2>&1'
                  ' || { tail -60 /tmp/build.log >&2; exit 3; };'
                  ' ./_build/default/vpn_port_oracle/main.exe < /oracle/input.json')
        done = subprocess.run(['docker', 'run', '--rm', '--network', 'none',
                               '--mount', f'type=bind,source={work},target=/oracle,readonly',
                               '--entrypoint', 'bash', image(), '-lc', script],
                              capture_output=True, text=True, timeout=timeout)
        if done.returncode:
            raise SystemExit(f'candidate oracle failed ({done.returncode}):\n{done.stderr[-6000:]}')
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    provenance = dict(upstream_commit=inventory['upstream_commit'], image=image(),
                      oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
                      runner_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest())
    return json.loads(lines[-1]), provenance
