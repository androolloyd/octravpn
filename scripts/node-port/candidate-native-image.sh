#!/usr/bin/env bash
# Build octra-candidate-native:<pin>: lite_node at the candidate commit, built
# with its own storage wrapper (controls/lib/gc_build.py), mcl and a Rust
# toolchain for the Circle WASM host library. The base image supplies opam
# 4.14.2 with upstream's locked dependencies.
#   scripts/node-port/candidate-native-image.sh <lite_node clone> [base image]
set -euo pipefail
upstream=$1
base=${2:-octra-native-oracle-recovery:20261017}
root=$(cd "$(dirname "$0")/../.." && pwd)
pin=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["upstream_commit"])' "$root/docs/rust-node/source-map-candidate.json")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -C "$upstream" archive --format=tar -o "$work/src.tar" "$pin"
name=octra-candidate-build-$$
docker run --name "$name" -v "$work:/in" --entrypoint bash "$base" -lc '
  set -euo pipefail
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null 2>&1
  source ~/.cargo/env
  mkdir -p /home/opam/pin && cd /home/opam/pin && tar xf /in/src.tar
  [ -d ../build/_build ] && cp -r ../build/_build . || true
  mkdir -p mcl/obj mcl/lib && make -s -C mcl MCL_FP_BIT=256 MCL_FR_BIT=256 lib/libmcl.a >/dev/null
  opam exec -- python3 controls/lib/gc_build.py -- dune build lib node_runtime circle_runtime net'
docker commit -c 'WORKDIR /home/opam/pin' "$name" "octra-candidate-native:${pin:0:8}" >/dev/null
docker rm "$name" >/dev/null
echo "octra-candidate-native:${pin:0:8}"
