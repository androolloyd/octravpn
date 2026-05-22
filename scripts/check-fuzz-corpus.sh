#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fuzz_dir="fuzz"
corpus_dir="${fuzz_dir}/corpus"

if [[ ! -d "$fuzz_dir" ]]; then
  echo "missing ${fuzz_dir}/ directory" >&2
  exit 1
fi

targets_file="$(mktemp)"
corpus_file="$(mktemp)"
stale_file="$(mktemp)"
trap 'rm -f "$targets_file" "$corpus_file" "$stale_file"' EXIT

(
  cd "$fuzz_dir"
  cargo fuzz list
) | sort > "$targets_file"

if [[ -d "$corpus_dir" ]]; then
  find "$corpus_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort > "$corpus_file"
else
  : > "$corpus_file"
fi

comm -23 "$corpus_file" "$targets_file" > "$stale_file"
if [[ -s "$stale_file" ]]; then
  echo "stale fuzz corpus directories found:" >&2
  sed 's/^/  /' "$stale_file" >&2
  echo "each fuzz/corpus/<target> directory must match a target from cargo fuzz list" >&2
  exit 1
fi

echo "fuzz corpus directories match registered cargo-fuzz targets"
