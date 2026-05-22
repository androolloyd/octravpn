#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

threshold="${OCTRA_COVERAGE_FAIL_UNDER:-20}"
output_dir="${OCTRA_COVERAGE_OUTPUT_DIR:-coverage}"

if ! cargo tarpaulin --version >/dev/null 2>&1; then
  cargo install cargo-tarpaulin --locked
fi

cargo tarpaulin \
  --workspace \
  --all-targets \
  --timeout 300 \
  --fail-under "$threshold" \
  --out Xml \
  --output-dir "$output_dir" \
  --exclude-files 'target/*' 'fuzz/*' 'crates/*/benches/*'
