#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

threshold="${OCTRA_COVERAGE_FAIL_UNDER:-20}"
output_dir="${OCTRA_COVERAGE_OUTPUT_DIR:-coverage}"

if ! cargo tarpaulin --version >/dev/null 2>&1; then
  # No `--locked`: tarpaulin's pinned lock pulls cargo-platform 0.3.3
  # (rustc 1.91), which won't build on the repo's pinned 1.88. Letting
  # cargo resolve fresh uses the MSRV-aware resolver to pick a
  # compatible dependency set. (CI installs a prebuilt binary, so this
  # path is the local-dev fallback.)
  cargo install cargo-tarpaulin
fi

cargo tarpaulin \
  --workspace \
  --all-targets \
  --timeout 300 \
  --fail-under "$threshold" \
  --out Xml \
  --output-dir "$output_dir" \
  --exclude-files 'target/*' 'fuzz/*' 'crates/*/benches/*'
