#!/usr/bin/env bash
# Positive security fixtures plus negative controls against the real amlc VM.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
: "${AMLC:?Set AMLC to the pinned real compiler}"
OCTRA_BIN="${OCTRA_BIN:-../octra-foundry/target/debug/octra}"
"$AMLC" check program/main-v3.aml
"$AMLC" check program/main-v4.aml
"$AMLC" check program/main-v5.aml
"$AMLC" check program/private-admin-factory.aml
"$OCTRA_BIN" forge test --contract program/main-v4.aml --root program/tests/v4 --amlc "$AMLC"
"$OCTRA_BIN" forge test --contract program/main-v5.aml --root program/tests/v5 --amlc "$AMLC"
for fixture in false-result wrong-revert host-operation; do
  log=$(mktemp)
  if "$OCTRA_BIN" forge test --root "program/tests/negative/$fixture" --amlc "$AMLC" >"$log" 2>&1; then
    cat "$log"; rm -f "$log"
    echo "FAIL: negative control unexpectedly passed: $fixture" >&2; exit 1
  fi
  # A setup/compiler failure is not the intended negative-control result.
  if ! grep -q '^AML result: 0 passed; 1 failed' "$log"; then
    cat "$log"; rm -f "$log"
    echo "FAIL: negative control did not execute: $fixture" >&2; exit 1
  fi
  rm -f "$log"
  echo "PASS: negative control fails as expected: $fixture"
done
log=$(mktemp)
if "$OCTRA_BIN" forge test --contract program/main-v4.aml --root program/tests/v4 --amlc "$AMLC" --filter no_such_method >"$log" 2>&1; then
  cat "$log"; rm -f "$log"; echo 'FAIL: empty selection passed' >&2; exit 1
fi
grep -q 'no AML test methods matched' "$log"
rm -f "$log"
echo 'PASS: empty test selection fails'
